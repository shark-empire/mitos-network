//! DHCPv6 (RFC 8415), client side.
//!
//! Two independent modes, since real networks mix and match:
//!
//! - **Stateless** ([`request_stateless_info`]): on most networks IPv6
//!   hosts get their *address* via SLAAC (router advertisements,
//!   handled entirely by the kernel -- nothing for mitos-network to
//!   do) and only need DHCPv6 for *options* it doesn't carry (DNS
//!   servers, domain search) unless the network also runs RDNSS (RFC
//!   8106). A single Information-Request/Reply exchange, no lease to
//!   track.
//! - **Stateful** ([`request_stateful_lease`] plus [`renew`]/[`rebind`]/
//!   [`release`]): the DHCPv6 equivalent of DHCPv4's DISCOVER/OFFER/
//!   REQUEST/ACK dance, for networks where the DHCPv6 server (not
//!   router advertisements) is the source of truth for address
//!   assignment. SOLICIT carries both an IA_NA (requesting an address)
//!   and the Rapid Commit option, so a server that supports rapid
//!   commit can skip straight to a Reply; otherwise this falls back to
//!   the full Solicit/Advertise/Request/Reply exchange.
//!
//! Renew/Rebind always go out multicast (to the same
//! All_DHCP_Relay_Agents_and_Servers group as Solicit) rather than
//! unicast to the server directly: RFC 8415 18.2.4 only allows
//! unicasting a Renew when the server granted a Server Unicast option
//! in an earlier Reply, which this client doesn't track, so it always
//! takes the multicast path that's valid regardless. A server that
//! *requires* unicast Renew is a rare enough configuration that this
//! client will just fall through to Rebind (also multicast, and
//! usable by any server servicing the link) instead, rather than
//! adding a second address-tracking mechanism for the shortcut alone.

use crate::errors::{NetworkError, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: &str = "ff02::1:2";

const MSG_SOLICIT: u8 = 1;
const MSG_ADVERTISE: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_RENEW: u8 = 5;
const MSG_REBIND: u8 = 6;
const MSG_REPLY: u8 = 7;
const MSG_RELEASE: u8 = 8;
const MSG_INFORMATION_REQUEST: u8 = 11;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IA_ADDR: u16 = 5;
const OPT_ORO: u16 = 6; // Option Request
const OPT_ELAPSED_TIME: u16 = 8;
const OPT_STATUS_CODE: u16 = 13;
const OPT_RAPID_COMMIT: u16 = 14;
const OPT_DNS_SERVERS: u16 = 23;
const OPT_DOMAIN_LIST: u16 = 24;

/// DUID-LL (type 3): link-layer address only, no time component to get
/// wrong across a clock-less first boot. `hardware-type 1` = Ethernet.
/// Stable for the interface's lifetime (it's derived from the MAC),
/// which is exactly what RFC 8415 wants a client to keep using across
/// Renew/Rebind and, ideally, reboots -- so this needs no separate
/// persistence of its own.
fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut duid = vec![0x00, 0x03, 0x00, 0x01];
    duid.extend_from_slice(&mac);
    duid
}

fn push_option(buf: &mut Vec<u8>, code: u16, data: &[u8]) {
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn parse_options(mut buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let code = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            break;
        }
        out.push((code, buf[4..4 + len].to_vec()));
        buf = &buf[4 + len..];
    }
    out
}

/// Centiseconds since `start`, saturating at the 16-bit field's max
/// (RFC 8415's own convention for "a long time", not an error).
fn elapsed_cs(start: Instant) -> u16 {
    let ms = start.elapsed().as_millis();
    (ms / 10).min(u16::MAX as u128) as u16
}

fn random_xid3() -> [u8; 3] {
    // Same "mix wall-clock time with our own pid" reasoning as
    // `dhcp::client::random_xid` -- collision-avoidance against other
    // transactions, not cryptographic unpredictability.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let mixed = nanos ^ (std::process::id() << 8);
    [(mixed >> 16) as u8, (mixed >> 8) as u8, mixed as u8]
}

fn multicast_dest(scope_id: u32) -> Result<SocketAddrV6> {
    let addr: Ipv6Addr = ALL_DHCP_RELAY_AGENTS_AND_SERVERS
        .parse()
        .map_err(|_| NetworkError::Dhcp("invalid multicast address".into()))?;
    Ok(SocketAddrV6::new(addr, SERVER_PORT, 0, scope_id))
}

fn bind_client_socket(timeout: Duration) -> Result<UdpSocket> {
    let sock = UdpSocket::bind(format!("[::]:{CLIENT_PORT}"))
        .map_err(|e| NetworkError::Dhcp(format!("bind udp/{CLIENT_PORT} failed: {e}")))?;
    sock.set_read_timeout(Some(timeout))?;
    Ok(sock)
}

fn parse_dns_and_domain(options: &[(u16, Vec<u8>)]) -> (Vec<Ipv6Addr>, Vec<String>) {
    let mut dns_servers = Vec::new();
    let mut domain_search = Vec::new();
    for (code, data) in options {
        if *code == OPT_DNS_SERVERS {
            for chunk in data.chunks_exact(16) {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(chunk);
                dns_servers.push(Ipv6Addr::from(octets));
            }
        } else if *code == OPT_DOMAIN_LIST {
            // RFC 1035 DNS-name encoding (length-prefixed labels); a
            // minimal decoder, sufficient for a flat search-domain list.
            let mut i = 0;
            while i < data.len() {
                let mut labels = Vec::new();
                while i < data.len() && data[i] != 0 {
                    let len = data[i] as usize;
                    i += 1;
                    if i + len > data.len() {
                        break;
                    }
                    labels.push(String::from_utf8_lossy(&data[i..i + len]).to_string());
                    i += len;
                }
                i += 1; // skip terminating zero
                if !labels.is_empty() {
                    domain_search.push(labels.join("."));
                }
            }
        }
    }
    (dns_servers, domain_search)
}

// ---- Stateless (Information-Request) -----------------------------------

#[derive(Debug, Default, Clone)]
pub struct StatelessInfo {
    pub dns_servers: Vec<Ipv6Addr>,
    pub domain_search: Vec<String>,
}

fn build_information_request(xid: [u8; 3], mac: [u8; 6]) -> Vec<u8> {
    let mut buf = vec![MSG_INFORMATION_REQUEST];
    buf.extend_from_slice(&xid);
    push_option(&mut buf, OPT_CLIENTID, &duid_ll(mac));
    let oro = [OPT_DNS_SERVERS.to_be_bytes(), OPT_DOMAIN_LIST.to_be_bytes()].concat();
    push_option(&mut buf, OPT_ORO, &oro);
    buf
}

/// Sends an Information-Request and returns whatever stateless options
/// the network's DHCPv6 server hands back. Used to supplement SLAAC
/// with DNS servers, which router advertisements alone don't carry
/// unless the network also runs RDNSS (RFC 8106).
pub fn request_stateless_info(
    ifname: &str,
    mac: [u8; 6],
    timeout: Duration,
) -> Result<StatelessInfo> {
    let scope_id = crate::ip::interface::get_by_name(ifname)?.index as u32;
    let sock = bind_client_socket(timeout)?;

    let xid = random_xid3();
    let msg = build_information_request(xid, mac);
    sock.send_to(&msg, multicast_dest(scope_id)?)?;

    let mut buf = [0u8; 1500];
    let (n, _) = sock.recv_from(&mut buf)?;
    if n < 4 || buf[0] != MSG_REPLY || buf[1..4] != xid {
        return Err(NetworkError::Dhcp("did not receive a matching DHCPv6 REPLY".into()));
    }
    let options = parse_options(&buf[4..n]);
    let (dns_servers, domain_search) = parse_dns_and_domain(&options);
    Ok(StatelessInfo { dns_servers, domain_search })
}

// ---- Stateful (IA_NA) ----------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease6 {
    pub address: Ipv6Addr,
    /// Always 128 for a DHCPv6 IA_NA lease (it names one host, not a
    /// subnet) -- kept explicit for symmetry with `ip::address::add`'s
    /// signature, which every other address source in this crate also
    /// goes through.
    pub prefixlen: u8,
    pub iaid: u32,
    /// The granting server's DUID, opaque bytes -- required to address
    /// a later Release at the right server (Renew/Rebind don't need it
    /// themselves, since both go out multicast, but Release should
    /// still identify which server's binding it's releasing).
    pub server_id: Vec<u8>,
    #[serde(default)]
    pub dns_servers: Vec<Ipv6Addr>,
    #[serde(default)]
    pub domain_search: Vec<String>,
    pub preferred_lifetime_secs: u32,
    pub valid_lifetime_secs: u32,
    /// Server-suggested renew/rebind times; 0 means "not suggested,
    /// client's choice" per RFC 8415 21.4, handled in
    /// `renewal_time`/`rebind_time` below.
    pub t1_secs: u32,
    pub t2_secs: u32,
    /// Unix timestamp; see `dhcp::lease::Lease::obtained_at_unix` for
    /// why this is stored as an integer rather than a `SystemTime`.
    pub obtained_at_unix: u64,
}

impl Lease6 {
    pub fn obtained_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.obtained_at_unix)
    }
    pub fn renewal_time(&self) -> SystemTime {
        let t1 = if self.t1_secs > 0 {
            self.t1_secs as u64
        } else {
            self.valid_lifetime_secs as u64 / 2
        };
        self.obtained_at() + Duration::from_secs(t1)
    }
    pub fn rebind_time(&self) -> SystemTime {
        let t2 = if self.t2_secs > 0 {
            self.t2_secs as u64
        } else {
            self.valid_lifetime_secs as u64 * 7 / 8
        };
        self.obtained_at() + Duration::from_secs(t2)
    }
    pub fn expires_at(&self) -> SystemTime {
        self.obtained_at() + Duration::from_secs(self.valid_lifetime_secs as u64)
    }
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at()
    }
}

/// One parsed IA_NA option: its own fixed header plus whatever an
/// IAADDR/StatusCode suboption inside it said. `address` is `None` if
/// the IA_NA carried no IAADDR suboption at all (e.g. a server
/// declining with only a Status Code).
struct IaNa {
    iaid: u32,
    t1: u32,
    t2: u32,
    address: Option<Ipv6Addr>,
    preferred_lifetime: u32,
    valid_lifetime: u32,
    status: Option<(u16, String)>,
}

fn parse_ia_na(data: &[u8]) -> Option<IaNa> {
    if data.len() < 12 {
        return None;
    }
    let iaid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let t1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let t2 = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let mut ia = IaNa {
        iaid,
        t1,
        t2,
        address: None,
        preferred_lifetime: 0,
        valid_lifetime: 0,
        status: None,
    };
    for (code, sub) in parse_options(&data[12..]) {
        match code {
            OPT_IA_ADDR if sub.len() >= 24 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&sub[0..16]);
                ia.address = Some(Ipv6Addr::from(octets));
                ia.preferred_lifetime = u32::from_be_bytes([sub[16], sub[17], sub[18], sub[19]]);
                ia.valid_lifetime = u32::from_be_bytes([sub[20], sub[21], sub[22], sub[23]]);
            }
            OPT_STATUS_CODE if sub.len() >= 2 => {
                ia.status = Some((
                    u16::from_be_bytes([sub[0], sub[1]]),
                    String::from_utf8_lossy(&sub[2..]).to_string(),
                ));
            }
            _ => {}
        }
    }
    Some(ia)
}

fn oro() -> Vec<u8> {
    [OPT_DNS_SERVERS.to_be_bytes(), OPT_DOMAIN_LIST.to_be_bytes()].concat()
}

fn build_solicit(xid: [u8; 3], mac: [u8; 6], iaid: u32, elapsed: u16) -> Vec<u8> {
    let mut buf = vec![MSG_SOLICIT];
    buf.extend_from_slice(&xid);
    push_option(&mut buf, OPT_CLIENTID, &duid_ll(mac));
    push_option(&mut buf, OPT_ELAPSED_TIME, &elapsed.to_be_bytes());
    push_option(&mut buf, OPT_RAPID_COMMIT, &[]);
    push_option(&mut buf, OPT_ORO, &oro());
    let mut ia_na = Vec::new();
    ia_na.extend_from_slice(&iaid.to_be_bytes());
    ia_na.extend_from_slice(&0u32.to_be_bytes()); // T1: let the server decide
    ia_na.extend_from_slice(&0u32.to_be_bytes()); // T2: let the server decide
    push_option(&mut buf, OPT_IA_NA, &ia_na);
    buf
}

/// Builds a Request, Renew, or Rebind -- identical shape apart from the
/// message type and whether a Server ID is included (Request/Renew
/// address a specific server and must echo its ID back; Rebind is
/// deliberately open to whichever server on the link can answer it, so
/// it omits one, per RFC 8415 18.2.5).
fn build_ia_request(
    msg_type: u8,
    xid: [u8; 3],
    mac: [u8; 6],
    server_id: Option<&[u8]>,
    iaid: u32,
    addr: Ipv6Addr,
    preferred: u32,
    valid: u32,
    elapsed: u16,
) -> Vec<u8> {
    let mut buf = vec![msg_type];
    buf.extend_from_slice(&xid);
    push_option(&mut buf, OPT_CLIENTID, &duid_ll(mac));
    if let Some(sid) = server_id {
        push_option(&mut buf, OPT_SERVERID, sid);
    }
    push_option(&mut buf, OPT_ELAPSED_TIME, &elapsed.to_be_bytes());
    push_option(&mut buf, OPT_ORO, &oro());
    let mut ia_addr = Vec::new();
    ia_addr.extend_from_slice(&addr.octets());
    ia_addr.extend_from_slice(&preferred.to_be_bytes());
    ia_addr.extend_from_slice(&valid.to_be_bytes());
    let mut ia_na = Vec::new();
    ia_na.extend_from_slice(&iaid.to_be_bytes());
    ia_na.extend_from_slice(&0u32.to_be_bytes());
    ia_na.extend_from_slice(&0u32.to_be_bytes());
    push_option(&mut ia_na, OPT_IA_ADDR, &ia_addr);
    push_option(&mut buf, OPT_IA_NA, &ia_na);
    buf
}

/// One receive attempt, bounded by the socket's configured read
/// timeout: a timed-out or short/malformed/mismatched-transaction
/// datagram is surfaced as `Err` rather than retried internally, same
/// division of responsibility as `request_stateless_info` already
/// uses -- callers that want retries (`manager`'s lease-check tick,
/// `connection::activation`) loop at a higher level instead of this
/// function guessing how many attempts is enough for them.
fn recv_matching(sock: &UdpSocket, want_xid: [u8; 3]) -> Result<(u8, Vec<(u16, Vec<u8>)>)> {
    let mut buf = [0u8; 1500];
    let (n, _) = sock.recv_from(&mut buf)?;
    if n < 4 {
        return Err(NetworkError::Dhcp("DHCPv6 response too short".into()));
    }
    if buf[1..4] != want_xid {
        return Err(NetworkError::Dhcp("DHCPv6 response transaction id mismatch".into()));
    }
    Ok((buf[0], parse_options(&buf[4..n])))
}

fn require_success(ia: &IaNa) -> Result<()> {
    if let Some((code, msg)) = &ia.status {
        if *code != 0 {
            return Err(NetworkError::Dhcp(format!(
                "DHCPv6 server declined (status {code}): {msg}"
            )));
        }
    }
    Ok(())
}

fn lease_from_reply(
    ia: IaNa,
    server_id: Vec<u8>,
    dns_servers: Vec<Ipv6Addr>,
    domain_search: Vec<String>,
) -> Result<Lease6> {
    require_success(&ia)?;
    let address = ia
        .address
        .ok_or_else(|| NetworkError::Dhcp("DHCPv6 REPLY carried no address".into()))?;
    Ok(Lease6 {
        address,
        prefixlen: 128,
        iaid: ia.iaid,
        server_id,
        dns_servers,
        domain_search,
        preferred_lifetime_secs: ia.preferred_lifetime,
        valid_lifetime_secs: ia.valid_lifetime,
        t1_secs: ia.t1,
        t2_secs: ia.t2,
        obtained_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

/// Runs a stateful DHCPv6 exchange for one IA_NA address: Solicit
/// (with Rapid Commit) first, falling back to Solicit/Advertise/
/// Request/Reply if no server answers the rapid-commit shortcut.
/// `iaid` is derived from the interface index -- stable for the life
/// of the interface, which is what RFC 8415 wants an IAID to be, and
/// simpler than persisting a separately-generated one across restarts.
pub fn request_stateful_lease(ifname: &str, mac: [u8; 6], timeout: Duration) -> Result<Lease6> {
    let iface = crate::ip::interface::get_by_name(ifname)?;
    let iaid = iface.index as u32;
    let sock = bind_client_socket(timeout)?;
    let dest = multicast_dest(iface.index as u32)?;
    let start = Instant::now();

    let solicit_xid = random_xid3();
    let solicit = build_solicit(solicit_xid, mac, iaid, elapsed_cs(start));
    sock.send_to(&solicit, dest)?;
    let (msg_type, options) = recv_matching(&sock, solicit_xid)?;

    let server_id = options
        .iter()
        .find(|(c, _)| *c == OPT_SERVERID)
        .map(|(_, v)| v.clone())
        .ok_or_else(|| NetworkError::Dhcp("DHCPv6 response carried no Server ID".into()))?;
    let ia = options
        .iter()
        .find(|(c, _)| *c == OPT_IA_NA)
        .and_then(|(_, v)| parse_ia_na(v))
        .ok_or_else(|| NetworkError::Dhcp("DHCPv6 response carried no IA_NA".into()))?;

    if msg_type == MSG_REPLY {
        // Rapid commit: the server answered the Solicit directly.
        let (dns, domains) = parse_dns_and_domain(&options);
        return lease_from_reply(ia, server_id, dns, domains);
    }
    if msg_type != MSG_ADVERTISE {
        return Err(NetworkError::Dhcp(format!(
            "unexpected DHCPv6 message type {msg_type} in response to Solicit"
        )));
    }
    require_success(&ia)?;
    let advertised_addr = ia
        .address
        .ok_or_else(|| NetworkError::Dhcp("DHCPv6 ADVERTISE carried no address".into()))?;

    let request_xid = random_xid3();
    let request = build_ia_request(
        MSG_REQUEST,
        request_xid,
        mac,
        Some(&server_id),
        iaid,
        advertised_addr,
        ia.preferred_lifetime,
        ia.valid_lifetime,
        elapsed_cs(start),
    );
    sock.send_to(&request, dest)?;
    let (msg_type, options) = recv_matching(&sock, request_xid)?;
    if msg_type != MSG_REPLY {
        return Err(NetworkError::Dhcp(format!(
            "unexpected DHCPv6 message type {msg_type} in response to Request"
        )));
    }
    let server_id = options
        .iter()
        .find(|(c, _)| *c == OPT_SERVERID)
        .map(|(_, v)| v.clone())
        .unwrap_or(server_id);
    let ia = options
        .iter()
        .find(|(c, _)| *c == OPT_IA_NA)
        .and_then(|(_, v)| parse_ia_na(v))
        .ok_or_else(|| NetworkError::Dhcp("DHCPv6 REPLY carried no IA_NA".into()))?;
    let (dns, domains) = parse_dns_and_domain(&options);
    lease_from_reply(ia, server_id, dns, domains)
}

fn renew_or_rebind(
    msg_type: u8,
    ifname: &str,
    mac: [u8; 6],
    lease: &Lease6,
    timeout: Duration,
    include_server_id: bool,
) -> Result<Lease6> {
    let iface = crate::ip::interface::get_by_name(ifname)?;
    let sock = bind_client_socket(timeout)?;
    let dest = multicast_dest(iface.index as u32)?;
    let start = Instant::now();

    let xid = random_xid3();
    let server_id_ref = if include_server_id { Some(lease.server_id.as_slice()) } else { None };
    let msg = build_ia_request(
        msg_type,
        xid,
        mac,
        server_id_ref,
        lease.iaid,
        lease.address,
        lease.preferred_lifetime_secs,
        lease.valid_lifetime_secs,
        elapsed_cs(start),
    );
    sock.send_to(&msg, dest)?;
    let (got_type, options) = recv_matching(&sock, xid)?;
    if got_type != MSG_REPLY {
        return Err(NetworkError::Dhcp(format!(
            "unexpected DHCPv6 message type {got_type} in response to Renew/Rebind"
        )));
    }
    let server_id = options
        .iter()
        .find(|(c, _)| *c == OPT_SERVERID)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| lease.server_id.clone());
    let ia = options
        .iter()
        .find(|(c, _)| *c == OPT_IA_NA)
        .and_then(|(_, v)| parse_ia_na(v))
        .ok_or_else(|| NetworkError::Dhcp("DHCPv6 REPLY carried no IA_NA".into()))?;
    let (dns, domains) = parse_dns_and_domain(&options);
    lease_from_reply(ia, server_id, dns, domains)
}

/// Unicast-addressed *in content* (via the Server ID option) but sent
/// multicast -- see the module doc comment for why.
pub fn renew(ifname: &str, mac: [u8; 6], lease: &Lease6, timeout: Duration) -> Result<Lease6> {
    renew_or_rebind(MSG_RENEW, ifname, mac, lease, timeout, true)
}

/// Open to any server on the link, used when `renew` fails or times
/// out (the binding's original server may be unreachable).
pub fn rebind(ifname: &str, mac: [u8; 6], lease: &Lease6, timeout: Duration) -> Result<Lease6> {
    renew_or_rebind(MSG_REBIND, ifname, mac, lease, timeout, false)
}

/// Tells the server this client is done with the lease. Best-effort by
/// design: RFC 8415 18.2.7 has the client stop using the address
/// immediately regardless of whether a Reply ever arrives, so a
/// missing/timed-out response isn't treated as failure here -- the
/// caller (`connection::deactivation`) shouldn't be blocked from
/// tearing down an interface by a server that's gone quiet.
pub fn release(ifname: &str, mac: [u8; 6], lease: &Lease6, timeout: Duration) -> Result<()> {
    let iface = crate::ip::interface::get_by_name(ifname)?;
    let sock = bind_client_socket(timeout)?;
    let dest = multicast_dest(iface.index as u32)?;
    let xid = random_xid3();
    let msg = build_ia_request(
        MSG_RELEASE,
        xid,
        mac,
        Some(&lease.server_id),
        lease.iaid,
        lease.address,
        lease.preferred_lifetime_secs,
        lease.valid_lifetime_secs,
        0,
    );
    sock.send_to(&msg, dest)?;
    let _ = recv_matching(&sock, xid); // best-effort; see doc comment above
    Ok(())
}

/// Convenience wrapper for `connection::deactivation`: loads whatever
/// v6 lease was persisted for this interface (if any -- a
/// SLAAC/stateless-only connection has none, which isn't an error
/// here) and releases it, mirroring `dhcp::client::release`'s shape
/// for the v4 case.
pub fn release_persisted(ifname: &str) -> Result<()> {
    let Some(lease) = crate::persistence::state::load_lease6(ifname)? else {
        return Ok(());
    };
    let mac = crate::dhcp::get_mac(ifname)?;
    let _ = release(ifname, mac, &lease, Duration::from_secs(2));
    crate::persistence::state::clear_lease6(ifname)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ia_na_option_round_trips_through_parse() {
        let mut ia_na = Vec::new();
        ia_na.extend_from_slice(&42u32.to_be_bytes()); // iaid
        ia_na.extend_from_slice(&100u32.to_be_bytes()); // t1
        ia_na.extend_from_slice(&160u32.to_be_bytes()); // t2
        let mut ia_addr = Vec::new();
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        ia_addr.extend_from_slice(&addr.octets());
        ia_addr.extend_from_slice(&300u32.to_be_bytes()); // preferred
        ia_addr.extend_from_slice(&600u32.to_be_bytes()); // valid
        push_option(&mut ia_na, OPT_IA_ADDR, &ia_addr);

        let parsed = parse_ia_na(&ia_na).expect("should parse");
        assert_eq!(parsed.iaid, 42);
        assert_eq!(parsed.t1, 100);
        assert_eq!(parsed.t2, 160);
        assert_eq!(parsed.address, Some(addr));
        assert_eq!(parsed.preferred_lifetime, 300);
        assert_eq!(parsed.valid_lifetime, 600);
        assert!(parsed.status.is_none());
    }

    #[test]
    fn status_code_option_is_parsed() {
        let mut ia_na = Vec::new();
        ia_na.extend_from_slice(&1u32.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes());
        ia_na.extend_from_slice(&0u32.to_be_bytes());
        let mut status = Vec::new();
        status.extend_from_slice(&2u16.to_be_bytes()); // NoAddrsAvail
        status.extend_from_slice(b"no addresses available");
        push_option(&mut ia_na, OPT_STATUS_CODE, &status);

        let parsed = parse_ia_na(&ia_na).unwrap();
        assert_eq!(parsed.status, Some((2, "no addresses available".to_string())));
        assert!(require_success(&parsed).is_err());
    }

    #[test]
    fn lease_falls_back_to_rfc_default_renew_times_when_server_omits_t1_t2() {
        let ia = IaNa {
            iaid: 1,
            t1: 0,
            t2: 0,
            address: Some(Ipv6Addr::LOCALHOST),
            preferred_lifetime: 1000,
            valid_lifetime: 2000,
            status: None,
        };
        let lease = lease_from_reply(ia, vec![1, 2, 3], vec![], vec![]).unwrap();
        // T1 defaults to 50% of valid lifetime, T2 to 87.5%.
        assert_eq!(
            lease.renewal_time().duration_since(lease.obtained_at()).unwrap(),
            Duration::from_secs(1000)
        );
        assert_eq!(
            lease.rebind_time().duration_since(lease.obtained_at()).unwrap(),
            Duration::from_secs(1750)
        );
    }
}
