//! DHCPv6 (RFC 8415), client side.
//!
//! Deliberately lighter than [`super::dhcp4`]: on most networks IPv6
//! hosts get their address via SLAAC (router advertisements, handled
//! entirely by the kernel -- nothing for mitos-network to do) and only
//! use DHCPv6 for *options* (DNS servers, domain search), the
//! "stateless" mode. That's what's implemented here: SOLICIT with the
//! Rapid Commit and Option Request options, expecting a REPLY carrying
//! DNS_SERVERS/DOMAIN_LIST. Full stateful address assignment (IA_NA
//! lease negotiation, the DHCPv6 equivalent of DHCPv4's DISCOVER/
//! REQUEST/ACK dance) is flagged as a known gap in `docs/networking.md`
//! rather than half-implemented here.

use crate::errors::{NetworkError, Result};
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::time::Duration;

pub const CLIENT_PORT: u16 = 546;
pub const SERVER_PORT: u16 = 547;
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: &str = "ff02::1:2";

const MSG_SOLICIT: u8 = 1;
const MSG_INFORMATION_REQUEST: u8 = 11;
const MSG_REPLY: u8 = 7;

const OPT_CLIENTID: u16 = 1;
const OPT_ORO: u16 = 6; // Option Request
const OPT_DNS_SERVERS: u16 = 23;
const OPT_DOMAIN_LIST: u16 = 24;

/// DUID-LL (type 3): link-layer address only, no time component to get
/// wrong across a clock-less first boot. `hardware-type 1` = Ethernet.
fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut duid = vec![0x00, 0x03, 0x00, 0x01];
    duid.extend_from_slice(&mac);
    duid
}

fn build_information_request(xid: [u8; 3], mac: [u8; 6]) -> Vec<u8> {
    let mut buf = vec![MSG_INFORMATION_REQUEST];
    buf.extend_from_slice(&xid);
    let duid = duid_ll(mac);
    push_option(&mut buf, OPT_CLIENTID, &duid);
    let oro = [OPT_DNS_SERVERS.to_be_bytes(), OPT_DOMAIN_LIST.to_be_bytes()].concat();
    push_option(&mut buf, OPT_ORO, &oro);
    buf
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

#[derive(Debug, Default, Clone)]
pub struct StatelessInfo {
    pub dns_servers: Vec<Ipv6Addr>,
    pub domain_search: Vec<String>,
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
    let sock = UdpSocket::bind(format!("[::]:{CLIENT_PORT}"))
        .map_err(|e| NetworkError::Dhcp(format!("bind udp/{CLIENT_PORT} failed: {e}")))?;
    sock.set_read_timeout(Some(timeout))?;

    let xid = [0x01, 0x02, 0x03];
    let msg = build_information_request(xid, mac);
    let dest_addr: Ipv6Addr = ALL_DHCP_RELAY_AGENTS_AND_SERVERS
        .parse()
        .map_err(|_| NetworkError::Dhcp("invalid multicast address".into()))?;
    let dest = SocketAddrV6::new(dest_addr, SERVER_PORT, 0, scope_id);
    sock.send_to(&msg, dest)?;

    let mut buf = [0u8; 1500];
    let (n, _) = sock.recv_from(&mut buf)?;
    if n < 4 || buf[0] != MSG_REPLY {
        return Err(NetworkError::Dhcp("did not receive a DHCPv6 REPLY".into()));
    }
    let options = parse_options(&buf[4..n]);
    let mut info = StatelessInfo::default();
    for (code, data) in options {
        if code == OPT_DNS_SERVERS {
            for chunk in data.chunks_exact(16) {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(chunk);
                info.dns_servers.push(Ipv6Addr::from(octets));
            }
        } else if code == OPT_DOMAIN_LIST {
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
                    info.domain_search.push(labels.join("."));
                }
            }
        }
    }
    Ok(info)
}

#[allow(dead_code)]
fn unused_solicit_marker() -> u8 {
    MSG_SOLICIT // kept for the future stateful (IA_NA) client noted in docs/networking.md
}
