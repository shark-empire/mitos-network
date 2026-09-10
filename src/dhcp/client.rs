//! DHCPv4 client state machine: DISCOVER -> OFFER -> REQUEST -> ACK,
//! over a raw broadcast UDP socket bound to the target interface.
//!
//! Bound specifically with `SO_BINDTODEVICE` (Linux-only) rather than
//! just `0.0.0.0:68`, so activating two interfaces at once can't cross
//! each other's replies -- this matters once Ethernet+Wi-Fi+a VPN are
//! all plausibly coming up around the same time at boot.

use super::dhcp4::{self, MSG_ACK, MSG_NAK, MSG_OFFER};
use super::lease::Lease;
use crate::errors::{NetworkError, Result};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn bound_broadcast_socket(ifname: &str) -> Result<UdpSocket> {
    // SAFETY: standard socket(2)/setsockopt(2)/bind(2) sequence; every
    // buffer passed to libc is stack-local and lives for the call.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(NetworkError::Io(std::io::Error::last_os_error()));
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as u32,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as u32,
        );
        let cname = std::ffi::CString::new(ifname)
            .map_err(|_| NetworkError::Parse("bad interface name".into()))?;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cname.as_ptr() as *const libc::c_void,
            ifname.len() as u32,
        );

        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = dhcp4::CLIENT_PORT.to_be();
        addr.sin_addr.s_addr = libc::INADDR_ANY.to_be();
        let rc = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(NetworkError::Dhcp(format!(
                "bind to udp/68 on {ifname} failed: {e}"
            )));
        }
        Ok(<UdpSocket as std::os::unix::io::FromRawFd>::from_raw_fd(fd))
    }
}

fn get_mac(ifname: &str) -> Result<[u8; 6]> {
    let iface = crate::ip::interface::get_by_name(ifname)?;
    iface
        .hwaddr
        .ok_or_else(|| NetworkError::Dhcp(format!("{ifname} has no hardware address")))
}

fn random_xid() -> u32 {
    // No RNG dependency: mix the current time with our own pid, which
    // is exactly the entropy DHCP's collision-avoidance actually needs
    // (uniqueness against other clients on the same segment, not
    // cryptographic unpredictability).
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    nanos ^ (std::process::id() << 16)
}

/// Runs a full DISCOVER/OFFER/REQUEST/ACK exchange and returns the
/// resulting lease. Blocks the calling thread for up to `timeout`;
/// `connection::activation` calls this from a worker thread, not the
/// manager's own command-loop thread.
pub fn acquire(ifname: &str, _ifindex: i32, timeout: Duration) -> Result<Lease> {
    let mac = get_mac(ifname)?;
    let sock = bound_broadcast_socket(ifname)?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
    let broadcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, dhcp4::SERVER_PORT);
    let hostname = crate::dns::hostname::current();

    let deadline = Instant::now() + timeout;
    let xid = random_xid();

    // --- DISCOVER, retried with backoff until an OFFER arrives -------
    let mut buf = [0u8; 1500];
    let offer = loop {
        if Instant::now() >= deadline {
            return Err(NetworkError::Timeout(format!("no DHCPOFFER on {ifname}")));
        }
        let discover = dhcp4::build_discover(xid, mac, hostname.as_deref());
        sock.send_to(&discover, broadcast)?;
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(pkt) = dhcp4::parse(&buf[..n]) {
                    if pkt.xid == xid && pkt.message_type() == Some(MSG_OFFER) {
                        break pkt;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    };

    let server_id = offer
        .get_option(dhcp4::OPT_SERVER_ID)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(Ipv4Addr::from)
        .ok_or_else(|| NetworkError::Dhcp("OFFER missing server identifier".into()))?;

    // --- REQUEST, retried the same way until ACK/NAK ------------------
    let ack = loop {
        if Instant::now() >= deadline {
            return Err(NetworkError::Timeout(format!("no DHCPACK on {ifname}")));
        }
        let request = dhcp4::build_request(xid, mac, offer.yiaddr, server_id, hostname.as_deref());
        sock.send_to(&request, broadcast)?;
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(pkt) = dhcp4::parse(&buf[..n]) {
                    if pkt.xid != xid {
                        continue;
                    }
                    match pkt.message_type() {
                        Some(MSG_ACK) => break pkt,
                        Some(MSG_NAK) => {
                            return Err(NetworkError::Dhcp(format!(
                                "server {server_id} sent DHCPNAK"
                            )))
                        }
                        _ => continue,
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    };

    lease_from_ack(&ack, server_id)
}

fn lease_from_ack(ack: &dhcp4::Packet, server_id: Ipv4Addr) -> Result<Lease> {
    let prefixlen = ack
        .get_option(dhcp4::OPT_SUBNET_MASK)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(|m| u32::from_be_bytes(m).count_ones() as u8)
        .unwrap_or(24);
    let gateway = ack
        .get_option(dhcp4::OPT_ROUTER)
        .and_then(|b| b.get(0..4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(Ipv4Addr::from);
    let dns_servers = ack
        .get_option(dhcp4::OPT_DNS)
        .map(|b| {
            b.chunks_exact(4)
                .filter_map(|c| <[u8; 4]>::try_from(c).ok())
                .map(Ipv4Addr::from)
                .collect()
        })
        .unwrap_or_default();
    let domain = ack
        .get_option(dhcp4::OPT_DOMAIN_NAME)
        .map(|b| String::from_utf8_lossy(b).to_string());
    let lease_time_secs = ack
        .get_option(dhcp4::OPT_LEASE_TIME)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(3600);

    Ok(Lease {
        address: ack.yiaddr,
        prefixlen,
        gateway,
        dns_servers,
        domain,
        server_id,
        lease_time_secs,
        obtained_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

/// Renews (or, on failure, silently gives up and lets the caller fall
/// back to a fresh [`acquire`]) an existing lease via a unicast REQUEST.
pub fn renew(ifname: &str, lease: &Lease) -> Result<Lease> {
    let mac = get_mac(ifname)?;
    let sock = bound_broadcast_socket(ifname)?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
    let xid = random_xid();
    let request = dhcp4::build_renew_request(xid, mac, lease.address);
    sock.send_to(
        &request,
        SocketAddrV4::new(lease.server_id, dhcp4::SERVER_PORT),
    )?;

    let mut buf = [0u8; 1500];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(pkt) = dhcp4::parse(&buf[..n]) {
                    if pkt.xid == xid && pkt.message_type() == Some(MSG_ACK) {
                        return lease_from_ack(&pkt, lease.server_id);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(NetworkError::Timeout(format!(
        "no reply renewing lease on {ifname}"
    )))
}

/// Sends DHCPRELEASE for whatever lease is on record for `ifname`, if
/// any. Best-effort: a missing/unreadable lease file is not an error,
/// since "nothing to release" is the common case on a clean shutdown.
pub fn release(ifname: &str) -> Result<()> {
    let Some(lease) = crate::persistence::state::load_lease(ifname)? else {
        return Ok(());
    };
    let mac = get_mac(ifname)?;
    let sock = bound_broadcast_socket(ifname)?;
    let release = dhcp4::build_release(random_xid(), mac, lease.address, lease.server_id);
    sock.send_to(
        &release,
        SocketAddrV4::new(lease.server_id, dhcp4::SERVER_PORT),
    )?;
    crate::persistence::state::clear_lease(ifname)?;
    Ok(())
}
