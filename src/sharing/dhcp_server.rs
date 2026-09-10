//! A minimal DHCPv4 server for clients of a hotspot/shared connection.
//! Reuses `dhcp::dhcp4`'s packet (de)serialization -- the wire format
//! is identical, it's just OFFER/ACK coming from mitos-network instead
//! of DISCOVER/REQUEST going to some upstream server.

use crate::dhcp::dhcp4::{self, MSG_DISCOVER, MSG_REQUEST};
use crate::errors::{NetworkError, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct DhcpServerConfig {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub prefixlen: u8,
    pub lease_time_secs: u32,
    pub dns_servers: Vec<Ipv4Addr>,
}

struct LeaseTable {
    /// MAC -> assigned address. A `HashMap` is plenty for a hotspot's
    /// realistic handful of clients; this is not meant to scale to an
    /// enterprise DHCP server's client count.
    by_mac: HashMap<[u8; 6], Ipv4Addr>,
    next_candidate: u32,
}

impl LeaseTable {
    fn allocate(&mut self, mac: [u8; 6], cfg: &DhcpServerConfig) -> Option<Ipv4Addr> {
        if let Some(existing) = self.by_mac.get(&mac) {
            return Some(*existing);
        }
        let start = u32::from(cfg.pool_start);
        let end = u32::from(cfg.pool_end);
        if end < start {
            return None; // misconfigured pool; caller validated ranges before start()
        }
        let taken: std::collections::HashSet<u32> =
            self.by_mac.values().map(|a| u32::from(*a)).collect();
        for _ in 0..=(end - start) {
            let candidate = start + (self.next_candidate - start) % (end - start + 1);
            self.next_candidate = candidate + 1;
            if !taken.contains(&candidate) {
                let addr = Ipv4Addr::from(candidate);
                self.by_mac.insert(mac, addr);
                return Some(addr);
            }
        }
        None // pool exhausted
    }
}

pub struct ServerHandle {
    stop: Arc<Mutex<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServerHandle {
    pub fn stop(mut self) {
        *self.stop.lock().unwrap() = true;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn start(cfg: DhcpServerConfig) -> Result<ServerHandle> {
    let sock = bound_server_socket(&cfg.interface)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?; // periodic wakeups to check `stop`

    let stop = Arc::new(Mutex::new(false));
    let stop_clone = stop.clone();
    let thread = std::thread::Builder::new()
        .name(format!("mitos-dhcpd-{}", cfg.interface))
        .spawn(move || run(sock, cfg, stop_clone))?;

    Ok(ServerHandle {
        stop,
        thread: Some(thread),
    })
}

fn bound_server_socket(ifname: &str) -> Result<UdpSocket> {
    // SAFETY: standard socket/setsockopt/bind sequence; all buffers are
    // stack-local for the duration of the call.
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
            &one as *const _ as *const _,
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const _,
            4,
        );
        let cname = std::ffi::CString::new(ifname).unwrap();
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cname.as_ptr() as *const _,
            ifname.len() as u32,
        );
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = dhcp4::SERVER_PORT.to_be();
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
                "bind udp/67 on {ifname} failed: {e}"
            )));
        }
        Ok(<UdpSocket as std::os::unix::io::FromRawFd>::from_raw_fd(fd))
    }
}

fn run(sock: UdpSocket, cfg: DhcpServerConfig, stop: Arc<Mutex<bool>>) {
    let mut leases = LeaseTable {
        by_mac: HashMap::new(),
        next_candidate: u32::from(cfg.pool_start),
    };
    let mut buf = [0u8; 1500];
    loop {
        if *stop.lock().unwrap() {
            return;
        }
        let (n, _src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                crate::logging::logger::error(&format!("dhcp server on {}: {e}", cfg.interface));
                continue;
            }
        };
        let Some(pkt) = dhcp4::parse(&buf[..n]) else {
            continue;
        };
        let reply = match pkt.message_type() {
            Some(MSG_DISCOVER) => leases
                .allocate(pkt.chaddr, &cfg)
                .map(|addr| build_reply(&pkt, addr, &cfg, dhcp4::MSG_OFFER)),
            Some(MSG_REQUEST) => {
                let requested = pkt
                    .get_option(dhcp4::OPT_REQUESTED_IP)
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map(Ipv4Addr::from)
                    .unwrap_or(pkt.ciaddr);
                if leases.by_mac.get(&pkt.chaddr) == Some(&requested) {
                    Some(build_reply(&pkt, requested, &cfg, dhcp4::MSG_ACK))
                } else {
                    Some(build_reply(&pkt, requested, &cfg, dhcp4::MSG_NAK))
                }
            }
            _ => None,
        };
        if let Some(reply_bytes) = reply {
            let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, dhcp4::CLIENT_PORT);
            let _ = sock.send_to(&reply_bytes, dest);
        }
    }
}

fn build_reply(
    request: &dhcp4::Packet,
    yiaddr: Ipv4Addr,
    cfg: &DhcpServerConfig,
    msg_type: u8,
) -> Vec<u8> {
    let mut options = vec![
        (dhcp4::OPT_MSG_TYPE, vec![msg_type]),
        (dhcp4::OPT_SERVER_ID, cfg.server_ip.octets().to_vec()),
    ];
    if msg_type != dhcp4::MSG_NAK {
        options.push((
            dhcp4::OPT_SUBNET_MASK,
            crate::ip::ipv4::subnet_mask(cfg.prefixlen)
                .octets()
                .to_vec(),
        ));
        options.push((dhcp4::OPT_ROUTER, cfg.server_ip.octets().to_vec()));
        options.push((
            dhcp4::OPT_LEASE_TIME,
            cfg.lease_time_secs.to_be_bytes().to_vec(),
        ));
        if !cfg.dns_servers.is_empty() {
            let dns_bytes = cfg.dns_servers.iter().flat_map(|a| a.octets()).collect();
            options.push((dhcp4::OPT_DNS, dns_bytes));
        }
    }
    let pkt = dhcp4::Packet {
        op: dhcp4::OP_BOOTREPLY,
        xid: request.xid,
        secs: 0,
        flags: request.flags,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: if msg_type == dhcp4::MSG_NAK {
            Ipv4Addr::UNSPECIFIED
        } else {
            yiaddr
        },
        siaddr: cfg.server_ip,
        chaddr: request.chaddr,
        options,
    };
    dhcp4::serialize(&pkt)
}
