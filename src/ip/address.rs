//! Address parsing (CIDR strings used throughout config/profiles) and
//! netlink-backed address management (`ip addr add/del`, in NetworkManager
//! terms).

use super::netlink::{self, NlSocket};
use crate::errors::{NetworkError, Result};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Address {
    pub index: i32,
    pub ip: IpAddr,
    pub prefixlen: u8,
    pub label: Option<String>,
}

/// Parses `"192.168.1.50/24"` / `"fe80::1/64"` into `(ip, prefixlen)`.
/// This is the one canonical CIDR parser mitos-network uses -- config
/// validation, connection profiles and the netctl CLI all route through
/// it so "what counts as a valid address" is defined in exactly one place.
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (ip_part, len_part) = s
        .split_once('/')
        .ok_or_else(|| NetworkError::Parse(format!("'{s}' is not in CIDR form (addr/prefix)")))?;
    let ip: IpAddr = ip_part
        .parse()
        .map_err(|_| NetworkError::Parse(format!("'{ip_part}' is not a valid IP address")))?;
    let prefixlen: u8 = len_part
        .parse()
        .map_err(|_| NetworkError::Parse(format!("'{len_part}' is not a valid prefix length")))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefixlen > max {
        return Err(NetworkError::Parse(format!(
            "prefix length {prefixlen} out of range for {ip}"
        )));
    }
    Ok((ip, prefixlen))
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

pub fn add(index: i32, ip: IpAddr, prefixlen: u8) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let family = super::Family::of(ip).raw();
    let hdr = netlink::build_ifaddrmsg(family, prefixlen, index);
    let mut attrs = netlink::AttrBuilder::new();
    let bytes = ip_bytes(ip);
    attrs.bytes(netlink::IFA_LOCAL, &bytes);
    attrs.bytes(netlink::IFA_ADDRESS, &bytes);
    if let IpAddr::V4(v4) = ip {
        let bcast = super::ipv4::broadcast_address(v4, prefixlen);
        attrs.bytes(netlink::IFA_BROADCAST, &bcast.octets());
    }
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    sock.request(
        netlink::RTM_NEWADDR,
        netlink::NLM_F_CREATE | netlink::NLM_F_REPLACE,
        &payload,
    )
}

pub fn del(index: i32, ip: IpAddr, prefixlen: u8) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let family = super::Family::of(ip).raw();
    let hdr = netlink::build_ifaddrmsg(family, prefixlen, index);
    let mut attrs = netlink::AttrBuilder::new();
    attrs.bytes(netlink::IFA_LOCAL, &ip_bytes(ip));
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    sock.request(netlink::RTM_DELADDR, 0, &payload)
}

/// Lists addresses; `index = None` lists every interface's addresses.
pub fn list(index: Option<i32>) -> Result<Vec<Address>> {
    let mut out = Vec::new();
    for family in [netlink::AF_INET, netlink::AF_INET6] {
        let mut sock = NlSocket::new()?;
        let hdr = netlink::build_ifaddrmsg(family, 0, index.unwrap_or(0));
        let replies = sock.dump(netlink::RTM_GETADDR, &hdr)?;
        for body in &replies {
            if let Some(a) = netlink::parse_addr(body) {
                if let Some(idx) = index {
                    if a.index != idx {
                        continue;
                    }
                }
                let ip = bytes_to_ip(family, &a.address);
                if let Some(ip) = ip {
                    out.push(Address {
                        index: a.index,
                        ip,
                        prefixlen: a.prefixlen,
                        label: a.label,
                    });
                }
            }
        }
    }
    Ok(out)
}

fn bytes_to_ip(family: u8, b: &[u8]) -> Option<IpAddr> {
    if family == netlink::AF_INET && b.len() == 4 {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])))
    } else if family == netlink::AF_INET6 && b.len() == 16 {
        let mut oct = [0u8; 16];
        oct.copy_from_slice(b);
        Some(IpAddr::V6(std::net::Ipv6Addr::from(oct)))
    } else {
        None
    }
}

/// Removes every address currently on `index` -- used before applying a
/// fresh static profile or before handing an interface back to DHCP.
pub fn flush(index: i32) -> Result<()> {
    for a in list(Some(index))? {
        del(index, a.ip, a.prefixlen)?;
    }
    Ok(())
}
