//! ARP / NDP neighbor table (`ip neigh` equivalent). Mostly used by
//! `monitoring::diagnostics` and `mitos-netctl` for troubleshooting --
//! "is the gateway even resolving?" is one of the first questions in
//! any connectivity bug report.

use super::netlink::{self, NlSocket};
use crate::errors::Result;
use std::net::IpAddr;

const RTM_GETNEIGH: u16 = 30;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Permanent,
    Unknown,
}

impl NeighborState {
    fn from_raw(state: u16) -> Self {
        match state {
            0x01 => NeighborState::Incomplete,
            0x02 => NeighborState::Reachable,
            0x04 => NeighborState::Stale,
            0x08 => NeighborState::Delay,
            0x10 => NeighborState::Probe,
            0x20 => NeighborState::Failed,
            0x80 => NeighborState::Permanent,
            _ => NeighborState::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub ifindex: i32,
    pub ip: IpAddr,
    pub mac: Option<[u8; 6]>,
    pub state: NeighborState,
}

pub fn list(ifindex: Option<i32>) -> Result<Vec<Neighbor>> {
    let mut out = Vec::new();
    for family in [netlink::AF_INET, netlink::AF_INET6] {
        let mut sock = NlSocket::new()?;
        // ndmsg: family(1) pad(3) ifindex(4) state(2) flags(1) type(1) = 12 bytes
        let hdr = vec![family, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let replies = sock.dump(RTM_GETNEIGH, &hdr)?;
        for body in &replies {
            if body.len() < 12 {
                continue;
            }
            let idx = i32::from_ne_bytes(body[4..8].try_into().unwrap());
            if let Some(want) = ifindex {
                if idx != want {
                    continue;
                }
            }
            let state = u16::from_ne_bytes(body[8..10].try_into().unwrap());
            let attrs = netlink::parse_attrs(&body[12..]);
            let ip = attrs.get(&NDA_DST).and_then(|b| bytes_to_ip(family, b));
            let mac = attrs.get(&NDA_LLADDR).and_then(|b| {
                if b.len() >= 6 {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&b[..6]);
                    Some(m)
                } else {
                    None
                }
            });
            if let Some(ip) = ip {
                out.push(Neighbor {
                    ifindex: idx,
                    ip,
                    mac,
                    state: NeighborState::from_raw(state),
                });
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
