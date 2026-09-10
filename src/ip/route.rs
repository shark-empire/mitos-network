//! Route table management, on top of `ip::netlink`.

use super::netlink::{self, NlSocket};
use crate::errors::Result;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteProtocol {
    /// Configured by mitos-network directly (static profile / manual route).
    Static,
    /// Learned from a DHCP lease.
    Dhcp,
    /// Installed by the kernel itself (e.g. the connected-subnet route).
    Kernel,
}

impl RouteProtocol {
    fn raw(self) -> u8 {
        match self {
            RouteProtocol::Static => netlink::RTPROT_STATIC,
            RouteProtocol::Dhcp => netlink::RTPROT_DHCP,
            RouteProtocol::Kernel => 2, // RTPROT_KERNEL
        }
    }
}

#[derive(Debug, Clone)]
pub struct Route {
    /// `None` destination means the default route (0.0.0.0/0 or ::/0).
    pub destination: Option<(IpAddr, u8)>,
    pub gateway: Option<IpAddr>,
    pub oif_index: i32,
    pub metric: Option<u32>,
    pub protocol: RouteProtocol,
}

fn addr_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

fn family_of(route: &Route) -> super::Family {
    if let Some((dst, _)) = route.destination {
        super::Family::of(dst)
    } else if let Some(gw) = route.gateway {
        super::Family::of(gw)
    } else {
        super::Family::V4
    }
}

fn build(route: &Route, msg_type: u16, extra_flags: u16) -> Result<()> {
    let family = family_of(route).raw();
    let dst_len = route.destination.map(|(_, l)| l).unwrap_or(0);
    let hdr = netlink::build_rtmsg(
        family,
        dst_len,
        netlink::RT_TABLE_MAIN,
        route.protocol.raw(),
        if route.gateway.is_some() {
            netlink::RT_SCOPE_UNIVERSE
        } else {
            netlink::RT_SCOPE_LINK
        },
        netlink::RTN_UNICAST,
    );
    let mut attrs = netlink::AttrBuilder::new();
    if let Some((dst, _)) = route.destination {
        attrs.bytes(netlink::RTA_DST, &addr_bytes(dst));
    }
    if let Some(gw) = route.gateway {
        attrs.bytes(netlink::RTA_GATEWAY, &addr_bytes(gw));
    }
    attrs.u32(netlink::RTA_OIF, route.oif_index as u32);
    if let Some(metric) = route.metric {
        attrs.u32(netlink::RTA_PRIORITY, metric);
    }
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    let mut sock = NlSocket::new()?;
    sock.request(msg_type, extra_flags, &payload)
}

pub fn add(route: &Route) -> Result<()> {
    build(route, netlink::RTM_NEWROUTE, netlink::NLM_F_CREATE | netlink::NLM_F_REPLACE)
}

pub fn del(route: &Route) -> Result<()> {
    build(route, netlink::RTM_DELROUTE, 0)
}

/// Convenience for the common "make this device's gateway the default
/// route" case that `routing::default_route` drives after DHCP/static
/// activation.
pub fn set_default(oif_index: i32, gateway: IpAddr, metric: u32, protocol: RouteProtocol) -> Result<()> {
    add(&Route {
        destination: None,
        gateway: Some(gateway),
        oif_index,
        metric: Some(metric),
        protocol,
    })
}

pub fn list(family: super::Family) -> Result<Vec<Route>> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_rtmsg(family.raw(), 0, 0, 0, 0, 0);
    let replies = sock.dump(netlink::RTM_GETROUTE, &hdr)?;
    let mut out = Vec::new();
    for body in &replies {
        if let Some(r) = netlink::parse_route(body) {
            if r.table != netlink::RT_TABLE_MAIN {
                continue;
            }
            let destination = r.dst.and_then(|b| bytes_to_ip(r.family, &b)).map(|ip| (ip, r.dst_len));
            let gateway = r.gateway.and_then(|b| bytes_to_ip(r.family, &b));
            out.push(Route {
                destination,
                gateway,
                oif_index: r.oif.unwrap_or(0),
                metric: r.priority,
                protocol: RouteProtocol::Kernel,
            });
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

// ---- policy routing (FIB rules) ---------------------------------------
//
// Used by `routing::policy` to give a connection (typically a
// split-tunnel VPN) its own routing table, selected by source address,
// without disturbing the main table everything else uses.

/// Adds a rule: "traffic sourced from `src`/`prefixlen` looks up `table`,
/// at `priority` (lower runs first, same convention as `ip rule`)".
pub fn add_source_rule(src: IpAddr, prefixlen: u8, table: u8, priority: u32) -> Result<()> {
    let family = super::Family::of(src).raw();
    let hdr = netlink::build_fib_rule_hdr(family, prefixlen, table, netlink::FR_ACT_TO_TBL);
    let mut attrs = netlink::AttrBuilder::new();
    attrs.bytes(netlink::FRA_SRC, &addr_bytes(src));
    attrs.u32(netlink::FRA_PRIORITY, priority);
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    let mut sock = NlSocket::new()?;
    sock.request(netlink::RTM_NEWRULE, netlink::NLM_F_CREATE, &payload)
}

pub fn del_source_rule(src: IpAddr, prefixlen: u8, table: u8, priority: u32) -> Result<()> {
    let family = super::Family::of(src).raw();
    let hdr = netlink::build_fib_rule_hdr(family, prefixlen, table, netlink::FR_ACT_TO_TBL);
    let mut attrs = netlink::AttrBuilder::new();
    attrs.bytes(netlink::FRA_SRC, &addr_bytes(src));
    attrs.u32(netlink::FRA_PRIORITY, priority);
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    let mut sock = NlSocket::new()?;
    sock.request(netlink::RTM_DELRULE, 0, &payload)
}

/// Adds a route into a non-main table (used together with
/// [`add_source_rule`] -- the rule sends matching traffic here instead
/// of the main table).
pub fn add_to_table(route: &Route, table: u8) -> Result<()> {
    let family = family_of(route).raw();
    let dst_len = route.destination.map(|(_, l)| l).unwrap_or(0);
    let hdr = netlink::build_rtmsg(
        family,
        dst_len,
        table,
        route.protocol.raw(),
        netlink::RT_SCOPE_UNIVERSE,
        netlink::RTN_UNICAST,
    );
    let mut attrs = netlink::AttrBuilder::new();
    if let Some((dst, _)) = route.destination {
        attrs.bytes(netlink::RTA_DST, &addr_bytes(dst));
    }
    if let Some(gw) = route.gateway {
        attrs.bytes(netlink::RTA_GATEWAY, &addr_bytes(gw));
    }
    attrs.u32(netlink::RTA_OIF, route.oif_index as u32);
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    let mut sock = NlSocket::new()?;
    sock.request(netlink::RTM_NEWROUTE, netlink::NLM_F_CREATE | netlink::NLM_F_REPLACE, &payload)
}
