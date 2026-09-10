//! A small hand-rolled `NETLINK_ROUTE` client.
//!
//! This is the one place in mitos-network that talks to the kernel's
//! own networking stack directly (via `AF_NETLINK` sockets) rather than
//! shelling out to a CLI tool. Interfaces, addresses and routes are all
//! managed here; everything above this module (`ip::address`,
//! `ip::route`, `ip::interface`, `device::*`) is policy built on top of
//! it. Per the project's own architecture: mitos-network does not
//! implement TCP/IP -- this module is a thin, faithful mapping onto the
//! rtnetlink ABI the kernel already exposes.
//!
//! Struct layouts and constants below come from the stable, versioned
//! Linux UAPI headers (`linux/rtnetlink.h`, `linux/if_link.h`,
//! `linux/if_addr.h`, `linux/netlink.h`) rather than any crate, so this
//! module has zero dependency on rtnetlink/neli-style wrapper crates.
//! Messages are serialized/deserialized by hand (native-endian byte
//! arrays) rather than via `#[repr(C)]` + transmute, so there is no
//! reliance on the compiler picking the same padding/alignment the
//! kernel ABI expects.

#![allow(dead_code)] // this module defines the full rtnetlink ABI surface; not every
                      // constant is consumed yet by every caller.

use crate::errors::{NetworkError, Result};
use std::collections::HashMap;
use std::os::unix::io::RawFd;

// ---- netlink.h -------------------------------------------------------

const AF_NETLINK: libc::c_int = 16;
const NETLINK_ROUTE: libc::c_int = 0;

const NLMSG_ALIGNTO: usize = 4;
const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP: u16 = 0x100 | 0x200; // NLM_F_ROOT | NLM_F_MATCH
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_REPLACE: u16 = 0x100;

// ---- rtnetlink.h message types ---------------------------------------

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

// Multicast group bits for a "monitor" socket (device::discovery uses these).
pub const RTMGRP_LINK: u32 = 0x1;
pub const RTMGRP_IPV4_IFADDR: u32 = 0x10;
pub const RTMGRP_IPV4_ROUTE: u32 = 0x40;
pub const RTMGRP_IPV6_IFADDR: u32 = 0x100;
pub const RTMGRP_IPV6_ROUTE: u32 = 0x400;

// ---- if_link.h / if_addr.h / rtnetlink.h attribute + flag constants --

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_INFO_KIND: u16 = 1;
pub const IFLA_INFO_DATA: u16 = 2;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_BROADCAST: u16 = 4;

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_TABLE: u16 = 15;

pub const FRA_SRC: u16 = 2;
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_TABLE: u16 = 15;
pub const FR_ACT_TO_TBL: u8 = 1;

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RTPROT_STATIC: u8 = 4;
pub const RTPROT_DHCP: u8 = 16;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTN_UNICAST: u8 = 1;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

fn align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

// ---- attribute (de)serialization -------------------------------------

/// Builds a `TLV` attribute chain in wire format.
#[derive(Default)]
pub struct AttrBuilder {
    buf: Vec<u8>,
}

impl AttrBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn push_raw(&mut self, rta_type: u16, payload: &[u8]) -> &mut Self {
        let rta_len = 4 + payload.len();
        self.buf.extend_from_slice(&(rta_len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&rta_type.to_ne_bytes());
        self.buf.extend_from_slice(payload);
        let padded = align(rta_len);
        self.buf.resize(self.buf.len() + (padded - rta_len), 0);
        self
    }

    pub fn u8(&mut self, rta_type: u16, v: u8) -> &mut Self {
        self.push_raw(rta_type, &[v])
    }
    pub fn u32(&mut self, rta_type: u16, v: u32) -> &mut Self {
        self.push_raw(rta_type, &v.to_ne_bytes())
    }
    pub fn bytes(&mut self, rta_type: u16, v: &[u8]) -> &mut Self {
        self.push_raw(rta_type, v)
    }
    /// A NUL-terminated string, as `IFLA_IFNAME`/`IFLA_INFO_KIND` expect.
    pub fn nul_str(&mut self, rta_type: u16, v: &str) -> &mut Self {
        let mut payload = v.as_bytes().to_vec();
        payload.push(0);
        self.push_raw(rta_type, &payload)
    }
    /// A nested attribute (e.g. `IFLA_LINKINFO` wrapping `IFLA_INFO_KIND`).
    pub fn nested(&mut self, rta_type: u16, inner: &AttrBuilder) -> &mut Self {
        self.push_raw(rta_type, &inner.buf)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Parses a flat attribute chain into a type -> payload map. Good enough
/// here since none of the attributes mitos-network reads repeat within
/// one message; a repeated type simply keeps the last occurrence.
pub fn parse_attrs(mut buf: &[u8]) -> HashMap<u16, Vec<u8>> {
    let mut out = HashMap::new();
    while buf.len() >= 4 {
        let rta_len = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        let rta_type = u16::from_ne_bytes([buf[2], buf[3]]);
        if rta_len < 4 || rta_len > buf.len() {
            break;
        }
        out.insert(rta_type, buf[4..rta_len].to_vec());
        let padded = align(rta_len);
        if padded >= buf.len() {
            break;
        }
        buf = &buf[padded..];
    }
    out
}

// ---- socket -----------------------------------------------------------

pub struct NlSocket {
    fd: RawFd,
    seq: u32,
}

impl NlSocket {
    pub fn new() -> Result<Self> {
        Self::with_groups(0)
    }

    /// A socket subscribed to multicast `groups` (see the `RTMGRP_*`
    /// constants) additionally receives unsolicited notifications --
    /// used by `device::discovery`'s hotplug monitor.
    pub fn with_groups(groups: u32) -> Result<Self> {
        // SAFETY: standard socket(2)/bind(2) calls with a stack-local
        // sockaddr; no pointers escape this function.
        unsafe {
            let fd = libc::socket(
                AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            );
            if fd < 0 {
                return Err(NetworkError::Netlink(format!(
                    "socket(AF_NETLINK) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = AF_NETLINK as libc::sa_family_t;
            addr.nl_pid = 0; // let the kernel assign our port id
            addr.nl_groups = groups;
            let rc = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            );
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(NetworkError::Netlink(format!("bind(AF_NETLINK) failed: {e}")));
            }
            Ok(NlSocket { fd, seq: 1 })
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Sends one request and, for non-dump requests, waits for the ack.
    /// For dump requests, use [`NlSocket::dump`] instead.
    pub fn request(&mut self, msg_type: u16, mut flags: u16, payload: &[u8]) -> Result<()> {
        flags |= NLM_F_REQUEST | NLM_F_ACK;
        let seq = self.send(msg_type, flags, payload)?;
        for (t, _flags, body) in self.recv_until_done(seq)? {
            if t == NLMSG_ERROR {
                check_ack(&body)?;
            }
        }
        Ok(())
    }

    /// Sends a `NLM_F_DUMP` request and collects every reply message's
    /// raw payload (i.e. everything after the `nlmsghdr`).
    pub fn dump(&mut self, msg_type: u16, payload: &[u8]) -> Result<Vec<Vec<u8>>> {
        let seq = self.send(msg_type, NLM_F_REQUEST | NLM_F_DUMP, payload)?;
        let mut out = Vec::new();
        for (t, _flags, body) in self.recv_until_done(seq)? {
            if t == NLMSG_ERROR {
                check_ack(&body)?;
            } else if t != NLMSG_DONE {
                out.push(body);
            }
        }
        Ok(out)
    }

    fn send(&mut self, msg_type: u16, flags: u16, payload: &[u8]) -> Result<u32> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        let total_len = NLMSG_HDRLEN + payload.len();
        let mut buf = Vec::with_capacity(align(total_len));
        buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid: kernel fills this in
        buf.extend_from_slice(payload);
        buf.resize(align(buf.len()), 0);

        // SAFETY: fd is a valid, owned netlink socket; buf is a plain
        // byte buffer we just built.
        let n = unsafe { libc::send(self.fd, buf.as_ptr() as *const _, buf.len(), 0) };
        if n < 0 {
            return Err(NetworkError::Netlink(format!(
                "send() failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(seq)
    }

    /// Reads datagrams until a `NLMSG_DONE`/non-multi terminal message
    /// for `seq` is seen, returning every `(type, flags, payload)` along
    /// the way.
    fn recv_until_done(&self, seq: u32) -> Result<Vec<(u16, u16, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            // SAFETY: buf is sized and owned for the duration of the call.
            let n = unsafe {
                libc::recv(self.fd, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
            if n < 0 {
                return Err(NetworkError::Netlink(format!(
                    "recv() failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let mut rest = &buf[..n as usize];
            let mut done = false;
            while rest.len() >= NLMSG_HDRLEN {
                let len = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
                let msg_type = u16::from_ne_bytes(rest[4..6].try_into().unwrap());
                let flags = u16::from_ne_bytes(rest[6..8].try_into().unwrap());
                let msg_seq = u32::from_ne_bytes(rest[8..12].try_into().unwrap());
                if len < NLMSG_HDRLEN || len > rest.len() {
                    break;
                }
                let body = rest[NLMSG_HDRLEN..len].to_vec();
                let is_multi = flags & 0x02 != 0; // NLM_F_MULTI
                if msg_seq == seq || msg_type == NLMSG_ERROR {
                    if msg_type == NLMSG_DONE {
                        done = true;
                    } else {
                        out.push((msg_type, flags, body));
                    }
                }
                if !is_multi && msg_type != NLMSG_DONE {
                    done = done || msg_type == NLMSG_ERROR || msg_seq == seq;
                }
                rest = &rest[align(len)..];
            }
            if done || out.iter().any(|(t, _, _)| *t == NLMSG_ERROR) {
                break;
            }
            // A single reply that wasn't NLM_F_MULTI and wasn't DONE/ERROR
            // (e.g. a plain ack-less single-message dump) also terminates.
            if n == 0 {
                break;
            }
        }
        Ok(out)
    }

    /// Reads one datagram from a multicast-subscribed socket and hands
    /// each contained message's `(type, body)` to `f`, collecting the
    /// `Some` results. Unlike [`NlSocket::request`]/[`NlSocket::dump`],
    /// there is no sequence number to match -- multicast notifications
    /// are unsolicited.
    pub fn recv_multicast<T>(&self, f: impl Fn(u16, &[u8]) -> Option<T>) -> Result<Vec<T>> {
        let mut buf = vec![0u8; 32 * 1024];
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            return Err(NetworkError::Netlink(format!(
                "recv() failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut rest = &buf[..n as usize];
        let mut out = Vec::new();
        while rest.len() >= NLMSG_HDRLEN {
            let len = u32::from_ne_bytes(rest[0..4].try_into().unwrap()) as usize;
            let msg_type = u16::from_ne_bytes(rest[4..6].try_into().unwrap());
            if len < NLMSG_HDRLEN || len > rest.len() {
                break;
            }
            if let Some(v) = f(msg_type, &rest[NLMSG_HDRLEN..len]) {
                out.push(v);
            }
            rest = &rest[align(len)..];
        }
        Ok(out)
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// `NLMSG_ERROR` payload is `{ i32 error; nlmsghdr orig; ... }`. `error
/// == 0` is a plain ack (success); anything else is `-errno`.
fn check_ack(body: &[u8]) -> Result<()> {
    if body.len() < 4 {
        return Err(NetworkError::Netlink("truncated ack".into()));
    }
    let errno = i32::from_ne_bytes(body[0..4].try_into().unwrap());
    if errno == 0 {
        Ok(())
    } else {
        let msg = std::io::Error::from_raw_os_error(-errno);
        Err(NetworkError::Netlink(msg.to_string()))
    }
}

// ---- ifinfomsg / ifaddrmsg / rtmsg headers ----------------------------

pub fn build_ifinfomsg(index: i32, flags: u32, change: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.push(0u8); // ifi_family (AF_UNSPEC)
    b.push(0u8); // pad
    b.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type, kernel fills on create
    b.extend_from_slice(&index.to_ne_bytes());
    b.extend_from_slice(&flags.to_ne_bytes());
    b.extend_from_slice(&change.to_ne_bytes());
    b
}

pub fn build_ifaddrmsg(family: u8, prefixlen: u8, index: i32) -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.push(family);
    b.push(prefixlen);
    b.push(0u8); // ifa_flags
    b.push(RT_SCOPE_UNIVERSE);
    b.extend_from_slice(&index.to_ne_bytes());
    b
}

#[allow(clippy::too_many_arguments)]
pub fn build_rtmsg(family: u8, dst_len: u8, table: u8, protocol: u8, scope: u8, rtype: u8) -> Vec<u8> {
    vec![family, dst_len, 0, 0, table, protocol, scope, rtype, 0, 0, 0, 0]
}

/// `fib_rule_hdr`: family(1) dst_len(1) src_len(1) tos(1) table(1)
/// res1(1) res2(1) action(1) flags(4) = 12 bytes.
pub fn build_fib_rule_hdr(family: u8, src_len: u8, table: u8, action: u8) -> Vec<u8> {
    vec![family, 0, src_len, 0, table, 0, 0, action, 0, 0, 0, 0]
}

/// A parsed `RTM_NEWLINK`/`RTM_GETLINK` reply: the fixed `ifinfomsg`
/// header plus the attributes callers care about.
pub struct LinkInfo {
    pub index: i32,
    pub flags: u32,
    pub name: String,
    pub mtu: u32,
    pub hwaddr: Option<[u8; 6]>,
    pub operstate: Option<u8>,
    /// `IFLA_LINKINFO`'s `IFLA_INFO_KIND`, e.g. `"bridge"`, `"bond"`,
    /// `"wireguard"`, `"tun"`, `"vlan"` -- `None` for a plain physical
    /// NIC, which has no `IFLA_LINKINFO` at all.
    pub kind: Option<String>,
}

pub fn parse_link(body: &[u8]) -> Option<LinkInfo> {
    if body.len() < 16 {
        return None;
    }
    let index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
    let flags = u32::from_ne_bytes(body[8..12].try_into().unwrap());
    let attrs = parse_attrs(&body[16..]);
    let name = attrs
        .get(&IFLA_IFNAME)
        .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    let mtu = attrs
        .get(&IFLA_MTU)
        .and_then(|b| b.get(0..4))
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
        .unwrap_or(0);
    let hwaddr = attrs.get(&IFLA_ADDRESS).and_then(|b| {
        if b.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&b[..6]);
            Some(mac)
        } else {
            None
        }
    });
    let operstate = attrs.get(&IFLA_OPERSTATE).and_then(|b| b.first().copied());
    let kind = attrs.get(&IFLA_LINKINFO).and_then(|linkinfo| {
        let nested = parse_attrs(linkinfo);
        nested
            .get(&IFLA_INFO_KIND)
            .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string())
    });
    Some(LinkInfo { index, flags, name, mtu, hwaddr, operstate, kind })
}

pub struct AddrInfo {
    pub index: i32,
    pub family: u8,
    pub prefixlen: u8,
    pub address: Vec<u8>,
    pub label: Option<String>,
}

pub fn parse_addr(body: &[u8]) -> Option<AddrInfo> {
    if body.len() < 8 {
        return None;
    }
    let family = body[0];
    let prefixlen = body[1];
    let index = i32::from_ne_bytes(body[4..8].try_into().unwrap());
    let attrs = parse_attrs(&body[8..]);
    let address = attrs
        .get(&IFA_LOCAL)
        .or_else(|| attrs.get(&IFA_ADDRESS))
        .cloned()
        .unwrap_or_default();
    let label = attrs
        .get(&IFA_LABEL)
        .map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').to_string());
    Some(AddrInfo { index, family, prefixlen, address, label })
}

pub struct RouteInfo {
    pub family: u8,
    pub dst_len: u8,
    pub table: u8,
    pub dst: Option<Vec<u8>>,
    pub gateway: Option<Vec<u8>>,
    pub oif: Option<i32>,
    pub priority: Option<u32>,
}

pub fn parse_route(body: &[u8]) -> Option<RouteInfo> {
    if body.len() < 12 {
        return None;
    }
    let family = body[0];
    let dst_len = body[1];
    let table = body[4];
    let attrs = parse_attrs(&body[12..]);
    let dst = attrs.get(&RTA_DST).cloned();
    let gateway = attrs.get(&RTA_GATEWAY).cloned();
    let oif = attrs
        .get(&RTA_OIF)
        .and_then(|b| b.get(0..4))
        .map(|b| i32::from_ne_bytes(b.try_into().unwrap()));
    let priority = attrs
        .get(&RTA_PRIORITY)
        .and_then(|b| b.get(0..4))
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
    Some(RouteInfo { family, dst_len, table, dst, gateway, oif, priority })
}
