//! Interface enumeration and link (up/down/MTU) control.

use super::netlink::{self, NlSocket};
use crate::errors::{NetworkError, Result};

#[derive(Debug, Clone)]
pub struct Interface {
    pub index: i32,
    pub name: String,
    pub flags: u32,
    pub mtu: u32,
    pub hwaddr: Option<[u8; 6]>,
    /// `IF_OPER_*` from `<linux/if.h>`: 0 unknown .. 6 up. `Some(6)` means
    /// carrier is present (cable plugged in / associated to an AP).
    pub operstate: Option<u8>,
    /// Virtual link kind (`"bridge"`, `"wireguard"`, ...), `None` for
    /// physical hardware. See `device::discovery::classify`.
    pub kind: Option<String>,
}

impl Interface {
    pub fn is_up(&self) -> bool {
        self.flags & netlink::IFF_UP != 0
    }
    pub fn has_carrier(&self) -> bool {
        self.flags & netlink::IFF_RUNNING != 0
    }
    pub fn is_loopback(&self) -> bool {
        self.flags & netlink::IFF_LOOPBACK != 0
    }
}

pub fn list() -> Result<Vec<Interface>> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_ifinfomsg(0, 0, 0);
    let replies = sock.dump(netlink::RTM_GETLINK, &hdr)?;
    Ok(replies
        .iter()
        .filter_map(|b| netlink::parse_link(b))
        .map(|l| Interface {
            index: l.index,
            name: l.name,
            flags: l.flags,
            mtu: l.mtu,
            hwaddr: l.hwaddr,
            operstate: l.operstate,
            kind: l.kind,
        })
        .collect())
}

pub fn get_by_name(name: &str) -> Result<Interface> {
    list()?
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| NetworkError::NotFound(format!("interface '{name}'")))
}

pub fn get_by_index(index: i32) -> Result<Interface> {
    list()?
        .into_iter()
        .find(|i| i.index == index)
        .ok_or_else(|| NetworkError::NotFound(format!("interface index {index}")))
}

pub fn set_up(index: i32) -> Result<()> {
    set_flags(index, netlink::IFF_UP, netlink::IFF_UP)
}

pub fn set_down(index: i32) -> Result<()> {
    set_flags(index, 0, netlink::IFF_UP)
}

fn set_flags(index: i32, flags: u32, change: u32) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_ifinfomsg(index, flags, change);
    sock.request(netlink::RTM_NEWLINK, 0, &hdr)
}

/// Sets a device's hardware (MAC) address. Most drivers reject this
/// while the link is administratively up; `device::mac::set` documents
/// the up/down dance callers need around it.
pub fn set_hwaddr(index: i32, mac: [u8; 6]) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_ifinfomsg(index, 0, 0);
    let mut attrs = netlink::AttrBuilder::new();
    attrs.bytes(netlink::IFLA_ADDRESS, &mac);
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    sock.request(netlink::RTM_NEWLINK, 0, &payload)
}

pub fn set_mtu(index: i32, mtu: u32) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_ifinfomsg(index, 0, 0);
    let mut attrs = netlink::AttrBuilder::new();
    attrs.u32(netlink::IFLA_MTU, mtu);
    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    sock.request(netlink::RTM_NEWLINK, 0, &payload)
}

/// Deletes a virtual link (bridge, VLAN, WireGuard device, ...). Refuses
/// to be used on a device that looks like real hardware would be a
/// policy decision for the caller, not this low-level wrapper.
pub fn delete(index: i32) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_ifinfomsg(index, 0, 0);
    sock.request(netlink::RTM_DELLINK, 0, &hdr)
}

/// Creates a virtual link of kind `kind` (e.g. `"wireguard"`, `"bridge"`,
/// `"dummy"`) named `name`. Returns once the link exists; the caller
/// still needs a follow-up [`list`]/[`get_by_name`] to learn its index.
pub fn create_virtual(name: &str, kind: &str) -> Result<()> {
    let mut sock = NlSocket::new()?;
    let hdr = netlink::build_ifinfomsg(0, 0, 0);
    let mut link_info = netlink::AttrBuilder::new();
    link_info.nul_str(netlink::IFLA_INFO_KIND, kind);

    let mut attrs = netlink::AttrBuilder::new();
    attrs.nul_str(netlink::IFLA_IFNAME, name);
    attrs.nested(netlink::IFLA_LINKINFO, &link_info);

    let mut payload = hdr;
    payload.extend(attrs.into_bytes());
    sock.request(
        netlink::RTM_NEWLINK,
        netlink::NLM_F_CREATE | netlink::NLM_F_EXCL,
        &payload,
    )
}
