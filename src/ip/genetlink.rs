//! A small `NETLINK_GENERIC` ("genl") client: just enough to resolve a
//! dynamically-registered kernel family name (e.g. `"wireguard"`) to
//! the numeric family id its messages must be addressed to, plus the
//! `genlmsghdr` framing every genl message carries.
//!
//! Unlike `rtnetlink` (`ip::netlink`), where message types
//! (`RTM_NEWLINK`, ...) are a fixed, well-known set, a genl family's
//! id is assigned dynamically when its kernel module loads and has to
//! be looked up at runtime via the always-present `"nlctrl"` family
//! (well-known id [`GENL_ID_CTRL`]) -- this module is that lookup,
//! cross-referenced against `include/uapi/linux/genetlink.h`. It
//! reuses [`super::netlink::NlSocket`] for the actual transport, since
//! netlink message framing (the `nlmsghdr`, sequence numbers, ack/dump
//! termination) is identical regardless of which netlink protocol the
//! socket was created with -- only the payload after the header
//! differs, and for genl that payload starts with `genlmsghdr` rather
//! than a `rtnetlink`-specific fixed header like `ifinfomsg`.

use super::netlink::{self, NlSocket};
use crate::errors::{NetworkError, Result};

/// The well-known family id of `"nlctrl"`, the genl family used to
/// resolve every other genl family's id (and the only one whose id
/// isn't itself something you'd need to resolve first).
pub const GENL_ID_CTRL: u16 = 0x10;

const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

/// `genlmsghdr`: `{ u8 cmd; u8 version; u16 reserved; }`, 4 bytes,
/// sitting between the `nlmsghdr` (which `NlSocket` builds) and the
/// attribute chain.
pub fn build_genlmsghdr(cmd: u8, version: u8) -> Vec<u8> {
    vec![cmd, version, 0, 0]
}

/// Looks up `family_name`'s numeric id by querying `nlctrl`. Returns
/// [`NetworkError::Netlink`] if the family isn't registered -- for
/// `"wireguard"` specifically, that means the kernel module isn't
/// loaded (`modprobe wireguard`), same as `wg` itself would report.
pub fn resolve_family(sock: &mut NlSocket, family_name: &str) -> Result<u16> {
    let mut attrs = netlink::AttrBuilder::new();
    attrs.nul_str(CTRL_ATTR_FAMILY_NAME, family_name);
    let mut payload = build_genlmsghdr(CTRL_CMD_GETFAMILY, 1);
    payload.extend(attrs.into_bytes());

    let replies = sock.query(GENL_ID_CTRL, 0, &payload).map_err(|_| {
        NetworkError::Netlink(format!(
            "generic netlink family '{family_name}' not found -- is its kernel module loaded?"
        ))
    })?;

    for body in &replies {
        // genlmsghdr (4 bytes) then the attribute chain.
        if body.len() < 4 {
            continue;
        }
        let attrs = netlink::parse_attrs(&body[4..]);
        if let Some(id) = attrs
            .get(&CTRL_ATTR_FAMILY_ID)
            .and_then(|b| b.get(0..2))
            .map(|b| u16::from_ne_bytes([b[0], b[1]]))
        {
            return Ok(id);
        }
    }
    Err(NetworkError::Netlink(format!(
        "generic netlink family '{family_name}' not found -- is its kernel module loaded?"
    )))
}

/// Opens a fresh genl socket and resolves `family_name` in one call --
/// the common case for callers (like `vpn::wireguard`) that just need
/// the id once before sending a single configuration message.
pub fn resolve(family_name: &str) -> Result<u16> {
    let mut sock = NlSocket::with_protocol(netlink::NETLINK_GENERIC, 0)?;
    resolve_family(&mut sock, family_name)
}
