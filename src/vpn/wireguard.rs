//! WireGuard client setup.
//!
//! The interface itself is created via the same netlink client the
//! rest of `ip::*` uses (`ip link add <n> type wireguard` is just an
//! `RTM_NEWLINK` with `IFLA_LINKINFO` kind `"wireguard"` -- the kernel's
//! WireGuard module registers itself as an ordinary rtnetlink link
//! type, so `ip::interface::create_virtual` needs no special-casing
//! for it). Setting the actual crypto parameters (private key, peer
//! public key, endpoint, allowed-ips) goes through WireGuard's own
//! generic-netlink family instead: `ip::genetlink` resolves
//! `"wireguard"` to its dynamically-assigned family id, and the
//! attribute layout below is cross-referenced against the public
//! `WG_CMD_SET_DEVICE` / `WGDEVICE_A_*` / `WGPEER_A_*` /
//! `WGALLOWEDIP_A_*` protocol WireGuard documents at
//! wireguard.com/embedding/ for exactly this kind of reimplementation,
//! rather than shelling out to the `wg` command-line tool.
//!
//! This is strictly better than the CLI approach, not just a purity
//! exercise: the private key is decoded in-process and handed straight
//! to the kernel inside a netlink message, so it never touches disk,
//! a process argv, or another process's environment at all, even
//! briefly.

use crate::errors::{NetworkError, Result};
use crate::ip::genetlink;
use crate::ip::netlink::{self, NlSocket};
use crate::security::secrets::SecretsBackend;
use crate::vpn::vpn::{VpnKind, VpnSession};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Deserialize)]
pub struct WireGuardConfig {
    pub interface: String,
    /// CIDR, e.g. `"10.0.0.2/32"`.
    pub address: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    #[serde(default = "default_allowed_ips")]
    pub peer_allowed_ips: String,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive_secs: u16,
}

fn default_allowed_ips() -> String {
    "0.0.0.0/0, ::/0".to_string()
}
fn default_keepalive() -> u16 {
    25
}

pub fn connect(config: &str, secrets: &dyn SecretsBackend, profile_id: &str) -> Result<VpnSession> {
    let cfg: WireGuardConfig = toml::from_str(config)
        .map_err(|e| NetworkError::Vpn(format!("invalid WireGuard config: {e}")))?;
    crate::security::validation::validate_interface_name(&cfg.interface)?;

    let private_key_b64 = secrets
        .get(profile_id, "wg-private-key")?
        .ok_or_else(|| NetworkError::Vpn(format!("no private key stored for '{profile_id}'")))?;

    // Idempotent: creating over an existing device of the same name is
    // a common re-activation path (daemon restart, profile re-enabled).
    if crate::ip::interface::get_by_name(&cfg.interface).is_err() {
        crate::ip::interface::create_virtual(&cfg.interface, "wireguard")?;
    }
    let iface = crate::ip::interface::get_by_name(&cfg.interface)?;

    let (addr, prefixlen) = crate::ip::address::parse_cidr(&cfg.address)?;
    crate::ip::address::add(iface.index, addr, prefixlen)?;

    set_crypto_params(&cfg, &private_key_b64)?;

    crate::device::link::bring_up(iface.index)?;

    for cidr in split_list(&cfg.peer_allowed_ips) {
        if let Ok((dst, len)) = crate::ip::address::parse_cidr(cidr) {
            let _ = crate::ip::route::add(&crate::ip::route::Route {
                destination: Some((dst, len)),
                gateway: None,
                oif_index: iface.index,
                metric: None,
                protocol: crate::ip::route::RouteProtocol::Static,
            });
        }
    }

    Ok(VpnSession {
        interface_name: cfg.interface,
        kind: VpnKind::WireGuard,
    })
}

pub fn disconnect(ifname: &str) -> Result<()> {
    let iface = crate::ip::interface::get_by_name(ifname)?;
    crate::ip::interface::delete(iface.index)
}

fn split_list(s: &str) -> impl Iterator<Item = &str> {
    s.split(',').map(str::trim).filter(|s| !s.is_empty())
}

// ---- WireGuard generic-netlink protocol --------------------------------
//
// From `include/uapi/linux/wireguard.h` (a public, stable UAPI --
// WireGuard explicitly documents this as the protocol third-party
// tools should speak directly, the same spirit in which this crate
// hand-rolls rtnetlink against its own UAPI headers rather than
// depending on a wrapper crate).

const WG_CMD_SET_DEVICE: u8 = 1;

const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

const WG_KEY_LEN: usize = 32;

fn set_crypto_params(cfg: &WireGuardConfig, private_key_b64: &str) -> Result<()> {
    let private_key = decode_key("private key", private_key_b64)?;
    let public_key = decode_key("peer public key", &cfg.peer_public_key)?;
    let endpoint = resolve_endpoint(&cfg.peer_endpoint)?;

    let mut peer = netlink::AttrBuilder::new();
    peer.bytes(WGPEER_A_PUBLIC_KEY, &public_key);
    peer.u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
    peer.bytes(WGPEER_A_ENDPOINT, &encode_sockaddr(endpoint));
    peer.u16(
        WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
        cfg.persistent_keepalive_secs,
    );

    let mut allowedips = netlink::AttrBuilder::new();
    for (i, cidr) in split_list(&cfg.peer_allowed_ips).enumerate() {
        let (addr, prefixlen) = crate::ip::address::parse_cidr(cidr)
            .map_err(|_| NetworkError::Vpn(format!("invalid allowed-ips entry '{cidr}'")))?;
        let mut entry = netlink::AttrBuilder::new();
        match addr {
            IpAddr::V4(v4) => {
                entry.u16(WGALLOWEDIP_A_FAMILY, netlink::AF_INET as u16);
                entry.bytes(WGALLOWEDIP_A_IPADDR, &v4.octets());
            }
            IpAddr::V6(v6) => {
                entry.u16(WGALLOWEDIP_A_FAMILY, netlink::AF_INET6 as u16);
                entry.bytes(WGALLOWEDIP_A_IPADDR, &v6.octets());
            }
        }
        entry.u8(WGALLOWEDIP_A_CIDR_MASK, prefixlen);
        // The index is the nested attribute's own type -- netlink's
        // usual idiom for an unnamed array via nested attrs (same
        // trick `WGDEVICE_A_PEERS` uses below for its one peer); the
        // kernel doesn't interpret the index itself, it just walks
        // every nested attribute it finds inside the parent.
        allowedips.nested(i as u16, &entry);
    }
    peer.nested(WGPEER_A_ALLOWEDIPS, &allowedips);

    let mut peers = netlink::AttrBuilder::new();
    peers.nested(0, &peer);

    let mut attrs = netlink::AttrBuilder::new();
    attrs.nul_str(WGDEVICE_A_IFNAME, &cfg.interface);
    attrs.bytes(WGDEVICE_A_PRIVATE_KEY, &private_key);
    if let Some(port) = cfg.listen_port {
        attrs.u16(WGDEVICE_A_LISTEN_PORT, port);
    }
    attrs.u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    attrs.nested(WGDEVICE_A_PEERS, &peers);

    let mut payload = genetlink::build_genlmsghdr(WG_CMD_SET_DEVICE, 1);
    payload.extend(attrs.into_bytes());

    let family = genetlink::resolve("wireguard").map_err(|e| {
        NetworkError::Vpn(format!(
            "WireGuard kernel module not available: {e} (try `modprobe wireguard`)"
        ))
    })?;
    let mut sock = NlSocket::with_protocol(netlink::NETLINK_GENERIC, 0)?;
    sock.request(family, 0, &payload)
        .map_err(|e| NetworkError::Vpn(format!("WG_CMD_SET_DEVICE failed: {e}")))
}

fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    endpoint
        .to_socket_addrs()
        .map_err(|e| NetworkError::Vpn(format!("cannot resolve peer endpoint '{endpoint}': {e}")))?
        .next()
        .ok_or_else(|| NetworkError::Vpn(format!("peer endpoint '{endpoint}' resolved to nothing")))
}

/// Raw `struct sockaddr_in`/`sockaddr_in6` bytes, exactly as the kernel
/// expects `WGPEER_A_ENDPOINT`'s payload: native-endian family, but
/// port and address in network byte order like any real socket
/// address. This one attribute is a wire struct, not a generic
/// int/string attribute -- which is why it doesn't follow
/// `AttrBuilder::u16`'s native-endian convention the way
/// `WGDEVICE_A_LISTEN_PORT` does just above.
fn encode_sockaddr(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut buf = Vec::with_capacity(16);
            buf.extend_from_slice(&(netlink::AF_INET as u16).to_ne_bytes());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&[0u8; 8]); // sin_zero padding
            buf
        }
        SocketAddr::V6(a) => {
            let mut buf = Vec::with_capacity(28);
            buf.extend_from_slice(&(netlink::AF_INET6 as u16).to_ne_bytes());
            buf.extend_from_slice(&a.port().to_be_bytes());
            buf.extend_from_slice(&0u32.to_ne_bytes()); // sin6_flowinfo
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&0u32.to_ne_bytes()); // sin6_scope_id
            buf
        }
    }
}

fn decode_key(field: &str, b64: &str) -> Result<[u8; WG_KEY_LEN]> {
    let bytes = base64_decode(b64.trim())
        .map_err(|_| NetworkError::Vpn(format!("{field} is not valid base64")))?;
    <[u8; WG_KEY_LEN]>::try_from(bytes.as_slice())
        .map_err(|_| NetworkError::Vpn(format!("{field} must decode to {WG_KEY_LEN} bytes")))
}

/// A small hand-rolled standard-alphabet (RFC 4648) base64 decoder --
/// WireGuard keys are always exactly 32 bytes (44 base64 characters,
/// one trailing `=`), so this only needs to handle that one shape, not
/// arbitrary-length or URL-safe-alphabet input, and pulling in a crate
/// for it would be a poor trade against the rest of this codebase's
/// dependency budget.
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let input = input.trim_end_matches('=');
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        let v = val(b).ok_or(())?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_a_32_byte_key() {
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded.len(), 32);
        assert!(decoded.iter().all(|&b| b == 0));
    }

    #[test]
    fn base64_round_trips_a_known_vector() {
        // RFC 4648 sec 10 test vector.
        let decoded = base64_decode("YW55IGNhcm5hbCBwbGVhc3VyZS4=").unwrap();
        assert_eq!(decoded, b"any carnal pleasure.");
    }

    #[test]
    fn decode_key_rejects_wrong_length() {
        // Valid base64, but only 4 bytes -- not a 32-byte key.
        assert!(decode_key("test", "AAAAAA==").is_err());
    }

    #[test]
    fn encode_sockaddr_v4_matches_c_struct_layout() {
        let addr: SocketAddr = "192.168.1.1:51820".parse().unwrap();
        let bytes = encode_sockaddr(addr);
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[0..2], &(netlink::AF_INET as u16).to_ne_bytes());
        // sin_port is network (big-endian) byte order: 51820 = 0xCA6C.
        assert_eq!(&bytes[2..4], &[0xCA, 0x6C]);
        assert_eq!(&bytes[4..8], &[192, 168, 1, 1]);
        assert_eq!(&bytes[8..16], &[0u8; 8]);
    }

    #[test]
    fn encode_sockaddr_v6_matches_c_struct_layout() {
        let addr: SocketAddr = "[fe80::1]:51820".parse().unwrap();
        let bytes = encode_sockaddr(addr);
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[0..2], &(netlink::AF_INET6 as u16).to_ne_bytes());
        assert_eq!(&bytes[2..4], &[0xCA, 0x6C]);
    }
}
