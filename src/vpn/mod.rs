//! VPN backends. Each kind gets its own module (`wireguard`, `openvpn`)
//! implementing the same small connect/disconnect shape; `vpn::vpn`
//! dispatches between them and tracks which interface belongs to which
//! active session.

pub mod openvpn;
pub mod tunnel;
pub mod vpn;
pub mod wireguard;

pub use vpn::{VpnKind, VpnSession};
