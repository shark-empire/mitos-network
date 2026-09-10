//! Internet connection sharing: turning one interface (usually Wi-Fi in
//! AP mode, but not necessarily) into an uplink for others, complete
//! with its own DHCP server and NAT.

pub mod dhcp_server;
pub mod hotspot;
pub mod internet_sharing;
pub mod nat;
