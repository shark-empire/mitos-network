//! A real DHCPv4 client (full DISCOVER/OFFER/REQUEST/ACK exchange over
//! a raw UDP broadcast socket) plus a lighter DHCPv6 client. Linux
//! doesn't ship a kernel-level DHCP client -- unlike routing or
//! addressing, this is genuinely an application-layer protocol
//! mitos-network has to speak itself, so unlike most of this crate,
//! this module *is* a from-scratch protocol implementation rather than
//! a policy layer over something the kernel already does.

use crate::errors::Result;

pub mod client;
pub mod dhcp4;
pub mod dhcp6;
pub mod lease;

pub use dhcp6::Lease6;
pub use lease::Lease;

/// The one legitimate way to get an interface's hardware address in
/// this crate (`ip::interface::Interface::hwaddr`, with a clear error
/// if it's unset) -- shared by both DHCP clients internally and by
/// callers (`connection::activation`, `manager`'s lease-renewal tick)
/// that need a MAC before invoking either one.
pub fn get_mac(ifname: &str) -> Result<[u8; 6]> {
    client::get_mac(ifname)
}
