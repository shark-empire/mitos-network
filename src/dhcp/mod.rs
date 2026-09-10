//! A real DHCPv4 client (full DISCOVER/OFFER/REQUEST/ACK exchange over
//! a raw UDP broadcast socket) plus a lighter DHCPv6 client. Linux
//! doesn't ship a kernel-level DHCP client -- unlike routing or
//! addressing, this is genuinely an application-layer protocol
//! mitos-network has to speak itself, so unlike most of this crate,
//! this module *is* a from-scratch protocol implementation rather than
//! a policy layer over something the kernel already does.

pub mod client;
pub mod dhcp4;
pub mod dhcp6;
pub mod lease;

pub use lease::Lease;
