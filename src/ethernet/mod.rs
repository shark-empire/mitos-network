//! Ethernet: mostly a thin specialization over `device::link` (the
//! generic bring-up/carrier-wait path in `connection::activation`
//! already handles "plug in -> DHCP -> internet" for any wired-style
//! device). What's genuinely Ethernet-specific lives here: driver-level
//! link status and speed/duplex via `ETHTOOL` ioctls, which give a more
//! detailed and sometimes more *current* picture than the netlink
//! `IFF_RUNNING` flag alone (some drivers are slow to update it).

pub mod auto;
pub mod ethernet;
pub mod link;
