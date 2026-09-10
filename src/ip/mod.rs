//! The IP layer: interfaces, addresses, routes and neighbors, all
//! implemented on top of the kernel's own netlink API (`ip::netlink`).
//!
//! Nothing in this module or its children implements a TCP/IP stack --
//! that's the Linux kernel's job. This is strictly the policy surface
//! mitos-network's higher layers (`device`, `ethernet`, `connection`,
//! `routing`) use to ask the kernel to do things.

pub mod address;
pub mod interface;
pub mod ipv4;
pub mod ipv6;
pub mod monitor;
pub mod neighbor;
mod netlink;
pub mod route;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn raw(self) -> u8 {
        match self {
            Family::V4 => netlink::AF_INET,
            Family::V6 => netlink::AF_INET6,
        }
    }

    pub fn of(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(_) => Family::V4,
            std::net::IpAddr::V6(_) => Family::V6,
        }
    }
}
