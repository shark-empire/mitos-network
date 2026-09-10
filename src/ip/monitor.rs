//! A netlink multicast "monitor" socket: subscribes to link/address
//! change notifications and hands back raw, minimally-parsed events.
//! Interpreting *what to do* about an event is `device::discovery`'s
//! job, not this module's -- this stays a thin transport wrapper, same
//! spirit as the rest of `ip::netlink`.

use super::netlink::{self, NlSocket};
use crate::errors::Result;

pub use netlink::{RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK};

#[derive(Debug, Clone)]
pub enum RawEvent {
    LinkNew { name: String },
    LinkDel { name: String },
    AddrNew { index: i32 },
    AddrDel { index: i32 },
}

pub struct Monitor {
    sock: NlSocket,
}

impl Monitor {
    pub fn new(groups: u32) -> Result<Self> {
        Ok(Monitor {
            sock: NlSocket::with_groups(groups)?,
        })
    }

    /// Blocks until the next multicast notification arrives.
    pub fn recv(&self) -> Result<Vec<RawEvent>> {
        self.sock.recv_multicast(|msg_type, body| match msg_type {
            netlink::RTM_NEWLINK => {
                netlink::parse_link(body).map(|l| RawEvent::LinkNew { name: l.name })
            }
            netlink::RTM_DELLINK => {
                netlink::parse_link(body).map(|l| RawEvent::LinkDel { name: l.name })
            }
            netlink::RTM_NEWADDR => {
                netlink::parse_addr(body).map(|a| RawEvent::AddrNew { index: a.index })
            }
            netlink::RTM_DELADDR => {
                netlink::parse_addr(body).map(|a| RawEvent::AddrDel { index: a.index })
            }
            _ => None,
        })
    }
}
