//! Bring-up/tear-down helpers that combine `ip::interface` with a wait
//! for carrier, since "the ioctl returned" and "the link is actually
//! usable" are different moments in time for real hardware.

use crate::errors::{NetworkError, Result};
use crate::ip::interface;
use std::time::{Duration, Instant};

pub fn bring_up(index: i32) -> Result<()> {
    interface::set_up(index)
}

pub fn bring_down(index: i32) -> Result<()> {
    interface::set_down(index)
}

/// Polls (there is no portable blocking "wait for carrier" primitive
/// without netlink event subscription plumbing per-caller, and this is
/// only ever used for short activation waits) until carrier appears or
/// `timeout` elapses.
pub fn wait_for_carrier(index: i32, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        let iface = interface::get_by_index(index)?;
        if iface.has_carrier() {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(NetworkError::Timeout(format!(
                "no carrier on interface index {index} after {:?}",
                timeout
            )));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
