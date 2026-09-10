//! IPv4 forwarding + masquerading -- the two kernel-level switches
//! internet sharing needs flipped, on top of what `firewall::Firewall`
//! already renders into nftables.

use crate::errors::Result;
use crate::firewall::Firewall;

/// Flips `/proc/sys/net/ipv4/ip_forward`. This is genuinely a raw
/// sysctl write, not a netlink operation -- forwarding is a global
/// kernel switch, not a per-link or per-route attribute, so there's no
/// rtnetlink message for it.
pub fn set_ipv4_forwarding(enabled: bool) -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", if enabled { "1" } else { "0" })?;
    Ok(())
}

pub fn enable(lan_interface: &str, wan_interface: &str, firewall: &mut Firewall) -> Result<()> {
    set_ipv4_forwarding(true)?;
    firewall.enable_sharing(lan_interface, wan_interface)
}

pub fn disable(lan_interface: &str, wan_interface: &str, firewall: &mut Firewall) -> Result<()> {
    firewall.disable_sharing(lan_interface, wan_interface)
    // Deliberately not flipping ip_forward back off here: another
    // sharing session or an unrelated feature might depend on it too.
    // Global on/off is left to explicit admin action / daemon shutdown.
}
