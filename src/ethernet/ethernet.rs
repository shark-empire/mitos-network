//! Ethernet device readiness. The actual activation flow (bring the
//! link up, wait for carrier, then DHCP or static addressing) is
//! generic across wired-style devices and lives in
//! `connection::activation` -- this module is what `manager` consults
//! *before* that, to decide whether an Ethernet device is worth trying
//! at all.

use crate::errors::Result;

/// Combines the netlink carrier flag with the driver's own
/// `ETHTOOL_GLINK` answer -- an interface only counts as ready when
/// both agree a cable is present, since drivers occasionally lag on
/// updating one or the other after a physical plug/unplug.
pub fn is_ready(ifname: &str) -> bool {
    let netlink_carrier = crate::ip::interface::get_by_name(ifname).map(|i| i.has_carrier()).unwrap_or(false);
    let ethtool_carrier = super::link::has_carrier(ifname).unwrap_or(netlink_carrier);
    netlink_carrier && ethtool_carrier
}

pub fn describe_link(ifname: &str) -> Result<String> {
    let settings = super::link::link_settings(ifname)?;
    Ok(super::auto::describe(&settings))
}
