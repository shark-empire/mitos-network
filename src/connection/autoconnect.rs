//! Decides which profile (if any) should be auto-activated on a device
//! that just became available, e.g. a cable was plugged in or a
//! previously-seen SSID came back into range.

use super::profile::ConnectionProfile;
use crate::device::{DeviceType, NetworkDevice};

/// Picks the best eligible profile for `device` out of `candidates`,
/// preferring (in order): explicitly pinned to this interface name,
/// higher `autoconnect_priority`, then most-recently-used (handled by
/// the caller passing `candidates` pre-sorted by
/// `persistence::profiles::recently_used_first`).
pub fn select<'a>(
    device: &NetworkDevice,
    candidates: &'a [ConnectionProfile],
) -> Option<&'a ConnectionProfile> {
    let mut eligible: Vec<&ConnectionProfile> = candidates
        .iter()
        .filter(|p| p.autoconnect && matches(p, device))
        .collect();

    eligible.sort_by(|a, b| {
        let pinned_a = a.interface_name.as_deref() == Some(device.name.as_str());
        let pinned_b = b.interface_name.as_deref() == Some(device.name.as_str());
        pinned_b
            .cmp(&pinned_a)
            .then(b.autoconnect_priority.cmp(&a.autoconnect_priority))
    });

    eligible.into_iter().next()
}

fn matches(profile: &ConnectionProfile, device: &NetworkDevice) -> bool {
    if profile.device_type != device.device_type {
        return false;
    }
    match &profile.interface_name {
        Some(name) => name == &device.name,
        None => true,
    }
}

/// Wi-Fi is a special case: a profile only "matches" a scan result if
/// the SSID (and, implicitly, whatever the AP is broadcasting for
/// security) lines up -- device-type/interface matching alone isn't
/// enough the way it is for wired autoconnect.
pub fn select_wifi<'a>(
    device: &NetworkDevice,
    candidates: &'a [ConnectionProfile],
    visible_ssids: &[String],
) -> Option<&'a ConnectionProfile> {
    if device.device_type != DeviceType::WiFi {
        return None;
    }
    let mut eligible: Vec<&ConnectionProfile> = candidates
        .iter()
        .filter(|p| {
            p.autoconnect
                && p.wifi
                    .as_ref()
                    .map(|w| visible_ssids.iter().any(|s| s == &w.ssid))
                    .unwrap_or(false)
        })
        .collect();
    eligible.sort_by_key(|p| std::cmp::Reverse(p.autoconnect_priority));
    eligible.into_iter().next()
}
