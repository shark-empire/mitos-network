//! Route metric assignment. Lower metric wins in the kernel's route
//! selection, so these numbers encode mitos-network's uplink
//! preference order: prefer a VPN over the connection carrying it,
//! prefer wired over wireless, prefer either over tethering-style
//! Bluetooth PAN. Values deliberately leave headroom between tiers for
//! per-connection `autoconnect_priority` adjustments.

use crate::device::DeviceType;

pub fn base_metric(device_type: DeviceType) -> u32 {
    match device_type {
        DeviceType::Vpn => 50,
        DeviceType::Ethernet => 100,
        DeviceType::Bridge | DeviceType::Bond => 150,
        DeviceType::WiFi => 600,
        DeviceType::Bluetooth => 700,
        DeviceType::Vlan | DeviceType::Tunnel => 400,
        DeviceType::Virtual | DeviceType::Loopback | DeviceType::Unknown => 900,
    }
}

/// A profile's own priority nudges the base metric without ever letting
/// it cross into a different device-type tier (a Wi-Fi network with
/// priority 100 should still lose to *any* wired connection).
pub fn effective_metric(device_type: DeviceType, autoconnect_priority: i32) -> u32 {
    let base = base_metric(device_type) as i64;
    let adjusted = base - (autoconnect_priority as i64).clamp(-40, 40);
    adjusted.clamp(1, 65535) as u32
}
