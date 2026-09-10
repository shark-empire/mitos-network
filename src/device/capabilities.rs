//! What a device can do -- used mostly to decide which `ipc::messages`
//! requests are even meaningful for it (no point offering "scan" on an
//! Ethernet port).

use super::device::DeviceType;

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct DeviceCapabilities {
    pub can_scan: bool,
    pub can_hotspot: bool,
    pub supports_carrier_detect: bool,
    pub is_virtual: bool,
}

pub fn detect(device_type: DeviceType) -> DeviceCapabilities {
    match device_type {
        DeviceType::WiFi => DeviceCapabilities {
            can_scan: true,
            can_hotspot: true,
            supports_carrier_detect: true,
            is_virtual: false,
        },
        DeviceType::Ethernet => DeviceCapabilities {
            can_scan: false,
            can_hotspot: false,
            supports_carrier_detect: true,
            is_virtual: false,
        },
        DeviceType::Bridge | DeviceType::Bond | DeviceType::Vlan | DeviceType::Tunnel
        | DeviceType::Vpn | DeviceType::Virtual => DeviceCapabilities {
            can_scan: false,
            can_hotspot: false,
            supports_carrier_detect: false,
            is_virtual: true,
        },
        DeviceType::Bluetooth => DeviceCapabilities {
            can_scan: true,
            can_hotspot: false,
            supports_carrier_detect: false,
            is_virtual: false,
        },
        DeviceType::Loopback | DeviceType::Unknown => DeviceCapabilities::default(),
    }
}
