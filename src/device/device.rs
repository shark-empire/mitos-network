use std::fmt;

/// What kind of interface this is. Deliberately mirrors the categories
/// every mainstream network manager exposes, so profiles and UI code
/// elsewhere in mitosOS don't need their own vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DeviceType {
    Ethernet,
    WiFi,
    Loopback,
    Bridge,
    Bond,
    Vlan,
    Tunnel,
    Vpn,
    Bluetooth,
    Virtual,
    Unknown,
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DeviceType::Ethernet => "ethernet",
            DeviceType::WiFi => "wifi",
            DeviceType::Loopback => "loopback",
            DeviceType::Bridge => "bridge",
            DeviceType::Bond => "bond",
            DeviceType::Vlan => "vlan",
            DeviceType::Tunnel => "tunnel",
            DeviceType::Vpn => "vpn",
            DeviceType::Bluetooth => "bluetooth",
            DeviceType::Virtual => "virtual",
            DeviceType::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Per-device state machine. Loosely mirrors NetworkManager's own
/// `NMDeviceState`, trimmed to what mitos-network actually acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceState {
    /// mitos-network is deliberately not touching this device (see
    /// `general.unmanaged-devices` in `network.toml`).
    Unmanaged,
    /// Managed, but the link isn't there yet (cable unplugged, radio off).
    Unavailable,
    Disconnected,
    Connecting,
    /// L2 is up (associated / carrier present) but IP configuration
    /// (DHCP or static) hasn't finished yet.
    IpConfiguring,
    Activated,
    Deactivating,
    Failed,
}

impl DeviceState {
    pub fn is_connected(self) -> bool {
        matches!(self, DeviceState::Activated)
    }
}

impl fmt::Display for DeviceState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single network interface as mitos-network sees it: the merge of
/// what the kernel reports (`ip::interface::Interface`) plus the policy
/// state layered on top.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkDevice {
    pub name: String,
    pub index: u32,
    pub device_type: DeviceType,
    pub state: DeviceState,
    pub mac_address: Option<String>,
    pub mtu: u32,
    #[serde(default)]
    pub ipv4_addresses: Vec<String>,
    #[serde(default)]
    pub ipv6_addresses: Vec<String>,
    #[serde(default)]
    pub carrier: bool,
    /// The kernel driver backing this device, when known (from
    /// `/sys/class/net/<name>/device/driver`), purely informational --
    /// shown in `mitos-netctl device show` for bug reports.
    #[serde(default)]
    pub driver: Option<String>,
    /// The active connection profile's id, if any (see `connection::profile`).
    #[serde(default)]
    pub active_connection: Option<String>,
}

impl NetworkDevice {
    pub fn is_wireless(&self) -> bool {
        self.device_type == DeviceType::WiFi
    }
}
