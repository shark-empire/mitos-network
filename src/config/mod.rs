//! Daemon configuration: `config/network.toml`, `interfaces.toml`,
//! `dns.toml` and `wireless.toml` all load into one `NetworkConfig`.
//!
//! This is deliberately *not* where per-connection Wi-Fi/VPN profiles
//! live -- those are user-editable, added/removed at runtime, and go
//! through `connection::profile` + `persistence::profiles` instead.
//! This module is the daemon's own static/base configuration.

mod defaults;
mod loader;
pub mod parser;
mod validation;

pub use defaults::default_config;
pub use loader::load;
pub use validation::validate;

/// The compiled-in default `/etc/resolv.conf` path -- used as a fallback
/// by `dns::resolver` when a caller doesn't have a loaded `DnsConfig`
/// (or its custom `resolv-conf-path`) at hand.
pub fn defaults_resolv_conf_path() -> &'static str {
    defaults::DEFAULT_RESOLV_CONF
}

/// The compiled-in default runtime data directory (leases, profiles,
/// secrets) -- `persistence::*` falls back to this until `main` calls
/// `persistence::state::init` with the loaded config's `data-dir`.
pub fn defaults_data_dir() -> &'static str {
    defaults::DEFAULT_DATA_DIR
}

pub fn defaults_socket_path() -> &'static str {
    defaults::DEFAULT_SOCKET_PATH
}

pub fn defaults_config_dir() -> &'static str {
    defaults::DEFAULT_CONFIG_DIR
}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceConfig>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub wireless: WirelessConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GeneralConfig {
    pub manage_all_devices: bool,
    #[serde(default)]
    pub unmanaged_devices: Vec<String>,
    pub ipv6_enabled: bool,
    pub connectivity_check_url: String,
    pub connectivity_check_interval_secs: u64,
    pub socket_path: String,
    pub data_dir: String,
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        defaults::default_config().general
    }
}

/// How an interface gets its address. Mirrors the "Auto (DHCP)" vs
/// "Manual" choice every mainstream network manager exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressMethod {
    #[default]
    Auto,
    Manual,
    Disabled,
    LinkLocal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceConfig {
    #[serde(default = "default_method")]
    pub method: AddressMethod,
    /// CIDR notation, e.g. "192.168.1.50/24". Only used when method is Manual.
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default = "default_true")]
    pub autoconnect: bool,
}

fn default_method() -> AddressMethod {
    AddressMethod::Auto
}
fn default_true() -> bool {
    true
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        InterfaceConfig {
            method: AddressMethod::Auto,
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
            mtu: None,
            autoconnect: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    /// Use whatever DNS servers the active connection (DHCP, VPN, ...) hands us.
    Auto,
    /// Always use `servers` below, ignoring what connections provide.
    Manual,
    /// Don't touch /etc/resolv.conf at all.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsConfig {
    pub mode: DnsMode,
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(default)]
    pub search_domains: Vec<String>,
    pub resolv_conf_path: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        defaults::default_config().dns
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WirelessConfig {
    pub enabled: bool,
    #[serde(default)]
    pub country_code: Option<String>,
    pub scan_interval_secs: u64,
    #[serde(default)]
    pub powersave: bool,
    /// wpa_supplicant control-interface directory.
    pub ctrl_interface_dir: String,
}

impl Default for WirelessConfig {
    fn default() -> Self {
        defaults::default_config().wireless
    }
}
