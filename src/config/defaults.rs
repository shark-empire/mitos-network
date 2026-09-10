use super::{DnsConfig, DnsMode, GeneralConfig, NetworkConfig, WirelessConfig};
use std::collections::HashMap;

pub const DEFAULT_SOCKET_PATH: &str = "/run/mitos-network/network.sock";
pub const DEFAULT_DATA_DIR: &str = "/var/lib/mitos-network";
pub const DEFAULT_CONFIG_DIR: &str = "/etc/mitos-network";
pub const DEFAULT_RESOLV_CONF: &str = "/etc/resolv.conf";
pub const DEFAULT_CONNECTIVITY_URL: &str = "http://connectivity.mitos-os.org/check";

/// Fallback configuration used when no files exist under
/// `/etc/mitos-network` yet (first boot) and as the base that
/// `config::loader` overlays on-disk files onto.
pub fn default_config() -> NetworkConfig {
    NetworkConfig {
        general: GeneralConfig {
            manage_all_devices: true,
            unmanaged_devices: vec!["lo".to_string()],
            ipv6_enabled: true,
            connectivity_check_url: DEFAULT_CONNECTIVITY_URL.to_string(),
            connectivity_check_interval_secs: 30,
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            data_dir: DEFAULT_DATA_DIR.to_string(),
            log_level: "info".to_string(),
        },
        interfaces: HashMap::new(),
        dns: DnsConfig {
            mode: DnsMode::Auto,
            servers: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            search_domains: Vec::new(),
            resolv_conf_path: DEFAULT_RESOLV_CONF.to_string(),
        },
        wireless: WirelessConfig {
            enabled: true,
            country_code: None,
            scan_interval_secs: 60,
            powersave: false,
            ctrl_interface_dir: "/run/mitos-network/wpa".to_string(),
        },
    }
}
