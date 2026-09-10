use super::{defaults, NetworkConfig};
use crate::errors::Result;
use std::path::Path;

/// Load configuration from a directory containing `network.toml`,
/// `interfaces.toml`, `dns.toml` and `wireless.toml`. Any file that is
/// missing falls back to the matching section of `default_config()`,
/// so a fresh mitosOS install with zero files still boots with sane
/// (DHCP-everywhere, public DNS) defaults.
pub fn load(config_dir: &Path) -> Result<NetworkConfig> {
    let mut cfg = defaults::default_config();

    if let Some(general) = super::parser::parse_optional::<TopLevelGeneral>(
        &config_dir.join("network.toml"),
    )? {
        cfg.general = general.general;
    }
    if let Some(interfaces) = super::parser::parse_optional::<TopLevelInterfaces>(
        &config_dir.join("interfaces.toml"),
    )? {
        cfg.interfaces = interfaces.interface;
    }
    if let Some(dns) = super::parser::parse_optional::<TopLevelDns>(&config_dir.join("dns.toml"))?
    {
        cfg.dns = dns.dns;
    }
    if let Some(wireless) =
        super::parser::parse_optional::<TopLevelWireless>(&config_dir.join("wireless.toml"))?
    {
        cfg.wireless = wireless.wireless;
    }

    super::validation::validate(&cfg)?;
    Ok(cfg)
}

// Each on-disk file has its section nested under a top-level table
// matching the file's own name (see config/network.toml etc. shipped
// with this crate), so a stray typo in one file can't silently
// overwrite an unrelated section.
#[derive(serde::Deserialize)]
struct TopLevelGeneral {
    general: super::GeneralConfig,
}
#[derive(serde::Deserialize)]
struct TopLevelInterfaces {
    #[serde(default)]
    interface: std::collections::HashMap<String, super::InterfaceConfig>,
}
#[derive(serde::Deserialize)]
struct TopLevelDns {
    dns: super::DnsConfig,
}
#[derive(serde::Deserialize)]
struct TopLevelWireless {
    wireless: super::WirelessConfig,
}
