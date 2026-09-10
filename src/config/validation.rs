use super::NetworkConfig;
use crate::errors::{NetworkError, Result};
use std::net::IpAddr;

/// Sanity-check a loaded config before the manager starts acting on it.
/// This runs once at startup (and again on SIGHUP reload) -- catching a
/// typo'd DNS server here is much friendlier than watching every lookup
/// on the box fail five minutes later.
pub fn validate(cfg: &NetworkConfig) -> Result<()> {
    if cfg.general.socket_path.is_empty() {
        return Err(NetworkError::Config("general.socket-path must not be empty".into()));
    }

    for server in &cfg.dns.servers {
        server
            .parse::<IpAddr>()
            .map_err(|_| NetworkError::Config(format!("invalid DNS server address: {server}")))?;
    }

    for (name, iface) in &cfg.interfaces {
        if name.is_empty() {
            return Err(NetworkError::Config("interface name must not be empty".into()));
        }
        if iface.method == super::AddressMethod::Manual && iface.addresses.is_empty() {
            return Err(NetworkError::Config(format!(
                "interface '{name}' uses method = manual but lists no addresses"
            )));
        }
        for addr in &iface.addresses {
            crate::ip::address::parse_cidr(addr).map_err(|_| {
                NetworkError::Config(format!("interface '{name}': invalid address '{addr}'"))
            })?;
        }
    }

    if cfg.wireless.scan_interval_secs == 0 {
        return Err(NetworkError::Config(
            "wireless.scan-interval-secs must be > 0".into(),
        ));
    }

    Ok(())
}
