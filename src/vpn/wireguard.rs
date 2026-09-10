//! WireGuard client setup.
//!
//! The interface itself is created via the same netlink client the
//! rest of `ip::*` uses (`ip link add <name> type wireguard` is just an
//! `RTM_NEWLINK` with `IFLA_LINKINFO` kind `"wireguard"` -- the kernel's
//! WireGuard module registers itself as an rtnetlink link type, so this
//! needs no special-casing). Setting the actual crypto parameters
//! (private key, peer public key, endpoint, allowed-ips) goes through
//! the `wg` command-line tool rather than hand-rolling WireGuard's own
//! netlink family or UAPI socket protocol -- `wg` is the reference
//! implementation's own tool, already installed anywhere WireGuard is
//! usable at all, and getting key handling exactly right by hand is
//! exactly the kind of thing worth not reimplementing.

use crate::errors::{NetworkError, Result};
use crate::security::secrets::SecretsBackend;
use crate::vpn::vpn::{VpnKind, VpnSession};
use serde::Deserialize;
use std::io::Write;
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct WireGuardConfig {
    pub interface: String,
    /// CIDR, e.g. `"10.0.0.2/32"`.
    pub address: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    #[serde(default = "default_allowed_ips")]
    pub peer_allowed_ips: String,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive_secs: u16,
}

fn default_allowed_ips() -> String {
    "0.0.0.0/0, ::/0".to_string()
}
fn default_keepalive() -> u16 {
    25
}

pub fn connect(config: &str, secrets: &dyn SecretsBackend, profile_id: &str) -> Result<VpnSession> {
    let cfg: WireGuardConfig = toml::from_str(config)
        .map_err(|e| NetworkError::Vpn(format!("invalid WireGuard config: {e}")))?;
    crate::security::validation::validate_interface_name(&cfg.interface)?;

    let private_key = secrets
        .get(profile_id, "wg-private-key")?
        .ok_or_else(|| NetworkError::Vpn(format!("no private key stored for '{profile_id}'")))?;

    // Idempotent: creating over an existing device of the same name is
    // a common re-activation path (daemon restart, profile re-enabled).
    if crate::ip::interface::get_by_name(&cfg.interface).is_err() {
        crate::ip::interface::create_virtual(&cfg.interface, "wireguard")?;
    }
    let iface = crate::ip::interface::get_by_name(&cfg.interface)?;

    let (addr, prefixlen) = crate::ip::address::parse_cidr(&cfg.address)?;
    crate::ip::address::add(iface.index, addr, prefixlen)?;

    set_crypto_params(&cfg, &private_key)?;

    crate::device::link::bring_up(iface.index)?;

    for cidr in cfg
        .peer_allowed_ips
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok((dst, len)) = crate::ip::address::parse_cidr(cidr) {
            let _ = crate::ip::route::add(&crate::ip::route::Route {
                destination: Some((dst, len)),
                gateway: None,
                oif_index: iface.index,
                metric: None,
                protocol: crate::ip::route::RouteProtocol::Static,
            });
        }
    }

    Ok(VpnSession {
        interface_name: cfg.interface,
        kind: VpnKind::WireGuard,
    })
}

fn set_crypto_params(cfg: &WireGuardConfig, private_key: &str) -> Result<()> {
    // The private key never touches argv (visible to any local user via
    // `ps`) -- write it to a mode-0600 temp file `wg` reads instead,
    // then remove it immediately.
    let key_path = std::env::temp_dir().join(format!("mitos-wg-{}.key", std::process::id()));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&key_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(private_key.trim().as_bytes())?;
    }

    let mut cmd = Command::new("wg");
    cmd.arg("set")
        .arg(&cfg.interface)
        .arg("private-key")
        .arg(&key_path);
    if let Some(port) = cfg.listen_port {
        cmd.arg("listen-port").arg(port.to_string());
    }
    cmd.arg("peer")
        .arg(&cfg.peer_public_key)
        .arg("endpoint")
        .arg(&cfg.peer_endpoint)
        .arg("allowed-ips")
        .arg(&cfg.peer_allowed_ips)
        .arg("persistent-keepalive")
        .arg(cfg.persistent_keepalive_secs.to_string());

    let result = cmd.status();
    let _ = std::fs::remove_file(&key_path);

    let status = result.map_err(|e| NetworkError::Vpn(format!("failed to run `wg set`: {e}")))?;
    if !status.success() {
        return Err(NetworkError::Vpn(format!("`wg set` exited with {status}")));
    }
    Ok(())
}

pub fn disconnect(ifname: &str) -> Result<()> {
    let iface = crate::ip::interface::get_by_name(ifname)?;
    crate::ip::interface::delete(iface.index)
}
