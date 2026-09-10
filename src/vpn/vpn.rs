use crate::errors::{NetworkError, Result};
use crate::security::secrets::SecretsBackend;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnKind {
    WireGuard,
    OpenVpn,
}

pub struct VpnSession {
    pub interface_name: String,
    pub kind: VpnKind,
}

static ACTIVE: Mutex<Option<HashMap<String, VpnKind>>> = Mutex::new(None);

fn track(interface_name: &str, kind: VpnKind) {
    ACTIVE
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(interface_name.to_string(), kind);
}

fn untrack(interface_name: &str) -> Option<VpnKind> {
    ACTIVE
        .lock()
        .unwrap()
        .as_mut()
        .and_then(|m| m.remove(interface_name))
}

/// `config` is kind-specific: TOML key/value text for WireGuard
/// (`vpn::wireguard`'s `WireGuardConfig`), a filesystem path to an
/// `.ovpn` file for OpenVPN.
pub fn connect(
    kind: VpnKind,
    config: &str,
    secrets: &dyn SecretsBackend,
    profile_id: &str,
) -> Result<VpnSession> {
    let session = match kind {
        VpnKind::WireGuard => super::wireguard::connect(config, secrets, profile_id)?,
        VpnKind::OpenVpn => super::openvpn::connect(config, secrets, profile_id)?,
    };
    track(&session.interface_name, kind);
    Ok(session)
}

pub fn disconnect(interface_name: &str) -> Result<()> {
    match untrack(interface_name) {
        Some(VpnKind::WireGuard) => super::wireguard::disconnect(interface_name),
        Some(VpnKind::OpenVpn) => super::openvpn::disconnect(interface_name),
        None => Err(NetworkError::NotFound(format!(
            "no active VPN session on '{interface_name}'"
        ))),
    }
}
