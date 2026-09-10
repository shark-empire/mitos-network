//! Maps an authenticated peer to what it's allowed to do. Kept as a
//! small, explicit enum rather than free-form strings so a typo can't
//! silently open a hole.

use super::permissions::PeerIdentity;
use crate::errors::{NetworkError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Read-only: device/connection/state queries. Safe for anyone.
    ViewState,
    /// Activate/deactivate/add/remove connection profiles.
    ManageConnections,
    ManageWifi,
    ManageVpn,
    ManageFirewall,
    ManageHotspot,
    /// Change daemon configuration itself, reload, shut down.
    Admin,
}

/// The group whose members get every capability short of root-only
/// `Admin` actions -- mirrors the traditional `netdev`/`wheel` model so
/// a desktop user doesn't need a password prompt to join a Wi-Fi network.
pub const PRIVILEGED_GROUP: &str = "netdev";

pub fn check(identity: &PeerIdentity, capability: Capability) -> Result<()> {
    let allowed = match capability {
        Capability::ViewState => true,
        Capability::Admin => identity.is_root(),
        _ => identity.is_root() || identity.in_group(PRIVILEGED_GROUP),
    };
    if allowed {
        Ok(())
    } else {
        Err(NetworkError::PermissionDenied(format!(
            "uid {} lacks {capability:?}",
            identity.uid
        )))
    }
}
