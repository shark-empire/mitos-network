//! Station-mode orchestration: the functions `connection::activation`
//! and `connection::deactivation` actually call. Everything below this
//! is either the wpa_supplicant control client (`wifi::wpa`) or pure
//! policy (`wifi::security`, `wifi::roaming`).

use super::security::SecurityType;
use super::wpa::WpaCtrl;
use crate::errors::{NetworkError, Result};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static CTRL_DIR: OnceLock<String> = OnceLock::new();

/// Called once from `main` with `wireless.ctrl-interface-dir` from
/// config -- must match wpa_supplicant's own `ctrl_interface=` setting,
/// since this is how the two processes find each other.
pub fn init(ctrl_dir: &str) {
    let _ = CTRL_DIR.set(ctrl_dir.to_string());
}

fn ctrl_dir() -> String {
    CTRL_DIR.get().cloned().unwrap_or_else(|| "/run/mitos-network/wpa".to_string())
}

/// Joins `ssid` on `ifname`, waiting for association to complete.
/// wpa_supplicant itself must already be running against this
/// interface (mitos-network supervises *starting* wpa_supplicant as
/// part of bringing a Wi-Fi device up -- see `device::link::bring_up`
/// plus the daemon startup sequence in `docs/architecture.md` -- this
/// function only drives an already-running instance's control socket).
pub fn connect(ifname: &str, ssid: &str, security: SecurityType, passphrase: Option<&str>) -> Result<()> {
    crate::security::validation::validate_ssid(ssid)?;
    let ctrl = WpaCtrl::connect(&ctrl_dir(), ifname)?;

    // Clear out any previously-configured network for this SSID so
    // repeated connects (e.g. after a password change) don't pile up
    // stale entries in wpa_supplicant's own config.
    for (id, existing_ssid) in ctrl.list_networks().unwrap_or_default() {
        if existing_ssid.trim_matches('"') == ssid {
            let _ = ctrl.remove_network(id);
        }
    }

    let id = ctrl.add_network()?;
    ctrl.set_network_quoted(id, "ssid", ssid)?;
    ctrl.set_network_raw(id, "key_mgmt", security.key_mgmt())?;

    match (security.needs_passphrase(), passphrase) {
        (false, _) => {}
        (true, Some(pass)) if security.is_enterprise() => {
            // Enterprise (802.1X): `pass` is treated as the identity's
            // password; a real deployment also needs `identity` and a
            // CA cert path, which belong in `ConnectionProfile`'s wifi
            // settings as a follow-up -- flagged in docs/networking.md.
            ctrl.set_network_quoted(id, "password", pass)?;
        }
        (true, Some(pass)) => {
            crate::security::validation::validate_wpa_passphrase(pass)?;
            ctrl.set_network_quoted(id, "psk", pass)?;
        }
        (true, None) => {
            return Err(NetworkError::Wifi(format!(
                "'{ssid}' requires a passphrase but none was provided/stored"
            )));
        }
    }

    ctrl.enable_network(id)?;
    ctrl.select_network(id)?;

    wait_for_association(&ctrl, ssid, Duration::from_secs(20))
}

fn wait_for_association(ctrl: &WpaCtrl, ssid: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = ctrl.status()?;
        let state = status.get("wpa_state").map(String::as_str).unwrap_or("");
        let current_ssid = status.get("ssid").map(String::as_str).unwrap_or("");
        if state == "COMPLETED" && current_ssid == ssid {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(NetworkError::Timeout(format!(
                "association with '{ssid}' did not complete (last state: {state})"
            )));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

pub fn disconnect(ifname: &str) -> Result<()> {
    let ctrl = WpaCtrl::connect(&ctrl_dir(), ifname)?;
    ctrl.disconnect()
}

pub fn forget(ifname: &str, ssid: &str) -> Result<()> {
    let ctrl = WpaCtrl::connect(&ctrl_dir(), ifname)?;
    for (id, existing_ssid) in ctrl.list_networks()? {
        if existing_ssid.trim_matches('"') == ssid {
            ctrl.remove_network(id)?;
        }
    }
    ctrl.save_config()
}

pub fn current_status(ifname: &str) -> Result<std::collections::HashMap<String, String>> {
    WpaCtrl::connect(&ctrl_dir(), ifname)?.status()
}

/// Where wpa_supplicant should create its control socket for `ifname`
/// -- used by whatever spawns wpa_supplicant itself (kept as a plain
/// path helper here since both that spawn point and this module need
/// to agree on it).
pub fn ctrl_socket_path(ifname: &str) -> PathBuf {
    PathBuf::from(ctrl_dir()).join(ifname)
}
