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
    CTRL_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| "/run/mitos-network/wpa".to_string())
}

/// 802.1X (Enterprise) configuration. Resolved by the caller
/// (`connection::activation`) from `ConnectionProfile`'s `WifiSettings`
/// plus `security::secrets` before being passed in here -- this module
/// only speaks to wpa_supplicant, it doesn't know about profiles or
/// secrets storage.
#[derive(Debug, Default)]
pub struct EapConfig<'a> {
    pub identity: Option<&'a str>,
    pub ca_cert_path: Option<&'a str>,
    pub client_cert_path: Option<&'a str>,
    pub private_key_path: Option<&'a str>,
    pub private_key_password: Option<&'a str>,
    /// Pin a specific outer EAP method (`"PEAP"`, `"TTLS"`, `"TLS"`,
    /// ...) instead of leaving it to wpa_supplicant/the server to
    /// negotiate. See `connection::profile::WifiSettings::eap_method`
    /// for why an unpinned method is a real weakening, not just a
    /// missing nicety.
    pub eap_method: Option<&'a str>,
    /// Pin the inner (phase 2) method for tunneled EAP (PEAP/TTLS),
    /// e.g. `"auth=MSCHAPV2"`.
    pub eap_phase2: Option<&'a str>,
}

/// Joins `ssid` on `ifname`, waiting for association to complete.
/// wpa_supplicant itself must already be running against this
/// interface (mitos-network supervises *starting* wpa_supplicant as
/// part of bringing a Wi-Fi device up -- see `device::link::bring_up`
/// plus the daemon startup sequence in `docs/architecture.md` -- this
/// function only drives an already-running instance's control socket).
pub fn connect(
    ifname: &str,
    ssid: &str,
    security: SecurityType,
    passphrase: Option<&str>,
    eap: Option<&EapConfig<'_>>,
) -> Result<()> {
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

    if security.is_enterprise() {
        let eap = eap.ok_or_else(|| {
            NetworkError::Wifi(format!(
                "'{ssid}' is an Enterprise network but no EAP identity/certificate \
                 configuration was provided"
            ))
        })?;
        configure_eap(&ctrl, id, ssid, eap, passphrase)?;
    } else {
        match (security.needs_passphrase(), passphrase) {
            (false, _) => {}
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
    }

    ctrl.enable_network(id)?;
    ctrl.select_network(id)?;

    wait_for_association(&ctrl, ssid, Duration::from_secs(20))
}

/// Sets the wpa_supplicant `SET_NETWORK` fields for 802.1X auth:
/// identity always, then either a password (PEAP/TTLS) or a client
/// cert + private key (EAP-TLS) -- at least one of the two is
/// required, but not both -- plus whichever of the certificate paths
/// were supplied.
fn configure_eap(
    ctrl: &WpaCtrl,
    id: u32,
    ssid: &str,
    eap: &EapConfig<'_>,
    password: Option<&str>,
) -> Result<()> {
    let identity = eap.identity.ok_or_else(|| {
        NetworkError::Wifi(format!(
            "'{ssid}' is an Enterprise network but no EAP identity (username) was configured"
        ))
    })?;
    ctrl.set_network_quoted(id, "identity", identity)?;

    if let Some(method) = eap.eap_method {
        crate::security::validation::validate_eap_method(method)?;
        ctrl.set_network_raw(id, "eap", &method.to_ascii_uppercase())?;
    }
    if let Some(phase2) = eap.eap_phase2 {
        crate::security::validation::validate_quoted_value("EAP phase2", phase2)?;
        ctrl.set_network_quoted(id, "phase2", phase2)?;
    }

    match password {
        Some(pass) => ctrl.set_network_quoted(id, "password", pass)?,
        None if eap.client_cert_path.is_none() => {
            return Err(NetworkError::Wifi(format!(
                "'{ssid}' needs either a password or a client certificate for Enterprise auth"
            )));
        }
        None => {}
    }

    match eap.ca_cert_path {
        Some(ca) => {
            crate::security::validation::validate_cert_path("CA certificate path", ca)?;
            check_cert_readable(ca)?;
            ctrl.set_network_quoted(id, "ca_cert", ca)?;
        }
        None => {
            // Not a hard error: some guest/captive EAP deployments
            // genuinely have nothing to pin. But an unvalidated RADIUS
            // server is exactly what lets a rogue AP impersonate a
            // known enterprise network and phish these credentials, so
            // this is surfaced loudly rather than silently accepted.
            crate::logging::logger::warn(&format!(
                "connecting to Enterprise network '{ssid}' with no CA certificate configured -- \
                 the server's identity will not be validated"
            ));
        }
    }

    if let Some(cert) = eap.client_cert_path {
        crate::security::validation::validate_cert_path("client certificate path", cert)?;
        check_cert_readable(cert)?;
        ctrl.set_network_quoted(id, "client_cert", cert)?;
    }
    if let Some(key) = eap.private_key_path {
        crate::security::validation::validate_cert_path("private key path", key)?;
        check_cert_readable(key)?;
        ctrl.set_network_quoted(id, "private_key", key)?;
        if let Some(key_pass) = eap.private_key_password {
            ctrl.set_network_quoted(id, "private_key_passwd", key_pass)?;
        }
    }
    Ok(())
}

/// Fails fast with a clear error rather than letting a bad path reach
/// wpa_supplicant, where it'd surface as an opaque handshake failure.
fn check_cert_readable(path: &str) -> Result<()> {
    std::fs::File::open(path)
        .map(|_| ())
        .map_err(|e| NetworkError::Config(format!("cannot read '{path}': {e}")))
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
