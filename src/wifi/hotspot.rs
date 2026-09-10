//! Turns a Wi-Fi adapter into an access point via `hostapd` -- the
//! standard, well-audited tool every mainstream Linux network manager
//! delegates AP mode to, rather than reimplementing beacon frames and
//! the 4-way handshake's AP side from scratch.
//!
//! This module only owns the radio: generating `hostapd.conf` and
//! supervising the process. Giving the AP interface an address, running
//! a DHCP server for its clients, and NAT'ing them out to the internet
//! is `sharing::hotspot`'s job, one layer up.

use crate::errors::{NetworkError, Result};
use crate::security::validation::{
    validate_interface_name, validate_ssid, validate_wpa_passphrase,
};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::Mutex;

pub struct HotspotConfig {
    pub interface: String,
    pub ssid: String,
    pub passphrase: Option<String>,
    pub channel: u8,
    /// `"g"` for 2.4GHz, `"a"` for 5GHz.
    pub hw_mode: String,
}

fn config_path(ifname: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/mitos-network/hostapd-{ifname}.conf"))
}

fn render_config(cfg: &HotspotConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("interface={}\n", cfg.interface));
    out.push_str("driver=nl80211\n");
    out.push_str(&format!("ssid={}\n", cfg.ssid));
    out.push_str(&format!("hw_mode={}\n", cfg.hw_mode));
    out.push_str(&format!("channel={}\n", cfg.channel));
    out.push_str("ieee80211n=1\n");
    out.push_str("wmm_enabled=1\n");
    match &cfg.passphrase {
        Some(pass) => {
            out.push_str("wpa=2\n");
            out.push_str(&format!("wpa_passphrase={pass}\n"));
            out.push_str("wpa_key_mgmt=WPA-PSK\n");
            out.push_str("rsn_pairwise=CCMP\n");
        }
        None => {
            // Open hotspot -- deliberately still explicit rather than
            // just omitting the wpa* lines, so this file makes the
            // (unusual, should-be-rare) choice visible to an admin
            // reading it later.
            out.push_str("# open network: no wpa_passphrase configured\n");
        }
    }
    out
}

static CHILDREN: Mutex<Option<HashMap<String, Child>>> = Mutex::new(None);

/// Starts (or restarts) `hostapd` for `cfg.interface`. The interface
/// itself must already be up with its AP-mode IP address assigned --
/// see `sharing::hotspot` for that orchestration.
pub fn start(cfg: &HotspotConfig) -> Result<()> {
    validate_interface_name(&cfg.interface)?;
    validate_ssid(&cfg.ssid)?;
    if let Some(p) = &cfg.passphrase {
        validate_wpa_passphrase(p)?;
    }
    stop(&cfg.interface); // idempotent restart

    let path = config_path(&cfg.interface);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    {
        let mut f = std::fs::File::create(&path)?;
        f.write_all(render_config(cfg).as_bytes())?;
    }

    let child = Command::new("hostapd")
        .arg(&path)
        .spawn()
        .map_err(|e| NetworkError::Wifi(format!("failed to spawn hostapd: {e}")))?;

    let mut children = CHILDREN.lock().unwrap();
    children
        .get_or_insert_with(HashMap::new)
        .insert(cfg.interface.clone(), child);
    Ok(())
}

pub fn stop(ifname: &str) {
    if let Some(mut child) = CHILDREN
        .lock()
        .unwrap()
        .as_mut()
        .and_then(|m| m.remove(ifname))
    {
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = std::fs::remove_file(config_path(ifname));
}

pub fn is_running(ifname: &str) -> bool {
    CHILDREN
        .lock()
        .unwrap()
        .as_ref()
        .map(|m| m.contains_key(ifname))
        .unwrap_or(false)
}
