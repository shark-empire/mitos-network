//! A client for wpa_supplicant's Unix-domain-socket control interface.
//!
//! This is a real (if partial) implementation of the same text
//! protocol `wpa_cli` speaks: a `SOCK_DGRAM` Unix socket, one line in,
//! one reply back (`"OK"`, `"FAIL"`, or command-specific text). Command
//! syntax and reply shapes here are cross-referenced against
//! wpa_supplicant's own `wpa_ctrl.h`/`ctrl_iface.c` documentation.
//! Not implemented: the unsolicited event stream (`ATTACH` +
//! `CTRL-EVENT-*` push notifications) -- `wifi::scanner` polls
//! `SCAN_RESULTS` after a short delay instead of subscribing to
//! `CTRL-EVENT-SCAN-RESULTS`. Documented as a known gap in
//! `docs/networking.md`.

use crate::errors::{NetworkError, Result};
use std::collections::HashMap;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

pub struct WpaCtrl {
    sock: UnixDatagram,
    client_path: PathBuf,
}

impl WpaCtrl {
    pub fn connect(ctrl_dir: &str, ifname: &str) -> Result<Self> {
        crate::security::validation::validate_interface_name(ifname)?;
        let server_path = format!("{ctrl_dir}/{ifname}");
        let client_path = PathBuf::from(format!("/tmp/mitos-wpa-{ifname}-{}", std::process::id()));
        let _ = std::fs::remove_file(&client_path);
        let sock = UnixDatagram::bind(&client_path)
            .map_err(|e| NetworkError::Wifi(format!("bind control client socket: {e}")))?;
        sock.connect(&server_path)
            .map_err(|e| NetworkError::Wifi(format!("connect to wpa_supplicant at {server_path}: {e}")))?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(WpaCtrl { sock, client_path })
    }

    fn request(&self, cmd: &str) -> Result<String> {
        self.sock.send(cmd.as_bytes())?;
        let mut buf = vec![0u8; 8192];
        let n = self.sock.recv(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).trim_end().to_string())
    }

    fn request_ok(&self, cmd: &str) -> Result<()> {
        let reply = self.request(cmd)?;
        if reply.trim() == "OK" {
            Ok(())
        } else {
            Err(NetworkError::Wifi(format!("'{cmd}' failed: {reply}")))
        }
    }

    pub fn ping(&self) -> Result<bool> {
        Ok(self.request("PING")?.trim() == "PONG")
    }

    pub fn scan(&self) -> Result<()> {
        self.request_ok("SCAN")
    }

    pub fn scan_results_raw(&self) -> Result<String> {
        self.request("SCAN_RESULTS")
    }

    pub fn status(&self) -> Result<HashMap<String, String>> {
        let raw = self.request("STATUS")?;
        Ok(raw
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }

    /// `SIGNAL_POLL` -> `RSSI=-45\nLINKSPEED=130\nNOISE=9999\nFREQUENCY=5180`.
    /// Only meaningful while associated; used by `monitoring::signal`.
    pub fn signal_poll(&self) -> Result<HashMap<String, String>> {
        let raw = self.request("SIGNAL_POLL")?;
        Ok(raw
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }

    /// Returns the new network's id.
    pub fn add_network(&self) -> Result<u32> {
        let reply = self.request("ADD_NETWORK")?;
        reply.trim().parse().map_err(|_| NetworkError::Wifi(format!("unexpected ADD_NETWORK reply: {reply}")))
    }

    pub fn set_network_quoted(&self, id: u32, key: &str, value: &str) -> Result<()> {
        // wpa_supplicant expects string-valued fields (ssid, psk,
        // identity, password, ...) wrapped in literal double quotes.
        self.request_ok(&format!("SET_NETWORK {id} {key} \"{value}\""))
    }

    pub fn set_network_raw(&self, id: u32, key: &str, value: &str) -> Result<()> {
        self.request_ok(&format!("SET_NETWORK {id} {key} {value}"))
    }

    pub fn enable_network(&self, id: u32) -> Result<()> {
        self.request_ok(&format!("ENABLE_NETWORK {id}"))
    }

    pub fn disable_network(&self, id: u32) -> Result<()> {
        self.request_ok(&format!("DISABLE_NETWORK {id}"))
    }

    /// Enables `id` and disables every other configured network --
    /// wpa_supplicant's normal way of saying "connect to this one".
    pub fn select_network(&self, id: u32) -> Result<()> {
        self.request_ok(&format!("SELECT_NETWORK {id}"))
    }

    pub fn remove_network(&self, id: u32) -> Result<()> {
        self.request_ok(&format!("REMOVE_NETWORK {id}"))
    }

    pub fn list_networks(&self) -> Result<Vec<(u32, String)>> {
        let raw = self.request("LIST_NETWORKS")?;
        Ok(raw
            .lines()
            .skip(1) // header: "network id / ssid / bssid / flags"
            .filter_map(|l| {
                let mut parts = l.split('\t');
                let id: u32 = parts.next()?.parse().ok()?;
                let ssid = parts.next()?.to_string();
                Some((id, ssid))
            })
            .collect())
    }

    pub fn disconnect(&self) -> Result<()> {
        self.request_ok("DISCONNECT")
    }

    pub fn reconnect(&self) -> Result<()> {
        self.request_ok("RECONNECT")
    }

    pub fn save_config(&self) -> Result<()> {
        self.request_ok("SAVE_CONFIG")
    }
}

impl Drop for WpaCtrl {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.client_path);
    }
}
