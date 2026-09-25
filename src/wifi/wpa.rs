//! A client for wpa_supplicant's Unix-domain-socket control interface.
//!
//! This is a real (if partial) implementation of the same text
//! protocol `wpa_cli` speaks: a `SOCK_DGRAM` Unix socket, one line in,
//! one reply back (`"OK"`, `"FAIL"`, or command-specific text). Command
//! syntax and reply shapes here are cross-referenced against
//! wpa_supplicant's own `wpa_ctrl.h`/`ctrl_iface.c` documentation.
//!
//! [`WpaCtrl`] is the synchronous request/reply half; [`WpaMonitor`]
//! is the other half, the unsolicited `CTRL-EVENT-*` push stream a
//! client subscribes to via `ATTACH` -- see its doc comment for why
//! that's a genuinely separate connection rather than a mode switch on
//! the same one.

use crate::errors::{NetworkError, Result};
use std::collections::HashMap;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct WpaCtrl {
    sock: UnixDatagram,
    client_path: PathBuf,
}

impl WpaCtrl {
    pub fn connect(ctrl_dir: &str, ifname: &str) -> Result<Self> {
        crate::security::validation::validate_interface_name(ifname)?;
        let server_path = format!("{ctrl_dir}/{ifname}");
        // Unpredictable, not `<ifname>-<pid>`: a fixed, guessable client
        // path in a world-writable directory is exactly the kind of
        // thing another local user could pre-place a symlink at ahead
        // of time. See `security::tempfile`.
        let client_path =
            crate::security::tempfile::random_temp_path(&format!("mitos-wpa-{ifname}"), "sock")?;
        let sock = UnixDatagram::bind(&client_path)
            .map_err(|e| NetworkError::Wifi(format!("bind control client socket: {e}")))?;
        sock.connect(&server_path).map_err(|e| {
            NetworkError::Wifi(format!("connect to wpa_supplicant at {server_path}: {e}"))
        })?;
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
        reply
            .trim()
            .parse()
            .map_err(|_| NetworkError::Wifi(format!("unexpected ADD_NETWORK reply: {reply}")))
    }

    pub fn set_network_quoted(&self, id: u32, key: &str, value: &str) -> Result<()> {
        // wpa_supplicant expects string-valued fields (ssid, psk,
        // identity, password, ca_cert, ...) wrapped in literal double
        // quotes. A value containing a quote would close the literal
        // early and inject extra tokens into the control command --
        // some of these fields (ssid, above all) are attacker-supplied
        // in the sense that any nearby rogue AP can broadcast an
        // arbitrary SSID, so this is a real boundary, not just
        // defensive style.
        crate::security::validation::validate_quoted_value(key, value)?;
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

/// A subscription to wpa_supplicant's unsolicited event stream
/// (`ATTACH` / `CTRL-EVENT-*` pushes), used to wait for a specific
/// event -- e.g. `wifi::scanner` waiting for `CTRL-EVENT-SCAN-RESULTS`
/// instead of guessing how long a scan takes.
///
/// Deliberately a *second* connection to the same control socket
/// `WpaCtrl` talks to, not a second use of the same one: once
/// attached, wpa_supplicant pushes event lines onto a socket with no
/// framing that distinguishes "this is a push" from "this is the
/// reply to the command you just sent" -- a synchronous
/// request/reply caller and an asynchronous event reader sharing one
/// socket would race each other for whichever message arrives next.
/// `wpa_cli` avoids exactly this by keeping separate `ctrl_conn`/
/// `mon_conn` sockets; this mirrors that.
pub struct WpaMonitor {
    sock: UnixDatagram,
    client_path: PathBuf,
}

impl WpaMonitor {
    pub fn attach(ctrl_dir: &str, ifname: &str) -> Result<Self> {
        crate::security::validation::validate_interface_name(ifname)?;
        let server_path = format!("{ctrl_dir}/{ifname}");
        let client_path = crate::security::tempfile::random_temp_path(
            &format!("mitos-wpa-mon-{ifname}"),
            "sock",
        )?;
        let sock = UnixDatagram::bind(&client_path)
            .map_err(|e| NetworkError::Wifi(format!("bind monitor socket: {e}")))?;
        sock.connect(&server_path).map_err(|e| {
            NetworkError::Wifi(format!(
                "connect monitor to wpa_supplicant at {server_path}: {e}"
            ))
        })?;
        let mon = WpaMonitor { sock, client_path };
        let reply = mon.raw_request("ATTACH")?;
        if reply.trim() != "OK" {
            return Err(NetworkError::Wifi(format!("ATTACH failed: {reply}")));
        }
        Ok(mon)
    }

    fn raw_request(&self, cmd: &str) -> Result<String> {
        self.sock.send(cmd.as_bytes())?;
        let mut buf = vec![0u8; 8192];
        let n = self.sock.recv(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).trim_end().to_string())
    }

    /// Blocks, for up to `timeout` total across however many
    /// unrelated pushes arrive first, for the first event whose name
    /// is one of `names`. wpa_supplicant prefixes unsolicited pushes
    /// with a priority level (e.g. `<2>CTRL-EVENT-SCAN-RESULTS`),
    /// which this strips before matching. `Ok(None)` means the
    /// timeout elapsed without a match, not an error -- callers that
    /// have a sensible fallback for "never heard back" (like
    /// `wifi::scanner`, which can just read whatever `SCAN_RESULTS`
    /// has anyway) shouldn't have to match on a specific error variant
    /// to take it.
    pub fn wait_for_any(&self, names: &[&str], timeout: Duration) -> Result<Option<String>> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            self.sock.set_read_timeout(Some(remaining))?;
            let mut buf = vec![0u8; 8192];
            let n = match self.sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            };
            let line = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
            let event = line
                .strip_prefix('<')
                .and_then(|s| s.split_once('>'))
                .map(|(_, rest)| rest)
                .unwrap_or(line.as_str());
            if names.iter().any(|n| event.starts_with(n)) {
                return Ok(Some(line));
            }
            // Some other CTRL-EVENT-* we're not waiting for -- keep
            // reading within whatever's left of the deadline.
        }
    }
}

impl Drop for WpaMonitor {
    fn drop(&mut self) {
        let _ = self.raw_request("DETACH");
        let _ = std::fs::remove_file(&self.client_path);
    }
}
