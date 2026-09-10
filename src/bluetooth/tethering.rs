//! Bluetooth PAN (Personal Area Network) tethering -- sharing an
//! internet connection over Bluetooth (NAP role) or using a phone's
//! Bluetooth tethering as an uplink (PANU role).
//!
//! `bluetoothctl` itself has no PAN/network commands; this shells out to
//! `bt-network` (from the `bluez-tools` package), the conventional
//! command-line front-end for BlueZ's `org.bluez.Network1` D-Bus
//! interface. If `bluez-tools` isn't installed, these calls fail with a
//! clear "failed to run bt-network" error rather than silently no-op'ing.

use crate::errors::{NetworkError, Result};
use std::process::Command;

fn run(args: &[&str]) -> Result<String> {
    let output = Command::new("bt-network")
        .args(args)
        .output()
        .map_err(|e| {
            NetworkError::Other(format!(
                "failed to run bt-network (is bluez-tools installed?): {e}"
            ))
        })?;
    if !output.status.success() {
        return Err(NetworkError::Other(format!(
            "bt-network {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Connects to a remote device's Network Access Point (NAP) service --
/// i.e. this box is the client of someone else's Bluetooth-shared
/// connection (a phone's "Bluetooth tethering" feature).
pub fn connect_panu(remote_mac: &str) -> Result<String> {
    // bt-network prints the resulting bnep interface name (e.g. "bnep0")
    // on success.
    let out = run(&["-c", remote_mac, "nap"])?;
    Ok(out.trim().to_string())
}

pub fn disconnect(remote_mac: &str) -> Result<()> {
    run(&["-d", remote_mac]).map(|_| ())
}

/// Registers this box as a NAP server, so *other* devices can pair and
/// get network access through it -- typically then bridged/NAT'd out
/// via `sharing::internet_sharing` the same as a Wi-Fi hotspot, once the
/// resulting `bnep0` device appears (see `device::discovery::classify`,
/// which already recognizes `bnep*` as `DeviceType::Bluetooth`).
pub fn start_nap_server(bridge_interface: &str) -> Result<()> {
    run(&["-s", "nap", bridge_interface]).map(|_| ())
}

pub fn stop_nap_server() -> Result<()> {
    run(&["-S", "nap"]).map(|_| ())
}
