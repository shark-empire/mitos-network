use crate::errors::{NetworkError, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct BluetoothDevice {
    pub mac: String,
    pub name: String,
    pub paired: bool,
    pub connected: bool,
}

fn run(args: &[&str]) -> Result<String> {
    let output = Command::new("bluetoothctl")
        .args(args)
        .output()
        .map_err(|e| NetworkError::Other(format!("failed to run bluetoothctl: {e}")))?;
    if !output.status.success() {
        return Err(NetworkError::Other(format!(
            "bluetoothctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn power_on() -> Result<()> {
    run(&["power", "on"]).map(|_| ())
}

pub fn power_off() -> Result<()> {
    run(&["power", "off"]).map(|_| ())
}

pub fn start_scan() -> Result<()> {
    run(&["scan", "on"]).map(|_| ())
}

pub fn stop_scan() -> Result<()> {
    run(&["scan", "off"]).map(|_| ())
}

/// Parses `bluetoothctl devices`' `"Device AA:BB:CC:DD:EE:FF Some Name"`
/// lines. Paired/connected status comes from a follow-up `info` call
/// per device since `devices` alone doesn't include it.
pub fn list_devices() -> Result<Vec<BluetoothDevice>> {
    let raw = run(&["devices"])?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut parts = line.splitn(3, ' ');
        if parts.next() != Some("Device") {
            continue;
        }
        let Some(mac) = parts.next() else { continue };
        let name = parts.next().unwrap_or(mac).to_string();
        let info = run(&["info", mac]).unwrap_or_default();
        out.push(BluetoothDevice {
            mac: mac.to_string(),
            name,
            paired: info.contains("Paired: yes"),
            connected: info.contains("Connected: yes"),
        });
    }
    Ok(out)
}

pub fn pair(mac: &str) -> Result<()> {
    run(&["pair", mac]).map(|_| ())
}

pub fn trust(mac: &str) -> Result<()> {
    run(&["trust", mac]).map(|_| ())
}

pub fn connect(mac: &str) -> Result<()> {
    run(&["connect", mac]).map(|_| ())
}

pub fn disconnect(mac: &str) -> Result<()> {
    run(&["disconnect", mac]).map(|_| ())
}

pub fn remove(mac: &str) -> Result<()> {
    run(&["remove", mac]).map(|_| ())
}
