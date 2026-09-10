//! BSS (access point) selection when several APs share one SSID -- a
//! home mesh system or enterprise multi-AP deployment. wpa_supplicant
//! does its own roaming once associated; this is the policy mitos-network
//! applies at *initial* connection time and when deciding whether a
//! manual "roam now" request (`mitos-netctl wifi roam`) is worth acting on.

use super::network::WifiNetwork;

/// An already-associated BSS needs to be enough *better* than the
/// current one to justify a roam -- without this, a client can
/// ping-pong between two APs of nearly equal signal.
const ROAM_HYSTERESIS_DBM: i32 = 8;

pub fn best_bss<'a>(networks: &'a [WifiNetwork], ssid: &str) -> Option<&'a WifiNetwork> {
    networks
        .iter()
        .filter(|n| n.ssid == ssid)
        .max_by_key(|n| n.signal_dbm)
}

/// Whether it's worth switching from `current_bssid` to whatever the
/// strongest visible BSS for `ssid` is right now.
pub fn should_roam(
    networks: &[WifiNetwork],
    ssid: &str,
    current_bssid: &str,
) -> Option<&WifiNetwork> {
    let current_signal = networks
        .iter()
        .find(|n| n.bssid == current_bssid)
        .map(|n| n.signal_dbm)?;
    let candidate = best_bss(networks, ssid)?;
    if candidate.bssid != current_bssid
        && candidate.signal_dbm - current_signal >= ROAM_HYSTERESIS_DBM
    {
        Some(candidate)
    } else {
        None
    }
}
