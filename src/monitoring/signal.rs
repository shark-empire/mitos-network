//! Wi-Fi signal strength, via wpa_supplicant's `SIGNAL_POLL`.

use crate::errors::Result;
use crate::wifi::wpa::WpaCtrl;

#[derive(Debug, Clone, Copy, Default)]
pub struct SignalInfo {
    pub rssi_dbm: Option<i32>,
    pub link_speed_mbps: Option<i32>,
    pub frequency_mhz: Option<u32>,
}

pub fn current(ctrl_dir: &str, ifname: &str) -> Result<SignalInfo> {
    let ctrl = WpaCtrl::connect(ctrl_dir, ifname)?;
    let poll = ctrl.signal_poll()?;
    Ok(SignalInfo {
        rssi_dbm: poll.get("RSSI").and_then(|v| v.parse().ok()),
        link_speed_mbps: poll.get("LINKSPEED").and_then(|v| v.parse().ok()),
        frequency_mhz: poll.get("FREQUENCY").and_then(|v| v.parse().ok()),
    })
}
