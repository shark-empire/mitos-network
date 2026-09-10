//! Triggers and collects Wi-Fi scans.

use super::network::{parse_scan_results, WifiNetwork};
use super::wpa::WpaCtrl;
use crate::errors::Result;
use std::thread;
use std::time::Duration;

/// wpa_supplicant scans asynchronously; without subscribing to the
/// unsolicited event stream (see the caveat in `wifi::wpa`), the
/// pragmatic approach is: ask it to scan, give it long enough to
/// finish (a single-channel active scan is a few hundred ms; a full
/// 2.4+5GHz sweep is usually done within this window), then read
/// results. `manager::scheduler` re-runs this periodically anyway
/// (`wireless.scan-interval-secs`), so a slightly stale read here just
/// gets corrected on the next tick.
const SCAN_SETTLE_TIME: Duration = Duration::from_secs(3);

pub fn scan(ctrl_dir: &str, ifname: &str) -> Result<Vec<WifiNetwork>> {
    let ctrl = WpaCtrl::connect(ctrl_dir, ifname)?;
    ctrl.scan()?;
    thread::sleep(SCAN_SETTLE_TIME);
    let raw = ctrl.scan_results_raw()?;
    Ok(parse_scan_results(&raw))
}

/// Reads the last scan results without triggering a new scan --
/// cheaper, used when a caller just wants "what's visible right now"
/// (e.g. autoconnect deciding whether a known SSID is in range) rather
/// than a fresh, several-second scan.
pub fn last_results(ctrl_dir: &str, ifname: &str) -> Result<Vec<WifiNetwork>> {
    let ctrl = WpaCtrl::connect(ctrl_dir, ifname)?;
    let raw = ctrl.scan_results_raw()?;
    Ok(parse_scan_results(&raw))
}
