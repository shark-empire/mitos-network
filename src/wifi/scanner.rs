//! Triggers and collects Wi-Fi scans.

use super::network::{parse_scan_results, WifiNetwork};
use super::wpa::{WpaCtrl, WpaMonitor};
use crate::errors::Result;
use std::time::Duration;

/// Upper bound on how long a scan is allowed to take before this just
/// reads whatever `SCAN_RESULTS` has anyway: a single-channel active
/// scan is a few hundred ms, a full 2.4+5GHz sweep is usually done
/// within a few seconds, so anything beyond this points at a stuck
/// driver rather than a scan still legitimately in progress.
/// `manager::scheduler` re-runs this periodically anyway
/// (`wireless.scan-interval-secs`), so even a read this safety net had
/// to cut short just gets corrected on the next tick.
const SCAN_MAX_WAIT: Duration = Duration::from_secs(8);

pub fn scan(ctrl_dir: &str, ifname: &str) -> Result<Vec<WifiNetwork>> {
    let ctrl = WpaCtrl::connect(ctrl_dir, ifname)?;
    // Attach *before* triggering the scan, not after: otherwise a scan
    // that finishes fast enough could push CTRL-EVENT-SCAN-RESULTS
    // before this is listening for it, and this would wait the full
    // SCAN_MAX_WAIT for an event that already happened. If ATTACH
    // itself fails (a wpa_supplicant build without event-stream
    // support, or just a transient error), fall back to the old
    // trigger-then-settle behavior rather than failing the scan
    // outright -- a working scan beats a strictly-correct one here.
    match WpaMonitor::attach(ctrl_dir, ifname) {
        Ok(monitor) => {
            ctrl.scan()?;
            let _ = monitor.wait_for_any(
                &["CTRL-EVENT-SCAN-RESULTS", "CTRL-EVENT-SCAN-FAILED"],
                SCAN_MAX_WAIT,
            )?;
        }
        Err(_) => {
            ctrl.scan()?;
            std::thread::sleep(Duration::from_secs(3));
        }
    }
    let raw = ctrl.scan_results_raw()?;
    Ok(parse_scan_results(&raw))
}

/// Reads the last scan results without triggering a new scan --
/// cheaper, used when a caller just wants "what's visible right now"
/// (e.g. autoconnect deciding whether a known SSID is in range) rather
/// than a fresh scan.
pub fn last_results(ctrl_dir: &str, ifname: &str) -> Result<Vec<WifiNetwork>> {
    let ctrl = WpaCtrl::connect(ctrl_dir, ifname)?;
    let raw = ctrl.scan_results_raw()?;
    Ok(parse_scan_results(&raw))
}
