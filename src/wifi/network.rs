//! `WifiNetwork`: a single scan-result BSS, plus the `SCAN_RESULTS`
//! table parser.

use super::security::SecurityType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub security: SecurityType,
}

impl WifiNetwork {
    /// 0-100 bar-style signal quality, the way desktop UIs show it
    /// rather than a raw dBm figure. Uses the same -100..-50 dBm ->
    /// 0..100 mapping NetworkManager's `nm-utils` applies.
    pub fn signal_percent(&self) -> u8 {
        let clamped = self.signal_dbm.clamp(-100, -50);
        (((clamped + 100) * 2) as u8).min(100)
    }
}

/// Parses wpa_supplicant's `SCAN_RESULTS` reply:
/// ```text
/// bssid / frequency / signal level / flags / ssid
/// 00:11:22:33:44:55	2412	-42	[WPA2-PSK-CCMP][ESS]	MyNetwork
/// ```
pub fn parse_scan_results(raw: &str) -> Vec<WifiNetwork> {
    raw.lines()
        .skip(1) // header line
        .filter_map(|line| {
            let mut cols = line.split('\t');
            let bssid = cols.next()?.to_string();
            let frequency_mhz: u32 = cols.next()?.parse().ok()?;
            let signal_dbm: i32 = cols.next()?.parse().ok()?;
            let flags = cols.next()?;
            let ssid = cols.next().unwrap_or("").to_string();
            if ssid.is_empty() {
                return None; // hidden network with no probe response SSID yet
            }
            Some(WifiNetwork {
                ssid,
                bssid,
                frequency_mhz,
                signal_dbm,
                security: SecurityType::from_flags(flags),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_results() {
        let raw = "bssid / frequency / signal level / flags / ssid\n\
                    aa:bb:cc:dd:ee:ff\t2412\t-45\t[WPA2-PSK-CCMP][ESS]\tHomeNet\n\
                    11:22:33:44:55:66\t5180\t-60\t[SAE-CCMP][ESS]\tCafeWiFi\n";
        let nets = parse_scan_results(raw);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].ssid, "HomeNet");
        assert_eq!(nets[0].security, SecurityType::Wpa2Psk);
        assert_eq!(nets[1].security, SecurityType::Wpa3Sae);
    }

    #[test]
    fn signal_percent_maps_range() {
        let n = WifiNetwork {
            ssid: "x".into(),
            bssid: "x".into(),
            frequency_mhz: 2412,
            signal_dbm: -50,
            security: SecurityType::Open,
        };
        assert_eq!(n.signal_percent(), 100);
        let n2 = WifiNetwork {
            signal_dbm: -100,
            ..n
        };
        assert_eq!(n2.signal_percent(), 0);
    }
}
