use mitos_network::wifi::network::{parse_scan_results, WifiNetwork};
use mitos_network::wifi::roaming::{best_bss, should_roam};
use mitos_network::wifi::security::SecurityType;

fn net(ssid: &str, bssid: &str, signal: i32) -> WifiNetwork {
    WifiNetwork { ssid: ssid.to_string(), bssid: bssid.to_string(), frequency_mhz: 2412, signal_dbm: signal, security: SecurityType::Wpa2Psk }
}

#[test]
fn parses_wpa_supplicant_scan_results_table() {
    let raw = "bssid / frequency / signal level / flags / ssid\n\
               aa:bb:cc:dd:ee:ff\t2412\t-40\t[WPA2-PSK-CCMP][ESS]\tHomeNet\n";
    let nets = parse_scan_results(raw);
    assert_eq!(nets.len(), 1);
    assert_eq!(nets[0].security, SecurityType::Wpa2Psk);
}

#[test]
fn best_bss_picks_strongest_signal_for_ssid() {
    let nets = vec![net("HomeNet", "aa:aa:aa:aa:aa:aa", -70), net("HomeNet", "bb:bb:bb:bb:bb:bb", -40), net("OtherNet", "cc:cc:cc:cc:cc:cc", -20)];
    let best = best_bss(&nets, "HomeNet").unwrap();
    assert_eq!(best.bssid, "bb:bb:bb:bb:bb:bb");
}

#[test]
fn roaming_hysteresis_prevents_ping_pong() {
    // Only 3 dBm better -- below the hysteresis threshold, should NOT roam.
    let nets = vec![net("HomeNet", "aa:aa:aa:aa:aa:aa", -50), net("HomeNet", "bb:bb:bb:bb:bb:bb", -47)];
    assert!(should_roam(&nets, "HomeNet", "aa:aa:aa:aa:aa:aa").is_none());

    // 15 dBm better -- comfortably above threshold, should roam.
    let nets_strong = vec![net("HomeNet", "aa:aa:aa:aa:aa:aa", -70), net("HomeNet", "bb:bb:bb:bb:bb:bb", -55)];
    let target = should_roam(&nets_strong, "HomeNet", "aa:aa:aa:aa:aa:aa").expect("should roam");
    assert_eq!(target.bssid, "bb:bb:bb:bb:bb:bb");
}
