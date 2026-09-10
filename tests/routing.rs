use mitos_network::device::DeviceType;
use mitos_network::routing::metrics;

#[test]
fn ethernet_beats_wifi_beats_bluetooth() {
    let eth = metrics::base_metric(DeviceType::Ethernet);
    let wifi = metrics::base_metric(DeviceType::WiFi);
    let bt = metrics::base_metric(DeviceType::Bluetooth);
    assert!(eth < wifi, "ethernet should have a lower (preferred) metric than wifi");
    assert!(wifi < bt, "wifi should be preferred over bluetooth");
}

#[test]
fn vpn_is_preferred_over_everything_else() {
    let vpn = metrics::base_metric(DeviceType::Vpn);
    let eth = metrics::base_metric(DeviceType::Ethernet);
    assert!(vpn < eth);
}

#[test]
fn autoconnect_priority_cannot_cross_device_type_tiers() {
    // Even a maximally-boosted Wi-Fi profile must not out-rank a
    // minimally-boosted Ethernet one -- the clamp in effective_metric
    // exists specifically to guarantee this.
    let best_wifi = metrics::effective_metric(DeviceType::WiFi, i32::MAX);
    let worst_ethernet = metrics::effective_metric(DeviceType::Ethernet, i32::MIN);
    assert!(best_wifi > worst_ethernet);
}
