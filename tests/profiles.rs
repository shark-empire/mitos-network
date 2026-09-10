use mitos_network::connection::autoconnect;
use mitos_network::connection::profile::ConnectionProfile;
use mitos_network::device::{DeviceState, DeviceType, NetworkDevice};
use mitos_network::persistence::profiles;
use mitos_network::wifi::SecurityType;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("mitos-network-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn sample_device(name: &str, device_type: DeviceType) -> NetworkDevice {
    NetworkDevice {
        name: name.to_string(),
        index: 1,
        device_type,
        state: DeviceState::Disconnected,
        mac_address: None,
        mtu: 1500,
        ipv4_addresses: Vec::new(),
        ipv6_addresses: Vec::new(),
        carrier: true,
        driver: None,
        active_connection: None,
    }
}

#[test]
fn save_load_and_delete_round_trip() {
    let dir = temp_dir("profiles");
    let mut profile = ConnectionProfile::new_wifi("home-wifi", "HomeNet", SecurityType::Wpa2Psk);
    profile.autoconnect_priority = 5;

    profiles::save(&dir, &profile).expect("save");
    let loaded = profiles::load_all(&dir).expect("load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, "home-wifi");
    assert_eq!(loaded[0].autoconnect_priority, 5);

    profiles::delete(&dir, "home-wifi").expect("delete");
    let after_delete = profiles::load_all(&dir).expect("load after delete");
    assert!(after_delete.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn autoconnect_prefers_pinned_interface() {
    let device = sample_device("eth0", DeviceType::Ethernet);
    let mut generic = ConnectionProfile::new_wifi("generic", "x", SecurityType::Open);
    generic.device_type = DeviceType::Ethernet;
    generic.interface_name = None;
    generic.autoconnect_priority = 100;

    let mut pinned = ConnectionProfile::new_wifi("pinned", "y", SecurityType::Open);
    pinned.device_type = DeviceType::Ethernet;
    pinned.interface_name = Some("eth0".to_string());
    pinned.autoconnect_priority = 0;

    let candidates = vec![generic, pinned];
    let chosen = autoconnect::select(&device, &candidates).expect("a profile matches");
    assert_eq!(
        chosen.id, "pinned",
        "an interface-pinned profile should win even over a higher-priority generic one"
    );
}

#[test]
fn autoconnect_wifi_requires_visible_ssid() {
    let device = sample_device("wlan0", DeviceType::WiFi);
    let known = ConnectionProfile::new_wifi("known", "KnownNet", SecurityType::Wpa2Psk);

    let visible_without_it = vec!["OtherNet".to_string()];
    assert!(autoconnect::select_wifi(&device, &[known.clone()], &visible_without_it).is_none());

    let visible_with_it = vec!["KnownNet".to_string()];
    assert!(autoconnect::select_wifi(&device, &[known], &visible_with_it).is_some());
}
