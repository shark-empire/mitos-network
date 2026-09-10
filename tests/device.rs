use mitos_network::device::{capabilities, device::DeviceType, discovery, mac};
use mitos_network::ip::interface::Interface;

fn iface(name: &str, flags: u32, kind: Option<&str>) -> Interface {
    Interface { index: 1, name: name.to_string(), flags, mtu: 1500, hwaddr: None, operstate: None, kind: kind.map(str::to_string) }
}

#[test]
fn mac_format_and_parse_round_trip() {
    let mac_bytes = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let formatted = mac::format(mac_bytes);
    assert_eq!(formatted, "02:11:22:33:44:55");
    assert_eq!(mac::parse(&formatted).unwrap(), mac_bytes);
    assert_eq!(mac::parse("02-11-22-33-44-55").unwrap(), mac_bytes); // dash separator also accepted
    assert!(mac::parse("not-a-mac").is_err());
}

#[test]
fn classify_loopback_by_flag() {
    const IFF_LOOPBACK: u32 = 0x8;
    let lo = iface("lo", IFF_LOOPBACK, None);
    assert_eq!(discovery::classify(&lo), DeviceType::Loopback);
}

#[test]
fn classify_virtual_links_by_kind() {
    assert_eq!(discovery::classify(&iface("br0", 0, Some("bridge"))), DeviceType::Bridge);
    assert_eq!(discovery::classify(&iface("bond0", 0, Some("bond"))), DeviceType::Bond);
    assert_eq!(discovery::classify(&iface("wg0", 0, Some("wireguard"))), DeviceType::Vpn);
    assert_eq!(discovery::classify(&iface("gre0", 0, Some("gre"))), DeviceType::Tunnel);
}

#[test]
fn wifi_and_ethernet_capabilities_differ() {
    let wifi_caps = capabilities::detect(DeviceType::WiFi);
    let eth_caps = capabilities::detect(DeviceType::Ethernet);
    assert!(wifi_caps.can_scan);
    assert!(wifi_caps.can_hotspot);
    assert!(!eth_caps.can_scan);
    assert!(!eth_caps.can_hotspot);
    assert!(eth_caps.supports_carrier_detect);
}
