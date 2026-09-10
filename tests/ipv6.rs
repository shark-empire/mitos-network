use mitos_network::ip::ipv6;

#[test]
fn link_local_from_mac_matches_rfc4291_example() {
    let mac = [0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc];
    let addr = ipv6::link_local_from_mac(mac);
    assert!(ipv6::is_link_local(&addr));
    assert_eq!(addr.to_string(), "fe80::234:56ff:fe78:9abc");
}

#[test]
fn unique_local_classification() {
    let ula: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let global: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(ipv6::is_unique_local(&ula));
    assert!(!ipv6::is_unique_local(&global));
}
