//! IPv4 address math, exercised through the public crate API (the
//! same logic also has unit tests inside `src/ip/ipv4.rs` itself --
//! these confirm the *public* surface behaves the same way).

use mitos_network::ip::ipv4;
use std::net::Ipv4Addr;

#[test]
fn subnet_mask_common_prefixes() {
    assert_eq!(ipv4::subnet_mask(24), Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(ipv4::subnet_mask(16), Ipv4Addr::new(255, 255, 0, 0));
    assert_eq!(ipv4::subnet_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    assert_eq!(ipv4::subnet_mask(32), Ipv4Addr::new(255, 255, 255, 255));
}

#[test]
fn broadcast_and_network_addresses() {
    let addr = Ipv4Addr::new(10, 20, 30, 40);
    assert_eq!(ipv4::network_address(addr, 24), Ipv4Addr::new(10, 20, 30, 0));
    assert_eq!(ipv4::broadcast_address(addr, 24), Ipv4Addr::new(10, 20, 30, 255));
}

#[test]
fn same_subnet_detection() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let b = Ipv4Addr::new(192, 168, 1, 200);
    let c = Ipv4Addr::new(192, 168, 2, 10);
    assert!(ipv4::same_subnet(a, b, 24));
    assert!(!ipv4::same_subnet(a, c, 24));
}
