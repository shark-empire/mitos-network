use mitos_network::dns::{resolver, servers::DnsServerRegistry};
use std::net::IpAddr;

#[test]
fn apply_to_writes_expected_resolv_conf_format() {
    let path = std::env::temp_dir().join("mitos-network-test-resolv.conf");
    let dns_servers: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()];
    let search = vec!["example.com".to_string()];

    resolver::apply_to(&path, &dns_servers, &search).expect("write succeeds");
    let contents = std::fs::read_to_string(&path).unwrap();

    assert!(contents.contains("search example.com"));
    assert!(contents.contains("nameserver 1.1.1.1"));
    assert!(contents.contains("nameserver 9.9.9.9"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn server_registry_merges_by_priority_and_dedupes() {
    let mut reg = DnsServerRegistry::default();
    let a: IpAddr = "1.1.1.1".parse().unwrap();
    let b: IpAddr = "9.9.9.9".parse().unwrap();
    let c: IpAddr = "8.8.8.8".parse().unwrap();

    reg.set("ethernet", vec![a, b], vec!["home.arpa".to_string()], 0);
    reg.set("vpn", vec![c, a], vec!["corp.example".to_string()], 100); // higher priority wins ordering

    let (servers, search) = reg.merged();
    assert_eq!(servers[0], c); // vpn's servers come first (higher priority)
    assert_eq!(servers.iter().filter(|s| **s == a).count(), 1); // deduped across sources
    assert!(search.contains(&"corp.example".to_string()));
    assert!(search.contains(&"home.arpa".to_string()));
}
