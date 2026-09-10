//! Rendering is pure string generation -- testable without ever
//! invoking the real `nft` binary (`firewall::nftables::apply` does
//! that part, and is intentionally not covered here).

use mitos_network::firewall::nftables::render;
use mitos_network::firewall::zones::{builtin_zones, DefaultPolicy};
use mitos_network::firewall::{Action, Direction, Protocol, Rule};

#[test]
fn trusted_zone_gets_a_blanket_accept() {
    let mut zones = builtin_zones();
    for z in &mut zones {
        if z.name == "trusted" {
            z.interfaces.push("tun0".to_string());
        }
    }
    let ruleset = render(&zones, &[], &[], &[]);
    assert!(ruleset.contains("iifname { \"tun0\" } accept"));
}

#[test]
fn public_zone_rule_is_scoped_to_its_own_interfaces() {
    let mut zones = builtin_zones();
    for z in &mut zones {
        if z.name == "public" {
            z.interfaces.push("wlan0".to_string());
            assert_eq!(z.default_policy, DefaultPolicy::Drop);
        }
    }
    let rule = Rule::allow_inbound_port("ssh", "public", Protocol::Tcp, 22);
    let ruleset = render(&zones, &[rule], &[], &[]);
    assert!(ruleset.contains("iifname { \"wlan0\" } tcp dport 22 accept"));
}

#[test]
fn masquerade_and_forward_pairs_render_when_sharing() {
    let zones = builtin_zones();
    let ruleset = render(
        &zones,
        &[],
        &["wlan0".to_string()],
        &[("eth0".to_string(), "wlan0".to_string())],
    );
    assert!(ruleset.contains("oifname \"wlan0\" masquerade"));
    assert!(ruleset.contains("iifname \"eth0\" oifname \"wlan0\" accept"));
}

#[test]
fn outbound_rule_has_no_interface_qualifier() {
    let zones = builtin_zones();
    let rule = Rule {
        direction: Direction::Outbound,
        action: Action::Drop,
        ..Rule::allow_inbound_port("block-x", "public", Protocol::Tcp, 9999)
    };
    let ruleset = render(&zones, &[rule], &[], &[]);
    assert!(ruleset.contains("tcp dport 9999 drop"));
}
