//! `ethernet::link`/`ethernet::ethernet` talk to real hardware via
//! `ETHTOOL` ioctls and are not exercised here (see
//! `docs/troubleshooting.md` for how to test them on real hardware).
//! `ethernet::auto::describe` is pure formatting and is covered.

use mitos_network::ethernet::auto::describe;
use mitos_network::ethernet::link::LinkSettings;

#[test]
fn describes_full_duplex_autonegotiated_link() {
    let settings = LinkSettings { speed_mbps: Some(1000), full_duplex: true, autoneg: true };
    assert_eq!(describe(&settings), "1000 Mbps, full duplex (auto-negotiated)");
}

#[test]
fn describes_unknown_speed_gracefully() {
    let settings = LinkSettings { speed_mbps: None, full_duplex: false, autoneg: false };
    assert_eq!(describe(&settings), "unknown speed, half duplex (fixed)");
}
