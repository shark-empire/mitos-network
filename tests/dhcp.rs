//! DHCPv4 packet framing and lease timing math -- both pure, so both
//! testable without a socket, root, or a real DHCP server. The actual
//! network exchange in `dhcp::client::acquire` needs all three and is
//! not covered here; see docs/networking.md.

use mitos_network::dhcp::dhcp4;
use mitos_network::dhcp::Lease;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn discover_offer_request_ack_round_trip() {
    let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    let xid = 0x1234_5678;

    let discover = dhcp4::build_discover(xid, mac, Some("mitos-host"));
    let parsed = dhcp4::parse(&discover).expect("discover parses");
    assert_eq!(parsed.message_type(), Some(dhcp4::MSG_DISCOVER));
    assert_eq!(parsed.xid, xid);
    assert_eq!(parsed.chaddr, mac);

    let request = dhcp4::build_request(
        xid,
        mac,
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(10, 0, 0, 1),
        None,
    );
    let parsed_req = dhcp4::parse(&request).expect("request parses");
    assert_eq!(parsed_req.message_type(), Some(dhcp4::MSG_REQUEST));
    assert_eq!(
        parsed_req.get_option(dhcp4::OPT_REQUESTED_IP),
        Some([10, 0, 0, 5].as_slice())
    );
}

#[test]
fn release_carries_client_and_server_addresses() {
    let mac = [0, 0, 0, 0, 0, 1];
    let release = dhcp4::build_release(
        1,
        mac,
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(10, 0, 0, 1),
    );
    let parsed = dhcp4::parse(&release).unwrap();
    assert_eq!(parsed.message_type(), Some(dhcp4::MSG_RELEASE));
    assert_eq!(parsed.ciaddr, Ipv4Addr::new(10, 0, 0, 5));
}

fn sample_lease(lease_time_secs: u32) -> Lease {
    Lease {
        address: Ipv4Addr::new(192, 168, 1, 50),
        prefixlen: 24,
        gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain: None,
        server_id: Ipv4Addr::new(192, 168, 1, 1),
        lease_time_secs,
        obtained_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

#[test]
fn lease_renewal_and_rebind_timing() {
    let lease = sample_lease(3600);
    let obtained = lease.obtained_at();
    assert_eq!(
        lease.renewal_time(),
        obtained + std::time::Duration::from_secs(1800)
    ); // T1: 50%
    assert_eq!(
        lease.rebind_time(),
        obtained + std::time::Duration::from_secs(3150)
    ); // T2: 87.5%
    assert!(!lease.is_expired());
}
