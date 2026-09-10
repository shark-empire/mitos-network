//! RFC 2131/2132 packet (de)serialization. Pure and allocation-light so
//! it's cheap to unit test without a socket or root.

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

pub const OP_BOOTREQUEST: u8 = 1;
pub const OP_BOOTREPLY: u8 = 2;
pub const HTYPE_ETHER: u8 = 1;

pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_DOMAIN_NAME: u8 = 15;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQUEST_LIST: u8 = 55;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_END: u8 = 255;
pub const OPT_PAD: u8 = 0;

pub const MSG_DISCOVER: u8 = 1;
pub const MSG_OFFER: u8 = 2;
pub const MSG_REQUEST: u8 = 3;
pub const MSG_DECLINE: u8 = 4;
pub const MSG_ACK: u8 = 5;
pub const MSG_NAK: u8 = 6;
pub const MSG_RELEASE: u8 = 7;

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct Packet {
    pub op: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Packet {
    pub fn get_option(&self, code: u8) -> Option<&[u8]> {
        self.options.iter().find(|(c, _)| *c == code).map(|(_, v)| v.as_slice())
    }

    pub fn message_type(&self) -> Option<u8> {
        self.get_option(OPT_MSG_TYPE).and_then(|v| v.first().copied())
    }
}

fn base_request(xid: u32, mac: [u8; 6], secs: u16) -> Packet {
    Packet {
        op: OP_BOOTREQUEST,
        xid,
        secs,
        flags: 0x8000, // ask for a broadcast reply: we have no IP yet to receive a unicast one
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        chaddr: mac,
        options: Vec::new(),
    }
}

const DEFAULT_PARAM_REQUEST_LIST: [u8; 4] = [OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_DOMAIN_NAME];

pub fn build_discover(xid: u32, mac: [u8; 6], hostname: Option<&str>) -> Vec<u8> {
    let mut pkt = base_request(xid, mac, 0);
    pkt.options.push((OPT_MSG_TYPE, vec![MSG_DISCOVER]));
    pkt.options.push((OPT_CLIENT_ID, client_id(mac)));
    pkt.options.push((OPT_PARAM_REQUEST_LIST, DEFAULT_PARAM_REQUEST_LIST.to_vec()));
    if let Some(h) = hostname {
        pkt.options.push((OPT_HOSTNAME, h.as_bytes().to_vec()));
    }
    serialize(&pkt)
}

pub fn build_request(
    xid: u32,
    mac: [u8; 6],
    requested_ip: Ipv4Addr,
    server_id: Ipv4Addr,
    hostname: Option<&str>,
) -> Vec<u8> {
    let mut pkt = base_request(xid, mac, 0);
    pkt.options.push((OPT_MSG_TYPE, vec![MSG_REQUEST]));
    pkt.options.push((OPT_CLIENT_ID, client_id(mac)));
    pkt.options.push((OPT_REQUESTED_IP, requested_ip.octets().to_vec()));
    pkt.options.push((OPT_SERVER_ID, server_id.octets().to_vec()));
    pkt.options.push((OPT_PARAM_REQUEST_LIST, DEFAULT_PARAM_REQUEST_LIST.to_vec()));
    if let Some(h) = hostname {
        pkt.options.push((OPT_HOSTNAME, h.as_bytes().to_vec()));
    }
    serialize(&pkt)
}

/// A renewal REQUEST (unicast to the server that granted the lease) has
/// `ciaddr` set and omits `OPT_REQUESTED_IP`/`OPT_SERVER_ID`, per RFC 2131 4.3.2.
pub fn build_renew_request(xid: u32, mac: [u8; 6], client_ip: Ipv4Addr) -> Vec<u8> {
    let mut pkt = base_request(xid, mac, 0);
    pkt.ciaddr = client_ip;
    pkt.flags = 0; // we have a working IP now, a unicast reply is fine
    pkt.options.push((OPT_MSG_TYPE, vec![MSG_REQUEST]));
    pkt.options.push((OPT_CLIENT_ID, client_id(mac)));
    serialize(&pkt)
}

pub fn build_release(xid: u32, mac: [u8; 6], client_ip: Ipv4Addr, server_id: Ipv4Addr) -> Vec<u8> {
    let mut pkt = base_request(xid, mac, 0);
    pkt.ciaddr = client_ip;
    pkt.options.push((OPT_MSG_TYPE, vec![MSG_RELEASE]));
    pkt.options.push((OPT_CLIENT_ID, client_id(mac)));
    pkt.options.push((OPT_SERVER_ID, server_id.octets().to_vec()));
    serialize(&pkt)
}

fn client_id(mac: [u8; 6]) -> Vec<u8> {
    let mut v = vec![HTYPE_ETHER];
    v.extend_from_slice(&mac);
    v
}

pub fn serialize(pkt: &Packet) -> Vec<u8> {
    let mut buf = Vec::with_capacity(300);
    buf.push(pkt.op);
    buf.push(HTYPE_ETHER);
    buf.push(6); // hlen
    buf.push(0); // hops
    buf.extend_from_slice(&pkt.xid.to_be_bytes());
    buf.extend_from_slice(&pkt.secs.to_be_bytes());
    buf.extend_from_slice(&pkt.flags.to_be_bytes());
    buf.extend_from_slice(&pkt.ciaddr.octets());
    buf.extend_from_slice(&pkt.yiaddr.octets());
    buf.extend_from_slice(&pkt.siaddr.octets());
    buf.extend_from_slice(&[0, 0, 0, 0]); // giaddr: no relay agent
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&pkt.chaddr);
    buf.extend_from_slice(&chaddr);
    buf.extend_from_slice(&[0u8; 64]); // sname
    buf.extend_from_slice(&[0u8; 128]); // file
    buf.extend_from_slice(&MAGIC_COOKIE);
    for (code, data) in &pkt.options {
        buf.push(*code);
        buf.push(data.len() as u8);
        buf.extend_from_slice(data);
    }
    buf.push(OPT_END);
    buf
}

pub fn parse(buf: &[u8]) -> Option<Packet> {
    if buf.len() < 240 || buf[236..240] != MAGIC_COOKIE {
        return None;
    }
    let op = buf[0];
    let xid = u32::from_be_bytes(buf[4..8].try_into().ok()?);
    let secs = u16::from_be_bytes(buf[8..10].try_into().ok()?);
    let flags = u16::from_be_bytes(buf[10..12].try_into().ok()?);
    let ciaddr = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let yiaddr = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let siaddr = Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]);
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&buf[28..34]);

    let mut options = Vec::new();
    let mut i = 240;
    while i < buf.len() {
        let code = buf[i];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= buf.len() {
            break;
        }
        let len = buf[i + 1] as usize;
        if i + 2 + len > buf.len() {
            break;
        }
        options.push((code, buf[i + 2..i + 2 + len].to_vec()));
        i += 2 + len;
    }

    Some(Packet { op, xid, secs, flags, ciaddr, yiaddr, siaddr, chaddr, options })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_round_trips_through_parse() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let bytes = build_discover(0xdead_beef, mac, Some("mitos-test"));
        let pkt = parse(&bytes).expect("valid packet");
        assert_eq!(pkt.xid, 0xdead_beef);
        assert_eq!(pkt.chaddr, mac);
        assert_eq!(pkt.message_type(), Some(MSG_DISCOVER));
        assert_eq!(pkt.get_option(OPT_HOSTNAME), Some(b"mitos-test".as_slice()));
    }

    #[test]
    fn request_carries_requested_ip_and_server_id() {
        let mac = [0, 1, 2, 3, 4, 5];
        let bytes = build_request(1, mac, Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(192, 168, 1, 1), None);
        let pkt = parse(&bytes).unwrap();
        assert_eq!(pkt.message_type(), Some(MSG_REQUEST));
        assert_eq!(pkt.get_option(OPT_REQUESTED_IP), Some([192, 168, 1, 50].as_slice()));
        assert_eq!(pkt.get_option(OPT_SERVER_ID), Some([192, 168, 1, 1].as_slice()));
    }
}
