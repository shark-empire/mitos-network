//! IPv6-specific helpers: link-local address derivation and classification.

use std::net::Ipv6Addr;

/// Derives the modified-EUI-64 link-local address (`fe80::/64`) for a
/// MAC address, per RFC 4291 appendix A -- flip the universal/local bit
/// (0x02) in the first octet and splice `ff:fe` into the middle.
pub fn link_local_from_mac(mac: [u8; 6]) -> Ipv6Addr {
    let mut eui64 = [0u8; 8];
    eui64[0] = mac[0] ^ 0x02;
    eui64[1] = mac[1];
    eui64[2] = mac[2];
    eui64[3] = 0xff;
    eui64[4] = 0xfe;
    eui64[5] = mac[3];
    eui64[6] = mac[4];
    eui64[7] = mac[5];
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([eui64[0], eui64[1]]),
        u16::from_be_bytes([eui64[2], eui64[3]]),
        u16::from_be_bytes([eui64[4], eui64[5]]),
        u16::from_be_bytes([eui64[6], eui64[7]]),
    )
}

pub fn is_link_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xffc0 == 0xfe80
}

pub fn is_unique_local(addr: &Ipv6Addr) -> bool {
    addr.segments()[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eui64_link_local() {
        // Well-known example MAC from RFC 4291 appendix A: 00:34:56:78:9A:BC
        let mac = [0x00, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let ll = link_local_from_mac(mac);
        assert!(is_link_local(&ll));
        assert_eq!(ll.segments()[4], 0x0234);
        assert_eq!(ll.segments()[5], 0x56ff);
        assert_eq!(ll.segments()[6], 0xfe78);
        assert_eq!(ll.segments()[7], 0x9abc);
    }
}
