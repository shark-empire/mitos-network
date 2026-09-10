//! IPv4-specific math: subnet masks and broadcast addresses. Small and
//! pure so it's trivially unit-testable without root or a real NIC.

use std::net::Ipv4Addr;

pub fn subnet_mask(prefixlen: u8) -> Ipv4Addr {
    if prefixlen == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let bits: u32 = u32::MAX << (32 - prefixlen as u32);
    Ipv4Addr::from(bits)
}

pub fn broadcast_address(addr: Ipv4Addr, prefixlen: u8) -> Ipv4Addr {
    let addr_bits = u32::from(addr);
    let mask_bits = u32::from(subnet_mask(prefixlen));
    Ipv4Addr::from(addr_bits | !mask_bits)
}

pub fn network_address(addr: Ipv4Addr, prefixlen: u8) -> Ipv4Addr {
    let addr_bits = u32::from(addr);
    let mask_bits = u32::from(subnet_mask(prefixlen));
    Ipv4Addr::from(addr_bits & mask_bits)
}

pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefixlen: u8) -> bool {
    network_address(a, prefixlen) == network_address(b, prefixlen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_slash_24() {
        assert_eq!(subnet_mask(24), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn broadcast_slash_24() {
        let addr = Ipv4Addr::new(192, 168, 1, 42);
        assert_eq!(broadcast_address(addr, 24), Ipv4Addr::new(192, 168, 1, 255));
    }

    #[test]
    fn broadcast_slash_30() {
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        assert_eq!(broadcast_address(addr, 30), Ipv4Addr::new(10, 0, 0, 7));
    }

    #[test]
    fn network_slash_16() {
        let addr = Ipv4Addr::new(172, 16, 55, 200);
        assert_eq!(network_address(addr, 16), Ipv4Addr::new(172, 16, 0, 0));
    }
}
