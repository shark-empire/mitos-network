//! Fallback DNS servers, used when nothing else (DHCP, a static
//! profile, `dns.toml` in Manual mode) has supplied any -- covers the
//! "plugged into a network that hands out an address but its DNS
//! server is unreachable/misconfigured" case, which is common enough
//! on hotel/guest Wi-Fi to be worth handling explicitly rather than
//! just leaving the box unable to resolve anything.

use std::net::IpAddr;
use std::time::Duration;

pub fn default_servers() -> Vec<IpAddr> {
    ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// A quick liveness probe for a DNS server: attempts to resolve a
/// well-known name against it isn't practical without a hand-rolled DNS
/// client, so this instead does what actually matters operationally --
/// checks whether the server answers on port 53 at all (TCP connect,
/// which every real resolver listens on alongside UDP).
pub fn is_reachable(server: IpAddr, timeout: Duration) -> bool {
    std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(server, 53), timeout).is_ok()
}

/// Called by `connectivity::checker` when DNS looks broken: if none of
/// the currently-configured servers answer, temporarily layer the
/// fallback servers on top rather than leaving the user stranded.
pub fn servers_or_fallback(configured: &[IpAddr]) -> Vec<IpAddr> {
    let timeout = Duration::from_millis(800);
    if configured.iter().any(|s| is_reachable(*s, timeout)) {
        configured.to_vec()
    } else {
        default_servers()
    }
}
