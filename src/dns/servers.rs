//! Tracks which active connection contributed which DNS servers, so
//! that deactivating one connection doesn't blow away DNS servers a
//! *different* still-active connection needs (a laptop with both
//! Ethernet and a VPN up is the common case this matters for).

use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Default)]
pub struct DnsServerRegistry {
    /// connection id -> (servers, search domains, priority). VPNs
    /// generally get priority over the underlying physical connection.
    per_connection: HashMap<String, (Vec<IpAddr>, Vec<String>, i32)>,
}

impl DnsServerRegistry {
    pub fn set(&mut self, connection_id: &str, servers: Vec<IpAddr>, search: Vec<String>, priority: i32) {
        self.per_connection.insert(connection_id.to_string(), (servers, search, priority));
    }

    pub fn clear(&mut self, connection_id: &str) {
        self.per_connection.remove(connection_id);
    }

    /// Merges every active connection's servers, highest priority
    /// first, de-duplicated -- what actually gets written to
    /// `/etc/resolv.conf` by `dns::resolver::apply_static`.
    pub fn merged(&self) -> (Vec<IpAddr>, Vec<String>) {
        let mut entries: Vec<&(Vec<IpAddr>, Vec<String>, i32)> = self.per_connection.values().collect();
        entries.sort_by_key(|(_, _, prio)| std::cmp::Reverse(*prio));

        let mut servers = Vec::new();
        let mut search = Vec::new();
        for (s, d, _) in entries {
            for ip in s {
                if !servers.contains(ip) {
                    servers.push(*ip);
                }
            }
            for domain in d {
                if !search.contains(domain) {
                    search.push(domain.clone());
                }
            }
        }
        (servers, search)
    }
}
