//! A tiny TTL cache. mitos-network doesn't run a resolver, but a few
//! internal callers (`connectivity::checker`'s periodic probe, mainly)
//! benefit from not re-resolving the same connectivity-check hostname
//! every 30 seconds.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

#[derive(Default)]
pub struct DnsCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<Vec<IpAddr>> {
        let entries = self.entries.lock().unwrap();
        entries
            .get(name)
            .filter(|e| e.expires_at > Instant::now())
            .map(|e| e.addrs.clone())
    }

    pub fn insert(&self, name: &str, addrs: Vec<IpAddr>, ttl: Duration) {
        let mut entries = self.entries.lock().unwrap();
        entries.insert(
            name.to_string(),
            Entry {
                addrs,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// Resolves via the system resolver (`std::net::ToSocketAddrs`,
    /// backed by glibc's `getaddrinfo`) on a cache miss.
    pub fn resolve(&self, host: &str, ttl: Duration) -> std::io::Result<Vec<IpAddr>> {
        if let Some(cached) = self.get(host) {
            return Ok(cached);
        }
        let addrs: Vec<IpAddr> = (host, 0u16).to_socket_addrs()?.map(|s| s.ip()).collect();
        self.insert(host, addrs.clone(), ttl);
        Ok(addrs)
    }
}
