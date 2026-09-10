use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub address: Ipv4Addr,
    pub prefixlen: u8,
    pub gateway: Option<Ipv4Addr>,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    #[serde(default)]
    pub domain: Option<String>,
    pub server_id: Ipv4Addr,
    pub lease_time_secs: u32,
    /// Unix timestamp; `SystemTime` itself isn't easily (de)serializable
    /// to TOML, so store the epoch seconds and convert at the edges.
    pub obtained_at_unix: u64,
}

impl Lease {
    pub fn obtained_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.obtained_at_unix)
    }

    /// T1 per RFC 2131 4.4.5: renew at 50% of the lease.
    pub fn renewal_time(&self) -> SystemTime {
        self.obtained_at() + Duration::from_secs(self.lease_time_secs as u64 / 2)
    }

    /// T2: rebind (broadcast) at 87.5% of the lease.
    pub fn rebind_time(&self) -> SystemTime {
        self.obtained_at() + Duration::from_secs(self.lease_time_secs as u64 * 7 / 8)
    }

    pub fn expires_at(&self) -> SystemTime {
        self.obtained_at() + Duration::from_secs(self.lease_time_secs as u64)
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at()
    }
}
