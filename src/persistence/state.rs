//! Base data directory + DHCP lease persistence (`dhcp::client` reads
//! and writes leases through here so a daemon restart can find an
//! existing lease before falling back to a fresh DISCOVER), plus the
//! last-applied proxy config (`proxy::proxy` -- same reasoning: a
//! restart shouldn't silently drop back to no proxy).

use super::database;
use crate::dhcp::{Lease, Lease6};
use crate::errors::Result;
use crate::proxy::ProxyConfig;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Called once from `main` after config load. Safe to call more than
/// once (e.g. in tests) -- later calls are ignored, first one wins.
pub fn init(dir: &Path) {
    let _ = DATA_DIR.set(dir.to_path_buf());
}

fn base_dir() -> PathBuf {
    DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(crate::config::defaults_data_dir()))
}

fn lease_path(ifname: &str) -> PathBuf {
    base_dir().join("leases").join(format!("{ifname}.json"))
}

pub fn save_lease(ifname: &str, lease: &Lease) -> Result<()> {
    database::write_json(&lease_path(ifname), lease)
}

pub fn load_lease(ifname: &str) -> Result<Option<Lease>> {
    database::read_json(&lease_path(ifname))
}

pub fn clear_lease(ifname: &str) -> Result<()> {
    database::remove(&lease_path(ifname))
}

fn lease6_path(ifname: &str) -> PathBuf {
    // Distinct filename from the v4 lease (`lease_path`, above): a
    // dual-stack interface legitimately holds both at once.
    base_dir().join("leases").join(format!("{ifname}.v6.json"))
}

pub fn save_lease6(ifname: &str, lease: &Lease6) -> Result<()> {
    database::write_json(&lease6_path(ifname), lease)
}

pub fn load_lease6(ifname: &str) -> Result<Option<Lease6>> {
    database::read_json(&lease6_path(ifname))
}

pub fn clear_lease6(ifname: &str) -> Result<()> {
    database::remove(&lease6_path(ifname))
}

fn proxy_config_path() -> PathBuf {
    base_dir().join("proxy.json")
}

pub fn save_proxy_config(cfg: &ProxyConfig) -> Result<()> {
    database::write_json(&proxy_config_path(), cfg)
}

pub fn load_proxy_config() -> Result<Option<ProxyConfig>> {
    database::read_json(&proxy_config_path())
}
