//! Base data directory + DHCP lease persistence (`dhcp::client` reads
//! and writes leases through here so a daemon restart can find an
//! existing lease before falling back to a fresh DISCOVER).

use super::database;
use crate::dhcp::Lease;
use crate::errors::Result;
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
