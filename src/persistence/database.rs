//! Not a database engine -- mitos-network has no need for one. This is
//! the shared "read/write a JSON file under the data dir, atomically"
//! primitive that `profiles` and `state` both build on, kept in one
//! place so the atomic-write dance (temp file + rename) is written
//! exactly once.

use crate::errors::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(value)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn list_dir(dir: &Path, extension: &str) -> Result<Vec<std::path::PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == extension).unwrap_or(false))
        .collect())
}
