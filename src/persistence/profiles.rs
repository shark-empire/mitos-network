//! Connection profile persistence: one TOML file per profile under
//! `<data-dir>/profiles/<id>.toml`. Secrets never live in these files -- see
//! `security::secrets` -- so a profile file is safe to back up, diff,
//! or hand to `mitos-netctl connection export` without leaking a Wi-Fi
//! password.

use crate::connection::profile::ConnectionProfile;
use crate::errors::{NetworkError, Result};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

fn profile_path(dir: &Path, id: &str) -> Result<PathBuf> {
    crate::security::validation::validate_identifier(id)?;
    Ok(dir.join(format!("{id}.toml")))
}

pub fn load_all(dir: &Path) -> Result<Vec<ConnectionProfile>> {
    std::fs::create_dir_all(dir)?;
    let mut out = Vec::new();
    for path in crate::persistence::database::list_dir(dir, "toml")? {
        let text = std::fs::read_to_string(&path)?;
        match toml::from_str::<ConnectionProfile>(&text) {
            Ok(p) => out.push(p),
            Err(e) => crate::logging::logger::warn(&format!(
                "skipping unreadable connection profile {}: {e}",
                path.display()
            )),
        }
    }
    Ok(out)
}

pub fn save(dir: &Path, profile: &ConnectionProfile) -> Result<()> {
    let path = profile_path(dir, &profile.id)?;
    crate::config::parser::write_atomic(&path, profile)
}

pub fn delete(dir: &Path, id: &str) -> Result<()> {
    let path = profile_path(dir, id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(NetworkError::NotFound(format!("connection profile '{id}'")))
        }
        Err(e) => Err(e.into()),
    }
}

/// Records that `id` was just used, so it sorts first next time
/// `recently_used_first` is consulted. Implemented as "touch the file's
/// mtime" rather than a separate timestamp field, so it doesn't change
/// the on-disk profile format at all.
pub fn touch(dir: &Path, id: &str) -> Result<()> {
    let path = profile_path(dir, id)?;
    let now = std::time::SystemTime::now();
    filetime_set_mtime_best_effort(&path, now);
    Ok(())
}

fn filetime_set_mtime_best_effort(path: &Path, _now: std::time::SystemTime) {
    // No extra crate for this: re-writing the file's own bytes back to
    // itself bumps mtime just as well as a dedicated syscall would, and
    // avoids adding a dependency for one field's worth of bookkeeping.
    if let Ok(contents) = std::fs::read(path) {
        let _ = std::fs::write(path, contents);
    }
}

/// Sorts `profiles` most-recently-used first, using each profile file's
/// mtime as the proxy for "last used" (see [`touch`]).
pub fn recently_used_first(dir: &Path, profiles: Vec<ConnectionProfile>) -> Vec<ConnectionProfile> {
    let mut with_mtime: Vec<(std::time::SystemTime, ConnectionProfile)> = profiles
        .into_iter()
        .map(|p| {
            let mtime = profile_path(dir, &p.id)
                .ok()
                .and_then(|path| std::fs::metadata(path).ok())
                .and_then(|m| m.modified().ok())
                .unwrap_or(UNIX_EPOCH);
            (mtime, p)
        })
        .collect();
    with_mtime.sort_by(|a, b| b.0.cmp(&a.0));
    with_mtime.into_iter().map(|(_, p)| p).collect()
}
