//! A small helper for the handful of places that need to hand a
//! secret (a WireGuard private key, OpenVPN credentials) to an
//! external process via a temporary file, or need a throwaway path
//! for a control-socket bind.
//!
//! All of them share the same two hazards: a *predictable* name in a
//! world-writable directory lets another local user pre-place a
//! symlink there ahead of time, and opening with `create(true)`
//! (rather than `create_new(true)`) means `open()` will happily
//! follow that symlink and write through it instead of refusing.
//! Chained together, that's a root-privileged daemon writing
//! attacker-chosen bytes into an attacker-chosen path.
//!
//! The fixes here are cheap and don't depend on any
//! deployment-specific mitigation (like systemd's `PrivateTmp=`, which
//! this project's unit file does set) being in place: an unpredictable
//! name, and refuse-if-it-already-exists semantics, so the code is
//! safe even if it's ever run outside that unit.

use crate::errors::{NetworkError, Result};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// 16 bytes of randomness, hex-encoded -- enough that guessing or
/// racing to pre-place a symlink at the resulting path isn't
/// practical. This only needs to be unpredictable, not
/// cryptographically strong, so a direct `/dev/urandom` read is
/// simpler than pulling in a CSPRNG/rand crate for one call site.
fn random_suffix() -> Result<String> {
    let mut buf = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| NetworkError::Other(format!("reading /dev/urandom: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Builds an unpredictable path under the system temp directory:
/// `<tmp>/<prefix>-<random>.<suffix>`. Used for things that aren't a
/// plain `open()` target (e.g. a Unix datagram socket `bind()` path),
/// where the caller does its own creation/cleanup but still wants an
/// unguessable name.
pub fn random_temp_path(prefix: &str, suffix: &str) -> Result<PathBuf> {
    let name = format!("{prefix}-{}.{suffix}", random_suffix()?);
    Ok(std::env::temp_dir().join(name))
}

/// Creates a new file at an unpredictable temp path with mode 0600
/// applied atomically at creation time (no window where a more
/// permissive default mode is briefly in effect), refusing outright
/// if anything already exists at the chosen path rather than
/// following it. Returns the path (to hand to a subprocess as an
/// argument) and the open handle (to write the secret through).
pub fn create_secret_temp_file(prefix: &str, suffix: &str) -> Result<(PathBuf, File)> {
    // A handful of retries covers a genuine, non-adversarial name
    // collision; `create_new` guarantees we never overwrite or follow
    // anything if one occurs, adversarial or not.
    for _ in 0..4 {
        let path = random_temp_path(prefix, suffix)?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(NetworkError::Io(e)),
        }
    }
    Err(NetworkError::Other(
        "could not create a temp file after several attempts".into(),
    ))
}
