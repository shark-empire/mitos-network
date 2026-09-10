//! Where Wi-Fi passphrases, VPN pre-shared keys, and 802.1X credentials
//! live.
//!
//! Deliberately **not** stored inside `connection::profile`'s own TOML
//! files under `data/profiles/` -- profiles are the kind of thing a user
//! might `cat`, back up, or paste into a bug report, and secrets have no
//! business sitting in plain sight there the way early NetworkManager
//! keyfiles (in)famously did.
//!
//! This module defines the trait boundary and ships exactly one backend
//! (`FileSecretsBackend`): one `0600`-permission file per secret under
//! `<data-dir>/secrets/`, root-owned, never world- or group-readable.
//! That is an *interim* measure, not the end state -- the real answer on
//! mitosOS is a proper secrets service (`mitos-auth`, sibling daemon to
//! mitos-session) that mitos-network should authenticate to and fetch
//! secrets from at connection-activation time, the same way a desktop
//! keyring backs NetworkManager elsewhere. `SecretsBackend` exists as a
//! trait specifically so swapping the file backend for an
//! `AuthServiceSecretsBackend` later is a one-line change at the call
//! site in `manager::manager`, not a rewrite.

use crate::errors::{NetworkError, Result};
use std::io::Write;
use std::path::PathBuf;

pub trait SecretsBackend: Send + Sync {
    /// `owner` is a stable id for the thing the secret belongs to (a
    /// connection profile id, e.g. `"wifi-home"`); `key` distinguishes
    /// which secret within it (`"psk"`, `"eap-password"`, `"private-key"`).
    fn get(&self, owner: &str, key: &str) -> Result<Option<String>>;
    fn set(&self, owner: &str, key: &str, value: &str) -> Result<()>;
    fn delete_all(&self, owner: &str) -> Result<()>;
}

pub struct FileSecretsBackend {
    dir: PathBuf,
}

impl FileSecretsBackend {
    pub fn new(data_dir: &std::path::Path) -> Self {
        FileSecretsBackend { dir: data_dir.join("secrets") }
    }

    fn path(&self, owner: &str, key: &str) -> Result<PathBuf> {
        super::validation::validate_identifier(owner)?;
        super::validation::validate_identifier(key)?;
        Ok(self.dir.join(format!("{owner}.{key}")))
    }
}

impl SecretsBackend for FileSecretsBackend {
    fn get(&self, owner: &str, key: &str) -> Result<Option<String>> {
        let path = self.path(owner, key)?;
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, owner: &str, key: &str, value: &str) -> Result<()> {
        let path = self.path(owner, key)?;
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(value.as_bytes())?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete_all(&self, owner: &str) -> Result<()> {
        super::validation::validate_identifier(owner)?;
        let prefix = format!("{owner}.");
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }
}

/// A backend that always reports "no secret stored" -- useful for
/// `--no-secrets` test runs and for interfaces (Ethernet, most VPN
/// server-cert setups) that never need one.
pub struct NullSecretsBackend;

impl SecretsBackend for NullSecretsBackend {
    fn get(&self, _owner: &str, _key: &str) -> Result<Option<String>> {
        Ok(None)
    }
    fn set(&self, owner: &str, _key: &str, _value: &str) -> Result<()> {
        Err(NetworkError::Other(format!(
            "no secrets backend configured; cannot store a secret for '{owner}'"
        )))
    }
    fn delete_all(&self, _owner: &str) -> Result<()> {
        Ok(())
    }
}
