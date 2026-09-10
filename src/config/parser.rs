use crate::errors::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;

/// Parse a TOML file into `T`, returning `Ok(None)` (not an error) when
/// the file simply doesn't exist yet -- first boot, or an optional file
/// like `wireless.toml` on a wired-only machine.
pub fn parse_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(toml::from_str(&contents)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Serialize `value` to TOML and write it atomically (write to a temp
/// file in the same directory, then rename) so a crash mid-write never
/// leaves a half-written config file on disk.
pub fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let text = toml::to_string_pretty(value)?;
    let tmp = path.with_extension("toml.tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
