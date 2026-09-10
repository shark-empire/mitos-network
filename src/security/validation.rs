//! Shared input validation for anything that ends up on the wire to
//! wpa_supplicant, hostapd, nftables or a shell-invoked helper. Centralizing
//! this is a security boundary, not just tidiness: every one of those
//! consumers is a plain-text config/command format, so an unchecked SSID
//! or interface name is an injection vector.

use crate::errors::{NetworkError, Result};

/// Linux's `IFNAMSIZ` is 16 including the NUL terminator.
pub fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        return Err(NetworkError::Parse(format!(
            "interface name '{name}' must be 1-15 characters"
        )));
    }
    if name.contains('/') || name.contains(char::is_whitespace) || name == "." || name == ".." {
        return Err(NetworkError::Parse(format!("interface name '{name}' contains invalid characters")));
    }
    Ok(())
}

/// SSIDs are up to 32 *bytes* (not necessarily valid UTF-8 per spec, but
/// mitos-network only accepts UTF-8 ones, matching every mainstream tool).
pub fn validate_ssid(ssid: &str) -> Result<()> {
    if ssid.is_empty() || ssid.as_bytes().len() > 32 {
        return Err(NetworkError::Parse("SSID must be 1-32 bytes".into()));
    }
    if ssid.contains('\0') || ssid.contains('\n') || ssid.contains('"') {
        return Err(NetworkError::Parse("SSID contains invalid characters".into()));
    }
    Ok(())
}

/// WPA2/WPA3-Personal passphrases are 8-63 ASCII characters (a full
/// 64-hex-digit PSK is also technically valid but not handled here).
pub fn validate_wpa_passphrase(pass: &str) -> Result<()> {
    if pass.len() < 8 || pass.len() > 63 {
        return Err(NetworkError::Parse("WPA passphrase must be 8-63 characters".into()));
    }
    if !pass.is_ascii() {
        return Err(NetworkError::Parse("WPA passphrase must be ASCII".into()));
    }
    Ok(())
}

/// A conservative allow-list for anything embedded into a generated
/// nftables/hostapd/dnsmasq config file as a bare token (connection ids,
/// zone names, profile ids).
pub fn validate_identifier(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 {
        return Err(NetworkError::Parse(format!("identifier '{id}' must be 1-64 characters")));
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return Err(NetworkError::Parse(format!(
            "identifier '{id}' may only contain letters, digits, '-', '_', '.'"
        )));
    }
    Ok(())
}
