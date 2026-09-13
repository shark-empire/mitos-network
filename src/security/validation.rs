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
        return Err(NetworkError::Parse(format!(
            "interface name '{name}' contains invalid characters"
        )));
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
        return Err(NetworkError::Parse(
            "SSID contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// WPA2/WPA3-Personal passphrases are 8-63 ASCII characters (a full
/// 64-hex-digit PSK is also technically valid but not handled here).
pub fn validate_wpa_passphrase(pass: &str) -> Result<()> {
    if pass.len() < 8 || pass.len() > 63 {
        return Err(NetworkError::Parse(
            "WPA passphrase must be 8-63 characters".into(),
        ));
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
        return Err(NetworkError::Parse(format!(
            "identifier '{id}' must be 1-64 characters"
        )));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(NetworkError::Parse(format!(
            "identifier '{id}' may only contain letters, digits, '-', '_', '.'"
        )));
    }
    Ok(())
}

/// A Bluetooth (or any 802-style) MAC address: exactly `XX:XX:XX:XX:XX:XX`
/// in upper- or lower-case hex. Every caller that shells out to
/// `bluetoothctl`/`bt-network` with an address routes it through here
/// first -- `bluetoothctl` takes the address as a bare positional
/// argument (never shell-interpreted, so this isn't about shell
/// injection), but rejecting anything that isn't a well-formed address
/// up front is cheap and closes off argument-confusion entirely.
pub fn validate_mac_address(mac: &str) -> Result<()> {
    let bad = || NetworkError::Parse(format!("'{mac}' is not a valid MAC address"));
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() != 6 {
        return Err(bad());
    }
    for octet in octets {
        if octet.len() != 2 || !octet.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad());
        }
    }
    Ok(())
}

/// A value destined for a `wpa_supplicant` control-interface
/// `SET_NETWORK <id> <field> "<value>"` command (ssid, psk, identity,
/// password, ca_cert, client_cert, private_key, ...). wpa_supplicant's
/// quoted-string parsing does not define an escape for embedded quotes
/// in this codebase's favor, so rather than trying to round-trip
/// arbitrary bytes through it, anything that would break out of the
/// quoted literal is rejected outright. This is what actually stops a
/// crafted value (an attacker-broadcast SSID, or a passphrase/identity
/// that happens to contain a quote) from injecting extra tokens into
/// the control command.
pub fn validate_quoted_value(field: &str, value: &str) -> Result<()> {
    if value.contains('"') || value.contains('\\') || value.contains('\0') || value.contains('\n')
    {
        return Err(NetworkError::Wifi(format!(
            "{field} may not contain a quote, backslash, or control character"
        )));
    }
    Ok(())
}

/// A filesystem path for a certificate/key handed to wpa_supplicant
/// (`ca_cert`, `client_cert`, `private_key`). Requires an absolute path
/// so wpa_supplicant's own working directory can't change which file is
/// actually read, and applies the same quoting rule as any other
/// wpa_supplicant string field. Existence/readability is checked
/// separately at the point of use, since that requires I/O.
pub fn validate_cert_path(field: &str, path: &str) -> Result<()> {
    if !path.starts_with('/') {
        return Err(NetworkError::Config(format!(
            "{field} must be an absolute path"
        )));
    }
    validate_quoted_value(field, path)
}
