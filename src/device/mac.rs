//! MAC address formatting/parsing and (rarely-needed) spoofing support.

use crate::errors::{NetworkError, Result};

pub fn format(mac: [u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub fn parse(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return Err(NetworkError::Parse(format!("'{s}' is not a MAC address")));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16)
            .map_err(|_| NetworkError::Parse(format!("'{s}' is not a MAC address")))?;
    }
    Ok(mac)
}

/// Sets a device's MAC address. Per the kernel's own rules the link
/// must be down for most drivers to accept this -- callers (typically
/// `connection::activation`, for a profile with a "cloned MAC") are
/// responsible for bringing it back up afterwards.
pub fn set(index: i32, mac: [u8; 6]) -> Result<()> {
    crate::ip::interface::set_hwaddr(index, mac)
}
