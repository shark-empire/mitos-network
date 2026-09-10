//! System hostname get/set. Small, but every DHCP client sends a
//! hostname option (`dhcp4::OPT_HOSTNAME`) and every DHCPv6 exchange
//! could too, so this earns its own file rather than being inlined.

use crate::errors::{NetworkError, Result};

/// Reads the kernel's current hostname (`gethostname(2)`), the same
/// value the `hostname` command and `dhcp::client` both use.
pub fn current() -> Option<String> {
    let mut buf = vec![0u8; 256];
    // SAFETY: buf is sized and owned for the duration of the call.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Sets the kernel hostname (`sethostname(2)`, requires `CAP_SYS_ADMIN`
/// -- i.e. this only works when mitos-network is running as root) and
/// mirrors it into `/etc/hostname` so it survives a reboot the same way
/// `hostnamectl` leaves things.
pub fn set(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 253 {
        return Err(NetworkError::Parse("hostname must be 1-253 characters".into()));
    }
    // SAFETY: name's bytes are valid for the length passed and outlive the call.
    let rc = unsafe { libc::sethostname(name.as_ptr() as *const libc::c_char, name.len()) };
    if rc != 0 {
        return Err(NetworkError::Io(std::io::Error::last_os_error()));
    }
    std::fs::write("/etc/hostname", format!("{name}\n"))?;
    Ok(())
}
