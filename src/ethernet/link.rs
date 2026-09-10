//! `ETHTOOL_GLINK`/`ETHTOOL_GSET` via `SIOCETHTOOL`, Linux's driver-level
//! link-status ioctl -- the same mechanism the real `ethtool` command
//! itself is built on.

use crate::errors::{NetworkError, Result};
use std::ffi::CString;

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GSET: u32 = 0x00000001;
const ETHTOOL_GLINK: u32 = 0x0000000a;

/// Mirrors enough of the kernel's legacy `struct ethtool_cmd` to read
/// `speed`/`duplex`; the fields after that (unused here) still need to
/// be present so the buffer is the size the kernel expects to write into.
#[repr(C)]
struct EthtoolCmd {
    cmd: u32,
    supported: u32,
    advertising: u32,
    speed: u16,
    duplex: u8,
    port: u8,
    phy_address: u8,
    transceiver: u8,
    autoneg: u8,
    mdio_support: u8,
    maxtxpkt: u32,
    maxrxpkt: u32,
    speed_hi: u16,
    eth_tp_mdix: u8,
    eth_tp_mdix_ctrl: u8,
    lp_advertising: u32,
    reserved: [u32; 2],
}

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

/// `ifreq` as the kernel expects it for an `ETHTOOL` ioctl: a 16-byte
/// interface name followed by a pointer to the ethtool command struct
/// (the field the kernel calls `ifr_data`, one member of `ifreq`'s
/// union -- laid out by hand here rather than via a `libc::ifreq`
/// binding, since not every ioctl use of `ifreq` agrees on which union
/// member is active).
#[repr(C)]
struct IfreqData {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_data: *mut libc::c_void,
}

fn ioctl_socket() -> Result<libc::c_int> {
    // SAFETY: a plain, immediately-error-checked socket(2) call.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(NetworkError::Io(std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn set_ifr_name(ifr: &mut IfreqData, ifname: &str) -> Result<()> {
    let cname = CString::new(ifname)
        .map_err(|_| NetworkError::Parse("interface name contains a NUL byte".into()))?;
    let bytes = cname.as_bytes_with_nul();
    if bytes.len() > libc::IFNAMSIZ {
        return Err(NetworkError::Parse(format!(
            "interface name '{ifname}' too long"
        )));
    }
    for (i, b) in bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    Ok(())
}

/// Driver-reported carrier state -- a second opinion alongside
/// `ip::interface::Interface::has_carrier` (which reads the kernel's
/// own `IFF_RUNNING` flag over netlink); the two should always agree,
/// and a persistent mismatch would itself be a useful diagnostic.
pub fn has_carrier(ifname: &str) -> Result<bool> {
    let fd = ioctl_socket()?;
    let mut value = EthtoolValue {
        cmd: ETHTOOL_GLINK,
        data: 0,
    };
    let mut ifr: IfreqData = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, ifname)?;
    ifr.ifr_data = &mut value as *mut _ as *mut libc::c_void;

    // SAFETY: `ifr` and `value` are valid, stack-owned, and outlive the
    // call; the kernel writes `value.data` in place.
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut ifr as *mut _) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(NetworkError::Device(format!(
            "ETHTOOL_GLINK on {ifname} failed: {err}"
        )));
    }
    Ok(value.data != 0)
}

#[derive(Debug, Clone, Copy)]
pub struct LinkSettings {
    pub speed_mbps: Option<u32>,
    pub full_duplex: bool,
    pub autoneg: bool,
}

pub fn link_settings(ifname: &str) -> Result<LinkSettings> {
    let fd = ioctl_socket()?;
    let mut cmd: EthtoolCmd = unsafe { std::mem::zeroed() };
    cmd.cmd = ETHTOOL_GSET;
    let mut ifr: IfreqData = unsafe { std::mem::zeroed() };
    set_ifr_name(&mut ifr, ifname)?;
    ifr.ifr_data = &mut cmd as *mut _ as *mut libc::c_void;

    // SAFETY: as above -- stack-owned buffers, sizes match what the
    // kernel expects for `ETHTOOL_GSET`.
    let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL, &mut ifr as *mut _) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    if rc < 0 {
        return Err(NetworkError::Device(format!(
            "ETHTOOL_GSET on {ifname} failed: {err}"
        )));
    }

    // 0xffff ("SPEED_UNKNOWN") in either half means the driver doesn't
    // know/report a speed (common when the link is down).
    let combined_speed = ((cmd.speed_hi as u32) << 16) | cmd.speed as u32;
    let speed_mbps = if cmd.speed == 0xffff || combined_speed == 0 {
        None
    } else {
        Some(combined_speed)
    };

    Ok(LinkSettings {
        speed_mbps,
        full_duplex: cmd.duplex == 1,
        autoneg: cmd.autoneg == 1,
    })
}
