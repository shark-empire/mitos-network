//! Turns kernel-reported interfaces into classified `NetworkDevice`s,
//! and watches for hotplug (cable/adapter/VPN-interface add-remove)
//! events so the manager doesn't have to poll.

use super::device::{DeviceState, DeviceType, NetworkDevice};
use crate::errors::Result;
use crate::ip::interface::Interface;
use std::path::Path;

/// Classifies an interface using the same signals real network managers
/// use: loopback flag, `IFLA_LINKINFO` kind for virtual links, and
/// `/sys/class/net/<name>/wireless` (the canonical, driver-independent
/// way to tell a Wi-Fi NIC from an Ethernet one on Linux) for the rest.
pub fn classify(iface: &Interface) -> DeviceType {
    if iface.is_loopback() {
        return DeviceType::Loopback;
    }
    if let Some(kind) = iface.kind.as_deref() {
        return match kind {
            "bridge" => DeviceType::Bridge,
            "bond" => DeviceType::Bond,
            "vlan" => DeviceType::Vlan,
            "wireguard" | "gre" | "gretap" | "ipip" | "sit" | "vxlan" => {
                if kind == "wireguard" {
                    DeviceType::Vpn
                } else {
                    DeviceType::Tunnel
                }
            }
            "tun" | "tap" => DeviceType::Tunnel,
            "dummy" | "veth" => DeviceType::Virtual,
            _ => DeviceType::Virtual,
        };
    }
    if sys_path(&iface.name, "wireless").exists() || sys_path(&iface.name, "phy80211").exists() {
        return DeviceType::WiFi;
    }
    if iface.name.starts_with("bnep") {
        return DeviceType::Bluetooth;
    }
    if sys_path(&iface.name, "device").exists() {
        return DeviceType::Ethernet;
    }
    DeviceType::Unknown
}

fn sys_path(name: &str, leaf: &str) -> std::path::PathBuf {
    Path::new("/sys/class/net").join(name).join(leaf)
}

pub fn driver_of(name: &str) -> Option<String> {
    let link = std::fs::read_link(sys_path(name, "device/driver")).ok()?;
    link.file_name().map(|n| n.to_string_lossy().to_string())
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A one-shot full scan of `/sys/class/net` + netlink, used at startup
/// and after a hotplug event to rebuild `device::DeviceRegistry`.
pub fn scan() -> Result<Vec<NetworkDevice>> {
    let ifaces = crate::ip::interface::list()?;
    let addrs = crate::ip::address::list(None).unwrap_or_default();

    Ok(ifaces
        .into_iter()
        .map(|iface| {
            let device_type = classify(&iface);
            let ipv4_addresses = addrs
                .iter()
                .filter(|a| a.index == iface.index && a.ip.is_ipv4())
                .map(|a| format!("{}/{}", a.ip, a.prefixlen))
                .collect();
            let ipv6_addresses = addrs
                .iter()
                .filter(|a| a.index == iface.index && a.ip.is_ipv6())
                .map(|a| format!("{}/{}", a.ip, a.prefixlen))
                .collect();
            let state = if iface.is_up() {
                if iface.has_carrier() {
                    DeviceState::Disconnected // manager promotes this once a connection activates
                } else {
                    DeviceState::Unavailable
                }
            } else {
                DeviceState::Unavailable
            };
            NetworkDevice {
                name: iface.name.clone(),
                index: iface.index as u32,
                device_type,
                state,
                mac_address: iface.hwaddr.map(format_mac),
                mtu: iface.mtu,
                ipv4_addresses,
                ipv6_addresses,
                carrier: iface.has_carrier(),
                driver: driver_of(&iface.name),
                active_connection: None,
            }
        })
        .collect())
}

/// Events the hotplug monitor thread emits.
#[derive(Debug, Clone)]
pub enum HotplugEvent {
    LinkAdded(String),
    LinkRemoved(String),
    LinkChanged(String),
    AddressChanged(String),
}

/// Spawns a background thread that blocks on a netlink multicast socket
/// (`RTMGRP_LINK | RTMGRP_IPV{4,6}_IFADDR`) and forwards parsed events
/// to `tx`. This is the *only* thread besides the manager's own command
/// loop that mitos-network normally runs continuously -- everything
/// else (IPC connections, DHCP timers) is on-demand or scheduled.
pub fn spawn_monitor(
    tx: std::sync::mpsc::Sender<HotplugEvent>,
) -> Result<std::thread::JoinHandle<()>> {
    use crate::ip::monitor::{
        Monitor, RawEvent, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK,
    };

    let groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    let monitor = Monitor::new(groups)?;
    let handle = std::thread::Builder::new()
        .name("mitos-network-monitor".into())
        .spawn(move || loop {
            match monitor.recv() {
                Ok(events) => {
                    for ev in events {
                        let mapped = match ev {
                            RawEvent::LinkNew { name } => HotplugEvent::LinkAdded(name),
                            RawEvent::LinkDel { name } => HotplugEvent::LinkRemoved(name),
                            RawEvent::AddrNew { index } | RawEvent::AddrDel { index } => {
                                HotplugEvent::AddressChanged(index.to_string())
                            }
                        };
                        if tx.send(mapped).is_err() {
                            return; // manager shut down; stop the thread quietly
                        }
                    }
                }
                Err(e) => {
                    crate::logging::logger::error(&format!("hotplug monitor recv error: {e}"));
                }
            }
        })?;
    Ok(handle)
}
