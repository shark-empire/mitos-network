//! Full "turn this Wi-Fi adapter into a hotspot" orchestration: radio
//! (`wifi::hotspot`) + interface addressing + a DHCP server for clients
//! + (optionally) NAT'ing them out through another interface.

use crate::errors::Result;
use crate::firewall::Firewall;
use crate::wifi::hotspot::HotspotConfig;
use std::net::Ipv4Addr;

pub struct HotspotSession {
    pub interface: String,
    dhcp: Option<super::dhcp_server::ServerHandle>,
    uplink: Option<String>,
}

const AP_SERVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
const AP_POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 10);
const AP_POOL_END: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 200);
const AP_PREFIXLEN: u8 = 24;

pub fn start(
    interface: &str,
    ssid: &str,
    passphrase: Option<&str>,
    uplink: Option<&str>,
    firewall: &mut Firewall,
) -> Result<HotspotSession> {
    let iface = crate::ip::interface::get_by_name(interface)?;
    crate::ip::address::flush(iface.index)?;
    crate::ip::address::add(iface.index, std::net::IpAddr::V4(AP_SERVER_IP), AP_PREFIXLEN)?;
    crate::device::link::bring_up(iface.index)?;

    crate::wifi::hotspot::start(&HotspotConfig {
        interface: interface.to_string(),
        ssid: ssid.to_string(),
        passphrase: passphrase.map(str::to_string),
        channel: 6,
        hw_mode: "g".to_string(),
    })?;

    let dhcp = super::dhcp_server::start(super::dhcp_server::DhcpServerConfig {
        interface: interface.to_string(),
        server_ip: AP_SERVER_IP,
        pool_start: AP_POOL_START,
        pool_end: AP_POOL_END,
        prefixlen: AP_PREFIXLEN,
        lease_time_secs: 3600,
        dns_servers: vec![AP_SERVER_IP], // clients ask us; we forward via whatever /etc/resolv.conf already has
    })?;

    firewall.assign_zone(interface, "home")?;
    if let Some(wan) = uplink {
        super::nat::enable(interface, wan, firewall)?;
    }

    Ok(HotspotSession { interface: interface.to_string(), dhcp: Some(dhcp), uplink: uplink.map(str::to_string) })
}

pub fn stop(mut session: HotspotSession, firewall: &mut Firewall) -> Result<()> {
    if let Some(dhcp) = session.dhcp.take() {
        dhcp.stop();
    }
    crate::wifi::hotspot::stop(&session.interface);
    if let Some(wan) = &session.uplink {
        super::nat::disable(&session.interface, wan, firewall)?;
    }
    let iface = crate::ip::interface::get_by_name(&session.interface)?;
    crate::ip::address::flush(iface.index)?;
    Ok(())
}
