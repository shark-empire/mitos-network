//! The non-Wi-Fi-specific case: sharing one interface's internet access
//! over another wired/virtual interface (e.g. a laptop's Wi-Fi uplink
//! shared to a device plugged into its Ethernet port). Same NAT
//! mechanism as `hotspot`, without the radio/AP-mode piece.

use crate::errors::Result;
use crate::firewall::Firewall;
use std::net::Ipv4Addr;

pub struct SharingSession {
    pub lan_interface: String,
    pub wan_interface: String,
    dhcp: Option<super::dhcp_server::ServerHandle>,
}

pub fn start(
    lan_interface: &str,
    wan_interface: &str,
    lan_server_ip: Ipv4Addr,
    prefixlen: u8,
    pool: (Ipv4Addr, Ipv4Addr),
    firewall: &mut Firewall,
) -> Result<SharingSession> {
    let iface = crate::ip::interface::get_by_name(lan_interface)?;
    crate::ip::address::add(iface.index, std::net::IpAddr::V4(lan_server_ip), prefixlen)?;
    crate::device::link::bring_up(iface.index)?;

    let dhcp = super::dhcp_server::start(super::dhcp_server::DhcpServerConfig {
        interface: lan_interface.to_string(),
        server_ip: lan_server_ip,
        pool_start: pool.0,
        pool_end: pool.1,
        prefixlen,
        lease_time_secs: 3600,
        dns_servers: vec![lan_server_ip],
    })?;

    firewall.assign_zone(lan_interface, "home")?;
    super::nat::enable(lan_interface, wan_interface, firewall)?;

    Ok(SharingSession {
        lan_interface: lan_interface.to_string(),
        wan_interface: wan_interface.to_string(),
        dhcp: Some(dhcp),
    })
}

pub fn stop(mut session: SharingSession, firewall: &mut Firewall) -> Result<()> {
    if let Some(dhcp) = session.dhcp.take() {
        dhcp.stop();
    }
    super::nat::disable(&session.lan_interface, &session.wan_interface, firewall)?;
    let iface = crate::ip::interface::get_by_name(&session.lan_interface)?;
    crate::ip::address::flush(iface.index)?;
    Ok(())
}
