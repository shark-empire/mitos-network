//! Turns a `ConnectionProfile` into an actually-configured, working
//! interface. This is the orchestration point that ties together
//! `device`, `ip`, `dhcp`, `dns`, `routing`, `wifi` and `vpn` -- by
//! design, none of those modules know about each other; this module is
//! where the "plug it all together" policy lives.

use super::connection::{ActiveConnection, ActiveConnectionState};
use super::profile::ConnectionProfile;
use crate::config::AddressMethod;
use crate::device::{DeviceState, DeviceType, NetworkDevice};
use crate::errors::{NetworkError, Result};
use crate::security::secrets::SecretsBackend;
use std::time::Duration;

const DHCP_TIMEOUT: Duration = Duration::from_secs(30);
const CARRIER_TIMEOUT: Duration = Duration::from_secs(10);

pub fn activate(
    profile: &ConnectionProfile,
    device: &mut NetworkDevice,
    secrets: &dyn SecretsBackend,
) -> Result<ActiveConnection> {
    device.state = DeviceState::Connecting;
    let index = device.index as i32;

    match profile.device_type {
        DeviceType::WiFi => {
            let wifi = profile
                .wifi
                .as_ref()
                .ok_or_else(|| NetworkError::Config(format!("profile '{}' has no [wifi] section", profile.id)))?;
            let passphrase = if wifi.has_secret {
                secrets.get(&profile.id, "psk")?
            } else {
                None
            };
            crate::wifi::wifi::connect(&device.name, &wifi.ssid, wifi.security, passphrase.as_deref())?;
        }
        DeviceType::Vpn => {
            let vpn = profile
                .vpn
                .as_ref()
                .ok_or_else(|| NetworkError::Config(format!("profile '{}' has no [vpn] section", profile.id)))?;
            let session = crate::vpn::vpn::connect(vpn.kind, &vpn.config, secrets, &profile.id)?;
            device.state = DeviceState::Activated;
            device.active_connection = Some(profile.id.clone());
            return Ok(ActiveConnection {
                profile_id: profile.id.clone(),
                device_name: session.interface_name,
                state: ActiveConnectionState::Activated,
                since: std::time::SystemTime::now(),
                failure_reason: None,
            });
        }
        _ => {
            crate::device::link::bring_up(index)?;
            crate::device::link::wait_for_carrier(index, CARRIER_TIMEOUT)?;
        }
    }

    device.state = DeviceState::IpConfiguring;
    crate::ip::address::flush(index)?;

    match profile.method {
        AddressMethod::Manual => apply_static(profile, index)?,
        AddressMethod::Auto => apply_dhcp(profile, device, index)?,
        AddressMethod::LinkLocal => { /* kernel/IPv6 SLAAC handles this; nothing to do */ }
        AddressMethod::Disabled => {}
    }

    if !profile.dns.is_empty() {
        let servers: Vec<std::net::IpAddr> = profile
            .dns
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        crate::dns::resolver::apply_static(&servers, &[])?;
    }

    device.state = DeviceState::Activated;
    device.active_connection = Some(profile.id.clone());

    Ok(ActiveConnection {
        profile_id: profile.id.clone(),
        device_name: device.name.clone(),
        state: ActiveConnectionState::Activated,
        since: std::time::SystemTime::now(),
        failure_reason: None,
    })
}

fn apply_static(profile: &ConnectionProfile, index: i32) -> Result<()> {
    for addr in &profile.addresses {
        let (ip, prefixlen) = crate::ip::address::parse_cidr(addr)?;
        crate::ip::address::add(index, ip, prefixlen)?;
    }
    if let Some(gw) = &profile.gateway {
        let gw: std::net::IpAddr = gw
            .parse()
            .map_err(|_| NetworkError::Config(format!("invalid gateway '{gw}'")))?;
        crate::routing::default_route::apply(index, gw, 100, crate::ip::route::RouteProtocol::Static)?;
    }
    Ok(())
}

fn apply_dhcp(_profile: &ConnectionProfile, device: &mut NetworkDevice, index: i32) -> Result<()> {
    let lease = crate::dhcp::client::acquire(&device.name, index, DHCP_TIMEOUT)?;
    crate::ip::address::add(index, std::net::IpAddr::V4(lease.address), lease.prefixlen)?;
    if let Some(gw) = lease.gateway {
        crate::routing::default_route::apply(index, std::net::IpAddr::V4(gw), 100, crate::ip::route::RouteProtocol::Dhcp)?;
    }
    if !lease.dns_servers.is_empty() {
        let servers = lease.dns_servers.iter().map(|a| std::net::IpAddr::V4(*a)).collect::<Vec<_>>();
        crate::dns::resolver::apply_static(&servers, &lease.domain.clone().into_iter().collect::<Vec<_>>())?;
    }
    device.ipv4_addresses = vec![format!("{}/{}", lease.address, lease.prefixlen)];
    crate::persistence::state::save_lease(&device.name, &lease)?;
    Ok(())
}
