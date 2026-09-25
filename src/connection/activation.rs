//! Turns a `ConnectionProfile` into an actually-configured, working
//! interface. This is the orchestration point that ties together
//! `device`, `ip`, `dhcp`, `dns`, `routing`, `wifi` and `vpn` -- by
//! design, none of those modules know about each other; this module is
//! where the "plug it all together" policy lives.

use super::connection::{ActiveConnection, ActiveConnectionState};
use super::profile::ConnectionProfile;
use crate::config::{AddressMethod, Ipv6Method};
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
            let wifi = profile.wifi.as_ref().ok_or_else(|| {
                NetworkError::Config(format!("profile '{}' has no [wifi] section", profile.id))
            })?;
            let passphrase = if wifi.has_secret {
                secrets.get(&profile.id, "psk")?
            } else if wifi.has_eap_secret {
                secrets.get(&profile.id, "eap-password")?
            } else {
                None
            };
            let key_password = if wifi.eap_private_key_path.is_some() {
                secrets.get(&profile.id, "eap-private-key-password")?
            } else {
                None
            };
            let eap = if wifi.security.is_enterprise() {
                Some(crate::wifi::wifi::EapConfig {
                    identity: wifi.eap_identity.as_deref(),
                    ca_cert_path: wifi.eap_ca_cert_path.as_deref(),
                    client_cert_path: wifi.eap_client_cert_path.as_deref(),
                    private_key_path: wifi.eap_private_key_path.as_deref(),
                    private_key_password: key_password.as_deref(),
                    eap_method: wifi.eap_method.as_deref(),
                    eap_phase2: wifi.eap_phase2.as_deref(),
                })
            } else {
                None
            };
            crate::wifi::wifi::connect(
                &device.name,
                &wifi.ssid,
                wifi.security,
                passphrase.as_deref(),
                eap.as_ref(),
            )?;
        }
        DeviceType::Vpn => {
            let vpn = profile.vpn.as_ref().ok_or_else(|| {
                NetworkError::Config(format!("profile '{}' has no [vpn] section", profile.id))
            })?;
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

    match profile.ipv6_method {
        Ipv6Method::Slaac => { /* kernel/IPv6 SLAAC handles this; nothing to do */ }
        Ipv6Method::SlaacWithStatelessDhcp => apply_dhcp6_stateless(device),
        Ipv6Method::Dhcp6 => apply_dhcp6(device, index)?,
    }

    if !profile.dns.is_empty() {
        let servers: Vec<std::net::IpAddr> =
            profile.dns.iter().filter_map(|s| s.parse().ok()).collect();
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
        crate::routing::default_route::apply(
            index,
            gw,
            100,
            crate::ip::route::RouteProtocol::Static,
        )?;
    }
    Ok(())
}

fn apply_dhcp(_profile: &ConnectionProfile, device: &mut NetworkDevice, index: i32) -> Result<()> {
    let lease = crate::dhcp::client::acquire(&device.name, index, DHCP_TIMEOUT)?;
    crate::ip::address::add(index, std::net::IpAddr::V4(lease.address), lease.prefixlen)?;
    if let Some(gw) = lease.gateway {
        crate::routing::default_route::apply(
            index,
            std::net::IpAddr::V4(gw),
            100,
            crate::ip::route::RouteProtocol::Dhcp,
        )?;
    }
    if !lease.dns_servers.is_empty() {
        let servers = lease
            .dns_servers
            .iter()
            .map(|a| std::net::IpAddr::V4(*a))
            .collect::<Vec<_>>();
        crate::dns::resolver::apply_static(
            &servers,
            &lease.domain.clone().into_iter().collect::<Vec<_>>(),
        )?;
    }
    device.ipv4_addresses = vec![format!("{}/{}", lease.address, lease.prefixlen)];
    crate::persistence::state::save_lease(&device.name, &lease)?;
    Ok(())
}

fn apply_dhcp6(device: &mut NetworkDevice, index: i32) -> Result<()> {
    let mac = crate::dhcp::get_mac(&device.name)?;
    let lease = crate::dhcp::dhcp6::request_stateful_lease(&device.name, mac, DHCP_TIMEOUT)?;
    crate::ip::address::add(index, std::net::IpAddr::V6(lease.address), lease.prefixlen)?;
    if !lease.dns_servers.is_empty() {
        let servers: Vec<std::net::IpAddr> =
            lease.dns_servers.iter().map(|a| std::net::IpAddr::V6(*a)).collect();
        crate::dns::resolver::apply_static(&servers, &lease.domain_search)?;
    }
    device.ipv6_addresses = vec![format!("{}/{}", lease.address, lease.prefixlen)];
    crate::persistence::state::save_lease6(&device.name, &lease)?;
    Ok(())
}

/// Unlike [`apply_dhcp6`], failure here doesn't fail activation: SLAAC
/// has already given the device a working address by the time this
/// runs, so a DHCPv6 server that's slow, absent, or doesn't support
/// stateless mode just means the connection proceeds without extra
/// DNS servers from it -- not that it's broken.
fn apply_dhcp6_stateless(device: &NetworkDevice) {
    let mac = match crate::dhcp::get_mac(&device.name) {
        Ok(mac) => mac,
        Err(_) => return,
    };
    match crate::dhcp::dhcp6::request_stateless_info(&device.name, mac, DHCP_TIMEOUT) {
        Ok(info) if !info.dns_servers.is_empty() => {
            let servers: Vec<std::net::IpAddr> =
                info.dns_servers.iter().map(|a| std::net::IpAddr::V6(*a)).collect();
            if let Err(e) = crate::dns::resolver::apply_static(&servers, &info.domain_search) {
                crate::logging::logger::warn(&format!(
                    "applying DHCPv6 stateless DNS info for {} failed: {e}",
                    device.name
                ));
            }
        }
        Ok(_) => {}
        Err(e) => crate::logging::logger::warn(&format!(
            "DHCPv6 stateless Information-Request on {} failed: {e}",
            device.name
        )),
    }
}
