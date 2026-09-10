//! The inverse of `activation`: tear an interface back down to an
//! unconfigured state cleanly, releasing whatever resources the
//! activation path acquired.

use super::connection::{ActiveConnection, ActiveConnectionState};
use crate::device::{DeviceState, DeviceType, NetworkDevice};
use crate::errors::Result;

pub fn deactivate(active: &mut ActiveConnection, device: &mut NetworkDevice) -> Result<()> {
    device.state = DeviceState::Deactivating;
    active.state = ActiveConnectionState::Deactivating;

    let index = device.index as i32;

    if device.device_type == DeviceType::Vpn {
        crate::vpn::vpn::disconnect(&device.name)?;
    } else {
        // A DHCP lease should be released, not just abandoned, so the
        // server can hand the address to someone else promptly.
        let _ = crate::dhcp::client::release(&device.name);
        crate::ip::address::flush(index)?;
        if device.device_type == DeviceType::WiFi {
            crate::wifi::wifi::disconnect(&device.name)?;
        }
    }

    device.state = DeviceState::Disconnected;
    device.active_connection = None;
    device.ipv4_addresses.clear();
    device.ipv6_addresses.clear();
    active.state = ActiveConnectionState::Deactivated;
    Ok(())
}
