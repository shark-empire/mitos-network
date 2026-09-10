//! A coarse per-device health verdict, meant for a UI status dot more
//! than deep diagnostics (that's `diagnostics`'s job).

use crate::device::statistics::DeviceStatistics;
use crate::device::{DeviceState, NetworkDevice};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

pub fn device_health(device: &NetworkDevice, stats: Option<&DeviceStatistics>) -> HealthStatus {
    match device.state {
        DeviceState::Unmanaged | DeviceState::Unavailable => HealthStatus::Unknown,
        DeviceState::Failed => HealthStatus::Unhealthy,
        DeviceState::Connecting | DeviceState::IpConfiguring | DeviceState::Deactivating => HealthStatus::Degraded,
        DeviceState::Disconnected => HealthStatus::Unknown,
        DeviceState::Activated => {
            if !device.carrier {
                return HealthStatus::Unhealthy; // activated but no carrier is a contradiction worth flagging
            }
            if let Some(s) = stats {
                let total = s.rx_packets + s.tx_packets;
                let errors = s.rx_errors + s.tx_errors + s.rx_dropped + s.tx_dropped;
                if total > 0 && (errors * 100 / total.max(1)) > 5 {
                    return HealthStatus::Degraded; // >5% error/drop rate
                }
            }
            HealthStatus::Healthy
        }
    }
}
