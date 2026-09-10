use crate::connectivity::ConnectivityState;
use crate::device::{DeviceState, NetworkDevice};
use serde::{Deserialize, Serialize};

/// The manager's own top-level state -- what a desktop shell's network
/// indicator icon actually reflects. Deliberately mirrors the
/// vocabulary NetworkManager's `NMState` uses, since it's already the
/// vocabulary most Linux desktop UI code expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkState {
    Unknown,
    Unavailable,
    Disconnected,
    Connecting,
    /// A connection is up (IP configured) but nothing beyond the local
    /// link/subnet has been confirmed reachable yet.
    ConnectedLocal,
    /// At least one connection is up and the connectivity check passed.
    Connected,
    /// Connected, but the connectivity check came back `Limited`.
    Limited,
    /// Connected, but stuck behind a captive portal.
    Portal,
    Disconnecting,
}

/// Derives the manager's overall state from every device's individual
/// state plus the last connectivity check result. Pure function on
/// purpose -- `NetworkManager` calls this after anything that could
/// plausibly change it, rather than trying to track transitions
/// incrementally and risking drift.
pub fn overall_state(devices: &[NetworkDevice], connectivity: ConnectivityState) -> NetworkState {
    if devices.iter().any(|d| d.state == DeviceState::Connecting || d.state == DeviceState::IpConfiguring) {
        return NetworkState::Connecting;
    }
    if devices.iter().any(|d| d.state == DeviceState::Deactivating) {
        return NetworkState::Disconnecting;
    }
    if devices.iter().any(|d| d.state == DeviceState::Activated) {
        return match connectivity {
            ConnectivityState::Full => NetworkState::Connected,
            ConnectivityState::Limited => NetworkState::Limited,
            ConnectivityState::Portal => NetworkState::Portal,
            ConnectivityState::None | ConnectivityState::Unknown => NetworkState::ConnectedLocal,
        };
    }
    let any_manageable = devices.iter().any(|d| d.state != DeviceState::Unmanaged);
    if !any_manageable {
        return NetworkState::Unavailable;
    }
    let any_available = devices.iter().any(|d| d.state != DeviceState::Unavailable && d.state != DeviceState::Unmanaged);
    if !any_available {
        NetworkState::Unavailable
    } else {
        NetworkState::Disconnected
    }
}
