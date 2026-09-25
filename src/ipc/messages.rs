use crate::bluetooth::bluetooth::BluetoothDevice;
use crate::connection::ConnectionProfile;
use crate::connectivity::ConnectivityState;
use crate::device::{DeviceState, NetworkDevice};
use crate::firewall::Rule;
use crate::manager::state::NetworkState;
use crate::monitoring::diagnostics::DiagnosticReport;
use crate::proxy::ProxyConfig;
use crate::wifi::{SecurityType, WifiNetwork};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    GetState,
    ListDevices,
    GetDevice {
        name: String,
    },
    ListConnections,
    GetConnection {
        id: String,
    },
    AddConnection {
        profile: ConnectionProfile,
    },
    DeleteConnection {
        id: String,
    },
    ActivateConnection {
        id: String,
    },
    DeactivateConnection {
        id: String,
    },
    ScanWifi {
        device: String,
    },
    ListWifiNetworks {
        device: String,
    },
    ConnectWifi {
        device: String,
        ssid: String,
        security: SecurityType,
        passphrase: Option<String>,
    },
    ForgetWifi {
        device: String,
        ssid: String,
    },
    StartHotspot {
        device: String,
        ssid: String,
        passphrase: Option<String>,
        uplink: Option<String>,
    },
    StopHotspot {
        device: String,
    },
    SetFirewallZone {
        interface: String,
        zone: String,
    },
    AddFirewallRule {
        rule: Rule,
    },
    RemoveFirewallRule {
        id: String,
    },
    GetConnectivity,
    Diagnose,
    Reload,
    ListBluetoothDevices,
    BluetoothPower {
        on: bool,
    },
    BluetoothScan {
        on: bool,
    },
    PairBluetooth {
        mac: String,
    },
    TrustBluetooth {
        mac: String,
    },
    ConnectBluetooth {
        mac: String,
    },
    DisconnectBluetooth {
        mac: String,
    },
    RemoveBluetooth {
        mac: String,
    },
    SetProxyConfig {
        config: ProxyConfig,
    },
    GetProxyConfig,
    /// What proxy (or `DIRECT`) a client should use for a given URL,
    /// per the currently-active proxy config -- the actual answer for
    /// `ProxyMode::Auto`, which `GetProxyConfig` alone can't give
    /// (that just returns the *config*, i.e. the PAC URL, not what it
    /// evaluates to for any particular request).
    ResolveProxy {
        url: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Ok,
    State(NetworkState),
    Devices(Vec<NetworkDevice>),
    Device(NetworkDevice),
    Connections(Vec<ConnectionProfile>),
    Connection(ConnectionProfile),
    WifiNetworks(Vec<WifiNetwork>),
    Connectivity(ConnectivityState),
    Diagnostics(Box<DiagnosticReport>),
    BluetoothDevices(Vec<BluetoothDevice>),
    ProxyConfig(Option<ProxyConfig>),
    ProxyResolution(String),
    Error(String),
}

/// Pushed to any client that has issued at least one request on its
/// connection -- there's no separate `SUBSCRIBE` handshake, receiving
/// events is implicit for as long as the socket stays open, the same
/// low-ceremony model `mitos-session`'s IPC uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    StateChanged(NetworkState),
    DeviceAdded(NetworkDevice),
    DeviceRemoved(String),
    DeviceStateChanged { device: String, state: DeviceState },
    ConnectionActivated(String),
    ConnectionDeactivated(String),
    ConnectivityChanged(ConnectivityState),
}

/// What actually goes over the wire: a client `Request` addressed to
/// nothing in particular, or a server `Envelope` carrying either the
/// matching `Response` or an out-of-band `Event`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMessage {
    Response(Response),
    Event(Event),
}
