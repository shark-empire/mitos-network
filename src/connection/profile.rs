//! The persisted shape of "a thing you can connect to". Serialized as
//! TOML under `data/profiles/<id>.toml` by `persistence::profiles`;
//! secrets are deliberately *not* fields here (see `security::secrets`).

use crate::config::AddressMethod;
use crate::device::DeviceType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    /// Stable identifier (filename-safe), e.g. `"home-wifi"`. Distinct
    /// from `name`, which is just what's shown in a UI.
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    /// Pin to one interface by name, or `None` to match the first
    /// available device of `device_type`.
    #[serde(default)]
    pub interface_name: Option<String>,
    #[serde(default)]
    pub method: AddressMethod,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default = "default_true")]
    pub autoconnect: bool,
    /// Higher wins when several autoconnect-eligible profiles could
    /// apply to the same device (mirrors NetworkManager's own field).
    #[serde(default)]
    pub autoconnect_priority: i32,
    /// Hint for connectivity-conscious behavior elsewhere in mitosOS
    /// (e.g. deferring large downloads) -- mitos-network itself only
    /// stores and reports this, it doesn't enforce anything from it.
    #[serde(default)]
    pub metered: bool,
    #[serde(default)]
    pub wifi: Option<WifiSettings>,
    #[serde(default)]
    pub vpn: Option<VpnSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiSettings {
    pub ssid: String,
    pub security: crate::wifi::security::SecurityType,
    #[serde(default)]
    pub hidden: bool,
    /// Key into `security::secrets` (`get(&profile.id, "psk")`), not the
    /// passphrase itself.
    #[serde(default)]
    pub has_secret: bool,
    /// WPA2/WPA3-Enterprise (802.1X) fields; unused for Personal/PSK
    /// networks. `eap_identity` is the EAP username -- not secret,
    /// stored here the same way `ssid` is. Certificate fields are
    /// filesystem paths, not the certificates themselves:
    /// mitos-network doesn't manage a certificate store, just points
    /// wpa_supplicant at wherever the admin/user already placed them.
    #[serde(default)]
    pub eap_identity: Option<String>,
    /// CA certificate used to validate the RADIUS server's identity.
    /// This is what actually makes Enterprise Wi-Fi safe to use:
    /// without it, wpa_supplicant completes the handshake with *any*
    /// server claiming to be the right one, which is exactly what a
    /// rogue AP impersonating a known enterprise network relies on.
    #[serde(default)]
    pub eap_ca_cert_path: Option<String>,
    /// Client certificate + key, for EAP-TLS. Both unset for
    /// password-based methods (PEAP/TTLS with `eap_identity` +
    /// a secret).
    #[serde(default)]
    pub eap_client_cert_path: Option<String>,
    #[serde(default)]
    pub eap_private_key_path: Option<String>,
    /// Key into `security::secrets`
    /// (`get(&profile.id, "eap-password")`) for a PEAP/TTLS password,
    /// or (`get(&profile.id, "eap-private-key-password")`) for an
    /// encrypted EAP-TLS private key.
    #[serde(default)]
    pub has_eap_secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnSettings {
    pub kind: crate::vpn::vpn::VpnKind,
    /// For WireGuard: peer public key + endpoint. For OpenVPN: path to
    /// the (non-secret) `.ovpn` config. Kind-specific parsing happens
    /// in `vpn::vpn::connect`.
    pub config: String,
}

fn default_true() -> bool {
    true
}

impl ConnectionProfile {
    pub fn new_wifi(
        id: impl Into<String>,
        ssid: impl Into<String>,
        security: crate::wifi::security::SecurityType,
    ) -> Self {
        let ssid = ssid.into();
        ConnectionProfile {
            id: id.into(),
            name: ssid.clone(),
            device_type: DeviceType::WiFi,
            interface_name: None,
            method: AddressMethod::Auto,
            addresses: Vec::new(),
            gateway: None,
            dns: Vec::new(),
            autoconnect: true,
            autoconnect_priority: 0,
            metered: false,
            wifi: Some(WifiSettings {
                ssid,
                security,
                hidden: false,
                has_secret: security != crate::wifi::security::SecurityType::Open,
                eap_identity: None,
                eap_ca_cert_path: None,
                eap_client_cert_path: None,
                eap_private_key_path: None,
                has_eap_secret: false,
            }),
            vpn: None,
        }
    }
}
