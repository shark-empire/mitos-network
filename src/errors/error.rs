use std::fmt;

/// The one error type used across mitos-network.
///
/// Variants are deliberately coarse (per-subsystem, not per-function) --
/// the detail belongs in the `String` payload, which is what gets logged
/// and what `ipc::messages::Response::Error` sends back to `mitos-netctl`.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("netlink error: {0}")]
    Netlink(String),

    #[error("device error: {0}")]
    Device(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("DHCP error: {0}")]
    Dhcp(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Wi-Fi error: {0}")]
    Wifi(String),

    #[error("VPN error: {0}")]
    Vpn(String),

    #[error("firewall error: {0}")]
    Firewall(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("operation timed out: {0}")]
    Timeout(String),

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("{0}")]
    Other(String),
}

impl NetworkError {
    /// True for errors that are safe to retry (transient link/DHCP/DNS
    /// failures), as opposed to configuration mistakes that will just
    /// fail again. Used by `manager::scheduler` to decide whether to
    /// re-arm a retry timer.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            NetworkError::Timeout(_)
                | NetworkError::Dhcp(_)
                | NetworkError::Dns(_)
                | NetworkError::Netlink(_)
        )
    }
}

impl From<serde_json::Error> for NetworkError {
    fn from(e: serde_json::Error) -> Self {
        NetworkError::Parse(e.to_string())
    }
}

impl From<toml::de::Error> for NetworkError {
    fn from(e: toml::de::Error) -> Self {
        NetworkError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for NetworkError {
    fn from(e: toml::ser::Error) -> Self {
        NetworkError::Config(e.to_string())
    }
}

/// Small helper so call sites can write `.map_err(ctx("binding socket"))`
/// instead of a closure every time.
pub fn ctx(msg: &'static str) -> impl Fn(std::io::Error) -> NetworkError {
    move |e| NetworkError::Other(format!("{msg}: {e}"))
}
