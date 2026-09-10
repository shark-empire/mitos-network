use serde::{Deserialize, Serialize};

/// Mirrors the states every mainstream network manager's connectivity
/// checker exposes (NetworkManager's `NMConnectivityState` uses the
/// same four buckets under different names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectivityState {
    /// Haven't checked yet, or the last check itself failed to run.
    Unknown,
    /// No response at all -- likely no working default route/DNS.
    None,
    /// Got a response, but it looks like a captive portal (hotel/cafe
    /// Wi-Fi login page) rather than the real internet.
    Portal,
    /// Reached *something*, but not the expected response -- a
    /// firewall allowing some traffic but not general browsing, for
    /// instance.
    Limited,
    /// The connectivity-check endpoint responded exactly as expected.
    Full,
}

impl ConnectivityState {
    pub fn is_usable(self) -> bool {
        matches!(self, ConnectivityState::Full | ConnectivityState::Limited)
    }
}
