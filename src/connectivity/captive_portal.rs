//! Classifying a connectivity-check response as "clean", "portal", or
//! "something in between".

use super::internet::ConnectivityState;

/// `expected_status` is what the check URL is documented to return on
/// a genuinely open connection (204 is the near-universal convention --
/// `connectivity.mitos-os.org/check` returns 204 with an empty body,
/// same as the endpoints every major OS/browser vendor uses).
pub fn classify(status: u16, expected_status: u16, redirected: bool) -> ConnectivityState {
    if redirected || (300..400).contains(&status) {
        // A captive portal's entire mechanism is HTTP-redirecting (or,
        // for a plain 200, substituting) unauthenticated requests to
        // its login page.
        return ConnectivityState::Portal;
    }
    if status == expected_status {
        return ConnectivityState::Full;
    }
    if (200..300).contains(&status) {
        // Got *a* 2xx, just not the exact one expected -- e.g. a proxy
        // or filtering firewall answering on our behalf. Still counts
        // as "the network mostly works".
        return ConnectivityState::Limited;
    }
    ConnectivityState::Limited
}
