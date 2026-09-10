//! Wi-Fi: association, scanning, security, roaming and AP ("hotspot")
//! mode.
//!
//! mitos-network doesn't speak 802.11 or WPA itself -- that's
//! `wpa_supplicant` (station mode, `wifi::wpa`) and `hostapd` (AP mode,
//! `wifi::hotspot`), both already-hardened, widely-audited pieces of
//! software every mainstream Linux network manager builds on rather
//! than reimplements. This module is wpa_supplicant's *control
//! protocol* client plus the policy built on top of it: which network
//! to join, when to roam, how to classify security types.

pub mod hotspot;
pub mod network;
pub mod roaming;
pub mod scanner;
pub mod security;
pub mod wifi;
pub mod wpa;

pub use network::WifiNetwork;
pub use security::SecurityType;
