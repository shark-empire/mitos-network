//! Connection profiles: the user-facing, persisted "things you connect
//! to" (a Wi-Fi network, a wired autoconnect setup, a VPN tunnel) as
//! opposed to `device`, which is the physical/virtual interface a
//! profile gets activated *on*.

pub mod activation;
pub mod autoconnect;
pub mod connection;
pub mod deactivation;
pub mod profile;

pub use connection::{ActiveConnection, ActiveConnectionState};
pub use profile::ConnectionProfile;
