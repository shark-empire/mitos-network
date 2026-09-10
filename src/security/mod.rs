//! Authorization (who is allowed to do what over the IPC socket) and
//! secrets handling (Wi-Fi/VPN credentials). Two separate concerns that
//! happen to both be "security", so they share a module.

pub mod permissions;
pub mod policy;
pub mod secrets;
pub mod validation;

pub use permissions::PeerIdentity;
pub use policy::Capability;
