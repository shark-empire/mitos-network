//! mitos-network as a library: the daemon binary (`src/main.rs`) and
//! the `mitos-netctl` CLI (`bin/mitos-netctl.rs`) both build on this --
//! `mitos-netctl` needs the same `ipc::messages` types and
//! `ipc::client` to talk to the running daemon, without needing to
//! duplicate any of it.

pub mod bluetooth;
pub mod config;
pub mod connection;
pub mod connectivity;
pub mod device;
pub mod dhcp;
pub mod dns;
pub mod errors;
pub mod ethernet;
pub mod firewall;
pub mod ip;
pub mod ipc;
pub mod logging;
pub mod manager;
pub mod monitoring;
pub mod persistence;
pub mod proxy;
pub mod routing;
pub mod security;
pub mod sharing;
pub mod vpn;
pub mod wifi;
