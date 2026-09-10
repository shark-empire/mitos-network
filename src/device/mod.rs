//! Device model: what network interfaces exist, what kind they are, and
//! what state they're in. This is the layer `manager::manager` looks at
//! to decide "what should happen next" -- it owns no policy of its own.

pub mod capabilities;
pub mod device;
pub mod discovery;
pub mod link;
pub mod mac;
pub mod manager;
pub mod statistics;

pub use device::{DeviceState, DeviceType, NetworkDevice};
pub use manager::DeviceRegistry;
