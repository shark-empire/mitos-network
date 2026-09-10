//! In-memory registry of known devices. `manager::manager::NetworkManager`
//! owns one of these; this module just keeps it internally consistent.

use super::device::{DeviceState, NetworkDevice};
use super::discovery;
use crate::errors::Result;
use std::collections::HashMap;

#[derive(Default)]
pub struct DeviceRegistry {
    devices: HashMap<String, NetworkDevice>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Full re-scan from the kernel, preserving each device's current
    /// `state`/`active_connection` (those are mitos-network's own policy
    /// state, not something the kernel knows about) across the refresh.
    pub fn refresh(&mut self, unmanaged: &[String]) -> Result<()> {
        let scanned = discovery::scan()?;
        let mut next = HashMap::with_capacity(scanned.len());
        for mut dev in scanned {
            if unmanaged.iter().any(|u| u == &dev.name) {
                dev.state = DeviceState::Unmanaged;
            } else if let Some(existing) = self.devices.get(&dev.name) {
                dev.state = existing.state;
                dev.active_connection = existing.active_connection.clone();
            }
            next.insert(dev.name.clone(), dev);
        }
        self.devices = next;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&NetworkDevice> {
        self.devices.get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut NetworkDevice> {
        self.devices.get_mut(name)
    }

    pub fn all(&self) -> impl Iterator<Item = &NetworkDevice> {
        self.devices.values()
    }

    pub fn set_state(&mut self, name: &str, state: DeviceState) {
        if let Some(d) = self.devices.get_mut(name) {
            d.state = state;
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.devices.remove(name);
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}
