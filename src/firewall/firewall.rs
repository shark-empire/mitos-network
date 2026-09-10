//! Ties `zones` + `rules` together and drives `nftables::apply` on
//! every change. This is the type `manager::manager` owns one of.

use super::rules::Rule;
use super::zones::{builtin_zones, Zone, DEFAULT_ZONE};
use crate::errors::{NetworkError, Result};

pub struct Firewall {
    zones: Vec<Zone>,
    rules: Vec<Rule>,
    masquerade_interfaces: Vec<String>,
    forward_pairs: Vec<(String, String)>,
}

impl Default for Firewall {
    fn default() -> Self {
        Firewall {
            zones: builtin_zones(),
            rules: Vec::new(),
            masquerade_interfaces: Vec::new(),
            forward_pairs: Vec::new(),
        }
    }
}

impl Firewall {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies the current in-memory state to the live nftables ruleset.
    /// Called after every mutating method below -- there's no separate
    /// "dirty" flag to forget to check.
    fn apply(&self) -> Result<()> {
        let ruleset = super::nftables::render(&self.zones, &self.rules, &self.masquerade_interfaces, &self.forward_pairs);
        super::nftables::apply(&ruleset)
    }

    pub fn assign_zone(&mut self, interface: &str, zone_name: &str) -> Result<()> {
        if !self.zones.iter().any(|z| z.name == zone_name) {
            return Err(NetworkError::Firewall(format!("unknown zone '{zone_name}'")));
        }
        for z in &mut self.zones {
            z.interfaces.retain(|i| i != interface);
        }
        if let Some(z) = self.zones.iter_mut().find(|z| z.name == zone_name) {
            z.interfaces.push(interface.to_string());
        }
        self.apply()
    }

    /// Interfaces without an explicit assignment default to
    /// [`zones::DEFAULT_ZONE`] the first time they're seen.
    pub fn ensure_default_zone(&mut self, interface: &str) -> Result<()> {
        let already_assigned = self.zones.iter().any(|z| z.interfaces.iter().any(|i| i == interface));
        if !already_assigned {
            self.assign_zone(interface, DEFAULT_ZONE)?;
        }
        Ok(())
    }

    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        self.rules.retain(|r| r.id != rule.id);
        self.rules.push(rule);
        self.apply()
    }

    pub fn remove_rule(&mut self, id: &str) -> Result<()> {
        self.rules.retain(|r| r.id != id);
        self.apply()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn zones(&self) -> &[Zone] {
        &self.zones
    }

    /// NAT-masquerades traffic going out `wan_interface` and allows
    /// `lan_interface` to forward through it -- what `sharing::nat`
    /// calls when standing up internet sharing.
    pub fn enable_sharing(&mut self, lan_interface: &str, wan_interface: &str) -> Result<()> {
        if !self.masquerade_interfaces.iter().any(|i| i == wan_interface) {
            self.masquerade_interfaces.push(wan_interface.to_string());
        }
        let pair = (lan_interface.to_string(), wan_interface.to_string());
        if !self.forward_pairs.contains(&pair) {
            self.forward_pairs.push(pair);
        }
        self.apply()
    }

    pub fn disable_sharing(&mut self, lan_interface: &str, wan_interface: &str) -> Result<()> {
        self.forward_pairs.retain(|(l, w)| !(l == lan_interface && w == wan_interface));
        if !self.forward_pairs.iter().any(|(_, w)| w == wan_interface) {
            self.masquerade_interfaces.retain(|i| i != wan_interface);
        }
        self.apply()
    }
}
