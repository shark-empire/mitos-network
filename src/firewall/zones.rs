//! firewalld-style zones: a named trust level applied per-interface.
//! Every mitosOS install ships the same four built-in zones; users add
//! rules within a zone rather than writing raw nftables.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultPolicy {
    /// Allow everything not explicitly blocked (e.g. a "Trusted" zone
    /// for the box's own VPN tunnel).
    Accept,
    /// Drop everything not explicitly allowed (default for "Public").
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub name: String,
    pub default_policy: DefaultPolicy,
    /// Interfaces currently assigned to this zone.
    #[serde(default)]
    pub interfaces: Vec<String>,
}

/// The four built-in zones every mitosOS install starts with -- this is
/// intentionally a small, fixed set (not the dozen-plus zones firewalld
/// ships) matching what a general-purpose desktop/laptop actually needs:
/// nothing beyond "how much do I trust what's on the other end of this
/// interface".
pub fn builtin_zones() -> Vec<Zone> {
    vec![
        Zone {
            name: "public".into(),
            default_policy: DefaultPolicy::Drop,
            interfaces: Vec::new(),
        },
        Zone {
            name: "home".into(),
            default_policy: DefaultPolicy::Drop,
            interfaces: Vec::new(),
        },
        Zone {
            name: "trusted".into(),
            default_policy: DefaultPolicy::Accept,
            interfaces: Vec::new(),
        },
        Zone {
            name: "block".into(),
            default_policy: DefaultPolicy::Drop,
            interfaces: Vec::new(),
        },
    ]
}

/// Reasonable defaults: an interface with no zone assignment yet
/// (freshly plugged in, not yet activated) is treated as `public` --
/// deny-by-default is the safe failure mode for a device mitosOS
/// doesn't know anything about yet.
pub const DEFAULT_ZONE: &str = "public";
