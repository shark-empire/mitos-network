//! Auto-negotiation policy.
//!
//! mitosOS deliberately never forces a specific speed/duplex -- that's
//! a niche, mistake-prone knob (mismatched forced settings between two
//! ends of a link is a classic cause of silently-terrible throughput)
//! that a general-purpose consumer OS has no business exposing by
//! default. `ethernet::link::link_settings` reports whether autoneg is
//! active purely as read-only diagnostic information; there is no
//! `set_speed`/`force_duplex` function here to call, on purpose.

use super::link::LinkSettings;

/// A human-readable one-liner for `mitos-netctl device show`, e.g.
/// `"1000 Mbps, full duplex (auto-negotiated)"`.
pub fn describe(settings: &LinkSettings) -> String {
    let speed = settings
        .speed_mbps
        .map(|s| format!("{s} Mbps"))
        .unwrap_or_else(|| "unknown speed".to_string());
    let duplex = if settings.full_duplex {
        "full duplex"
    } else {
        "half duplex"
    };
    let neg = if settings.autoneg {
        "auto-negotiated"
    } else {
        "fixed"
    };
    format!("{speed}, {duplex} ({neg})")
}
