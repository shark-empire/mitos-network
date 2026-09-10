//! Route selection policy on top of `ip::route`: which interface's
//! default route wins when several are up at once (Ethernet + Wi-Fi +
//! a VPN is the everyday case), and what metric a newly-activated
//! connection should get.

pub mod default_route;
pub mod metrics;
pub mod policy;
pub mod router;
