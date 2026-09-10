//! Internet reachability checking: is there a route to the internet at
//! all, and if so, is it actually open (vs. a captive portal
//! intercepting everything).

pub mod captive_portal;
pub mod checker;
pub mod internet;

pub use internet::ConnectivityState;
