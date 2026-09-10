//! Health/diagnostics surfaces -- the read-only reporting layer
//! `mitos-netctl status`/`diagnose` and `monitoring`-labeled IPC queries
//! draw from. Nothing here changes state; everything here answers
//! "what does the network look like right now".

pub mod diagnostics;
pub mod health;
pub mod signal;
pub mod statistics;
