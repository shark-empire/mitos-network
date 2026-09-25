//! System-wide proxy configuration -- what other mitosOS applications
//! (browsers, package tools, `mitos-utils`' network-aware commands)
//! pick up as their default proxy.

pub mod pac;
pub mod proxy;

pub use proxy::{resolve_for_url, ProxyConfig, ProxyMode};
