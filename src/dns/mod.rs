//! DNS configuration management: writing `/etc/resolv.conf`, tracking
//! which active connection contributed which servers, hostname get/set,
//! and a small TTL cache for anything in mitos-network itself that does
//! its own lookups (`connectivity::checker`, mainly).
//!
//! mitos-network does not run a caching resolver of its own -- glibc's
//! resolver (or, if mitosOS ever ships one, `systemd-resolved`'s
//! stub listener) still does the actual DNS protocol work. This module
//! only decides *which servers* end up in `/etc/resolv.conf`.

pub mod cache;
pub mod fallback;
pub mod hostname;
pub mod resolver;
pub mod servers;
