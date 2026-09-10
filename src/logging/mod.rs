//! Daemon logging (stderr / journal) and a separate security audit
//! trail. Deliberately hand-rolled rather than pulling in `tracing` or
//! `log` -- mitos-network's logging needs are simple (leveled lines to
//! stderr, which systemd already timestamps and journals) and this
//! keeps the dependency list short.

pub mod audit;
pub mod logger;
