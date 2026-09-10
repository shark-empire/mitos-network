//! On-disk persistence: connection profiles (`data/profiles/*.toml`),
//! DHCP leases, and other small bits of runtime state that need to
//! survive a daemon restart (which interface had which lease, so a
//! restart doesn't force an immediate re-DHCP on every device).

pub mod database;
pub mod profiles;
pub mod state;
