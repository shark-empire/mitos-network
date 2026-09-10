//! Firewall management: a small zone/rule model (`zones`, `rules`)
//! rendered down to an `nftables` ruleset (`nftables`) and applied via
//! the `nft` binary.
//!
//! Deliberately shells out to `nft` rather than speaking `NFNETLINK`
//! directly -- unlike `NETLINK_ROUTE` (this crate's own `ip::netlink`),
//! nftables' netlink protocol carries a bytecode-like rule
//! representation that the `nft` binary itself compiles from syntax;
//! reimplementing that compiler is a much larger undertaking than the
//! rest of this crate's netlink usage, and `nft -f <file>` is exactly
//! the interface nftables' own upstream documents for programmatic use.

pub mod firewall;
pub mod nftables;
pub mod rules;
pub mod zones;

pub use firewall::Firewall;
pub use rules::{Action, Direction, Protocol, Rule};
pub use zones::Zone;
