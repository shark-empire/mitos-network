//! Policy (source-based) routing: gives a connection its own routing
//! table via a FIB rule, so its routes don't have to fight the main
//! table's for priority. The main use case is a split-tunnel VPN --
//! only that connection's assigned source address should follow its
//! routes, everything else keeps using the main table untouched.

use crate::errors::Result;
use crate::ip::route::{self, Route};
use std::net::IpAddr;

/// Route table ids 1-252 are free for use (0, 253-255 are reserved --
/// see `<linux/rt_scope.h>`/`<linux/fib_rules.h>`); mitos-network claims
/// a small private range starting at 100 for per-connection tables so
/// collisions with anything else on the box are unlikely.
const TABLE_RANGE_START: u8 = 100;

pub fn table_for(connection_index: u8) -> u8 {
    TABLE_RANGE_START.saturating_add(connection_index)
}

/// Installs a policy-routing table for `src` (the address the
/// connection was assigned) pointing at `routes`, and a FIB rule
/// sending that source's traffic there.
pub fn install(src: IpAddr, table: u8, priority: u32, routes: &[Route]) -> Result<()> {
    for r in routes {
        route::add_to_table(r, table)?;
    }
    let prefixlen = if src.is_ipv4() { 32 } else { 128 };
    route::add_source_rule(src, prefixlen, table, priority)?;
    Ok(())
}

pub fn remove(src: IpAddr, table: u8, priority: u32, routes: &[Route]) -> Result<()> {
    let prefixlen = if src.is_ipv4() { 32 } else { 128 };
    let _ = route::del_source_rule(src, prefixlen, table, priority);
    for r in routes {
        let _ = route::del(r); // best-effort: the whole table is orphaned once the rule is gone anyway
    }
    Ok(())
}
