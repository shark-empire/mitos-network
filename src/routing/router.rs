//! A read-only, merged view of the routing table -- what
//! `mitos-netctl route show` and `monitoring::diagnostics` query.

use crate::errors::Result;
use crate::ip::route::Route;
use crate::ip::Family;
use std::net::IpAddr;

pub fn current(family: Family) -> Result<Vec<Route>> {
    crate::ip::route::list(family)
}

/// The route the kernel would actually pick for "the" default gateway:
/// the default route with the lowest metric, for the given family.
pub fn active_default_gateway(family: Family) -> Result<Option<(IpAddr, i32)>> {
    let routes = current(family)?;
    Ok(routes
        .into_iter()
        .filter(|r| r.destination.is_none() && r.gateway.is_some())
        .min_by_key(|r| r.metric.unwrap_or(u32::MAX))
        .map(|r| (r.gateway.unwrap(), r.oif_index)))
}
