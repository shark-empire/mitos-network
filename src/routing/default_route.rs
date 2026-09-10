//! Installing "the" default route for a newly-activated connection.

use crate::errors::Result;
use crate::ip::route::{self, RouteProtocol};
use crate::ip::Family;
use std::net::IpAddr;

/// Replaces any existing default route *for this address family* with
/// one via `gateway` on `oif_index`. Doesn't touch the other family's
/// default route (a v4 activation shouldn't clobber an existing v6
/// default and vice versa) or other interfaces' routes -- multi-uplink
/// preference is expressed entirely through `metric`
/// (`routing::metrics`), letting the kernel's own route selection
/// handle which one is actually used.
pub fn apply(oif_index: i32, gateway: IpAddr, metric: u32, protocol: RouteProtocol) -> Result<()> {
    let family = Family::of(gateway);
    for existing in route::list(family)? {
        if existing.destination.is_none() && existing.oif_index == oif_index {
            let _ = route::del(&existing);
        }
    }
    route::set_default(oif_index, gateway, metric, protocol)
}

pub fn remove(oif_index: i32, family: Family) -> Result<()> {
    for existing in route::list(family)? {
        if existing.destination.is_none() && existing.oif_index == oif_index {
            route::del(&existing)?;
        }
    }
    Ok(())
}
