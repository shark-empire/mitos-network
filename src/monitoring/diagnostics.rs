//! Pulls together a full point-in-time snapshot for `mitos-netctl
//! diagnose` / bug reports: routes, DNS, neighbors, and connectivity in
//! one place, since "what does my network actually look like" bug
//! reports otherwise mean running five different commands by hand.

use crate::connectivity::ConnectivityState;
use crate::dns::resolver::ResolvConf;
use crate::errors::Result;
use crate::ip::neighbor::Neighbor;
use crate::ip::route::Route;
use crate::ip::Family;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub devices: Vec<crate::device::NetworkDevice>,
    pub routes_v4: Vec<RouteSummary>,
    pub routes_v6: Vec<RouteSummary>,
    pub dns: DnsSummary,
    pub neighbors: Vec<NeighborSummary>,
    pub connectivity: ConnectivityState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSummary {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface_index: i32,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSummary {
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborSummary {
    pub ip: String,
    pub mac: Option<String>,
    pub interface_index: i32,
    pub reachable: bool,
}

fn summarize_route(r: &Route) -> RouteSummary {
    RouteSummary {
        destination: r
            .destination
            .map(|(ip, len)| format!("{ip}/{len}"))
            .unwrap_or_else(|| "default".to_string()),
        gateway: r.gateway.map(|g| g.to_string()),
        interface_index: r.oif_index,
        metric: r.metric,
    }
}

fn summarize_neighbor(n: &Neighbor) -> NeighborSummary {
    NeighborSummary {
        ip: n.ip.to_string(),
        mac: n.mac.map(crate::device::mac::format),
        interface_index: n.ifindex,
        reachable: matches!(
            n.state,
            crate::ip::neighbor::NeighborState::Reachable
                | crate::ip::neighbor::NeighborState::Permanent
        ),
    }
}

pub fn collect(
    devices: Vec<crate::device::NetworkDevice>,
    connectivity: ConnectivityState,
) -> Result<DiagnosticReport> {
    let routes_v4 = crate::ip::route::list(Family::V4)?
        .iter()
        .map(summarize_route)
        .collect();
    let routes_v6 = crate::ip::route::list(Family::V6)?
        .iter()
        .map(summarize_route)
        .collect();
    let ResolvConf {
        nameservers,
        search,
    } = crate::dns::resolver::read_current().unwrap_or_default();
    let neighbors = crate::ip::neighbor::list(None)?
        .iter()
        .map(summarize_neighbor)
        .collect();

    Ok(DiagnosticReport {
        devices,
        routes_v4,
        routes_v6,
        dns: DnsSummary {
            nameservers: nameservers.iter().map(|a| a.to_string()).collect(),
            search,
        },
        neighbors,
        connectivity,
    })
}
