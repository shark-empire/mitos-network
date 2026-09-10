use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    pub fn nft_name(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortSpec {
    pub start: u16,
    /// `None` for a single port; `Some(end)` for an inclusive range.
    pub end: Option<u16>,
}

impl PortSpec {
    pub fn single(port: u16) -> Self {
        PortSpec { start: port, end: None }
    }

    pub fn nft_expr(&self) -> String {
        match self.end {
            Some(end) => format!("{}-{}", self.start, end),
            None => self.start.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub zone: String,
    pub direction: Direction,
    pub action: Action,
    #[serde(default)]
    pub protocol: Option<Protocol>,
    #[serde(default)]
    pub port: Option<PortSpec>,
    /// Source address/CIDR restriction, e.g. `"192.168.1.0/24"`.
    #[serde(default)]
    pub source: Option<String>,
}

impl Rule {
    /// Allow inbound TCP or UDP to `port` within `zone` -- the common
    /// "let this app receive connections" request.
    pub fn allow_inbound_port(id: impl Into<String>, zone: impl Into<String>, protocol: Protocol, port: u16) -> Self {
        Rule {
            id: id.into(),
            zone: zone.into(),
            direction: Direction::Inbound,
            action: Action::Accept,
            protocol: Some(protocol),
            port: Some(PortSpec::single(port)),
            source: None,
        }
    }
}
