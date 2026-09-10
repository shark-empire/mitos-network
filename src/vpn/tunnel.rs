//! Generic (non-VPN-specific) tunnel interfaces: GRE, IPIP, SIT
//! (6-in-4), VXLAN. Thin wrappers over `ip::interface::create_virtual`
//! -- the kernel implements every one of these tunnel types natively,
//! rtnetlink just needs to be told which kind to create.

use crate::errors::Result;

#[derive(Debug, Clone, Copy)]
pub enum TunnelKind {
    Gre,
    Ipip,
    Sit,
    Vxlan,
}

impl TunnelKind {
    fn link_kind(self) -> &'static str {
        match self {
            TunnelKind::Gre => "gre",
            TunnelKind::Ipip => "ipip",
            TunnelKind::Sit => "sit",
            TunnelKind::Vxlan => "vxlan",
        }
    }
}

pub fn create(name: &str, kind: TunnelKind) -> Result<()> {
    crate::security::validation::validate_interface_name(name)?;
    crate::ip::interface::create_virtual(name, kind.link_kind())
}

pub fn destroy(name: &str) -> Result<()> {
    let iface = crate::ip::interface::get_by_name(name)?;
    crate::ip::interface::delete(iface.index)
}
