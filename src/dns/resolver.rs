use crate::config::{DnsConfig, DnsMode};
use crate::errors::Result;
use std::net::IpAddr;
use std::path::Path;

const HEADER: &str = "# Managed by mitos-network -- changes here will be overwritten.\n\
                       # Edit /etc/mitos-network/dns.toml instead.\n";

/// Writes `/etc/resolv.conf` (or wherever `dns.resolv-conf-path` points)
/// from an explicit server/search-domain list. This is the one function
/// every DNS source in the daemon (DHCP leases, static profiles, VPN
/// push-config, manual `dns.toml`) ultimately funnels through, so
/// there's exactly one place that decides the on-disk format.
pub fn apply_static(servers: &[IpAddr], search: &[String]) -> Result<()> {
    apply_to(
        Path::new(crate::config::defaults_resolv_conf_path()),
        servers,
        search,
    )
}

pub fn apply_to(path: &Path, servers: &[IpAddr], search: &[String]) -> Result<()> {
    let mut out = String::from(HEADER);
    if !search.is_empty() {
        out.push_str("search ");
        out.push_str(&search.join(" "));
        out.push('\n');
    }
    for s in servers {
        out.push_str(&format!("nameserver {s}\n"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("mitos-tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Applies whatever `dns.toml` says even when no active connection
/// supplied servers of its own -- covers `DnsMode::Manual` (always use
/// these, ignore DHCP) and the fallback path when nothing else has run yet.
pub fn apply_from_config(cfg: &DnsConfig) -> Result<()> {
    match cfg.mode {
        DnsMode::None => Ok(()),
        DnsMode::Manual => {
            let servers: Vec<IpAddr> = cfg.servers.iter().filter_map(|s| s.parse().ok()).collect();
            apply_to(
                Path::new(&cfg.resolv_conf_path),
                &servers,
                &cfg.search_domains,
            )
        }
        DnsMode::Auto => Ok(()), // left for whichever connection activates to populate
    }
}

#[derive(Debug, Default)]
pub struct ResolvConf {
    pub nameservers: Vec<IpAddr>,
    pub search: Vec<String>,
}

/// Reads back the currently-installed resolv.conf -- used by
/// `monitoring::diagnostics` ("what DNS servers is this box actually
/// using right now?").
pub fn read_current() -> Result<ResolvConf> {
    let text = std::fs::read_to_string(crate::config::defaults_resolv_conf_path())?;
    let mut out = ResolvConf::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("nameserver ") {
            if let Ok(ip) = rest.trim().parse() {
                out.nameservers.push(ip);
            }
        } else if let Some(rest) = line.strip_prefix("search ") {
            out.search = rest.split_whitespace().map(String::from).collect();
        }
    }
    Ok(out)
}
