//! Performs the actual HTTP check. A minimal hand-rolled HTTP/1.1
//! client over a plain `TcpStream` -- deliberately HTTP, not HTTPS: a
//! captive portal has to intercept plain HTTP to redirect it, which is
//! exactly the behavior this needs to detect, and every mainstream OS's
//! own connectivity-check endpoint is plain HTTP for the same reason.
//! Not a general-purpose HTTP client (no chunked transfer-encoding, no
//! keep-alive) -- it only needs to read one status line and an
//! optional `Location:` header.

use super::captive_portal;
use super::internet::ConnectivityState;
use crate::errors::{NetworkError, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const EXPECTED_STATUS: u16 = 204;

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        NetworkError::Config(format!("connectivity check URL '{url}' must be plain http://"))
    })?;
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, "/".to_string()));
    let (host, port) = authority.split_once(':').map(|(h, p)| (h, p.parse().unwrap_or(80))).unwrap_or((authority, 80));
    Ok(ParsedUrl { host: host.to_string(), port, path })
}

pub fn check(url: &str, timeout: Duration) -> Result<ConnectivityState> {
    let parsed = match parse_url(url) {
        Ok(p) => p,
        Err(_) => return Ok(ConnectivityState::Unknown),
    };

    let addr = format!("{}:{}", parsed.host, parsed.port);
    let mut stream = match std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| NetworkError::Dns(format!("could not resolve {}", parsed.host)))
        .and_then(|sock_addr| TcpStream::connect_timeout(&sock_addr, timeout).map_err(NetworkError::from))
    {
        Ok(s) => s,
        Err(_) => return Ok(ConnectivityState::None),
    };
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: mitos-network/0.1\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return Ok(ConnectivityState::None);
    }

    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() && response.is_empty() {
        return Ok(ConnectivityState::None);
    }

    let text = String::from_utf8_lossy(&response);
    let Some(status_line) = text.lines().next() else {
        return Ok(ConnectivityState::None);
    };
    // "HTTP/1.1 204 No Content"
    let Some(status) = status_line.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()) else {
        return Ok(ConnectivityState::None);
    };
    let has_location = text.lines().any(|l| l.to_ascii_lowercase().starts_with("location:"));

    Ok(captive_portal::classify(status, EXPECTED_STATUS, has_location))
}
