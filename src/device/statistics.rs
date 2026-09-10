//! Per-interface traffic counters, read from `/sys/class/net/<name>/statistics/*`.
//! This is the same source `ip -s link` uses, so numbers here should
//! always match what a user sees from the regular Linux tools.

use crate::errors::Result;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct DeviceStatistics {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

fn read_counter(name: &str, counter: &str) -> u64 {
    let path = Path::new("/sys/class/net").join(name).join("statistics").join(counter);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn read(name: &str) -> Result<DeviceStatistics> {
    Ok(DeviceStatistics {
        rx_bytes: read_counter(name, "rx_bytes"),
        tx_bytes: read_counter(name, "tx_bytes"),
        rx_packets: read_counter(name, "rx_packets"),
        tx_packets: read_counter(name, "tx_packets"),
        rx_errors: read_counter(name, "rx_errors"),
        tx_errors: read_counter(name, "tx_errors"),
        rx_dropped: read_counter(name, "rx_dropped"),
        tx_dropped: read_counter(name, "tx_dropped"),
    })
}

/// Point-in-time delta between two samples -- what `monitoring::statistics`
/// actually graphs (instantaneous throughput, not the lifetime counter).
pub fn delta(prev: &DeviceStatistics, cur: &DeviceStatistics) -> DeviceStatistics {
    DeviceStatistics {
        rx_bytes: cur.rx_bytes.saturating_sub(prev.rx_bytes),
        tx_bytes: cur.tx_bytes.saturating_sub(prev.tx_bytes),
        rx_packets: cur.rx_packets.saturating_sub(prev.rx_packets),
        tx_packets: cur.tx_packets.saturating_sub(prev.tx_packets),
        rx_errors: cur.rx_errors.saturating_sub(prev.rx_errors),
        tx_errors: cur.tx_errors.saturating_sub(prev.tx_errors),
        rx_dropped: cur.rx_dropped.saturating_sub(prev.rx_dropped),
        tx_dropped: cur.tx_dropped.saturating_sub(prev.tx_dropped),
    }
}
