//! Traffic-rate sampling across every managed device -- point-in-time
//! throughput, not lifetime counters (see `device::statistics::delta`).

use crate::device::statistics::{self, DeviceStatistics};
use crate::errors::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateSampler {
    last: HashMap<String, (Instant, DeviceStatistics)>,
}

impl Default for RateSampler {
    fn default() -> Self {
        RateSampler { last: HashMap::new() }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Rates {
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

impl RateSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Call periodically (the scheduler tick is the natural cadence);
    /// the first sample for a given device always returns zero rates
    /// since there's nothing to diff against yet.
    pub fn sample(&mut self, ifname: &str) -> Result<Rates> {
        let now = Instant::now();
        let current = statistics::read(ifname)?;
        let rates = match self.last.get(ifname) {
            Some((prev_time, prev_stats)) => {
                let elapsed = now.duration_since(*prev_time).as_secs_f64().max(0.001);
                let d = statistics::delta(prev_stats, &current);
                Rates { rx_bytes_per_sec: d.rx_bytes as f64 / elapsed, tx_bytes_per_sec: d.tx_bytes as f64 / elapsed }
            }
            None => Rates::default(),
        };
        self.last.insert(ifname.to_string(), (now, current));
        Ok(rates)
    }
}

/// Keeps `RateSampler` entries fresh: drop any device not seen for a
/// while (unplugged, deleted) so this doesn't grow unbounded across a
/// long-running daemon's lifetime.
pub fn prune_stale(sampler: &mut RateSampler, max_age: Duration) {
    let now = Instant::now();
    sampler.last.retain(|_, (t, _)| now.duration_since(*t) < max_age);
}
