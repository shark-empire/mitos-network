//! Periodic timers, each just a thread that sleeps and sends a
//! `Command::Tick` -- no generic closure-based job scheduler, since the
//! full set of periodic jobs this daemon runs is small, fixed, and
//! known at compile time.

use super::manager::{Command, TickKind};
use std::sync::mpsc::Sender;
use std::time::Duration;

pub struct SchedulerHandle {
    _threads: Vec<std::thread::JoinHandle<()>>,
}

fn spawn_tick(tx: Sender<Command>, interval: Duration, kind: TickKind, name: &str) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || loop {
            std::thread::sleep(interval);
            if tx.send(Command::Tick(kind)).is_err() {
                return; // manager shut down
            }
        })
        .expect("failed to spawn scheduler thread")
}

pub fn start(tx: Sender<Command>, connectivity_interval: Duration, wifi_scan_interval: Duration) -> SchedulerHandle {
    let threads = vec![
        spawn_tick(tx.clone(), connectivity_interval, TickKind::Connectivity, "mitos-net-sched-conn"),
        spawn_tick(tx.clone(), wifi_scan_interval, TickKind::WifiScan, "mitos-net-sched-wifi"),
        spawn_tick(tx.clone(), Duration::from_secs(30), TickKind::LeaseCheck, "mitos-net-sched-lease"),
        spawn_tick(tx, Duration::from_secs(5), TickKind::DeviceRefresh, "mitos-net-sched-refresh"),
    ];
    SchedulerHandle { _threads: threads }
}
