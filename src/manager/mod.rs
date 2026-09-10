//! The coordinator: owns every other subsystem's runtime state and is
//! the only thing that mutates it. `ipc::server` and `manager::scheduler`
//! are the only things that talk to it, and they do so exclusively by
//! sending `manager::Command`s down a channel -- there is exactly one
//! thread (`NetworkManager::run`'s) that ever touches devices,
//! connections, the firewall, etc., directly. Every other thread in the
//! daemon (per-IPC-connection threads, the scheduler's timers, the
//! netlink hotplug monitor) only ever moves messages, never state --
//! the same "single-threaded core, threads only move bytes" principle
//! `mitos-session` documents for its own architecture.

pub mod events;
pub mod manager;
pub mod scheduler;
pub mod state;

pub use manager::{Command, NetworkManager, TickKind};
pub use state::NetworkState;
