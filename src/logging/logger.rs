use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Called once from `main` after config is loaded (`general.log-level`).
pub fn set_level(name: &str) {
    let lvl = match name {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "debug" | "trace" => Level::Debug,
        _ => Level::Info,
    };
    MIN_LEVEL.store(lvl as u8, Ordering::Relaxed);
}

fn enabled(level: Level) -> bool {
    (level as u8) <= MIN_LEVEL.load(Ordering::Relaxed)
}

fn log(level: Level, msg: &str) {
    if !enabled(level) {
        return;
    }
    let tag = match level {
        Level::Error => "ERROR",
        Level::Warn => "WARN",
        Level::Info => "INFO",
        Level::Debug => "DEBUG",
    };
    // systemd/journald timestamps every line itself when running as a
    // service unit, so we don't duplicate a wall-clock prefix here --
    // running under a plain terminal during development just gets bare
    // "[LEVEL] message" lines, which is what mitos-netctl also expects
    // to see when it tails the daemon's stderr directly.
    eprintln!("[{tag}] {msg}");
}

pub fn error(msg: &str) {
    log(Level::Error, msg);
}
pub fn warn(msg: &str) {
    log(Level::Warn, msg);
}
pub fn info(msg: &str) {
    log(Level::Info, msg);
}
pub fn debug(msg: &str) {
    log(Level::Debug, msg);
}
