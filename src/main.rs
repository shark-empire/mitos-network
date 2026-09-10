//! mitos-network daemon entry point: load config, build the manager,
//! wire up its three input sources (IPC requests, the netlink hotplug
//! monitor, and the scheduler's timers), and run.

use mitos_network::manager::{Command, NetworkManager};
use mitos_network::{config, device, ipc, logging, manager};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_sig: libc::c_int) {
    // Async-signal-safe: only touches a `static` atomic, nothing else.
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    // SAFETY: `handle_termination_signal` only performs an atomic
    // store, which is on the short list of operations POSIX guarantees
    // are safe to do from a signal handler.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_termination_signal as libc::sighandler_t,
        );
    }
}

fn print_usage() {
    println!("mitos-network {}", env!("CARGO_PKG_VERSION"));
    println!("Usage: mitos-network [--config-dir <path>] [--version] [--help]");
}

fn main() {
    let mut config_dir = std::path::PathBuf::from(config::defaults_config_dir());
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config-dir" => {
                if let Some(v) = args.next() {
                    config_dir = std::path::PathBuf::from(v);
                } else {
                    eprintln!("--config-dir requires a path argument");
                    std::process::exit(2);
                }
            }
            "--version" => {
                println!("mitos-network {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" => {
                print_usage();
                return;
            }
            other => {
                eprintln!("unrecognized argument: {other}");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    let cfg = match config::load(&config_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "failed to load configuration from {}: {e}",
                config_dir.display()
            );
            std::process::exit(1);
        }
    };

    install_signal_handlers();

    let socket_path = cfg.general.socket_path.clone();
    let connectivity_interval =
        Duration::from_secs(cfg.general.connectivity_check_interval_secs.max(5));
    let wifi_scan_interval = Duration::from_secs(cfg.wireless.scan_interval_secs.max(10));

    let manager = match NetworkManager::new(cfg) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to initialize network manager: {e}");
            std::process::exit(1);
        }
    };

    let (tx, rx) = mpsc::channel::<Command>();

    // IPC server: its own thread, blocking on accept() forever.
    {
        let tx = tx.clone();
        let socket_path = socket_path.clone();
        std::thread::spawn(move || {
            if let Err(e) = ipc::server::serve(&socket_path, tx) {
                eprintln!("IPC server exited: {e}");
                std::process::exit(1);
            }
        });
    }

    // Hotplug monitor: forwards netlink link/address change
    // notifications as `Command::Hotplug`. The monitor itself only
    // knows about `HotplugEvent`s (see `device::discovery`); this small
    // relay is what turns those into manager `Command`s.
    {
        let (hotplug_tx, hotplug_rx) = mpsc::channel();
        match device::discovery::spawn_monitor(hotplug_tx) {
            Ok(_handle) => {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for ev in hotplug_rx.iter() {
                        if tx.send(Command::Hotplug(ev)).is_err() {
                            return;
                        }
                    }
                });
            }
            Err(e) => logging::logger::warn(&format!("could not start hotplug monitor: {e}")),
        }
    }

    // Scheduler: periodic connectivity checks, Wi-Fi scans, DHCP
    // renewal checks, and a fallback device-state poll.
    let _scheduler =
        manager::scheduler::start(tx.clone(), connectivity_interval, wifi_scan_interval);

    // Watches the signal-handler flag and asks the manager to shut down
    // cleanly, rather than doing anything non-signal-safe in the
    // handler itself.
    {
        let tx = tx.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(200));
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                let _ = tx.send(Command::Shutdown);
                return;
            }
        });
    }

    manager.run(rx);
}
