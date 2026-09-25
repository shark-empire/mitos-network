//! Accepts connections on the Unix socket and turns each one into
//! `manager::Command`s sent down a single channel to the manager's own
//! thread. Every function in this file only ever touches sockets and
//! channels -- no device/connection/firewall state lives here.

use super::messages::{Request, ServerMessage};
use super::{permissions, protocol};
use crate::errors::{NetworkError, Result};
use crate::manager::Command;
use crate::security::policy::{self, Capability};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

/// Caps how many IPC connections can be open at once. The socket is
/// world-connectable (see the `0o666` below), so without a cap, any
/// local user -- authenticated for exactly zero capabilities -- could
/// open connections in a loop and hold them open, each one costing a
/// thread, forever. 128 is far more than any real desktop ever has at
/// once (a shell prompt, a panel applet, an occasional `mitos-netctl`
/// call) while keeping the worst case small and fixed.
const MAX_CONNECTIONS: usize = 128;

/// Request handling here is shallow -- parse JSON, send one channel
/// message, wait for the reply, write JSON back -- with no deep
/// recursion, so the 8 MiB default thread stack is almost entirely
/// wasted. At the connection cap above, this bounds worst-case stack
/// memory for the whole IPC layer to `MAX_CONNECTIONS *
/// CONNECTION_STACK_SIZE` (32 MiB) instead of up to `MAX_CONNECTIONS *
/// 8 MiB` (1 GiB).
const CONNECTION_STACK_SIZE: usize = 256 * 1024;

/// Which `Capability` a given `Request` needs -- kept here (not in
/// `security::policy`) since it's really about *this* protocol's
/// specific requests, not a general security concept.
fn required_capability(req: &Request) -> Capability {
    match req {
        Request::GetState
        | Request::ListDevices
        | Request::GetDevice { .. }
        | Request::ListConnections
        | Request::GetConnection { .. }
        | Request::ListWifiNetworks { .. }
        | Request::GetConnectivity
        | Request::ListBluetoothDevices
        | Request::GetProxyConfig
        | Request::ResolveProxy { .. }
        | Request::Diagnose => Capability::ViewState,
        Request::AddConnection { .. }
        | Request::DeleteConnection { .. }
        | Request::ActivateConnection { .. }
        | Request::DeactivateConnection { .. } => Capability::ManageConnections,
        Request::ScanWifi { .. } | Request::ConnectWifi { .. } | Request::ForgetWifi { .. } => {
            Capability::ManageWifi
        }
        Request::StartHotspot { .. } | Request::StopHotspot { .. } => Capability::ManageHotspot,
        Request::SetFirewallZone { .. }
        | Request::AddFirewallRule { .. }
        | Request::RemoveFirewallRule { .. } => Capability::ManageFirewall,
        Request::BluetoothPower { .. }
        | Request::BluetoothScan { .. }
        | Request::PairBluetooth { .. }
        | Request::TrustBluetooth { .. }
        | Request::ConnectBluetooth { .. }
        | Request::DisconnectBluetooth { .. }
        | Request::RemoveBluetooth { .. } => Capability::ManageBluetooth,
        Request::SetProxyConfig { .. } => Capability::ManageProxy,
        Request::Reload => Capability::Admin,
    }
}

pub fn serve(socket_path: &str, manager_tx: Sender<Command>) -> Result<()> {
    let path = std::path::Path::new(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path); // stale socket from a previous, uncleanly-stopped run

    let listener = UnixListener::bind(path)?;
    // Socket-level permissions are the outer gate (anyone who can't
    // even open the socket can't be a peer at all); `security::policy`
    // is the finer-grained per-request gate on top.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    }
    crate::logging::logger::info(&format!("listening on {socket_path}"));

    let active_connections = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                crate::logging::logger::warn(&format!("accept() failed: {e}"));
                continue;
            }
        };

        // See `MAX_CONNECTIONS`: claim a slot first and only proceed
        // if that claim landed under the cap, so concurrent accepts
        // can never collectively overshoot it.
        let prior = active_connections.fetch_add(1, Ordering::SeqCst);
        if prior >= MAX_CONNECTIONS {
            active_connections.fetch_sub(1, Ordering::SeqCst);
            crate::logging::logger::warn("IPC connection cap reached, refusing a new connection");
            continue; // dropping `stream` here closes it
        }

        let tx = manager_tx.clone();
        let counter = active_connections.clone();
        let spawned = std::thread::Builder::new()
            .name("mitos-net-ipc-conn".into())
            .stack_size(CONNECTION_STACK_SIZE)
            .spawn(move || {
                let _slot = ConnectionSlot(counter);
                if let Err(e) = handle_connection(stream, tx) {
                    crate::logging::logger::debug(&format!("connection closed: {e}"));
                }
            });
        if let Err(e) = spawned {
            active_connections.fetch_sub(1, Ordering::SeqCst);
            crate::logging::logger::warn(&format!("failed to spawn connection handler: {e}"));
        }
    }
    Ok(())
}

/// Releases this connection's slot in `active_connections` when the
/// handler thread ends, including via a panic, so one misbehaving
/// connection can't also permanently shrink the cap for everyone
/// after it.
struct ConnectionSlot(Arc<AtomicUsize>);
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_connection(stream: UnixStream, manager_tx: Sender<Command>) -> Result<()> {
    let identity = permissions::peer_identity(&stream)?;
    let writer = Arc::new(Mutex::new(stream.try_clone()?));

    // Register for events up front; every connection implicitly
    // receives them regardless of whether it ever issues a request.
    let (reg_tx, reg_rx) = std::sync::mpsc::channel();
    manager_tx
        .send(Command::RegisterEventClient(reg_tx))
        .map_err(|_| NetworkError::Other("manager thread is gone".into()))?;
    let (client_id, event_rx) = reg_rx
        .recv()
        .map_err(|_| NetworkError::Other("manager did not reply to registration".into()))?;

    let event_writer = writer.clone();
    let event_thread = std::thread::spawn(move || {
        for ev in event_rx.iter() {
            let msg = ServerMessage::Event(ev);
            let mut w = event_writer.lock().unwrap();
            if protocol::write_message(&mut *w, &msg).is_err() {
                return;
            }
        }
    });

    let mut reader = stream;
    let result = request_loop(&mut reader, &writer, &manager_tx, identity);

    let _ = manager_tx.send(Command::UnregisterEventClient(client_id));
    drop(writer); // closes the write half so event_thread's next write fails and it exits
    let _ = event_thread.join();
    result
}

/// Per-connection request rate limit: independent of `MAX_CONNECTIONS`
/// (which bounds how many connections exist at all), this bounds how
/// much of the single-threaded manager's attention any *one* of them
/// can monopolize. 50/sec is far beyond any real client's needs
/// (`mitos-netctl` issues one request per invocation; even a
/// GUI polling for state changes has no reason to exceed a handful per
/// second) while still being generous enough that legitimate bursts
/// never notice it.
const MAX_REQUESTS_PER_SEC: u32 = 50;

fn request_loop(
    reader: &mut UnixStream,
    writer: &Arc<Mutex<UnixStream>>,
    manager_tx: &Sender<Command>,
    identity: crate::security::PeerIdentity,
) -> Result<()> {
    let mut window_start = std::time::Instant::now();
    let mut window_count: u32 = 0;
    loop {
        let req: Request = protocol::read_message(reader)?;

        // Fixed-window throttle: reset the count once a second has
        // elapsed; once over budget within a window, slow the offending
        // connection down (rather than dropping it) so a legitimate
        // burst degrades gracefully instead of erroring out.
        if window_start.elapsed() >= std::time::Duration::from_secs(1) {
            window_start = std::time::Instant::now();
            window_count = 0;
        }
        window_count += 1;
        if window_count > MAX_REQUESTS_PER_SEC {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let response = match policy::check(&identity, required_capability(&req)) {
            Ok(()) => {
                let (resp_tx, resp_rx) = std::sync::mpsc::channel();
                manager_tx
                    .send(Command::Request(req, identity, resp_tx))
                    .map_err(|_| NetworkError::Other("manager thread is gone".into()))?;
                resp_rx.recv().unwrap_or_else(|_| {
                    super::messages::Response::Error("manager did not reply".into())
                })
            }
            Err(e) => super::messages::Response::Error(e.to_string()),
        };

        let mut w = writer.lock().unwrap();
        protocol::write_message(&mut *w, &ServerMessage::Response(response))?;
    }
}
