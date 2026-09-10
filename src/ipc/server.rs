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
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

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
        | Request::Diagnose => Capability::ViewState,
        Request::AddConnection { .. }
        | Request::DeleteConnection { .. }
        | Request::ActivateConnection { .. }
        | Request::DeactivateConnection { .. } => Capability::ManageConnections,
        Request::ScanWifi { .. } | Request::ConnectWifi { .. } | Request::ForgetWifi { .. } => Capability::ManageWifi,
        Request::StartHotspot { .. } | Request::StopHotspot { .. } => Capability::ManageHotspot,
        Request::SetFirewallZone { .. } | Request::AddFirewallRule { .. } | Request::RemoveFirewallRule { .. } => {
            Capability::ManageFirewall
        }
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

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                crate::logging::logger::warn(&format!("accept() failed: {e}"));
                continue;
            }
        };
        let tx = manager_tx.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle_connection(stream, tx) {
                crate::logging::logger::debug(&format!("connection closed: {e}"));
            }
        });
    }
    Ok(())
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
    let (client_id, event_rx) = reg_rx.recv().map_err(|_| NetworkError::Other("manager did not reply to registration".into()))?;

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

fn request_loop(
    reader: &mut UnixStream,
    writer: &Arc<Mutex<UnixStream>>,
    manager_tx: &Sender<Command>,
    identity: crate::security::PeerIdentity,
) -> Result<()> {
    loop {
        let req: Request = protocol::read_message(reader)?;

        let response = match policy::check(&identity, required_capability(&req)) {
            Ok(()) => {
                let (resp_tx, resp_rx) = std::sync::mpsc::channel();
                manager_tx
                    .send(Command::Request(req, resp_tx))
                    .map_err(|_| NetworkError::Other("manager thread is gone".into()))?;
                resp_rx.recv().unwrap_or_else(|_| super::messages::Response::Error("manager did not reply".into()))
            }
            Err(e) => super::messages::Response::Error(e.to_string()),
        };

        let mut w = writer.lock().unwrap();
        protocol::write_message(&mut *w, &ServerMessage::Response(response))?;
    }
}
