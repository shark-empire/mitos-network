//! OpenVPN client: unlike WireGuard, OpenVPN has no simple netlink
//! surface at all -- TLS handshake, TUN device creation, and routing
//! are all handled internally by the `openvpn` binary itself. Every
//! mainstream network manager's OpenVPN plugin works the same way this
//! does: generate/locate a config file, spawn `openvpn`, track the
//! process.
//!
//! Tracking goes through OpenVPN's own management interface (a
//! line-based text protocol over a socket -- see OpenVPN's
//! `management-notes.txt`) rather than just holding a `Child` handle:
//! `--daemon` re-execs openvpn into the background, so a bare `Child`
//! only ever proves "spawning succeeded", not which process is
//! actually running the tunnel, what its real tun/tap device name is,
//! or whether it's still connected. This crate binds the management
//! socket itself and passes `--management-client` so openvpn connects
//! *out* to us (avoiding a race against polling for a socket file
//! openvpn hasn't created yet), then reads the live `>STATE:` event
//! feed and a tiny `--up` script's output (openvpn's own, official way
//! of reporting which device name it picked) to get real status and
//! the real interface name.

use crate::errors::{NetworkError, Result};
use crate::security::secrets::SecretsBackend;
use crate::vpn::vpn::{VpnKind, VpnSession};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

struct Session {
    child: Child,
    management: UnixStream,
    workdir: PathBuf,
    status: Arc<Mutex<SessionStatus>>,
}

/// Live status a running session's background reader keeps updated --
/// available to other parts of the daemon (IPC status queries, a
/// future `netctl vpn status`) via [`status`], not just used
/// internally.
#[derive(Debug, Default, Clone)]
pub struct SessionStatus {
    /// The last `>STATE:` value seen (`"CONNECTING"`, `"CONNECTED"`,
    /// `"RECONNECTING"`, ...) -- OpenVPN's own state names, passed
    /// through rather than remapped, since callers displaying this
    /// likely want to show OpenVPN's own vocabulary.
    pub state: String,
    /// The tun/tap device openvpn actually picked, once known (from
    /// the `--up` script's output, not guessed).
    pub ifname: Option<String>,
}

static SESSIONS: Mutex<Option<HashMap<String, Session>>> = Mutex::new(None);

/// `config` is a filesystem path to an existing `.ovpn` file (the file
/// itself is not a secret -- it's the certs/keys or auth credentials
/// *inside* it that are, and username/password auth is handled below
/// via a separately-supplied secret rather than embedding it in the file).
pub fn connect(
    config_path: &str,
    secrets: &dyn SecretsBackend,
    profile_id: &str,
) -> Result<VpnSession> {
    if !Path::new(config_path).is_file() {
        return Err(NetworkError::Vpn(format!(
            "OpenVPN config '{config_path}' not found"
        )));
    }

    let workdir = crate::security::tempfile::create_secret_temp_dir("mitos-ovpn")?;
    let cleanup_workdir = |workdir: &Path| {
        let _ = std::fs::remove_dir_all(workdir);
    };

    let mgmt_sock_path = workdir.join("mgmt.sock");
    let ifname_file = workdir.join("ifname");
    let up_script = workdir.join("up.sh");
    let down_script = workdir.join("down.sh");

    // OpenVPN's `--up`/`--down` scripts are its own, official way of
    // reporting which tun/tap device it picked (via the `$dev`
    // environment variable they're called with) -- simpler and more
    // reliable than trying to infer it from log output, and unlike the
    // management interface's own `>STATE:` line, `$dev` is exactly the
    // device name and nothing else.
    if let Err(e) = write_script(
        &up_script,
        &format!("#!/bin/sh\numask 077\nprintf '%s' \"$dev\" > '{}'\n", ifname_file.display()),
    )
    .and_then(|_| {
        write_script(&down_script, &format!("#!/bin/sh\n: > '{}'\n", ifname_file.display()))
    }) {
        cleanup_workdir(&workdir);
        return Err(e);
    }

    let listener = UnixListener::bind(&mgmt_sock_path).map_err(|e| {
        cleanup_workdir(&workdir);
        NetworkError::Vpn(format!("binding management socket: {e}"))
    })?;

    let mut cmd = Command::new("openvpn");
    cmd.arg("--config").arg(config_path);

    // Optional username/password auth (`auth-user-pass` in the .ovpn
    // file pointing at a file we generate here). OpenVPN has no stdin
    // or fd-based way to supply this -- `--auth-user-pass` with no
    // argument reads from the *controlling terminal*, not stdin, and
    // fails outright with no tty attached (as any daemon has none) --
    // so a temp file is the only option. The path is unpredictable and
    // opened with `create_new` (0600 applied atomically at creation)
    // so another local user can't win a race by pre-placing a symlink
    // at a guessed path; see `security::tempfile`.
    //
    // Deliberately NOT passing `--auth-nocache` here: combined with
    // `--auth-user-pass <file>`, OpenVPN has a long-standing bug where
    // a later TLS renegotiation re-reads credentials from the
    // controlling terminal instead of the file, which fails the same
    // way and silently drops the tunnel on its first `reneg-sec`
    // rollover. Every mainstream OS's OpenVPN integration leaves the
    // credentials cached in openvpn's own process memory for the
    // session for this reason; that's an acceptable tradeoff for a
    // long-running root daemon that isn't being ptraced.
    let mut userpass_path = None;
    if let (Some(user), Some(pass)) = (
        secrets.get(profile_id, "auth-username")?,
        secrets.get(profile_id, "auth-password")?,
    ) {
        let (path, mut f) =
            crate::security::tempfile::create_secret_temp_file("mitos-ovpn", "auth")?;
        writeln!(f, "{user}")?;
        writeln!(f, "{pass}")?;
        drop(f);
        cmd.arg("--auth-user-pass").arg(&path);
        userpass_path = Some(path);
    }

    cmd.arg("--management")
        .arg(&mgmt_sock_path)
        .arg("unix")
        // We bind-and-listen first specifically so openvpn can connect
        // *out* to us as soon as it starts, instead of us polling for
        // a socket file it hasn't created yet.
        .arg("--management-client")
        // Required for `--up`/`--down` user scripts to run at all --
        // wpa_supplicant-style "off by default" script execution.
        .arg("--script-security")
        .arg("2")
        .arg("--up")
        .arg(&up_script)
        .arg("--up-restart")
        .arg("--down")
        .arg(&down_script)
        .arg("--daemon")
        .arg(format!("mitos-openvpn-{profile_id}"));

    let child = cmd.spawn().map_err(|e| {
        cleanup_workdir(&workdir);
        NetworkError::Vpn(format!("failed to spawn openvpn: {e}"))
    });
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Err(e),
    };

    if let Some(path) = userpass_path {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(5));
            let _ = std::fs::remove_file(&path);
        });
    }

    let stream = match accept_with_timeout(&listener, Duration::from_secs(15)) {
        Ok(s) => s,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_workdir(&workdir);
            return Err(e);
        }
    };
    // One connection is all we expect (openvpn, once); stop listening
    // and remove the now-pointless socket path.
    drop(listener);
    let _ = std::fs::remove_file(&mgmt_sock_path);

    // Live-state notifications are opt-in over the management
    // protocol; without `state on`, the only state line we'd ever see
    // is a one-shot reply to an explicit `state` query.
    if let Err(e) = writeln!(&stream, "state on") {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_workdir(&workdir);
        return Err(e.into());
    }

    let status = Arc::new(Mutex::new(SessionStatus::default()));
    let (tx, rx) = mpsc::channel();
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_workdir(&workdir);
            return Err(e.into());
        }
    };
    {
        let status = Arc::clone(&status);
        let ifname_file = ifname_file.clone();
        std::thread::spawn(move || background_reader(reader_stream, status, ifname_file, Some(tx)));
    }

    let ifname = match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(MgmtEvent::Connected(ifname)) => {
            ifname.unwrap_or_else(|| format!("openvpn-{profile_id}"))
        }
        Ok(MgmtEvent::Failed(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_workdir(&workdir);
            return Err(NetworkError::Vpn(format!("openvpn failed to connect: {msg}")));
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_workdir(&workdir);
            return Err(NetworkError::Vpn(
                "timed out waiting for openvpn to report CONNECTED".into(),
            ));
        }
    };

    SESSIONS.lock().unwrap().get_or_insert_with(HashMap::new).insert(
        ifname.clone(),
        Session { child, management: stream, workdir, status },
    );

    Ok(VpnSession { interface_name: ifname, kind: VpnKind::OpenVpn })
}

pub fn disconnect(ifname: &str) -> Result<()> {
    let session = SESSIONS
        .lock()
        .unwrap()
        .as_mut()
        .and_then(|m| m.remove(ifname))
        .ok_or_else(|| {
            NetworkError::NotFound(format!("no tracked openvpn session for '{ifname}'"))
        })?;

    // Ask openvpn to shut itself down cleanly via the management
    // interface -- more reliable than only killing `session.child`,
    // which (per the module doc comment) may just be the --daemon
    // launcher rather than the actual long-running process.
    let _ = writeln!(&session.management, "signal SIGTERM");
    std::thread::sleep(Duration::from_millis(300));

    let mut child = session.child;
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&session.workdir);
    Ok(())
}

/// The live status of a tracked session, if any -- for IPC status
/// queries or `netctl` to surface real connection state instead of
/// just "activated: yes/no".
pub fn status(ifname: &str) -> Option<SessionStatus> {
    SESSIONS
        .lock()
        .unwrap()
        .as_ref()?
        .get(ifname)
        .map(|s| s.status.lock().unwrap().clone())
}

enum MgmtEvent {
    Connected(Option<String>),
    Failed(String),
}

/// Reads `>STATE:`/log lines off the management connection for as
/// long as it stays open, keeping `status` current. `initial_tx`, if
/// still present, is used to report the *first* CONNECTED or
/// fatal/auth-failure state back to whatever's waiting in `connect`;
/// once that fires (or the connection closes before it does), this
/// keeps running -- draining the socket matters even after the
/// initial wait, since an unread management connection would
/// otherwise sit there until its kernel-side buffer filled.
fn background_reader(
    stream: UnixStream,
    status: Arc<Mutex<SessionStatus>>,
    ifname_file: PathBuf,
    initial_tx: Option<mpsc::Sender<MgmtEvent>>,
) {
    let mut initial_tx = initial_tx;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break, // EOF or socket error: openvpn is gone
            Ok(_) => {}
        }
        let Some(rest) = line.trim_end().strip_prefix(">STATE:") else {
            continue;
        };
        let Some(state) = rest.split(',').nth(1) else {
            continue;
        };
        let state = state.to_string();
        status.lock().unwrap().state = state.clone();

        if state == "CONNECTED" {
            let ifname = read_ifname_with_retry(&ifname_file, Duration::from_secs(2));
            if let Some(name) = &ifname {
                status.lock().unwrap().ifname = Some(name.clone());
            }
            if let Some(tx) = initial_tx.take() {
                let _ = tx.send(MgmtEvent::Connected(ifname));
            }
        } else if state == "AUTH_FAILED" || state == "FATAL" {
            if let Some(tx) = initial_tx.take() {
                let _ = tx.send(MgmtEvent::Failed(format!("openvpn reported state {state}")));
            }
        }
    }
    if let Some(tx) = initial_tx.take() {
        let _ = tx.send(MgmtEvent::Failed(
            "management connection closed before reaching CONNECTED".into(),
        ));
    }
}

fn accept_with_timeout(listener: &UnixListener, timeout: Duration) -> Result<UnixStream> {
    listener
        .set_nonblocking(true)
        .map_err(|e| NetworkError::Vpn(format!("management socket setup: {e}")))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|e| NetworkError::Vpn(format!("management socket setup: {e}")))?;
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(NetworkError::Vpn(
                        "openvpn did not connect to the management socket in time".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn read_ifname_with_retry(path: &Path, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let name = contents.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn write_script(path: &Path, content: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}
