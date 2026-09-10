//! OpenVPN client: unlike WireGuard, OpenVPN has no simple netlink
//! surface at all -- TLS handshake, TUN device creation, and routing
//! are all handled internally by the `openvpn` binary itself. Every
//! mainstream network manager's OpenVPN plugin works the same way this
//! does: generate/locate a config file, spawn `openvpn`, track the
//! process.

use crate::errors::{NetworkError, Result};
use crate::security::secrets::SecretsBackend;
use crate::vpn::vpn::{VpnKind, VpnSession};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::Mutex;

static CHILDREN: Mutex<Option<HashMap<String, Child>>> = Mutex::new(None);

/// `config` is a filesystem path to an existing `.ovpn` file (the file
/// itself is not a secret -- it's the certs/keys or auth credentials
/// *inside* it that are, and username/password auth is handled below
/// via a separately-supplied secret rather than embedding it in the file).
pub fn connect(
    config_path: &str,
    secrets: &dyn SecretsBackend,
    profile_id: &str,
) -> Result<VpnSession> {
    if !std::path::Path::new(config_path).is_file() {
        return Err(NetworkError::Vpn(format!(
            "OpenVPN config '{config_path}' not found"
        )));
    }

    let mut cmd = Command::new("openvpn");
    cmd.arg("--config").arg(config_path);

    // Optional username/password auth (`auth-user-pass` in the .ovpn
    // file pointing at a file we generate here, mode 0600, deleted
    // right after openvpn reads it at startup).
    let mut userpass_path = None;
    if let (Some(user), Some(pass)) = (
        secrets.get(profile_id, "auth-username")?,
        secrets.get(profile_id, "auth-password")?,
    ) {
        let path = std::env::temp_dir().join(format!("mitos-ovpn-{profile_id}.auth"));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            writeln!(f, "{user}")?;
            writeln!(f, "{pass}")?;
        }
        cmd.arg("--auth-user-pass").arg(&path);
        cmd.arg("--auth-nocache"); // don't keep the plaintext password in openvpn's own memory longer than needed
        userpass_path = Some(path);
    }

    cmd.arg("--daemon")
        .arg(format!("mitos-openvpn-{profile_id}"));

    let child = cmd
        .spawn()
        .map_err(|e| NetworkError::Vpn(format!("failed to spawn openvpn: {e}")))?;

    // openvpn re-execs itself into the background with --daemon, so the
    // Child handle here tracks the launcher process, not necessarily
    // the long-running one -- good enough to know "did spawning even
    // succeed", but real lifecycle tracking (interface name, actual
    // PID, tearing it down cleanly) needs openvpn's management
    // interface (`--management`); flagged as a follow-up in
    // docs/networking.md rather than half-implemented here.
    if let Some(path) = userpass_path {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let _ = std::fs::remove_file(&path);
        });
    }

    // OpenVPN picks its own tun/tap device name (tun0, tun1, ...)
    // unless `--dev-node` pins one; without management-interface
    // introspection we don't know which one this session got, so a
    // logical placeholder tracks it internally for now.
    let logical_name = format!("openvpn-{profile_id}");
    CHILDREN
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(logical_name.clone(), child);

    Ok(VpnSession {
        interface_name: logical_name,
        kind: VpnKind::OpenVpn,
    })
}

pub fn disconnect(logical_name: &str) -> Result<()> {
    let mut child = CHILDREN
        .lock()
        .unwrap()
        .as_mut()
        .and_then(|m| m.remove(logical_name))
        .ok_or_else(|| {
            NetworkError::NotFound(format!("no tracked openvpn process for '{logical_name}'"))
        })?;
    child.kill().ok();
    let _ = child.wait();
    Ok(())
}
