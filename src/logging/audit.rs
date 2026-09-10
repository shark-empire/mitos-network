//! A separate, append-only security audit log: connection activations,
//! Wi-Fi credential changes, firewall rule changes, VPN sessions. Kept
//! apart from the regular daemon log (`logging::logger`) so an admin
//! can ship it somewhere durable without wading through routine chatter.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        AuditLog { path, file: Mutex::new(None) }
    }

    fn ensure_open(&self) -> std::io::Result<()> {
        let mut guard = self.file.lock().unwrap();
        if guard.is_none() {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let f = OpenOptions::new().create(true).append(true).open(&self.path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            *guard = Some(f);
        }
        Ok(())
    }

    /// `actor` is typically a peer credential (`uid:1000`) resolved by
    /// `ipc::permissions`; `action` is a short machine-parseable tag
    /// like `"wifi.connect"` or `"firewall.rule.add"`.
    pub fn record(&self, actor: &str, action: &str, detail: &str) {
        if self.ensure_open().is_err() {
            return; // audit logging must never crash the daemon
        }
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let line = format!("{ts} actor={actor} action={action} detail={detail}\n");
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}
