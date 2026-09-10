//! Resolving *who* is talking to us. The actual authorization decision
//! (which `Capability` a given identity has) lives in `security::policy`;
//! this module only answers "root? which groups?".

/// The identity of a Unix-domain-socket peer, resolved via
/// `SO_PEERCRED` by `ipc::permissions` right after `accept()`.
#[derive(Debug, Clone, Copy)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

impl PeerIdentity {
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// Whether this peer's primary or supplementary groups include
    /// `group_name` (e.g. `"netdev"`, the conventional Linux group for
    /// "may change network settings without being root").
    pub fn in_group(&self, group_name: &str) -> bool {
        if self.is_root() {
            return true;
        }
        group_gid(group_name)
            .map(|gid| gid == self.gid || uid_in_supplementary_group(self.uid, gid))
            .unwrap_or(false)
    }
}

fn group_gid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer into thread-local/static storage
    // owned by libc; we copy the one field we need out before returning.
    unsafe {
        let grp = libc::getgrnam(cname.as_ptr());
        if grp.is_null() {
            None
        } else {
            Some((*grp).gr_gid)
        }
    }
}

fn uid_in_supplementary_group(uid: u32, gid: u32) -> bool {
    // SAFETY: getpwuid/getgrgid return pointers into static buffers we
    // read immediately and never retain across calls.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return false;
        }
        let username = (*pw).pw_name;
        let grp = libc::getgrgid(gid);
        if grp.is_null() {
            return false;
        }
        let mut members = (*grp).gr_mem;
        while !(*members).is_null() {
            if libc::strcmp(*members, username) == 0 {
                return true;
            }
            members = members.add(1);
        }
        false
    }
}
