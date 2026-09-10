//! Resolves a connected Unix-socket peer's credentials via
//! `SO_PEERCRED`, then hands off to `security::policy` for the actual
//! allow/deny decision.

use crate::errors::{NetworkError, Result};
use crate::security::permissions::PeerIdentity;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

pub fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred`/`len` are stack-local and correctly sized for
    // `SO_PEERCRED`; this is the standard way to authenticate a Unix
    // domain socket peer on Linux.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(NetworkError::Other(format!("SO_PEERCRED failed: {}", std::io::Error::last_os_error())));
    }
    Ok(PeerIdentity { uid: cred.uid, gid: cred.gid, pid: cred.pid })
}
