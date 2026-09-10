//! Blocking client for the IPC protocol -- what `mitos-netctl` (and any
//! other future in-process caller) uses to talk to the daemon.

use super::messages::{Event, Request, Response, ServerMessage};
use super::protocol;
use crate::errors::{NetworkError, Result};
use std::os::unix::net::UnixStream;

pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub fn connect(socket_path: &str) -> Result<Self> {
        let stream = UnixStream::connect(socket_path).map_err(|e| {
            NetworkError::Other(format!("could not connect to mitos-network at {socket_path}: {e} (is the daemon running?)"))
        })?;
        Ok(Client { stream })
    }

    /// Sends `req` and waits for the matching `Response`, transparently
    /// discarding any `Event`s that arrive first -- the event stream and
    /// the request/response exchange share one connection, so a request
    /// issued right as something else changes can legitimately see an
    /// `Event` land before its own `Response` does.
    pub fn request(&mut self, req: Request) -> Result<Response> {
        protocol::write_message(&mut self.stream, &req)?;
        loop {
            match protocol::read_message(&mut self.stream)? {
                ServerMessage::Response(r) => return Ok(r),
                ServerMessage::Event(_) => continue,
            }
        }
    }

    /// Blocks for the next `Event` -- used by a `mitos-netctl monitor`
    /// style command. Any `Response` seen here (there shouldn't be one,
    /// with no outstanding request) is discarded rather than treated as
    /// an error, since a strict protocol violation here isn't this
    /// function's job to police.
    pub fn next_event(&mut self) -> Result<Event> {
        loop {
            match protocol::read_message(&mut self.stream)? {
                ServerMessage::Event(e) => return Ok(e),
                ServerMessage::Response(_) => continue,
            }
        }
    }
}
