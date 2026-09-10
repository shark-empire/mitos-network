//! Wire framing: a 4-byte little-endian length prefix followed by that
//! many bytes of JSON. JSON (not bincode, unlike `mitos-session`'s IPC)
//! is deliberate here -- `mitos-netctl` and any future non-Rust tooling
//! (a shell script, a GUI written in something else entirely) can speak
//! this protocol with nothing more than a length-prefixed-JSON parser,
//! no shared Rust struct definitions required.

use crate::errors::{NetworkError, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};

const MAX_MESSAGE_LEN: u32 = 16 * 1024 * 1024; // 16 MiB: generous, but not "a hostile peer can OOM us"

pub fn write_message<T: Serialize>(stream: &mut impl Write, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_MESSAGE_LEN as u64 {
        return Err(NetworkError::Other("outgoing IPC message too large".into()));
    }
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

pub fn read_message<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_LEN {
        return Err(NetworkError::Other(format!(
            "incoming IPC message too large ({len} bytes)"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}
