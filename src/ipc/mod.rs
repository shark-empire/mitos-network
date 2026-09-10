//! The control-plane API: a Unix domain socket at
//! `general.socket-path` (default `/run/mitos-network/network.sock`),
//! carrying length-prefixed JSON `Request`/`Response` messages, plus an
//! unsolicited `Event` stream for anything watching (a desktop shell's
//! network indicator, primarily). `mitos-netctl` and this daemon are
//! the two ends; anything else on mitosOS wanting network control goes
//! through the same protocol.

pub mod client;
pub mod messages;
pub mod permissions;
pub mod protocol;
pub mod server;

pub use messages::{Event, Request, Response};
