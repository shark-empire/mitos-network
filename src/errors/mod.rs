//! Central error type for mitos-network.
//!
//! Every subsystem returns `errors::Result<T>` rather than inventing its
//! own error enum, so the IPC layer (`ipc::messages::Response::Error`)
//! and the audit log (`logging::audit`) have exactly one shape to render.

mod error;

pub use error::NetworkError;

pub type Result<T> = std::result::Result<T, NetworkError>;
