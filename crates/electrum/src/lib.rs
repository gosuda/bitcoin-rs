#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Core Electrum method handlers and in-process handles.
pub mod methods;
/// TCP/TLS Electrum server.
pub mod server;
/// Per-connection JSON-RPC session handling.
pub mod session;
/// Subscription state and status notifications.
pub mod subscription;

pub use methods::{ElectrumError, IndexHandle, MempoolHandle, dispatch};
pub use server::{ElectrumServer, ServerConfig};
pub use session::{JsonRpcResponse, Session};
pub use subscription::{SessionSubscriptions, status_value};
