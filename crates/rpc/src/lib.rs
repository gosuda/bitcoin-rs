//! Synchronous Bitcoin Core-compatible JSON-RPC surface for `bitcoin-rs`.
//!
//! This crate intentionally exposes only watch-only wallet behavior. RPCs that
//! would reveal, import, create, or use private keys are disabled and return a
//! JSON-RPC internal-error response with the message
//! `wallet has no private keys; use external signer`. PSBT construction,
//! combination, analysis, and finalization stay available because they can be
//! driven by external signers without this process holding private key material.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// HTTP Basic and cookie authentication.
pub mod auth;
/// Dependency-injected RPC state.
pub mod context;
/// JSON-RPC error mapping.
pub mod error;
/// Method dispatch and Core-compatible handlers.
pub mod handlers;
/// Synchronous HTTP/1.1 JSON-RPC server.
pub mod server;

pub use auth::Auth;
pub use context::{BlockRecord, Context, NetworkState};
pub use error::RpcError;
pub use handlers::Handler;
pub use server::RpcServer;
