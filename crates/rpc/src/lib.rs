//! Synchronous Bitcoin Core-compatible JSON-RPC surface for `bitcoin-rs`.
//!
//! This node ships no wallet. RPCs that would fund, sign, or otherwise
//! require private key material are not implemented and answer
//! `method not found`. Descriptor utilities, `scantxoutset`, and PSBT
//! combination/finalization remain for watch-only workflows driven by
//! external signers without this process holding private key material.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// HTTP Basic and cookie authentication.
pub mod auth;
/// Dependency-injected RPC state.
pub mod context;
/// JSON-RPC error mapping.
pub mod error;
/// Esplora-compatible HTTP endpoints backed by node-owned indexes.
pub mod esplora;
/// Method dispatch and Core-compatible handlers.
pub mod handlers;
/// Bitcoin Core-compatible REST endpoints.
pub mod rest;
/// Synchronous HTTP/1.1 JSON-RPC server.
pub mod server;

pub use auth::Auth;

pub use error::RpcError;
pub use handlers::Handler;
pub use server::RpcServer;
