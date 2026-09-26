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
/// Standard-alphabet Base64 encode/decode for auth headers and PSBTs.
mod base64;
/// Core-compatible projection of concrete service status.
pub mod capabilities;
/// Bitcoin Core wire-contract boundary: versioned response types and the
/// sanctioned native<->bitcoin conversions backing them.
mod compat;
/// Dependency-injected RPC state.
pub mod context;
/// JSON-RPC error mapping.
mod error;
/// Esplora-compatible HTTP endpoints backed by node-owned indexes.
pub mod esplora;
/// Method dispatch and Core-compatible handlers.
pub mod handlers;
/// Declared compatibility surface versus Bitcoin Core 31.x.
pub mod manifest;
/// Unified registry: one row owns compat metadata plus dispatch arm.
pub(crate) mod registry;
/// Semantic Core projections without transport policy.
mod render;
/// Bitcoin Core-compatible REST endpoints.
pub mod rest;
/// Synchronous HTTP/1.1 JSON-RPC server.
mod server;
/// Transaction, block, and header rendering.
mod tx_render;
/// Bitcoin Core-compatible ZMQ notification protocol and transport.
pub mod zmq;

pub use auth::Auth;
pub use manifest::MANIFEST_TOML;

pub use error::RpcError;
pub use handlers::Handler;
pub use server::RpcServer;
