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
/// Bitcoin Core wire-contract boundary: versioned response types and the
/// sanctioned native<->bitcoin conversions backing them.
pub mod compat;
/// The Bitcoin Core compatibility manifest, and the checks that keep it true.
pub mod compat_manifest;
/// Dependency-injected RPC state.
pub mod context;
/// JSON-RPC error mapping.
pub mod error;
/// Esplora-compatible HTTP endpoints backed by node-owned indexes.
pub mod esplora;
/// Method dispatch and Core-compatible handlers.
pub mod handlers;
/// Declared compatibility surface versus Bitcoin Core 31.x.
pub mod manifest;
/// Unified registry: one row owns compat metadata plus dispatch arm.
pub(crate) mod registry;
/// Semantic Core projections without transport policy.
pub mod render;
/// Bitcoin Core-compatible REST endpoints.
pub mod rest;
/// Byte-level script helpers mirrored from `bitcoin-rs-script` (see module docs).
pub mod script_util;
/// Synchronous HTTP/1.1 JSON-RPC server.
pub mod server;
/// Transaction, block, and header rendering.
pub mod tx_render;

pub use auth::Auth;
pub use compat_manifest::{MANIFEST_TOML, Status as CompatStatus};

pub use error::RpcError;
pub use handlers::Handler;
pub use server::RpcServer;
