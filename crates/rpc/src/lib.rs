#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// HTTP Basic and cookie authentication.
pub mod auth;
/// Standard-alphabet Base64 encode/decode for auth headers and PSBTs.
mod base64;
/// Dependency-injected RPC state.
pub mod context;
/// Native <-> rust-bitcoin conversions and typed wire serialization.
pub(crate) mod convert;
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
