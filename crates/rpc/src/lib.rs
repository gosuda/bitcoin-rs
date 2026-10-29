//! Synchronous Bitcoin Core-compatible JSON-RPC surface for `bitcoin-rs`.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod auth;
mod base64;
pub(crate) mod compressed_tx;
pub mod context;
pub(crate) mod convert;
mod error;
pub mod esplora;
pub mod handlers;
pub mod manifest;
pub(crate) mod registry;
mod render;
pub mod rest;
mod server;
mod tx_render;
pub mod zmq;

pub use auth::Auth;
pub use manifest::MANIFEST_TOML;

pub use error::RpcError;
pub use handlers::Handler;
pub use server::{RpcServer, RpcSurface};
