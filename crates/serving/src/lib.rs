//! Synchronous Bitcoin Core-compatible JSON-RPC surface for `bitcoin-rs`.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod auth;
mod base64;
pub(crate) mod compressed_tx;
pub mod context;
pub(crate) mod convert;
pub(crate) mod decimal;
mod error;
pub mod esplora;
pub mod handlers;
pub mod manifest;
pub mod mining;
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

#[cfg(feature = "test-seam")]
pub use server::{handle_json, read_http_request};

#[cfg(test)]
pub(crate) mod test_error;

#[cfg(test)]
pub(crate) mod test_coins;
