//! Synchronous Bitcoin Core-compatible JSON-RPC surface for `bitcoin-rs`.
//!
//! This node ships no wallet. RPCs that would fund, sign, or otherwise
//! require private key material are not implemented and answer
//! `method not found`. Descriptor utilities, `scantxoutset`, and PSBT
//! combination/finalization remain for watch-only workflows driven by
//! external signers without this process holding private key material.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod base64;

/// Canonical transaction admission pipeline.
pub mod admission;
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
/// Canonical Bitcoin Core block and header JSON projections.
pub mod render;
/// Bitcoin Core-compatible REST endpoints.
pub mod rest;
/// Synchronous HTTP/1.1 JSON-RPC server.
pub mod server;
/// Canonical Bitcoin Core transaction JSON projections.
pub mod tx_render;

pub(crate) const fn bitcoin_network(network: bitcoin_rs_primitives::Network) -> bitcoin::Network {
    match network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    }
}

pub use auth::Auth;

pub use error::RpcError;
pub use handlers::Handler;
pub use server::{RpcLifecycle, RpcServer, RpcWarnings};
