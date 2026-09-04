//! Process-input adapters for the `bitcoin-rs` binary.
//!
//! CLI, environment, and TOML remain binary-owned [`bitcoin_rs_node::UserConfig`]
//! source adapters. Bitcoin Core `bitcoin.conf` file parsing lives here so
//! `node` only applies already-parsed user layers.

#![allow(missing_docs)]

/// Bitcoin Core `bitcoin.conf` process-input parser.
pub mod bitcoin_conf;
