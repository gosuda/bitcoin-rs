//! Process-input adapters for the `bitcoin-rs` binary.
//!
//! CLI, environment, and TOML remain [`bitcoin_rs_node::UserConfig`] source
//! adapters. Bitcoin Core `bitcoin.conf` file parsing lives here so `node`
//! only applies already-parsed user layers.

#![allow(missing_docs)]

/// Bitcoin Core `bitcoin.conf` process-input parser.
pub mod bitcoin_conf;

pub use bitcoin_conf::load_node_config;
