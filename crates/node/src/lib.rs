//! Integration crate for running a synchronous `bitcoin-rs` node.
//!
//! The crate owns process-level concerns: layered configuration, storage backend
//! selection, signal bridging, metrics/tracing setup, crash recovery, and the
//! central crossbeam-driven event loop that connects the subsystem crates.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Bitcoin Core configuration compatibility.
pub mod bitcoin_conf_compat;
/// Layered node configuration.
pub mod config;
/// Startup crash recovery.
pub mod crash_recovery;
/// Central synchronous event loop.
pub mod event_loop;
/// Block import pipeline.
pub mod import;
/// Tracing initialization.
pub mod logging;
/// Metrics instrumentation and optional exposition.
pub mod metrics;
/// Top-level node runner.
pub mod run;
/// Graceful shutdown.
pub mod shutdown;
/// Signal handling.
pub mod signal;
/// Shared node state.
pub mod state;
/// UTXO view adapter for consensus transaction checks.
pub mod utxo_view;

pub use bitcoin_rs_primitives::Network;
pub use config::{Auth, Config};
pub use run::run;
pub use state::ApplyError;
pub use utxo_view::UtxoSetView;
