//! Integration crate for running a synchronous `bitcoin-rs` node.
//!
//! The crate owns process-level concerns: layered configuration, storage backend
//! selection, signal bridging, metrics/tracing setup, crash recovery, and the
//! central crossbeam-driven event loop that connects the subsystem crates.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Block-apply pipeline executed by `NodeState::apply_block` and `BlockSync::tick`.
pub mod apply;
/// BIP9 deployment-state adapter over `BlockTree`.
pub mod bip9_context;
/// Bitcoin Core configuration compatibility.
pub mod bitcoin_conf_compat;
/// Adapter.
///
/// Bridges in-memory block records to the index crate's BlockSource trait.
pub mod block_source;
mod checkpoint;
mod checkpoint_fs;
/// Layered node configuration.
pub mod config;
/// Block corpus manifest for contiguous archive integrity.
pub mod corpus;
/// Startup crash recovery.
pub mod crash_recovery;
/// Central synchronous event loop.
pub mod event_loop;
mod g14_utxo_commit;
mod g2_muhash;
/// Block import pipeline.
pub mod import;
/// Tracing initialization.
pub mod logging;
/// Metrics instrumentation and optional exposition.
pub mod metrics;
/// Node-owned mining candidate lifecycle coordinator.
pub mod mining;
/// Node-side active-chain view for server-side P2P responders.
pub mod p2p_chain;

/// Switching the applied chain from one branch to another.
pub mod reorg;
/// Top-level node runner.
pub mod run;
/// Graceful shutdown.
pub mod shutdown;
/// Signal handling.
pub mod signal;
/// Shared node state.
pub mod state;
/// Block download orchestrator.
pub mod sync;
mod txindex_worker;
/// UTXO view adapter for consensus transaction checks.
pub mod utxo_view;
/// Prevout lookups across a window of consecutive blocks.
mod window_overlay;
/// ZMQ publisher trait + implementations for the notification subsystem.
pub mod zmq_publisher;

pub use bip9_context::BlockTreeContext;
pub use bitcoin_rs_primitives::Network;
pub use block_source::NodeBlockSource;
pub use config::{Auth, Config};
pub use mining::{GenerationKey, MiningCoordinator};
pub use p2p_chain::NodeP2pChainQuery;
pub use run::run;
pub use state::{ApplyError, DisconnectError};
pub use sync::BlockSync;
pub use txindex_worker::TxIndexRuntime;
pub use utxo_view::UtxoSetView;
#[cfg(feature = "zmq")]
pub use zmq_publisher::SocketZmqPublisher;
pub use zmq_publisher::{NoOpZmqPublisher, SequenceEvent, TracingZmqPublisher, ZmqPublisher};
