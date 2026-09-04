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
/// RPC status for concrete node-owned capabilities.
mod capabilities;
mod chainstate_journal;
mod checkpoint;
mod checkpoint_fs;
/// Periodic chainstate checkpoint publication during sync.
mod checkpoint_worker;
/// Layered node configuration.
pub mod config;
/// Typed in-process node lifecycle: the embedding surface over the same
/// service graph the daemon wires.
pub mod embed;
/// Central synchronous event loop.
pub mod event_loop;
/// Block import pipeline.
pub mod import;
/// Tracing initialization.
pub mod logging;
/// Mempool mutation observer publishing `A`/`R` sequence events.
pub mod mempool_observer;
/// Metrics instrumentation and optional exposition.
pub mod metrics;
/// Node-owned mining candidate lifecycle coordinator.
pub mod mining;
/// Node-side active-chain view for server-side P2P responders.
pub mod p2p_chain;
/// Chain-event reconciliation seam for index consumers.
pub mod reconcile;
/// Durable rollback evidence: witness and marker file protocol, warning snapshot.
mod recovery_evidence;

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
/// Inbound P2P transaction admission policy: orphan map and recent-rejects.
pub mod tx_admission;
/// P2P transaction ingress consumer.
pub mod tx_ingress;
/// Outbound transaction relay worker: announce accepted txs to peers
/// excluding the source connection.
pub mod tx_relay;
mod txindex_worker;
/// UTXO view adapter for consensus transaction checks.
pub mod utxo_view;
/// Prevout lookups across a window of consecutive blocks.
mod window_overlay;
/// ZMQ publisher trait + implementations for the notification subsystem.
pub mod zmq_publisher;

pub use bitcoin_rs_primitives::Network;
pub use block_source::NodeBlockSource;
pub use config::{
    Auth, NodeConfig, NotificationConfig, RuntimeInputs, ScriptIndexMode, UserConfig,
};
pub use embed::{Node, NodeError, SyncProgress};
pub use mining::{GenerationKey, MiningCoordinator};
pub use p2p_chain::NodeP2pChainQuery;
pub use run::run;
pub use state::{ApplyError, DisconnectError};
pub use sync::BlockSync;
pub use txindex_worker::TxIndexRuntime;
pub use utxo_view::UtxoSetView;
#[cfg(feature = "zmq")]
pub use zmq_publisher::SocketZmqPublisher;
pub use zmq_publisher::{
    NoOpZmqPublisher, SequenceEvent, TracingZmqPublisher, ZmqEndpointConfig, ZmqPublisher, ZmqTopic,
};
