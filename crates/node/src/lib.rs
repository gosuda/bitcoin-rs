//! Integration crate for running a synchronous `bitcoin-rs` node.
//!
//! The crate owns process-level concerns: layered configuration, storage backend
//! selection, signal bridging, metrics/tracing setup, crash recovery, the
//! chainstate facade that serializes applied-tip mutation, and the central
//! crossbeam-driven event loop that connects the subsystem crates.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Authoritative chainstate mutation: connect, disconnect, and window apply.
///
/// See `ARCH-07` in `docs/contracts/architecture.md`.
pub mod apply;
/// Derived post-commit consumers of a committed chain transition.
pub mod chain_effects;
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
/// Metrics instrumentation and optional exposition.
pub mod metrics;
/// Node-owned mining candidate lifecycle coordinator.
pub mod mining;
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
/// Custody-grade data-directory storage-footprint evidence.
pub mod storage_footprint;
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
/// Prevout lookups across a window of consecutive blocks.
mod window_overlay;
/// ZMQ publisher trait + implementations for the notification subsystem.
pub mod zmq_publisher;

pub use apply::{ChainTransition, Chainstate, ChainstateSnapshot};
pub use bitcoin_rs_primitives::Network;
pub use chain_effects::ChainEffects;
pub use config::{
    Auth, ChainstateJournalConfig, ChainstateJournalOverrides, IndexConfig, IndexOverrides,
    MiningConfig, MiningOverrides, NetworkSelection, NodeConfig, NotificationConfig,
    ObservabilityConfig, ObservabilityOverrides, P2pConfig, P2pOverrides, RpcConfig, RpcOverrides,
    RuntimeInputs, ScriptIndexMode, StorageConfig, StorageOverrides, UserConfig, ValidationConfig,
    ValidationOverrides, resolve,
};
pub use embed::{Node, NodeError, SyncProgress};
pub use mining::{GenerationKey, MiningCoordinator};
pub use run::run;
pub use state::{ApplyError, DisconnectError};
pub use storage_footprint::{
    DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES, EVIDENCE_FORMAT, MeasureStorageRequest,
    StorageFootprintEvidence, measure_storage_footprint, storage_footprint_json,
};
pub use sync::BlockSync;
pub use txindex_worker::TxIndexRuntime;
#[cfg(feature = "zmq")]
pub use zmq_publisher::SocketZmqPublisher;
pub use zmq_publisher::{
    NoOpZmqPublisher, SequenceEvent, TracingZmqPublisher, ZmqEndpointConfig, ZmqPublisher, ZmqTopic,
};
