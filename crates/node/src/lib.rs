//! Integration crate for running a synchronous `bitcoin-rs` node.
//!
//! The crate owns process-level concerns: layered configuration, storage backend
//! selection, signal bridging, metrics/tracing setup, and the central
//! crossbeam-driven event loop that composes chainstate with peer, mempool,
//! mining, index, and RPC services.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Derived post-commit consumers of a committed chain transition.
pub mod chain_effects;
/// Layered node configuration.
pub mod config;
/// Typed in-process node lifecycle: the embedding surface over the same
/// service graph the daemon wires.
pub mod embed;
/// Central synchronous event loop.
pub mod event_loop;

/// Owned startup, rollback, and ordered service shutdown.
mod lifecycle;
/// Tracing initialization.
mod logging;
/// Metrics instrumentation and optional exposition.
pub mod metrics;
/// Node-owned mining candidate lifecycle coordinator.
pub mod mining;
/// Node-owned adapter wiring recovery evidence into index and RPC sinks.
mod recovery_reporter;

/// Switching the applied chain from one branch to another.
pub mod reorg;
/// Top-level node runner.
pub mod run;
/// Graceful shutdown.
mod shutdown;
/// Signal handling.
mod signal;
/// Shared node state.
pub mod state;
mod storage_backend;
/// Custody-grade data-directory storage-footprint evidence.
pub mod storage_footprint;
/// Block download orchestrator.
pub mod sync;
/// P2P transaction ingress consumer.
pub mod tx_ingress;
pub use bitcoin_rs_primitives::Network;

pub use bitcoin_rs_rpc::zmq::{
    NoOpZmqPublisher, SequenceEvent, TracingZmqPublisher, ZmqEndpointConfig, ZmqPublisher, ZmqTopic,
};

pub use chain_effects::ChainFollowers;

pub use config::{
    Auth, ChainstateJournalOverrides, IndexConfig, IndexOverrides, MiningConfig, MiningOverrides,
    NetworkSelection, NodeConfig, NotificationConfig, ObservabilityConfig, ObservabilityOverrides,
    P2pConfig, P2pOverrides, RpcConfig, RpcOverrides, RuntimeInputs, ScriptIndexMode,
    StorageConfig, StorageOverrides, UserConfig, ValidationConfig, ValidationOverrides, resolve,
};

pub use embed::{Node, NodeError, SyncProgress};

pub use mining::MiningCoordinator;

pub use run::run;

pub use storage_footprint::{
    MeasureStorageRequest, StorageFootprintEvidence, measure_storage_footprint,
    storage_footprint_json,
};

pub use sync::BlockSync;

pub use bitcoin_rs_index::runtime::DerivedIndexRuntime;

#[cfg(feature = "zmq")]
pub use bitcoin_rs_rpc::zmq::SocketZmqPublisher;
