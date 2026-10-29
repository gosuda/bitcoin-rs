#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod chain_effects;
pub mod config;
mod embed;
mod event_loop;
pub mod options;

mod lifecycle;
pub mod metrics;
pub mod mining;
pub mod offline_import;
#[cfg(feature = "pool")]
mod pool;
pub mod reorg;
mod run;
#[cfg(not(windows))]
mod signal;
#[cfg(windows)]
#[path = "signal_windows.rs"]
mod signal;
mod snapshot;
#[cfg(not(feature = "test-seam"))]
#[allow(
    unreachable_pub,
    reason = "the public shape is exposed only by the explicit test seam"
)]
mod state;
#[cfg(feature = "test-seam")]
#[doc(hidden)]
pub mod state;
mod storage_backend;
pub mod sync;
#[cfg(not(feature = "test-seam"))]
#[allow(
    unreachable_pub,
    reason = "the worker entry point is exposed only by the explicit test seam"
)]
mod tx_ingress;
#[cfg(feature = "test-seam")]
#[doc(hidden)]
pub mod tx_ingress;
pub use bitcoin_rs_primitives::Network;

pub(crate) use bitcoin_rs_rpc::zmq::NoOpZmqPublisher;
pub use bitcoin_rs_rpc::zmq::ZmqEndpointConfig;
pub use bitcoin_rs_rpc::zmq::ZmqPublisher;

pub use chain_effects::{ChainFollowers, ConnectMutationError};

pub use bitcoin_rs_consensus::ValidationEngine;
pub use config::{
    Auth, NetworkSelection, NodeConfig, NotificationConfig, RuntimeInputs, ScriptIndexMode, resolve,
};

pub use options::{
    ChainstateJournalOverrides, IndexOverrides, MiningOverrides, ObservabilityOverrides,
    P2pOverrides, RpcOverrides, StorageOverrides, UserConfig, ValidationOverrides,
};

mod chain_feed;
pub use chain_feed::{
    BlockHeaderInfo, ChainReplay, ChainSnapshot, ChainStep, ChainSubscription, ChainTarget,
    ChainUpdate,
};
pub use embed::{Node, NodeError};

pub use state::DataDirLockError;

pub use mining::MiningCoordinator;

pub use run::run;

pub use sync::BlockSync;

pub use bitcoin_rs_index::runtime::DerivedIndexRuntime;

#[cfg(feature = "zmq")]
pub(crate) use bitcoin_rs_rpc::zmq::SocketZmqPublisher;
