#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(test, verification, kani))]
pub(crate) mod budget_model;
mod chain_effects;
pub mod config;
mod embed;
mod event_loop;
pub mod options;

mod lifecycle;
pub mod metrics;
pub mod mining;
pub mod offline_import;
pub mod p2p;
#[cfg(feature = "pool")]
pub mod pool;
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
#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
pub mod test_support;
#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
pub use test_support::TestError;
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
pub use bitcoin_rs_consensus::primitives::Network;

pub(crate) use bitcoin_rs_serving::zmq::NoOpZmqPublisher;
pub use bitcoin_rs_serving::zmq::ZmqEndpointConfig;
pub use bitcoin_rs_serving::zmq::ZmqPublisher;

pub use chain_effects::{ChainFollowers, ConnectMutationError};

pub use bitcoin_rs_consensus::ValidationEngine;
pub use config::{
    Auth, ConfigError, NetworkSelection, NodeConfig, NotificationConfig, RuntimeInputs,
    ScriptIndexMode, resolve,
};

pub use options::{
    IndexOverrides, MiningOverrides, ObservabilityOverrides, P2pOverrides, RpcOverrides,
    StorageOverrides, UserConfig, ValidationOverrides,
};

mod chain_feed;
pub use chain_feed::{
    BlockHeaderInfo, ChainReplay, ChainSnapshot, ChainStep, ChainSubscription, ChainTarget,
    ChainUpdate,
};
pub use embed::{Node, NodeError};

pub use snapshot::SnapshotImportError;
pub use state::{DataDirLockError, open::NodeOpenError, open::StartupVerificationPaths};

pub use mining::MiningCoordinator;

pub use offline_import::{OfflineImportError, run_offline_import};
pub use run::{RunError, run};

pub use p2p::BlockSync;

pub use bitcoin_rs_projection::runtime::DerivedIndexRuntime;

#[cfg(feature = "zmq")]
pub(crate) use bitcoin_rs_serving::zmq::SocketZmqPublisher;
