#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(test, verification, kani))]
pub(crate) mod budget_model;
mod chain_effects;
pub mod config;
mod embed;
mod event_loop;
pub mod facts_queue;
pub mod options;
pub use facts_queue::FactsQueue;

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
pub mod test_support {
    #[cfg(any(test, feature = "test-seam"))]
    #[derive(Debug, thiserror::Error)]
    pub enum TestError {
        #[error(transparent)]
        Config(#[from] crate::config::ConfigError),
        #[error(transparent)]
        Open(Box<crate::state::open::NodeOpenError>),
        #[error(transparent)]
        Run(#[from] crate::run::RunError),
        #[error(transparent)]
        OfflineImport(#[from] crate::offline_import::OfflineImportError),
        #[error(transparent)]
        IndexWorker(#[from] crate::state::IndexWorkerError),
        #[error(transparent)]
        Snapshot(Box<crate::snapshot::SnapshotImportError>),
        #[error(transparent)]
        DataDirLock(#[from] crate::state::DataDirLockError),
        #[error(transparent)]
        Connect(Box<crate::ConnectMutationError>),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Storage(#[from] bitcoin_rs_storage::StorageError),
        #[error(transparent)]
        Apply(Box<bitcoin_rs_chain::ApplyError>),
        #[error(transparent)]
        Recovery(Box<bitcoin_rs_chain::recovery::RecoveryError>),
        #[error(transparent)]
        Checkpoint(Box<bitcoin_rs_chain::CheckpointError>),
        #[error(transparent)]
        CheckpointSetup(#[from] bitcoin_rs_chain::CheckpointSetupError),
        #[error(transparent)]
        Maintenance(#[from] bitcoin_rs_chain::MaintenanceError),
        #[error(transparent)]
        AssumeUtxo(Box<bitcoin_rs_chain::AssumeUtxoError>),
        #[error(transparent)]
        P2pStart(#[from] bitcoin_rs_p2p::P2pServiceError),
        #[error(transparent)]
        HexToBytes(#[from] bitcoin::hex::HexToBytesError),
        #[error(transparent)]
        HexToArray(#[from] bitcoin::hex::HexToArrayError),
        #[error(transparent)]
        FromHex(#[from] bitcoin::consensus::encode::FromHexError),
        #[error(transparent)]
        Sonic(#[from] sonic_rs::Error),
        #[error(transparent)]
        Toml(#[from] toml::de::Error),
        #[error(transparent)]
        Decode(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error(transparent)]
        MiningControl(#[from] bitcoin_rs_rpc::mining::MiningControlError),
        #[error(transparent)]
        Mining(#[from] bitcoin_rs_rpc::mining::MiningError),
        #[cfg(feature = "pool")]
        #[error(transparent)]
        Job(#[from] bitcoin_rs_rpc::mining::pool::JobError),
        #[cfg(feature = "pool")]
        #[error(transparent)]
        Ledger(#[from] bitcoin_rs_rpc::mining::pool::ledger::LedgerError),
        #[cfg(feature = "pool")]
        #[error(transparent)]
        ChainView(#[from] bitcoin_rs_rpc::mining::pool::ledger::ChainViewError),
        #[cfg(feature = "pool")]
        #[error(transparent)]
        Sv1Config(#[from] bitcoin_rs_rpc::mining::pool::stratum::sv1::ConfigError),
        #[cfg(feature = "pool")]
        #[error(transparent)]
        LedgerUnavailable(#[from] bitcoin_rs_rpc::mining::pool::LedgerUnavailable),
        #[error(transparent)]
        PruneService(#[from] bitcoin_rs_rpc::context::PruneServiceError),
        #[error(transparent)]
        TxQuery(#[from] bitcoin_rs_index::query_api::TxQueryError),
        #[error(transparent)]
        AddrParse(#[from] std::net::AddrParseError),
        #[error(transparent)]
        ParseInt(#[from] std::num::ParseIntError),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        Chain(#[from] bitcoin_rs_chain::chain::ChainError),
        #[error(transparent)]
        Node(#[from] crate::embed::NodeError),
        #[error(transparent)]
        Rpc(#[from] bitcoin_rs_rpc::RpcError),
        #[error(transparent)]
        ChainChange(#[from] bitcoin_rs_mempool::ChainChangeError),
        #[error(transparent)]
        Peer(#[from] bitcoin_rs_p2p::PeerError),
        #[error(transparent)]
        Mempool(#[from] bitcoin_rs_mempool::MempoolError),
        #[error(transparent)]
        AddressParse(#[from] bitcoin::address::ParseError),
        #[error(transparent)]
        Disconnect(#[from] bitcoin_rs_chain::DisconnectError),
        #[error(transparent)]
        Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
        #[error(transparent)]
        Submit(#[from] bitcoin_rs_mempool::SubmitError),
        #[error(transparent)]
        CrossbeamRecvTimeout(#[from] crossbeam_channel::RecvTimeoutError),
        #[error("missing {0}")]
        Missing(&'static str),
        #[error("expectation failed: {0}")]
        ExpectationFailed(&'static str),
        #[error("timeout: {0}")]
        Timeout(&'static str),
        #[error("unexpected success: {0}")]
        UnexpectedSuccess(&'static str),
        #[error("thread panicked")]
        ThreadPanicked,
        #[error(transparent)]
        RegtestFixture(#[from] bitcoin_rs_chain::chain::regtest_fixture::RegtestFixtureError),
        #[error(transparent)]
        Prune(#[from] bitcoin_rs_storage::pruning::PruneError),
        #[error(transparent)]
        SnapshotUtxo(#[from] bitcoin_rs_storage::utxo::core_snapshot::SnapshotError),
        #[error(transparent)]
        DerivedIndexWorker(#[from] bitcoin_rs_index::runtime::DerivedIndexWorkerError),
        #[error(transparent)]
        Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
        #[error(transparent)]
        Reorg(#[from] bitcoin_rs_chain::reorg::ReorgError),
        #[error(transparent)]
        DataDir(#[from] bitcoin_rs_chain::events::DataDirError),
        #[error(transparent)]
        StdRecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
        #[error(transparent)]
        HeaderAdmission(#[from] bitcoin_rs_chain::HeaderAdmissionError),
        #[error(transparent)]
        Evidence(#[from] bitcoin_rs_storage::recovery_evidence::EvidenceError),
        #[error(transparent)]
        BitcoinEncode(#[from] bitcoin::consensus::encode::Error),
        #[error(transparent)]
        TryFromSlice(#[from] std::array::TryFromSliceError),
        #[error("channel send failed: {0}")]
        ChannelSend(&'static str),
        #[error("{0}")]
        Message(String),
        #[error("commit failed: {0}")]
        Commit(String),
        #[error("unexpected: {0}")]
        Unexpected(String),
        #[error("liveness failed: {0}")]
        Liveness(String),
        #[error("panic: {0}")]
        Panicked(&'static str),
        #[error(transparent)]
        Listener(#[from] bitcoin_rs_p2p::listener::ListenerError),
        #[error(transparent)]
        Recv(#[from] crossbeam_channel::RecvError),
        #[error(transparent)]
        TryRecv(#[from] crossbeam_channel::TryRecvError),
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub type TestResult = Result<(), TestError>;

    #[cfg(any(test, feature = "test-seam"))]
    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl<T> From<crossbeam_channel::SendError<T>> for TestError {
        fn from(_: crossbeam_channel::SendError<T>) -> Self {
            Self::ChannelSend("send failed")
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl TestError {
        #[must_use]
        pub fn message(message: impl Into<String>) -> Self {
            Self::Message(message.into())
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<crate::snapshot::SnapshotImportError> for TestError {
        fn from(error: crate::snapshot::SnapshotImportError) -> Self {
            Self::Snapshot(Box::new(error))
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<crate::ConnectMutationError> for TestError {
        fn from(error: crate::ConnectMutationError) -> Self {
            Self::Connect(Box::new(error))
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<bitcoin_rs_chain::ApplyError> for TestError {
        fn from(error: bitcoin_rs_chain::ApplyError) -> Self {
            Self::Apply(Box::new(error))
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<bitcoin_rs_chain::recovery::RecoveryError> for TestError {
        fn from(error: bitcoin_rs_chain::recovery::RecoveryError) -> Self {
            Self::Recovery(Box::new(error))
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<bitcoin_rs_chain::CheckpointError> for TestError {
        fn from(error: bitcoin_rs_chain::CheckpointError) -> Self {
            Self::Checkpoint(Box::new(error))
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<bitcoin_rs_chain::AssumeUtxoError> for TestError {
        fn from(error: bitcoin_rs_chain::AssumeUtxoError) -> Self {
            Self::AssumeUtxo(Box::new(error))
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    impl From<crate::state::open::NodeOpenError> for TestError {
        fn from(error: crate::state::open::NodeOpenError) -> Self {
            Self::Open(Box::new(error))
        }
    }
}
#[cfg(any(test, feature = "test-seam"))]
#[doc(hidden)]
pub use test_support::TestError;
pub mod budget;
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

pub(crate) use bitcoin_rs_rpc::zmq::NoOpZmqPublisher;
pub use bitcoin_rs_rpc::zmq::ZmqEndpointConfig;
pub use bitcoin_rs_rpc::zmq::ZmqPublisher;

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

pub use snapshot::{SnapshotImport, SnapshotImportError, ThreePositions};
pub use state::{DataDirLockError, open::NodeOpenError, open::StartupVerificationPaths};

pub use mining::MiningCoordinator;

pub use offline_import::{OfflineImportError, run_offline_import};
pub use run::{RunError, run};

pub use p2p::BlockSync;

pub use bitcoin_rs_index::runtime::DerivedIndexRuntime;

#[cfg(feature = "zmq")]
pub(crate) use bitcoin_rs_rpc::zmq::SocketZmqPublisher;
