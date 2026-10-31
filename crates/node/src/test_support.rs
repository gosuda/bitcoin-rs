//! Shared typed error for the node's own tests, benches and test-seam embedders.
//!
//! Every node test returns `Result<(), TestError>` rather than a type-erased carrier. The
//! `#[from]` arms cover the error types tests meet through the public entry
//! points; ad-hoc expectation failures use [`TestError::message`].

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
    Apply(Box<bitcoin_rs_chainstate::ApplyError>),
    #[error(transparent)]
    Recovery(Box<bitcoin_rs_chainstate::recovery::RecoveryError>),
    #[error(transparent)]
    Checkpoint(Box<bitcoin_rs_chainstate::CheckpointError>),
    #[error(transparent)]
    CheckpointSetup(#[from] bitcoin_rs_chainstate::CheckpointSetupError),
    #[error(transparent)]
    Maintenance(#[from] bitcoin_rs_chainstate::MaintenanceError),
    #[error(transparent)]
    AssumeUtxo(Box<bitcoin_rs_chainstate::AssumeUtxoError>),
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
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error(transparent)]
    MiningControl(#[from] bitcoin_rs_mining::MiningControlError),
    #[error(transparent)]
    Mining(#[from] bitcoin_rs_mining::MiningError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Job(#[from] bitcoin_rs_mining::pool::JobError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Ledger(#[from] bitcoin_rs_mining::pool::ledger::LedgerError),
    #[error(transparent)]
    PruneService(#[from] bitcoin_rs_rpc::context::PruneServiceError),
    #[error(transparent)]
    HistoricalQuery(#[from] bitcoin_rs_index::query_api::HistoricalQueryError),
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
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
    Disconnect(#[from] bitcoin_rs_chainstate::DisconnectError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
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
    RegtestFixture(#[from] bitcoin_rs_chain::regtest_fixture::RegtestFixtureError),
    #[error(transparent)]
    Prune(#[from] bitcoin_rs_storage::pruning::PruneError),
    #[error(transparent)]
    SnapshotUtxo(#[from] bitcoin_rs_utxo::core_snapshot::SnapshotError),
    #[error(transparent)]
    DerivedIndexWorker(#[from] bitcoin_rs_index::runtime::DerivedIndexWorkerError),
    #[error(transparent)]
    Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
    #[error(transparent)]
    Reorg(#[from] bitcoin_rs_chainstate::reorg::ReorgError),
    #[error(transparent)]
    DataDir(#[from] bitcoin_rs_chainstate::events::DataDirError),
    #[error(transparent)]
    StdRecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
    #[error(transparent)]
    HeaderAdmission(#[from] bitcoin_rs_chainstate::HeaderAdmissionError),
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
impl From<bitcoin_rs_chainstate::ApplyError> for TestError {
    fn from(error: bitcoin_rs_chainstate::ApplyError) -> Self {
        Self::Apply(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<bitcoin_rs_chainstate::recovery::RecoveryError> for TestError {
    fn from(error: bitcoin_rs_chainstate::recovery::RecoveryError) -> Self {
        Self::Recovery(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<bitcoin_rs_chainstate::CheckpointError> for TestError {
    fn from(error: bitcoin_rs_chainstate::CheckpointError) -> Self {
        Self::Checkpoint(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<bitcoin_rs_chainstate::AssumeUtxoError> for TestError {
    fn from(error: bitcoin_rs_chainstate::AssumeUtxoError) -> Self {
        Self::AssumeUtxo(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<crate::state::open::NodeOpenError> for TestError {
    fn from(error: crate::state::open::NodeOpenError) -> Self {
        Self::Open(Box::new(error))
    }
}
