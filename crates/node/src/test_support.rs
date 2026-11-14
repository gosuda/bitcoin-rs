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
    Apply(Box<bitcoin_rs_execution::ApplyError>),
    #[error(transparent)]
    Recovery(Box<bitcoin_rs_execution::recovery::RecoveryError>),
    #[error(transparent)]
    Checkpoint(Box<bitcoin_rs_execution::CheckpointError>),
    #[error(transparent)]
    CheckpointSetup(#[from] bitcoin_rs_execution::CheckpointSetupError),
    #[error(transparent)]
    Maintenance(#[from] bitcoin_rs_execution::MaintenanceError),
    #[error(transparent)]
    AssumeUtxo(Box<bitcoin_rs_execution::AssumeUtxoError>),
    #[error(transparent)]
    P2pStart(#[from] bitcoin_rs_wire::P2pServiceError),
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
    MiningControl(#[from] bitcoin_rs_serving::mining::MiningControlError),
    #[error(transparent)]
    Mining(#[from] bitcoin_rs_serving::mining::MiningError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Job(#[from] bitcoin_rs_serving::mining::pool::JobError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Ledger(#[from] bitcoin_rs_serving::mining::pool::ledger::LedgerError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    ChainView(#[from] bitcoin_rs_serving::mining::pool::ledger::ChainViewError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    Sv1Config(#[from] bitcoin_rs_serving::mining::pool::stratum::sv1::ConfigError),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    LedgerUnavailable(#[from] bitcoin_rs_serving::mining::pool::LedgerUnavailable),
    #[error(transparent)]
    PruneService(#[from] bitcoin_rs_serving::context::PruneServiceError),
    #[error(transparent)]
    TxQuery(#[from] bitcoin_rs_projection::query_api::TxQueryError),
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_execution::chain::ChainError),
    #[error(transparent)]
    Node(#[from] crate::embed::NodeError),
    #[error(transparent)]
    Rpc(#[from] bitcoin_rs_serving::RpcError),
    #[error(transparent)]
    ChainChange(#[from] bitcoin_rs_mempool::ChainChangeError),
    #[error(transparent)]
    Peer(#[from] bitcoin_rs_wire::PeerError),
    #[error(transparent)]
    Mempool(#[from] bitcoin_rs_mempool::MempoolError),
    #[error(transparent)]
    AddressParse(#[from] bitcoin::address::ParseError),
    #[error(transparent)]
    Disconnect(#[from] bitcoin_rs_execution::DisconnectError),
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
    RegtestFixture(#[from] bitcoin_rs_execution::chain::regtest_fixture::RegtestFixtureError),
    #[error(transparent)]
    Prune(#[from] bitcoin_rs_storage::pruning::PruneError),
    #[error(transparent)]
    SnapshotUtxo(#[from] bitcoin_rs_storage::utxo::core_snapshot::SnapshotError),
    #[error(transparent)]
    DerivedIndexWorker(#[from] bitcoin_rs_projection::runtime::DerivedIndexWorkerError),
    #[error(transparent)]
    Prioritise(#[from] bitcoin_rs_mempool::PrioritiseError),
    #[error(transparent)]
    Reorg(#[from] bitcoin_rs_execution::reorg::ReorgError),
    #[error(transparent)]
    DataDir(#[from] bitcoin_rs_execution::events::DataDirError),
    #[error(transparent)]
    StdRecvTimeout(#[from] std::sync::mpsc::RecvTimeoutError),
    #[error(transparent)]
    HeaderAdmission(#[from] bitcoin_rs_execution::HeaderAdmissionError),
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
    Listener(#[from] bitcoin_rs_wire::listener::ListenerError),
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
impl From<bitcoin_rs_execution::ApplyError> for TestError {
    fn from(error: bitcoin_rs_execution::ApplyError) -> Self {
        Self::Apply(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<bitcoin_rs_execution::recovery::RecoveryError> for TestError {
    fn from(error: bitcoin_rs_execution::recovery::RecoveryError) -> Self {
        Self::Recovery(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<bitcoin_rs_execution::CheckpointError> for TestError {
    fn from(error: bitcoin_rs_execution::CheckpointError) -> Self {
        Self::Checkpoint(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<bitcoin_rs_execution::AssumeUtxoError> for TestError {
    fn from(error: bitcoin_rs_execution::AssumeUtxoError) -> Self {
        Self::AssumeUtxo(Box::new(error))
    }
}

#[cfg(any(test, feature = "test-seam"))]
impl From<crate::state::open::NodeOpenError> for TestError {
    fn from(error: crate::state::open::NodeOpenError) -> Self {
        Self::Open(Box::new(error))
    }
}
