#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Storage(#[from] crate::StorageError),
    #[error(transparent)]
    Utxo(#[from] crate::utxo::set::UtxoError),
    #[error(transparent)]
    BlockSpends(#[from] crate::utxo::contract::BlockSpendsError),
    #[error(transparent)]
    UndoCodec(#[from] crate::utxo::undo_codec::UndoCodecError),
    #[error(transparent)]
    UndoLoad(#[from] crate::utxo::contract::UndoLoadError),
    #[error(transparent)]
    Snapshot(#[from] crate::utxo::core_snapshot::SnapshotError),
    #[error(transparent)]
    StateVerify(#[from] crate::utxo::core_snapshot::StateVerifyError),
    #[error("missing: {0}")]
    Missing(&'static str),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
