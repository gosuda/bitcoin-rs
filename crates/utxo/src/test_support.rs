#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Utxo(#[from] crate::set::UtxoError),
    #[error(transparent)]
    BlockSpends(#[from] crate::contract::BlockSpendsError),
    #[error(transparent)]
    UndoCodec(#[from] crate::undo_codec::UndoCodecError),
    #[error(transparent)]
    UndoLoad(#[from] crate::contract::UndoLoadError),
    #[error(transparent)]
    Rollback(#[from] crate::contract::RollbackError),
    #[error(transparent)]
    Snapshot(#[from] crate::core_snapshot::SnapshotError),
    #[error(transparent)]
    StateVerify(#[from] crate::core_snapshot::StateVerifyError),
    #[error(transparent)]
    Overlay(#[from] crate::overlay::WindowOverlayError),
    #[error("missing: {0}")]
    Missing(&'static str),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
