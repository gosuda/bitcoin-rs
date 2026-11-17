#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    BoundedRead(#[from] bitcoin_rs_storage::BoundedReadError),
    #[error(transparent)]
    Prune(#[from] bitcoin_rs_storage::pruning::PruneError),
    #[error(transparent)]
    Retention(#[from] bitcoin_rs_storage::pruning::RetentionError),
    #[error(transparent)]
    HistoryUnavailable(#[from] bitcoin_rs_storage::pruning::HistoryUnavailable),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
