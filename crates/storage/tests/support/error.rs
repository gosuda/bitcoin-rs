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
    #[cfg(feature = "redb")]
    #[error(transparent)]
    RedbDatabase(#[from] redb::DatabaseError),
    #[cfg(feature = "redb")]
    #[error(transparent)]
    RedbTransaction(#[from] redb::TransactionError),
    #[cfg(feature = "redb")]
    #[error(transparent)]
    RedbTable(#[from] redb::TableError),
    #[cfg(feature = "redb")]
    #[error(transparent)]
    RedbCommit(#[from] redb::CommitError),
    #[cfg(feature = "redb")]
    #[error(transparent)]
    RedbStorage(#[from] redb::StorageError),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
