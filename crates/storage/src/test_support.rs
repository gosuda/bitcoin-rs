#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Storage(#[from] crate::StorageError),
    #[error(transparent)]
    BoundedRead(#[from] crate::BoundedReadError),
    #[error(transparent)]
    JournalWriter(#[from] crate::chainstate_journal::JournalWriterError),
    #[error(transparent)]
    Checkpoint(#[from] crate::checkpoint::CheckpointError),
    #[error(transparent)]
    CheckpointLoad(#[from] crate::checkpoint::CheckpointLoadError),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error("unexpected success: {0}")]
    UnexpectedSuccess(&'static str),
    #[error("worker panicked: {0}")]
    WorkerPanicked(&'static str),
    #[error("blocked past the deadline: {0}")]
    Blocked(&'static str),
}

pub(crate) type TestResult<T = ()> = Result<T, TestError>;
