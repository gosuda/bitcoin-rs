use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum EngineOpenError {
    #[error("fjall error: {0}")]
    Fjall(#[from] fjall::Error),

    #[error("redb database error: {0}")]
    Redb(#[from] redb::DatabaseError),

    #[error("redb transaction error: {0}")]
    RedbTransaction(#[from] redb::TransactionError),
    #[error("redb table error: {0}")]
    RedbTable(#[from] redb::TableError),
    #[error("redb storage error: {0}")]
    RedbStorage(#[from] redb::StorageError),
    #[error("storage backend error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
}

#[derive(Debug, Error)]
pub(crate) enum ConvertError {
    #[error("unknown or unsupported schema epoch: {0}")]
    UnknownEpoch(u32),

    #[error("destination directory is not empty: {0}")]
    DestinationNotEmpty(PathBuf),

    #[error("failed to open storage engine: {0}")]
    EngineOpen(#[from] EngineOpenError),
    #[cfg(any(not(feature = "surrealkv"), not(feature = "mdbx")))]
    #[error("storage engine '{engine}' requires feature '{feature}'")]
    EngineNotCompiled {
        engine: String,
        feature: &'static str,
    },

    #[error("digest mismatch in namespace '{namespace}', family '{family}'")]
    DigestMismatch { namespace: String, family: String },

    #[error("storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("incompatible or corrupt storage data: {0}")]
    IncompatibleData(String),

    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    #[error("missing complete chainstate checkpoint; resync into a new datadir is required")]
    MissingCheckpoint,

    #[error("missing block or undo data at height {height}; resync into a new datadir is required")]
    MissingBlockData { height: u32 },

    #[error(
        "replayed chain does not match the copied durable head: {field} expected {expected}, found {found}"
    )]
    ReplayMismatch {
        field: &'static str,
        expected: String,
        found: String,
    },

    #[error("checkpoint artifact '{file}' does not match the manifest digest")]
    CheckpointDigestMismatch { file: &'static str },

    #[error("checkpoint does not match its manifest: {field} expected {expected}, found {found}")]
    CheckpointMismatch {
        field: &'static str,
        expected: String,
        found: String,
    },

    #[error("checkpoint publication at the durable head failed: {0}")]
    CheckpointPublish(#[source] bitcoin_rs_execution::recovery::ConvertedCheckpointError),
}
