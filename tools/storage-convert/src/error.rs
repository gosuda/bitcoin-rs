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

    #[error("snapshot archive for base {base} failed verification: {reason}")]
    SnapshotArchiveInvalid { base: String, reason: String },

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

    #[error("block file '{file}' record {index} has bad magic")]
    BadBlockMagic { file: String, index: u64 },

    #[error("block file '{file}' is truncated inside record {index}")]
    TruncatedBlockRecord { file: String, index: u64 },

    #[error(
        "block file '{file}' record {index} declares a {len}-byte body over the {max}-byte record limit"
    )]
    OversizeBlockRecord {
        file: String,
        index: u64,
        len: u32,
        max: u64,
    },

    #[error("block {hash} at height {height} is not a readable block: {reason}")]
    UnparseableBlock {
        height: u32,
        hash: String,
        reason: String,
    },

    #[error(
        "block record at height {height} stores hash {recorded} but its header hashes to {computed}"
    )]
    BlockHashMismatch {
        height: u32,
        recorded: String,
        computed: String,
    },

    #[error(
        "block record {hash} at height {height} conflicts with an earlier record of the same hash"
    )]
    ConflictingBlockRecord { height: u32, hash: String },

    #[error("chainstate holds no durable head, but the block archive holds records")]
    MissingDurableHead,

    #[error("the durable head block {hash} at height {height} is not in the block archive")]
    MissingTipRecord { height: u32, hash: String },

    #[error("block {hash} at height {height} is not connected to the canonical chain: {reason}")]
    CanonicalChainBroken {
        height: u32,
        hash: String,
        reason: &'static str,
    },

    #[error(
        "block {hash} is recorded at height {recorded} but the canonical chain places it at height {expected}"
    )]
    BlockHeightMismatch {
        recorded: u32,
        expected: u32,
        hash: String,
    },

    #[error("no undo row restores prevout {txid}:{vout} spent in block {hash} at height {height}")]
    MissingUndoRow {
        height: u32,
        hash: String,
        txid: String,
        vout: u32,
    },

    #[error("undo row for block {hash} at height {height} is unreadable: {source}")]
    UnreadableUndoRow {
        height: u32,
        hash: String,
        source: bitcoin_rs_storage::utxo::contract::UndoCodecError,
    },

    #[error("bulk index build failed: {0}")]
    BulkBuild(#[from] bitcoin_rs_projection::segment::bulk_builder::BulkBuilderError),
}
