#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Applied-block records shared with derived-index readers.
pub mod block_log;
/// Core-compatible capability status projection.
mod capabilities;
/// Confirmed block indexing over the workspace key-value store.
mod index;
/// Derived-index query contracts shared with surface adapters.
pub mod query_api;
/// Derived-index reconciliation phase and exact capability watermark alignment.
pub mod reconcile;
/// Open-time recovery for disposable derived index storage.
mod recovery;
/// Asynchronous durable derived-index runtime.
pub mod runtime;
/// Stable electrs-shaped row types.
pub mod types;
/// Object-safe, fenced access to the durable index writer.
pub mod writer;

pub use capabilities::{
    CapabilitySnapshot, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    TXINDEX_CAPABILITY, derived_index_status, disabled_txindex, txindex_snapshot,
};
pub use index::{
    BlockSource, ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexReader,
    IndexRowCounts, IndexWatermark, IndexWatermarks, IndexWriteFence, IndexWriter, Indexer,
    MAX_LIVE_SCRIPT_SIZE, NoSpentScripts, PreparedBatch, PreparedBatchLimits, PreparedBlock,
    ScriptHistoryEntry, ScriptLiveScan, SpentCoinScripts, TxIndexScan, TxIndexScanRow,
    TxIndexSnapshot,
};
pub use query_api::{
    DerivedIndexInfo, DerivedIndexQuery, RollbackWarningSource, ScriptHistoryRecord,
    ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, SpendingRecord, TxQueryError,
};
pub use types::{
    HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefixRow, ScriptHash, ScriptHashRow, ScriptLiveRow,
    SpendingPrefixRow,
};
