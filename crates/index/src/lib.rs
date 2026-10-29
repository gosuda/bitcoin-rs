#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Applied-block records shared with derived-index readers.
pub mod block_log;
pub use block_log::{BlockLog, BlockLogReader, BlockRecord};
/// Core-compatible capability status projection.
mod capabilities;
/// Confirmed block indexing over the workspace key-value store.
mod index;
/// Portable, versioned index bundles: export and fenced restore of `TxLookup` rows.
pub mod portable;
/// Derived-index query contracts shared with surface adapters.
pub mod query_api;
/// Derived-index reconciliation phase and exact capability watermark alignment.
pub mod reconcile;
/// Asynchronous durable derived-index runtime.
pub mod runtime;
/// Experimental, keyless BIP352 public scan material (no durable index or HTTP routes).
#[cfg(feature = "silent-payments")]
pub mod silent_payments;
/// Stable electrs-shaped row types.
pub mod types;
/// Object-safe, fenced access to the durable index writer.
mod writer;

pub use capabilities::{
    CapabilitySnapshot, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    derived_index_status, txindex_snapshot,
};
pub(crate) use index::NoSpentScripts;
pub use index::{
    BasicFilter, ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexReader,
    IndexRowCounts, IndexWatermark, IndexWatermarks, IndexWriteFence, IndexWriter, Indexer,
    MAX_LIVE_SCRIPT_SIZE, PreparedBatch, PreparedBatchLimits, PreparedBlock, ScriptLiveScan,
    SpentCoinScripts, TxIndexFamily, TxIndexPage, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use query_api::{
    CompactFilterQuery, DerivedIndexInfo, DerivedIndexQuery, RollbackWarningSource,
    ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, SpendingRecord,
    TxQueryError, TxUnavailableCause,
};
pub use types::{
    HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefixRow, ScriptHash, ScriptHashRow, ScriptLiveRow,
    SpendingPrefixRow,
};
