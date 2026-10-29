#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod block_log;
pub use block_log::{BlockLog, BlockLogReader, BlockRecord};
mod capabilities;
mod index;
pub mod portable;
pub mod query_api;
pub mod reconcile;
pub mod runtime;
/// Experimental, keyless BIP352 public scan material (no durable index or HTTP routes).
#[cfg(feature = "silent-payments")]
pub mod silent_payments;
pub mod types;
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
