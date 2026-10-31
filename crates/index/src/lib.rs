#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, verification))]
pub(crate) mod projection_model;

pub mod block_log;
pub use block_log::{BlockLog, BlockLogReader, BlockRecord};
mod capabilities;
mod index;
pub mod portable;
pub mod query_api;
pub mod reconcile;
pub mod runtime;
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
    SCRIPT_HISTORY_PAGE_MAX, ScriptHistoryPage, ScriptHistoryRecord, ScriptIndexQuery,
    ScriptIndexRecord, ScriptIndexSnapshot, SpendingRecord, TxQueryError, TxUnavailableCause,
};
pub use types::{
    HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefixRow, ScriptHash, ScriptHashRow, ScriptLiveRow,
    SpendingPrefixRow,
};
