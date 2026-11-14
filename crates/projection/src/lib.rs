#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, verification, kani))]
pub(crate) mod projection_model;

pub mod block_log;
pub use block_log::{BlockLog, BlockLogReader, BlockRecord};
mod capabilities;
mod index;
pub mod offline;
pub mod portable;
pub use portable::{ManifestArtifactTarget, attach_tx_lookup_artifact};
pub mod query_api;
pub mod reconcile;
pub mod runtime;
pub mod segment;
#[cfg(feature = "silent-payments")]
pub mod silent_payments;
pub mod snapshot_seed;
pub use writer::{
    CompactFilterAttachment, CompactFilterRow, ScriptHistoryAttachment, TxIndexWriter,
    TxLookupAttachment,
};
pub mod types;
mod writer;

pub use capabilities::{
    CapabilitySnapshot, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    derived_index_status, txindex_snapshot,
};
pub(crate) use index::NoSpentScripts;
pub use index::{
    BasicFilter, ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexReader,
    IndexWatermark, IndexWatermarks, IndexWriteFence, IndexWriter, Indexer, MAX_LIVE_SCRIPT_SIZE,
    PreparedBatch, PreparedBatchLimits, PreparedBlock, ScriptLiveScan, SpentCoin, SpentCoins,
    TxIndexPage, TxIndexScan, TxIndexScanRow, TxIndexSnapshot, index_format_version,
};
pub use offline::{IndexResetReport, reset_offline};
pub use query_api::{
    Answer, AppliedEpoch, CapabilityCoverage, CompactFilterQuery, CoveredPrefix, DerivedIndexInfo,
    DerivedIndexQuery, QueryMiss, RetryReason, RollbackWarningSource, SCRIPT_HISTORY_PAGE_MAX,
    ScriptHistoryPage, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord,
    ScriptIndexSnapshot, SpendingRecord, TransactionBlock, TxQueryError, TxUnavailableCause,
    VerificationState,
};
pub use reconcile::{CURSOR_BYTE_LEN, ConsumerCursor, CursorDecodeError};
pub use types::{
    HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefixRow, INDEX_FORMAT_VERSION_KEY,
    INDEX_FORMAT_VERSION_VALUE, ScriptHash, ScriptHashRow, ScriptHistoryOccurrence, ScriptLiveCoin,
    ScriptLiveRow, ScriptLiveValueError, SpendingPrefixRow, TxPosition, TxPositionValue,
    positions_are_valid,
};
