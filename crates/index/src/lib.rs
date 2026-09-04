#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Confirmed block indexing over the workspace key-value store.
pub mod index;
/// Unconfirmed transaction row writing over the workspace key-value store.
pub mod mempool;
/// Stable compact row types.
pub mod types;

pub use index::{
    BlockSource, ConsumerCursorUpdate, IndexCapabilities, IndexCapability, IndexError, IndexReader,
    IndexFormat, IndexRowCounts, IndexWatermark, IndexWatermarks, IndexWriteFence, IndexWriter, Indexer,
    IndexerLike, MAX_LIVE_SCRIPT_SIZE, NoSpentScripts, PreparedBatch, PreparedBatchLimits,
    PreparedBlock, ScriptHistoryEntry, ScriptLiveScan, SpentCoinScripts, TxIndexScan,
    TxIndexScanRow, TxIndexSnapshot,
};
pub use mempool::{MempoolRowCounts, MempoolRowWriter};
pub use types::{
    HASH_PREFIX_LEN, HASH_PREFIX_ROW_SIZE, HEADER_KEY_SIZE, HEADER_ROW_SIZE, HashPrefix,
    HashPrefixRow, HeaderRow, SCRIPT_LIVE_ROW_SIZE, ScriptHash, ScriptHashRow, ScriptLiveRow,
    SpendingPrefixRow, TxidRow,
};
