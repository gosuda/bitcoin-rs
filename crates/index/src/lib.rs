#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Confirmed block indexing over the workspace key-value store.
pub mod index;
/// Unconfirmed transaction row writing over the workspace key-value store.
pub mod mempool;
/// Derived-index reconciliation phase and exact capability watermark alignment.
pub mod reconcile;
/// Open-time recovery for disposable derived index storage.
pub mod recovery;
/// Stable electrs-shaped row types.
pub mod types;
/// Object-safe, fenced access to the durable index writer.
pub mod writer;

pub use index::{
    BlockSource, ConsumerCursorUpdate, INDEX_FORMAT_VERSION, IndexCapabilities, IndexCapability,
    IndexError, IndexFormat, IndexReader, IndexRowCounts, IndexWatermark, IndexWatermarks,
    IndexWriteFence, IndexWriter, Indexer, MAX_LIVE_SCRIPT_SIZE, NoSpentScripts, PreparedBatch,
    PreparedBatchLimits, PreparedBlock, ScriptHistoryEntry, ScriptLiveScan, SpentCoinScripts,
    TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use mempool::{MempoolRowCounts, MempoolRowWriter};
pub use types::{
    HASH_PREFIX_LEN, HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefix, HashPrefixRow, HeaderRow,
    SCRIPT_LIVE_ROW_SIZE, ScriptHash, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow, TxidRow,
};
