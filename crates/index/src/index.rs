//! Confirmed transaction indexing with separate read, preparation, and durable-write owners.

mod block;
mod capability;
mod error;
mod format;
mod prepared;
mod reader;
mod resolve;
mod rows;
mod snapshot;
mod state;
mod write;

pub use block::{MAX_LIVE_SCRIPT_SIZE, NoSpentScripts, SpentCoinScripts};
pub use capability::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};
pub use error::IndexError;
pub use format::{INDEX_FORMAT_VERSION, IndexFormat};
pub use prepared::{PreparedBatch, PreparedBatchLimits, PreparedBlock};
pub use reader::Indexer;
pub use resolve::{BlockSource, ScriptHistoryEntry};
pub use rows::IndexRowCounts;
pub use snapshot::{IndexReader, ScriptLiveScan, TxIndexScan, TxIndexScanRow, TxIndexSnapshot};
pub use state::{ConsumerCursorUpdate, IndexWriteFence};
pub use write::IndexWriter;

#[cfg(all(test, feature = "rocksdb"))]
mod tests;
