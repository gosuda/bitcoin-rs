//! Confirmed transaction indexing with separate read, preparation, and durable-write owners.

mod block;
mod capability;
mod error;
mod filters;
mod prepared;
mod reader;
mod rows;
mod snapshot;
mod state;
mod write;

pub(crate) use block::NoSpentScripts;
pub use block::{MAX_LIVE_SCRIPT_SIZE, SpentCoinScripts};
pub use capability::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};
pub use error::IndexError;
pub use filters::BasicFilter;
pub use prepared::{PreparedBatch, PreparedBatchLimits, PreparedBlock};
pub use reader::Indexer;
pub use rows::IndexRowCounts;
#[cfg(test)]
pub(crate) use snapshot::RowVisitor;
pub use snapshot::{
    IndexReader, ScriptLiveScan, TxIndexFamily, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use state::{ConsumerCursorUpdate, IndexWriteFence};
pub use write::IndexWriter;
pub(crate) use write::{PortableImportRow, index_format_version};

#[cfg(all(test, feature = "rocksdb"))]
mod tests;
