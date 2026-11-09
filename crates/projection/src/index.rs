mod block;
mod capability;
mod error;
mod filters;
mod prepared;
mod reader;
mod rows;
mod snapshot;
mod state;
mod tail_writes;
mod write;

pub(crate) use block::NoSpentScripts;
#[cfg(test)]
pub(crate) use block::{BodyFacts, committed_block_from_body};
pub use block::{MAX_LIVE_SCRIPT_SIZE, SpentCoin, SpentCoins};
pub(crate) use capability::read_coverage_floor;
pub use capability::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};
pub use error::IndexError;
pub use filters::BasicFilter;
pub use prepared::{PreparedBatch, PreparedBatchLimits, PreparedBlock};
pub use reader::Indexer;
pub use rows::IndexRowCounts;
pub use snapshot::{
    IndexReader, ScriptLiveScan, TxIndexPage, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use state::{ConsumerCursorUpdate, IndexWriteFence};
pub use write::IndexWriter;
pub use write::index_format_version;

#[cfg(test)]
mod tests;
