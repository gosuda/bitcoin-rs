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
pub(crate) use block::{BodyFacts, committed_block_from_image, parse_body};
pub use block::{MAX_LIVE_SCRIPT_SIZE, SpentCoin, SpentCoins};
pub(crate) use capability::put_bulk_publish_marks;
pub(crate) use capability::read_coverage_floor;
pub use capability::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};
pub use error::IndexError;
pub use filters::BasicFilter;
pub use prepared::{PreparedBatch, PreparedBatchLimits, PreparedBlock};
pub use reader::Indexer;
pub use snapshot::{
    IndexReader, ScriptLiveScan, TxIndexPage, TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use state::{ConsumerCursorUpdate, IndexWriteFence};
pub use write::IndexWriter;
pub use write::index_format_version;
pub(crate) use write::{rollback_prepare_capabilities, tail_rollback_group};

#[cfg(test)]
mod filter_build_tests;
#[cfg(test)]
mod tail_gate_tests;
#[cfg(test)]
mod tests;
