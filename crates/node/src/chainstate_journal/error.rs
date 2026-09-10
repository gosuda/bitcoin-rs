//! Shared typed failures for journal storage and head decoding.

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum JournalWriterError {
    /// Underlying filesystem error (segment append, sync, rename, ...).
    #[error("chainstate journal writer io error: {0}")]
    Io(#[from] std::io::Error),
    /// The storage flush dependency failed at a durability boundary.
    #[error("chainstate journal storage flush failed: {0}")]
    StorageFlush(String),
    /// Appends are not accepted in the writer's current state.
    #[error("chainstate journal writer is not open for appends: {state}")]
    NotOpen { state: &'static str },
    /// A record was appended whose height does not continue the journal.
    #[error("chainstate journal append out of order: got {got}, expected {expected}")]
    OutOfOrder { got: u32, expected: u32 },
    /// A live block advanced after its journal append failed. Further applies
    /// must stop until restart recovery discards the partial tail.
    #[error("chainstate journal has an untracked append gap at height {height}")]
    AppendGap { height: u32 },
    /// `head.json` is missing, unreadable, or fails its checksum.
    #[error("chainstate journal head marker is unreadable: {0}")]
    HeadUnreadable(String),
    /// The active segment does not match the durable cursor it claims.
    #[error("chainstate journal cursor mismatch: {0}")]
    CursorMismatch(String),
    /// Retained segment bytes reached the configured compaction budget.
    #[error("chainstate journal size {bytes} bytes reached configured limit {limit} bytes")]
    RetentionLimit { bytes: u64, limit: u64 },
    /// A reorg crossed below the checkpoint base this journal presupposes.
    #[error("journal fork height {fork_height} is below checkpoint base {base_height}")]
    ForkBelowBase { fork_height: u32, base_height: u32 },
}
