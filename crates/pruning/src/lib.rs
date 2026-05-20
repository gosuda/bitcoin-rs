#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Block-body pruning over persisted block rows.
pub mod block_pruner;
/// Pruning policy shapes matching Bitcoin Core semantics.
pub mod policy;
/// Undo-data pruning over persisted undo rows.
pub mod undo_pruner;
/// Utreexo-only block body deletion coordinator.
pub mod utreexo_only;

pub use block_pruner::{BlockPruner, block_body_key};
pub use policy::PrunePolicy;
pub use undo_pruner::{UndoPruner, block_undo_key};
pub use utreexo_only::{BlockProcessed, UtreexoOnlyCoordinator};

use bitcoin_rs_storage::StorageError;
use thiserror::Error;

/// Stages block-body and undo-row pruning into a caller-owned atomic batch.
///
/// This is intentionally narrow: node wiring uses it to combine manual-prune
/// row deletion with prune-height metadata in one backend commit.
#[doc(hidden)]
pub fn stage_block_and_undo_prune<S: bitcoin_rs_storage::KvStore>(
    store: &S,
    batch: &mut S::WriteBatch,
    current_tip_height: u32,
    policy: PrunePolicy,
) -> Result<(PruneOutcome, PruneOutcome), PruneError> {
    if policy.is_full_node() {
        return Ok((PruneOutcome::default(), PruneOutcome::default()));
    }

    let block_outcome = block_pruner::prune_prefixed_rows_into_batch(
        store,
        batch,
        block_pruner::BLOCK_BODY_PREFIX_BYTES,
        current_tip_height,
        policy,
    )?;
    let undo_outcome = block_pruner::prune_prefixed_rows_into_batch(
        store,
        batch,
        undo_pruner::BLOCK_UNDO_PREFIX_BYTES,
        current_tip_height,
        policy,
    )?;

    Ok((block_outcome, undo_outcome))
}

/// Result of one pruning pass.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    /// Number of payload bytes deleted from storage.
    pub bytes_freed: u64,
    /// Number of block or undo rows deleted from storage.
    pub blocks_removed: u64,
}

impl PruneOutcome {
    /// Adds one deleted row to the outcome.
    pub(crate) const fn record_removed(&mut self, bytes: u64) {
        self.bytes_freed = self.bytes_freed.saturating_add(bytes);
        self.blocks_removed = self.blocks_removed.saturating_add(1);
    }

    /// Returns true when no rows were deleted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.blocks_removed == 0
    }
}

/// Errors returned while pruning persisted block or undo rows.
#[derive(Debug, Error)]
pub enum PruneError {
    /// A storage backend operation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A storage row length could not fit in the pruning byte counter.
    #[error("storage row length {size} does not fit in u64")]
    RowSizeOverflow {
        /// Row length returned by the storage backend.
        size: usize,
    },
}

pub(crate) fn row_len_u64(value: &[u8]) -> Result<u64, PruneError> {
    u64::try_from(value.len()).map_err(|_| PruneError::RowSizeOverflow { size: value.len() })
}
