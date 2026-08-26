//! Deletion of historical block bodies and undo records, once the active
//! chain no longer needs them.
//!
//! This lives in `storage` rather than in a crate of its own (issue #164)
//! because it is a retention policy over the rows this crate already owns.
//! Its former crate declared `bitcoin-rs-utxo`, `bitcoin-rs-chain` and
//! `bitcoin` as dependencies and referenced none of them: the only things it
//! ever touched were this crate and `Hash256`.
//!
//! [`stage_block_and_undo_prune`] is the main entry point. It stages
//! block-body and undo-row deletion together with prune-height metadata into
//! one caller-owned atomic batch, so node wiring commits them in a single
//! backend commit. Undo rows are pruned against the durable tip rather than
//! the in-memory tip -- a crash restores to the last durable checkpoint and
//! must still be able to disconnect back through it, while block bodies are
//! re-downloadable and are not held to that constraint. After the index rows
//! commit, [`reclaim_staged_flat_block_files`] deletes the staged flat block
//! files, and [`PruneOutcome`] reports the bytes and row counts freed.
//!
//! [`PrunePolicy`] carries no behaviour of its own: the node builds one from
//! configuration and hands it in, which is the policy/mechanism split this
//! module keeps.
//!
//! Note that [`block_body_key`] and [`BLOCK_DATA_CF`] are not only pruning
//! concerns -- they are the block-body key schema, and the node reads bodies
//! through them on the ordinary path. That is the sharper reason this is a
//! storage module: the schema was living in the crate that deletes rows.

/// Block-body pruning over persisted block rows.
pub mod block_pruner;
/// Pruning policy shapes matching Bitcoin Core semantics.
pub mod policy;
/// Undo-data pruning over persisted undo rows.
pub mod undo_pruner;

pub use block_pruner::{BLOCK_DATA_CF, BlockPruner, block_body_key};
pub use policy::PrunePolicy;
pub use undo_pruner::{UndoPruner, block_undo_key};

use crate::{StorageError, WriteBatch as _};
use thiserror::Error;

/// Stages block-body and undo-row pruning into a caller-owned atomic batch.
///
/// This is intentionally narrow: node wiring uses it to combine manual-prune
/// row deletion with prune-height metadata in one backend commit.
#[doc(hidden)]
/// `durable_tip_height` is the height the node would restore to after a crash.
///
/// Undo records are pruned against it rather than against `current_tip_height`,
/// because the in-memory applied tip can run far ahead of the last durable
/// checkpoint. Pruning to the in-memory tip can delete the undo record for the
/// block the checkpoint names, and a crash then restores a chainstate that
/// cannot disconnect its own tip: the reorg fails with `UndoRecordMissing`.
/// Block bodies do not need this — they are re-downloadable, and undo records
/// are not.
pub fn stage_block_and_undo_prune<S: crate::KvStore>(
    store: &S,
    batch: &mut S::WriteBatch,
    block_files: &crate::FlatFileBlockStore,
    current_tip_height: u32,
    durable_tip_height: u32,
    policy: PrunePolicy,
) -> Result<(PruneOutcome, PruneOutcome, Vec<u32>), PruneError> {
    if policy.is_full_node() {
        return Ok((PruneOutcome::default(), PruneOutcome::default(), Vec::new()));
    }

    let prune_below_height = current_tip_height.saturating_sub(policy.retention_depth());
    let (block_outcome, block_files) = block_pruner::stage_flat_block_file_prune(
        store,
        batch,
        block_files,
        prune_below_height,
        policy,
    )?;
    let undo_outcome = block_pruner::prune_prefixed_rows_into_batch(
        store,
        batch,
        undo_pruner::BLOCK_UNDO_CF,
        undo_pruner::BLOCK_UNDO_PREFIX_BYTES,
        // The lower of the two tips, with the retention depth then subtracted
        // by the callee. Adding the depth to the durable tip first would prune
        // undo records within the reorg-safety margin of it, and that margin is
        // exactly the guarantee being protected: a restore to the durable tip
        // must be able to disconnect back through it.
        current_tip_height.min(durable_tip_height),
        policy,
    )?;

    Ok((block_outcome, undo_outcome, block_files))
}

/// Deletes staged flat block files after their block-index rows are committed.
#[doc(hidden)]
pub fn reclaim_staged_flat_block_files<S: crate::KvStore>(
    store: &S,
    block_files: &crate::FlatFileBlockStore,
    file_numbers: &[u32],
) -> Result<(), PruneError> {
    let mut batch = store.new_batch();
    let mut removed_metadata = false;
    for &file_no in file_numbers {
        if file_no == block_files.current_file_number() {
            continue;
        }
        let _ = block_files.delete_file_if_not_current(file_no)?;
        batch.delete(
            block_pruner::BLOCK_DATA_CF,
            &crate::block_file_max_height_key(file_no),
        );
        removed_metadata = true;
    }
    if removed_metadata {
        store.write(batch)?;
    }
    Ok(())
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
