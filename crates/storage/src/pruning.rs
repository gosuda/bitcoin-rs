//! Deletion of historical block bodies and undo records, once the active
//! chain no longer needs them.
//!

use alloc::sync::Arc;
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use core::mem::size_of;

mod block_pruner;
mod lease;

pub use crate::undo::block_undo_key;
pub use block_pruner::{BLOCK_DATA_CF, block_body_key};
pub use lease::{
    HistoryAccess, HistoryLease, HistoryUnavailable, MandatoryRetention, PruneReservation,
    RetentionBudget, RetentionError, RetentionLease, RetentionRegistry,
};
const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Block and undo pruning policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicy {
    /// Target serialized block-data footprint in mebibytes.
    pub target_size_mb: u64,
    /// Caller-requested number of blocks retained below the active tip.
    pub keep_below_tip: u32,
}

impl PrunePolicy {
    #[must_use]
    pub const fn is_full_node(self) -> bool {
        self.target_size_mb == u64::MAX
    }

    #[must_use]
    pub const fn target_size_bytes(self) -> u64 {
        self.target_size_mb.saturating_mul(BYTES_PER_MIB)
    }

    #[must_use]
    pub fn retention_depth(self) -> u32 {
        self.keep_below_tip.max(CORE_REORG_SAFETY_MARGIN)
    }
}

use crate::{BufferedWriteBatch, StorageError};
use thiserror::Error;

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";
const PRUNE_EXECUTED_METADATA_KEY: &[u8] = b"node:prune_executed";
/// Monotonic per-pass receipt: each prune batch stores its sequence value,
/// so a failed `write_durable` can prove whether *this* batch applied even
/// when a retry repeats the same frontier and requested height.
const PRUNE_BATCH_METADATA_KEY: &[u8] = b"node:prune_batch";

/// Reads one big-endian `u32` metadata row from the UTXO meta family.
fn load_u32_metadata<S: crate::KvStore>(
    store: &S,
    key: &[u8],
    what: &str,
) -> Result<Option<u32>, StorageError> {
    let Some(bytes) = store.get(crate::ColumnFamily::UtxoMeta, key)? else {
        return Ok(None);
    };
    if bytes.len() != size_of::<u32>() {
        return Err(StorageError::IncompatibleData(format!(
            "invalid persisted {what} length {}",
            bytes.len()
        )));
    }
    let mut encoded = [0_u8; size_of::<u32>()];
    encoded.copy_from_slice(&bytes);
    Ok(Some(u32::from_be_bytes(encoded)))
}

fn load_prune_batch<S: crate::KvStore>(store: &S) -> Result<Option<u64>, StorageError> {
    let Some(bytes) = store.get(crate::ColumnFamily::UtxoMeta, PRUNE_BATCH_METADATA_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != size_of::<u64>() {
        return Err(StorageError::IncompatibleData(format!(
            "invalid persisted prune batch length {}",
            bytes.len()
        )));
    }
    let mut encoded = [0_u8; size_of::<u64>()];
    encoded.copy_from_slice(&bytes);
    Ok(Some(u64::from_be_bytes(encoded)))
}

/// Loads the persisted manual-prune line.
/// This is the operator's requested height: intent, and never proof that
/// rows were deleted. The deleted range is
/// [`load_executed_frontier`].
pub fn load_pruneheight<S: crate::KvStore>(store: &S) -> Result<Option<u32>, StorageError> {
    load_u32_metadata(store, PRUNEHEIGHT_METADATA_KEY, "pruneheight")
}

pub fn load_executed_frontier<S: crate::KvStore>(
    store: &S,
) -> Result<Option<ExecutedFrontier>, StorageError> {
    let height = load_u32_metadata(store, PRUNE_EXECUTED_METADATA_KEY, "prune frontier")?;
    Ok(height.map(ExecutedFrontier::new))
}

/// The durable, monotonic executed prune frontier: one past the highest
/// block-body or undo row a committed prune pass deleted.
///
/// PRE: [`Self::NONE`] is the state of a store that has deleted nothing.
///
/// POST: a pass writes its frontier inside the same batch as its row deletions, so the
/// record and the deletion commit together or not at all, and a restart reconstructs
/// exactly the committed boundary. INVARIANT: the frontier never moves backwards, every
/// height below it is gone, and no lease is granted below it, so no reader can pin rows
/// the frontier names as deleted.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExecutedFrontier(u32);

impl ExecutedFrontier {
    pub const NONE: Self = Self(0);

    #[must_use]
    pub const fn new(height: u32) -> Self {
        Self(height)
    }

    /// The raw height: one past the highest deleted row.
    #[must_use]
    pub(crate) const fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub(crate) const fn advance(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }

    /// Loads the committed frontier without inferring deletions from surviving rows.
    ///
    /// Absence is legitimate only before any pass committed. A missing frontier
    /// alongside either prune record is incompatible data, never an empty frontier.
    pub fn reconstruct<S: crate::KvStore>(store: &S) -> Result<Self, StorageError> {
        if let Some(frontier) = load_executed_frontier(store)? {
            return Ok(frontier);
        }
        if load_pruneheight(store)?.is_some() || load_prune_batch(store)?.is_some() {
            return Err(StorageError::IncompatibleData(
                "missing executed prune frontier; preserve this store and replay into a separately named datadir".into(),
            ));
        }
        Ok(Self::NONE)
    }
}

/// What one pruning pass staged for its caller's atomic batch.
#[derive(Debug, Default)]
pub struct StagedPrune {
    pub blocks: PruneOutcome,
    pub undo: PruneOutcome,
    pub file_numbers: Vec<u32>,
    pub pruned_below: u32,
}

/// One manual prune pass.
///
/// PRE: the caller holds the pruning authority, so passes do not overlap.
///
/// INVARIANT: no lease is granted below the line this pass deletes through, because the
/// reservation refuses such grants from the moment it is taken.
pub fn prune_to_height<S: crate::KvStore>(
    store: &S,
    block_files: &crate::FlatFileBlockStore,
    retention: &Arc<RetentionRegistry>,
    applied_tip_height: u32,
    durable_tip_height: u32,
    pruneheight: u32,
    before_commit: impl FnOnce(u32) -> Result<(), StorageError>,
) -> Result<StagedPrune, PruneError> {
    let safe_prune_height = applied_tip_height.saturating_sub(CORE_REORG_SAFETY_MARGIN);
    if pruneheight > safe_prune_height {
        return Err(
            StorageError::InvalidOperation("prune height is within reorg safety margin").into(),
        );
    }
    let pruner_tip = pruneheight + CORE_REORG_SAFETY_MARGIN;
    let policy = PrunePolicy {
        target_size_mb: 0,
        keep_below_tip: CORE_REORG_SAFETY_MARGIN,
    };
    let policy_line = pruner_tip
        .min(durable_tip_height)
        .saturating_sub(policy.retention_depth());
    let reservation = retention.reserve(policy_line);

    let mut batch = store.new_batch();
    let staged = stage_block_and_undo_prune(store, &mut batch, block_files, policy, &reservation)?;
    before_commit(staged.pruned_below)?;
    batch.put(
        crate::ColumnFamily::UtxoMeta,
        PRUNEHEIGHT_METADATA_KEY,
        &pruneheight.to_be_bytes(),
    );
    let executed =
        ExecutedFrontier::reconstruct(store)?.advance(ExecutedFrontier::new(staged.pruned_below));
    batch.put(
        crate::ColumnFamily::UtxoMeta,
        PRUNE_EXECUTED_METADATA_KEY,
        &executed.get().to_be_bytes(),
    );
    let receipt = load_prune_batch(store)?.unwrap_or(0).wrapping_add(1);
    batch.put(
        crate::ColumnFamily::UtxoMeta,
        PRUNE_BATCH_METADATA_KEY,
        &receipt.to_be_bytes(),
    );
    if let Err(error) = store.write_durable(batch) {
        return match (
            load_executed_frontier(store),
            load_pruneheight(store),
            load_prune_batch(store),
        ) {
            (Ok(Some(persisted)), Ok(Some(persisted_height)), Ok(Some(persisted_receipt)))
                if persisted.get() >= executed.get()
                    && persisted_height == pruneheight
                    && persisted_receipt == receipt =>
            {
                reservation.commit(persisted.get());
                reclaim_staged_flat_block_files(store, block_files, &staged.file_numbers)?;
                Ok(staged)
            }
            (Ok(_), Ok(_), Ok(_)) => Err(error.into()),
            _ => {
                reservation.fail_closed();
                Err(error.into())
            }
        };
    }
    reservation.commit(executed.get());
    reclaim_staged_flat_block_files(store, block_files, &staged.file_numbers)?;
    Ok(staged)
}

/// Stages block-body and undo-row pruning into a caller-owned atomic batch.
///
/// PRE: `reservation` was taken from the registry the pass commits through, with a line
/// derived from the durable tip and the policy's retention depth.
///
/// The pass deletes through [`PruneReservation::line`] and never re-derives it, so a
/// lease registered after the reservation cannot narrow the range this batch has
/// already staged.
pub fn stage_block_and_undo_prune<S: crate::KvStore>(
    store: &S,
    batch: &mut BufferedWriteBatch,
    block_files: &crate::FlatFileBlockStore,
    policy: PrunePolicy,
    reservation: &PruneReservation,
) -> Result<StagedPrune, PruneError> {
    if policy.is_full_node() {
        return Ok(StagedPrune::default());
    }

    let prune_line = reservation.line();
    let (blocks, file_numbers) =
        block_pruner::stage_flat_block_file_prune(store, batch, block_files, prune_line, policy)?;
    let undo = block_pruner::prune_prefixed_rows_into_batch(
        store,
        batch,
        crate::ColumnFamily::UndoData,
        crate::undo::BLOCK_UNDO_PREFIX_BYTES,
        prune_line,
        policy,
    )?;

    let pruned_below = blocks
        .max_height
        .max(undo.max_height)
        .map_or(0, |height| height.saturating_add(1));
    Ok(StagedPrune {
        blocks,
        undo,
        file_numbers,
        pruned_below,
    })
}

/// Deletes staged flat block files after their block-index rows are committed.
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
#[derive(Copy, Clone, Debug, Default)]
pub struct PruneOutcome {
    /// Number of payload bytes deleted from storage.
    pub bytes_freed: u64,
    /// Number of block or undo rows deleted from storage.
    pub blocks_removed: u64,
    pub max_height: Option<u32>,
}

impl PruneOutcome {
    pub(crate) fn record_removed(&mut self, bytes: u64, height: u32) {
        self.bytes_freed = self.bytes_freed.saturating_add(bytes);
        self.blocks_removed = self.blocks_removed.saturating_add(1);
        self.max_height = Some(self.max_height.map_or(height, |seen| seen.max(height)));
    }

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
