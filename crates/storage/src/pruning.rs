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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicy {
    pub target_size_mb: u64,
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

pub fn load_pruneheight<S: crate::KvStore>(store: &S) -> Result<Option<u32>, StorageError> {
    load_u32_metadata(store, PRUNEHEIGHT_METADATA_KEY, "pruneheight")
}

pub fn load_executed_frontier<S: crate::KvStore>(
    store: &S,
) -> Result<Option<ExecutedFrontier>, StorageError> {
    let height = load_u32_metadata(store, PRUNE_EXECUTED_METADATA_KEY, "prune frontier")?;
    Ok(height.map(ExecutedFrontier::new))
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ExecutedFrontier(u32);

impl ExecutedFrontier {
    pub const NONE: Self = Self(0);

    #[must_use]
    pub const fn new(height: u32) -> Self {
        Self(height)
    }

    #[must_use]
    pub(crate) const fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub(crate) const fn advance(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }

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

#[derive(Debug, Default)]
pub struct StagedPrune {
    pub blocks: PruneOutcome,
    pub undo: PruneOutcome,
    pub file_numbers: Vec<u32>,
    pub pruned_below: u32,
}

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

#[derive(Copy, Clone, Debug, Default)]
pub struct PruneOutcome {
    pub bytes_freed: u64,
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

#[derive(Debug, Error)]
pub enum PruneError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("storage row length {size} does not fit in u64")]
    RowSizeOverflow {
        size: usize,
    },
}

pub(crate) fn row_len_u64(value: &[u8]) -> Result<u64, PruneError> {
    u64::try_from(value.len()).map_err(|_| PruneError::RowSizeOverflow { size: value.len() })
}
