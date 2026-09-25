//! Deletion of historical block bodies and undo records, once the active
//! chain no longer needs them.
//!
//! This lives in `storage` rather than in a crate of its own (issue #164)
//! because it is a retention policy over the rows this crate already owns.
//! Its former crate declared `bitcoin-rs-utxo`, `bitcoin-rs-chain` and
//! `bitcoin` as dependencies and referenced none of them: the only things it
//! ever touched were this crate and `Hash256`.
//!
//! [`crate::pruning::stage_block_and_undo_prune`] is the main entry point. It stages
//! block-body and undo-row deletion together with prune-height metadata into
//! one caller-owned atomic batch, so node wiring commits them in a single
//! backend commit. Both kinds of data are pruned against the durable tip
//! rather than the in-memory tip: a crash restores to the last durable
//! checkpoint, and bodies between that base and the crash-recovery sidecar tip
//! are evidence needed for local replay while undo records are needed to
//! disconnect back through the restored chain. After the index rows commit,
//! [`crate::pruning::reclaim_staged_flat_block_files`] deletes the staged flat block files,
//! and [`crate::pruning::PruneOutcome`] reports the bytes and row counts freed.
//!
//! Rows pinned by a live [`RetentionLease`] are never staged: the policy
//! line folds with the registry's retention floor before any deletion is
//! selected, so a reader holding a lease keeps exactly its required history.
//!
//! [`crate::pruning::PrunePolicy`] carries no behaviour of its own: the node builds one from
//! configuration and hands it in, which is the policy/mechanism split this
//! module keeps.
//!
//! Note that [`crate::pruning::block_body_key`] and [`crate::pruning::BLOCK_DATA_CF`] are not only pruning
//! concerns -- they are the block-body key schema, and the node reads bodies
//! through them on the ordinary path. That is the sharper reason this is a
//! storage module: the schema was living in the crate that deletes rows.

use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use core::mem::size_of;

/// Block-body pruning over persisted block rows.
pub mod block_pruner;
/// Retention leases that keep required history against pruning.
pub mod lease;
/// Pruning policy shapes matching Bitcoin Core semantics.
pub mod policy;
/// Undo-data pruning over persisted undo rows.
pub mod undo_pruner;

pub use block_pruner::{BLOCK_DATA_CF, BlockPruner, block_body_key};
pub use lease::{RetentionError, RetentionLease, RetentionRegistry};
pub use policy::PrunePolicy;
pub use undo_pruner::{UndoPruner, block_undo_key};

use crate::{BufferedWriteBatch, StorageError};
use thiserror::Error;

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";

/// Loads the persisted manual-prune line.
pub fn load_pruneheight<S: crate::KvStore>(store: &S) -> Result<Option<u32>, StorageError> {
    let Some(bytes) = store.get(crate::ColumnFamily::UtxoMeta, PRUNEHEIGHT_METADATA_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != size_of::<u32>() {
        return Err(StorageError::IncompatibleData(format!(
            "invalid persisted pruneheight length {}",
            bytes.len()
        )));
    }
    let mut encoded = [0_u8; size_of::<u32>()];
    encoded.copy_from_slice(&bytes);
    Ok(Some(u32::from_be_bytes(encoded)))
}

/// What one pruning pass staged for its caller's atomic batch.
///
/// [`stage_block_and_undo_prune`] fills this; the caller commits the batch,
/// reclaims the flat files, and then records [`StagedPrune::pruned_below`]
/// through [`RetentionRegistry::record_pruned_below`] so later lease
/// requests learn what is actually gone.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StagedPrune {
    /// Block-body rows the batch deletes.
    pub blocks: PruneOutcome,
    /// Undo rows the batch deletes.
    pub undo: PruneOutcome,
    /// Flat block files to reclaim after the batch commits.
    pub file_numbers: Vec<u32>,
    /// One past the highest deleted row height; zero when the pass staged
    /// nothing. This is the value to record through
    /// [`RetentionRegistry::record_pruned_below`]: floors at or below it
    /// may name deleted rows, floors above it name rows the pass left.
    pub pruned_below: u32,
}

/// One manual prune pass: clamps the line under the Core reorg margin, stages
/// rows, persists the prune height in the same batch, commits, records the
/// line, and reclaims files.
pub fn prune_to_height<S: crate::KvStore>(
    store: &S,
    block_files: &crate::FlatFileBlockStore,
    retention: &RetentionRegistry,
    applied_tip_height: u32,
    durable_tip_height: u32,
    pruneheight: u32,
    before_commit: impl FnOnce(u32) -> Result<(), StorageError>,
) -> Result<StagedPrune, PruneError> {
    let safe_prune_height = applied_tip_height.saturating_sub(CORE_REORG_SAFETY_MARGIN);
    if pruneheight > safe_prune_height {
        // The requested line would delete blocks still inside Core's reorg margin.
        return Err(
            StorageError::InvalidOperation("prune height is within reorg safety margin").into(),
        );
    }
    let pruner_tip = pruneheight + CORE_REORG_SAFETY_MARGIN;

    let mut batch = store.new_batch();
    let staged = stage_block_and_undo_prune(
        store,
        &mut batch,
        block_files,
        pruner_tip,
        durable_tip_height,
        PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: CORE_REORG_SAFETY_MARGIN,
        },
        retention,
    )?;
    before_commit(staged.pruned_below)?;
    batch.put(
        crate::ColumnFamily::UtxoMeta,
        PRUNEHEIGHT_METADATA_KEY,
        &pruneheight.to_be_bytes(),
    );
    store.write(batch)?;
    // Record before reclaim: acquiring a lease takes no transition lock,
    // so a lease granted between the committing write and this record
    // could otherwise pin rows the batch already deleted. Reclaim only
    // ever deletes files this recorded line already covers.
    retention.record_pruned_below(staged.pruned_below);
    reclaim_staged_flat_block_files(store, block_files, &staged.file_numbers)?;
    Ok(staged)
}

/// Stages block-body and undo-row pruning into a caller-owned atomic batch.
///
/// This is intentionally narrow: node wiring uses it to combine manual-prune
/// row deletion with prune-height metadata in one backend commit.
///
/// `durable_tip_height` is the height the node would restore to after a
/// crash. Both block bodies and undo records are pruned against it rather
/// than against `current_tip_height`, because the in-memory applied tip can
/// run far ahead of the last durable checkpoint. Bodies above this base may
/// be named by the crash-recovery sidecar and must remain available for
/// local replay; undo records below the base would prevent a restored chain
/// from disconnecting its own tip.
///
/// The pass never deletes rows pinned by a live [`RetentionLease`]: the
/// policy line is folded with [`RetentionRegistry::retention_floor`]. The
/// line reported in [`StagedPrune::pruned_below`] is one past the highest
/// row the pass actually staged — a byte target that stops early, or one
/// already met, leaves nothing to record.
pub fn stage_block_and_undo_prune<S: crate::KvStore>(
    store: &S,
    batch: &mut BufferedWriteBatch,
    block_files: &crate::FlatFileBlockStore,
    current_tip_height: u32,
    durable_tip_height: u32,
    policy: PrunePolicy,
    retention: &RetentionRegistry,
) -> Result<StagedPrune, PruneError> {
    if policy.is_full_node() {
        return Ok(StagedPrune::default());
    }

    let durable_tip = current_tip_height.min(durable_tip_height);
    let policy_line = durable_tip.saturating_sub(policy.retention_depth());
    // The retention floor binds before the byte target does: a lease holder
    // proved it needs rows at or above its floor, so the line stops there
    // even when the pass could free more below it.
    let prune_line = policy_line.min(retention.retention_floor().unwrap_or(u32::MAX));
    let (blocks, file_numbers) =
        block_pruner::stage_flat_block_file_prune(store, batch, block_files, prune_line, policy)?;
    let undo = block_pruner::prune_prefixed_rows_into_batch(
        store,
        batch,
        undo_pruner::BLOCK_UNDO_CF,
        undo_pruner::BLOCK_UNDO_PREFIX_BYTES,
        // The lease-clamped line, not a fresh derivation: the whole pass
        // must delete through one line, or a lease would hold block bodies
        // while their undo records delete around them (or the reverse).
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
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    /// Number of payload bytes deleted from storage.
    pub bytes_freed: u64,
    /// Number of block or undo rows deleted from storage.
    pub blocks_removed: u64,
    /// Highest row height the pass staged for deletion, if any. A pass
    /// whose byte target is met stops above rows it leaves behind, so
    /// this — not the requested line — is what a completed pass may claim
    /// as gone.
    pub max_height: Option<u32>,
}

impl PruneOutcome {
    /// Adds one deleted row to the outcome.
    pub(crate) fn record_removed(&mut self, bytes: u64, height: u32) {
        self.bytes_freed = self.bytes_freed.saturating_add(bytes);
        self.blocks_removed = self.blocks_removed.saturating_add(1);
        self.max_height = Some(self.max_height.map_or(height, |seen| seen.max(height)));
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
