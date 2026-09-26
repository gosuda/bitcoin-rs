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
//! Rows pinned by a live [`RetentionLease`] are never staged: the pass
//! reserves its deletion line through [`RetentionRegistry::reserve`], which
//! folds every live lease floor into that line before any deletion is
//! selected, so a reader holding a lease keeps exactly its required
//! history.
//!
//! Three prune meanings stay separate. The *requested* height is operator
//! intent (`node:pruneheight`). The *effective* line is that intent folded
//! with reorg safety, live retention, and the byte target. The
//! [`ExecutedFrontier`] (`node:prune_executed`) is the durable, monotonic
//! fact of what a committed pass deleted, written in the same batch as its
//! deletions: it is what a restart reconstructs and what refuses a lease,
//! and no consumer infers it from the intent line.
//!
//! [`crate::pruning::PrunePolicy`] carries no behaviour of its own: the node builds one from
//! configuration and hands it in, which is the policy/mechanism split this
//! module keeps.
//!
//! Note that [`crate::pruning::block_body_key`] and [`crate::pruning::BLOCK_DATA_CF`] are not only pruning
//! concerns -- they are the block-body key schema, and the node reads bodies
//! through them on the ordinary path. That is the sharper reason this is a
//! storage module: the schema was living in the crate that deletes rows.

use alloc::sync::Arc;
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
pub use lease::{
    HistoryAccess, HistoryLease, HistoryUnavailable, PruneReservation, RetentionBudget,
    RetentionError, RetentionLease, RetentionRegistry,
};
pub use policy::PrunePolicy;
pub use undo_pruner::{UndoPruner, block_undo_key};

use crate::{StorageError, WriteBatch as _};
use thiserror::Error;

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";
const PRUNE_EXECUTED_METADATA_KEY: &[u8] = b"node:prune_executed";

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

/// Loads the persisted manual-prune line.
///
/// This is the operator's requested height: intent, and never proof that
/// rows were deleted. The deleted range is
/// [`load_executed_frontier`].
pub fn load_pruneheight<S: crate::KvStore>(store: &S) -> Result<Option<u32>, StorageError> {
    load_u32_metadata(store, PRUNEHEIGHT_METADATA_KEY, "pruneheight")
}

/// Loads the persisted executed prune frontier, when the record exists.
pub fn load_executed_frontier<S: crate::KvStore>(
    store: &S,
) -> Result<Option<ExecutedFrontier>, StorageError> {
    let height = load_u32_metadata(store, PRUNE_EXECUTED_METADATA_KEY, "prune frontier")?;
    Ok(height.map(ExecutedFrontier::new))
}

/// The durable, monotonic executed prune frontier: one past the highest
/// block-body or undo row a committed prune pass deleted.
///
/// This is the one authoritative answer to "what history is permanently
/// gone?". Three meanings stay distinct: the *requested* prune height is
/// operator intent (`node:pruneheight`); the *effective* prune line is that
/// intent folded with reorg safety, active retention, and the byte target;
/// the frontier names only deletions that committed.
///
/// PRE: [`Self::NONE`] is the state of a store that has deleted nothing.
///
/// POST: a pass writes its frontier inside the same batch as its row
/// deletions, so the record and the deletion commit together or not at all,
/// and a restart reconstructs exactly the committed boundary.
///
/// INVARIANT: the frontier never moves backwards, every height below it is
/// gone, and no lease is granted below it, so no reader can pin rows the
/// frontier names as deleted.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutedFrontier(u32);

impl ExecutedFrontier {
    /// The frontier of a store that has deleted nothing.
    pub const NONE: Self = Self(0);

    /// Wraps a raw frontier height.
    #[must_use]
    pub const fn new(height: u32) -> Self {
        Self(height)
    }

    /// The raw height: one past the highest deleted row.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns true when `height` lies below the frontier: gone.
    #[must_use]
    pub const fn contains(self, height: u32) -> bool {
        height < self.0
    }

    /// The monotonic join of two frontiers.
    #[must_use]
    pub const fn advance(self, other: Self) -> Self {
        if self.0 >= other.0 { self } else { other }
    }

    /// Reconstructs a store's executed frontier, migrating a datadir that
    /// was pruned before the record existed.
    ///
    /// POST: the persisted record wins when it exists. Otherwise only a
    /// datadir that ran a pass before the record existed can have deleted
    /// history, and every such pass persisted its requested line, so:
    ///
    /// - no requested line at all means no pass ever ran, and the frontier
    ///   is [`Self::NONE`];
    /// - a family with surviving rows shows that every lower height of it is
    ///   gone, so the frontier is the *highest* of the two families' lowest
    ///   surviving heights: one pass prunes bodies and undo through one
    ///   line, so a floor must be safe for both — `min` would grant a lease
    ///   over rows the other family already lost, while `max` at worst
    ///   refuses a lease over rows that still exist;
    /// - an empty family proves nothing, because a node that never wrote
    ///   undo records also has an empty undo family;
    /// - with no rows in either family, the requested line is the only
    ///   bound left, and taking it refuses a lease rather than grant one
    ///   over rows that may already be gone.
    ///
    /// INVARIANT: the result never grants a lease over deleted rows. A raw
    /// `node:pruneheight` is intent: a pass clamped by a lease may have
    /// stopped below it, so while rows survive the intent line never sets
    /// the frontier.
    pub fn reconstruct<S: crate::KvStore>(store: &S) -> Result<Self, StorageError> {
        if let Some(frontier) = load_executed_frontier(store)? {
            return Ok(frontier);
        }
        let Some(requested) = load_pruneheight(store)? else {
            return Ok(Self::NONE);
        };
        let bodies = block_pruner::lowest_stored_height(
            store,
            block_pruner::BLOCK_DATA_CF,
            block_pruner::BLOCK_BODY_PREFIX_BYTES,
        )?;
        let undo = block_pruner::lowest_stored_height(
            store,
            undo_pruner::BLOCK_UNDO_CF,
            undo_pruner::BLOCK_UNDO_PREFIX_BYTES,
        )?;
        let frontier = match (bodies, undo) {
            (Some(bodies), Some(undo)) => bodies.max(undo),
            (Some(bodies), None) => bodies,
            (None, Some(undo)) => undo,
            (None, None) => requested,
        };
        Ok(Self::new(frontier))
    }
}

/// What one pruning pass staged for its caller's atomic batch.
///
/// [`stage_block_and_undo_prune`] fills this; the caller commits the batch,
/// reclaims the flat files, and then promotes [`StagedPrune::pruned_below`]
/// through [`PruneReservation::commit`] so later lease requests learn what
/// is actually gone.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StagedPrune {
    /// Block-body rows the batch deletes.
    pub blocks: PruneOutcome,
    /// Undo rows the batch deletes.
    pub undo: PruneOutcome,
    /// Flat block files to reclaim after the batch commits.
    pub file_numbers: Vec<u32>,
    /// One past the highest deleted row height; zero when the pass staged
    /// nothing. This is the value to promote through
    /// [`PruneReservation::commit`]: floors at or below it may name deleted
    /// rows, floors above it name rows the pass left.
    pub pruned_below: u32,
}

/// One manual prune pass.
///
/// It clamps the line under the Core reorg margin, reserves it, stages rows,
/// persists the requested height and the executed frontier in the same batch,
/// commits durably, and reclaims files.
///
/// PRE: the caller holds the pruning authority, so passes do not overlap.
///
/// POST: on `Ok`, the deletions and the [`ExecutedFrontier`] describing them
/// are committed through one durable batch and the registry's executed line
/// is at least [`StagedPrune::pruned_below`]; on `Err`, the outcome is
/// reconciled before the claim releases — a provably committed batch
/// promotes the line, a provably unapplied one releases the reservation,
/// and an unprovable one holds it until restart-time recovery.
///
/// INVARIANT: no lease is granted below the line this pass deletes
/// through, because the reservation refuses such grants from the moment it
/// is taken.
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
        // The requested line would delete blocks still inside Core's reorg margin.
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
    // Claim the deletion range before staging anything: from this point a
    // lease request below the reserved line is refused, so nothing can pin
    // rows this batch is about to delete.
    let reservation = retention.reserve(policy_line);

    let mut batch = store.new_batch();
    let staged = stage_block_and_undo_prune(store, &mut batch, block_files, policy, &reservation)?;
    before_commit(staged.pruned_below)?;
    batch.put(
        crate::ColumnFamily::UtxoMeta,
        PRUNEHEIGHT_METADATA_KEY,
        &pruneheight.to_be_bytes(),
    );
    // The frontier is the deletion's receipt. It shares this batch's atomic
    // and durable boundary, so a restart sees the record and the deletions
    // together and reconciles the committed batch instead of retrying a
    // pass that may already have applied (#632). Clamping with the
    // reconstruction keeps the record monotonic when a legacy datadir's
    // surviving rows prove more deletion than the record did.
    let executed =
        ExecutedFrontier::reconstruct(store)?.advance(ExecutedFrontier::new(staged.pruned_below));
    batch.put(
        crate::ColumnFamily::UtxoMeta,
        PRUNE_EXECUTED_METADATA_KEY,
        &executed.get().to_be_bytes(),
    );
    if let Err(error) = store.write_durable(batch) {
        // A durability error is not a rollback receipt: the batch may already
        // have been applied, so the claim cannot be released on `Err` alone.
        // The frontier record shares the deletions' atomic boundary, so its
        // presence proves the outcome.
        return match load_executed_frontier(store) {
            // The receipt persisted, so the deletions did too: the batch
            // proved itself durable despite the reported error, so run the
            // same in-memory follow-ups the success path would — the line
            // promotion and the flat-file reclaim — and hand the caller the
            // staged result. Answering `Err` here would strand claimable
            // files and leave every caller-side follow-up unapplied.
            Ok(Some(persisted)) if persisted.get() >= executed.get() => {
                reservation.commit(persisted.get());
                reclaim_staged_flat_block_files(store, block_files, &staged.file_numbers)?;
                Ok(staged)
            }
            // No new receipt persisted, so the atomic batch applied nothing:
            // dropping the reservation safely reopens lease grants.
            Ok(_) => Err(error.into()),
            // The outcome cannot be proven: fail closed and hold the claim
            // until restart-time recovery reconciles record and deletions.
            Err(_) => {
                reservation.fail_closed();
                Err(error.into())
            }
        };
    }
    // The durable batch is the receipt for the line promoted here. A failed
    // pass reconciled its outcome above: a provably applied batch promoted
    // the line, a provably unapplied one released the claim, and an
    // unprovable one still holds it until restart-time recovery.
    reservation.commit(executed.get());
    reclaim_staged_flat_block_files(store, block_files, &staged.file_numbers)?;
    Ok(staged)
}

/// Stages block-body and undo-row pruning into a caller-owned atomic batch.
///
/// This is intentionally narrow: node wiring uses it to combine manual-prune
/// row deletion with prune-height metadata in one backend commit.
///
/// PRE: `reservation` was taken from the registry the pass commits through,
/// with a line derived from the durable tip and the policy's retention
/// depth. The pass deletes through [`PruneReservation::line`] and never
/// re-derives it, so a lease registered after the reservation cannot narrow
/// the range this batch has already staged.
///
/// POST: the batch holds deletions strictly below the reserved line, and
/// [`StagedPrune::pruned_below`] is one past the highest row staged — a
/// byte target that stops early, or one already met, leaves nothing to
/// record.
///
/// INVARIANT: block bodies and undo records stage through the one reserved
/// line, so a lease never holds block bodies while their undo records
/// delete around them (or the reverse). Both kinds prune against the
/// durable tip rather than the in-memory applied tip: a crash restores to
/// the last durable checkpoint, bodies above that base may be named by the
/// crash-recovery sidecar and must stay available for local replay, and
/// undo records below the base are needed to disconnect the restored
/// chain's own tip.
pub fn stage_block_and_undo_prune<S: crate::KvStore>(
    store: &S,
    batch: &mut S::WriteBatch,
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
