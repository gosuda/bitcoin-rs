//! Bounded script-proof windows, ordered prefix commits, and failure disposition.

use super::BlockProvenance;
use super::BlockValidationContext;
use super::BlockValidationProof;
use super::ChainChangeProof;
use super::Chainstate;
use super::ConnectOutcome;
use super::PreparedApply;
use super::ProvenApply;
use super::ResolvedUtxoView;
use super::WindowApplyDisposition;
use super::WindowApplyError;
use super::connect::apply_committed_block_admitted;
use super::contextual::compute_verify_flags;
use super::durable::{
    ConnectCommitFacts, commit_connect_head, stored_body_row, sync_appended_blocks,
};
use super::prepare::parse_block_for_apply;
use super::prepare::plan_block_transactions;
use super::prepare::resolve_block_prevouts;
use super::publication::publish_connect;
use crate::apply::error::ApplyError;
use bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::CommitRecords;
use rayon::prelude::*;
use std::sync::Arc;

/// Blocks per durable group commit on the windowed IBD path.
///
/// Stated, not emergent (`RCV-02`): at the 30–75 blocks/s an IBD stream
/// sustains, 64 blocks is one durable batch every one to two seconds, and
/// the crash-redo bound is at most 64 body re-applies — the same order as
/// the journal's own batch cadence. [`DURABLE_HEAD_GROUP_MAX_BYTES`] bounds
/// the group from the memory side, because staged undo records and outcomes
/// ride in the group until it commits.
pub const DURABLE_HEAD_GROUP_BLOCKS: usize = 64;

/// Serialized block bytes one group may hold before it must commit.
///
/// Whichever cap hits first ends the group, so early-chain windows commit
/// every 64 blocks and tip-size windows commit on bytes well before that.
pub const DURABLE_HEAD_GROUP_MAX_BYTES: usize = 8 << 20;

/// How a committed block reaches its durable head and the published tip.
///
/// [`PublishMode::Now`] commits and publishes inside the per-block path.
/// [`PublishMode::Grouped`] buffers the commit facts in a [`WindowGroup`]:
/// the window syncs once per group, lands one head batch per verified
/// prefix, and publishes the prefix in order after the batch — one
/// `commit_id` per committed prefix, never beyond it (`RCV-02`).
pub(super) enum PublishMode<'a> {
    Now,
    Grouped(&'a mut WindowGroup),
}

/// One staged block awaiting its group's durable commit.
pub(super) struct PendingBlockCommit {
    /// Commit id 0 until the group's batch assigns the prefix id.
    pub outcome: ConnectOutcome,
    /// The block's encoded undo record, landed in the group's receipt.
    pub undo_record: Vec<u8>,
    pub tx_count_delta: u64,
    pub chain_tx_count_after: u64,
    /// This block's parent; the group's first entry anchors the lineage
    /// fence.
    pub prev_hash: Hash256,
}

/// A bounded verified prefix staged for one durable group commit.
///
/// Staging is infallible and in-memory; [`WindowGroup::flush`] does the
/// ordered durable work: sync the appended bytes once, land one head batch
/// naming every undo and locator row of the prefix, then publish the
/// prefix's tips in order. `Ok` from the batch is the receipt for the whole
/// prefix, so publication — which follows the flush — never outruns
/// durability (`INV-04`).
#[derive(Default)]
pub(super) struct WindowGroup {
    pending: Vec<PendingBlockCommit>,
    staged_bytes: usize,
    first_prev: Option<Hash256>,
}

impl WindowGroup {
    /// The chain view the next staged block builds on: the group's last
    /// staged tip, or `None` when the caller must read the published tip.
    ///
    /// Grouped blocks cannot read `applied_tip` for their predecessor — the
    /// prefix publishes only after its batch (`INV-04`) — so the staged
    /// outcome is the in-memory chain state the next block extends.
    pub(super) fn predecessor(
        &self,
        prev_hash: Hash256,
    ) -> core::result::Result<Option<(Arc<bitcoin_rs_chain::TipSnapshot>, u32)>, ApplyError> {
        let Some(last) = self.pending.last() else {
            return Ok(None);
        };
        if last.outcome.hash != prev_hash {
            return Err(ApplyError::PrevHashMismatch {
                tip: last.outcome.hash,
                prev: prev_hash,
            });
        }
        let height = last
            .outcome
            .height
            .checked_add(1)
            .ok_or(ApplyError::HeightOverflow(last.outcome.height))?;
        Ok(Some((Arc::new(last.outcome.tip.clone()), height)))
    }

    /// The cumulative chain tx count the next staged block advances, when a
    /// prefix is staged: publication has not stored the staged deltas yet.
    pub(super) fn chain_tx_count_base(&self) -> Option<u64> {
        self.pending.last().map(|last| last.chain_tx_count_after)
    }

    pub(super) fn stage(&mut self, pending: PendingBlockCommit) {
        self.staged_bytes += pending.outcome.block_bytes.len();
        if self.pending.is_empty() {
            self.first_prev = Some(pending.prev_hash);
        }
        self.pending.push(pending);
    }

    /// Whether the staged prefix has hit a group cap.
    fn should_flush(&self) -> bool {
        self.pending.len() >= DURABLE_HEAD_GROUP_BLOCKS
            || self.staged_bytes >= DURABLE_HEAD_GROUP_MAX_BYTES
    }

    /// Commits and publishes the staged prefix, returning its outcomes with
    /// the group's `commit_id`. On error nothing is drained: the prefix
    /// stays staged for the caller to retry or report.
    pub(super) fn flush(
        &mut self,
        handles: &Chainstate,
    ) -> core::result::Result<Vec<ConnectOutcome>, ApplyError> {
        let (last, first_prev) = match (self.pending.last(), self.first_prev) {
            (Some(last), Some(first_prev)) => (last, first_prev),
            _ => return Ok(Vec::new()),
        };
        let started = quanta::Instant::now();
        sync_appended_blocks(handles)?;
        metrics::histogram!("node.durable_head.group_sync_seconds")
            .record(started.elapsed().as_secs_f64());
        let mut undo_rows = Vec::with_capacity(self.pending.len());
        let mut body_rows = Vec::with_capacity(self.pending.len());
        for pending in &self.pending {
            undo_rows.push((
                pending.outcome.height,
                pending.outcome.hash,
                pending.undo_record.as_slice(),
            ));
            if let Some(row) =
                stored_body_row(handles, pending.outcome.height, pending.outcome.hash)?
            {
                body_rows.push(row);
            }
        }
        let facts = ConnectCommitFacts {
            prev_hash: first_prev,
            tip: last.outcome.hash,
            height: last.outcome.height,
            chain_tx_count_after: last.chain_tx_count_after,
            undo_extent: Some((last.outcome.height, last.outcome.hash)),
        };
        let started = quanta::Instant::now();
        let records = CommitRecords {
            undo_rows,
            body_rows,
        };
        let commit_id = commit_connect_head(handles, &facts, &records)?;
        metrics::histogram!("node.durable_head.group_commit_seconds")
            .record(started.elapsed().as_secs_f64());
        let staged = u32::try_from(self.pending.len()).unwrap_or(u32::MAX);
        metrics::histogram!("node.durable_head.group_blocks").record(f64::from(staged));
        for pending in &mut self.pending {
            pending.outcome.commit_id = commit_id;
        }
        // The batch is the receipt; now publish the prefix in order. The
        // values are the ones the batch certified, so this tail is as
        // infallible as the single-block publication.
        self.staged_bytes = 0;
        self.first_prev = None;
        let published = self
            .pending
            .drain(..)
            .map(|pending| {
                publish_connect(handles, &pending.outcome.tip, pending.tx_count_delta);
                pending.outcome
            })
            .collect::<Vec<_>>();
        metrics::counter!("node.durable_head.group_flushes").increment(1);
        Ok(published)
    }

    /// Drops the staged prefix without committing it. Only for fatal
    /// dispositions, where the state is torn and recovery owns the
    /// reconciliation; the prefix was never published.
    pub(super) fn abandon(&mut self) {
        self.pending.clear();
        self.staged_bytes = 0;
        self.first_prev = None;
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn apply_window_admitted(
    handles: &Chainstate,
    blocks: &[&Block],
    serialized: &[bytes::Bytes],
    proof: &ChainChangeProof<'_>,
) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
    if blocks.len() != serialized.len() {
        return Err(WindowApplyError {
            applied: 0,
            committed: Vec::new(),
            source: ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Kernel(format!(
                "window has {} blocks but {} serialized bodies",
                blocks.len(),
                serialized.len()
            ))),
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        });
    }
    let mut proven = prove_window(handles, blocks, serialized).into_iter();
    let mut group = WindowGroup::default();
    let mut committed: Vec<ConnectOutcome> = Vec::with_capacity(blocks.len());
    for (block, raw) in blocks.iter().zip(serialized) {
        match apply_committed_block_admitted(
            handles,
            block,
            Some(raw.clone()),
            proven.next(),
            BlockProvenance::Network,
            proof,
            PublishMode::Grouped(&mut group),
        ) {
            // The staged outcome sits in the group with commit id 0; the
            // flushed copy published below carries the group's id.
            Ok(_) => {}
            Err(source) => {
                if matches!(
                    source,
                    ApplyError::UtxoCommit(_)
                        | ApplyError::DurableHeadCommit(_)
                        | ApplyError::DurableHeadLineage { .. }
                ) {
                    // Torn or unreconcilable: the staged prefix was never
                    // published, and retrying it here would build on state
                    // recovery has to rebuild first.
                    group.abandon();
                    return Err(WindowApplyError {
                        applied: committed.len(),
                        committed,
                        source,
                        disposition: WindowApplyDisposition::Fatal,
                        invalidated: Box::default(),
                    });
                }
                let invalidated = invalidate_failed_subtree(handles, block, &source);
                let disposition = if is_permanent_apply_error(&source) {
                    WindowApplyDisposition::Permanent
                } else {
                    WindowApplyDisposition::Operational
                };
                // The prefix that committed in memory stays committed: flush
                // its durable group before reporting, so the durable head
                // and the published tip keep moving together. A flush
                // failure is the ambiguous-batch case: fatal, never retried.
                let flushed = group.flush(handles).map_err(|flush_error| {
                    group.abandon();
                    WindowApplyError {
                        applied: committed.len(),
                        committed: std::mem::take(&mut committed),
                        source: flush_error,
                        disposition: WindowApplyDisposition::Fatal,
                        invalidated: Box::default(),
                    }
                })?;
                committed.extend(flushed);
                return Err(WindowApplyError {
                    applied: committed.len(),
                    committed,
                    source,
                    disposition,
                    invalidated,
                });
            }
        }
        if group.should_flush() {
            let flushed = group.flush(handles).map_err(|flush_error| {
                group.abandon();
                WindowApplyError {
                    applied: committed.len(),
                    committed: std::mem::take(&mut committed),
                    source: flush_error,
                    disposition: WindowApplyDisposition::Fatal,
                    invalidated: Box::default(),
                }
            })?;
            committed.extend(flushed);
        }
    }
    let flushed = group
        .flush(handles)
        .map_err(|flush_error| WindowApplyError {
            applied: committed.len(),
            committed: std::mem::take(&mut committed),
            source: flush_error,
            disposition: WindowApplyDisposition::Fatal,
            invalidated: Box::default(),
        })?;
    committed.extend(flushed);
    Ok(committed)
}

/// Marks the failed block's header subtree invalid while the chain transition
/// is still held, so the window caller can purge download state without the
/// frontier ever re-offering a descendant of a permanently invalid block.
///
/// Only permanent failures invalidate. Operational failures (storage, UTXO
/// commit, shutdown) are transient: the block stays retryable, so nothing may
/// be marked `Invalid` here. A header missing from the tree (rejected before
/// insertion, e.g. prev-hash mismatch or `PoW` failure) has no subtree to
/// invalidate, which leaves the list empty and the classification untouched.
pub(super) fn invalidate_failed_subtree(
    handles: &Chainstate,
    block: &Block,
    source: &ApplyError,
) -> Box<[Hash256]> {
    if !is_permanent_apply_error(source) {
        return Box::default();
    }
    let hash = block.block_hash().0;
    let mut tree = handles.block_tree.write();
    let Some(node_id) = tree.lookup(hash) else {
        return Box::default();
    };
    tree.invalidate_subtree(node_id)
        .unwrap_or_default()
        .into_boxed_slice()
}

/// Returns true when an apply failure is a permanent block-invalidity
/// condition, not an operational error.
///
/// Only these failures poison the branch: the block and its descendants can
/// never become valid, so invalidating the subtree is safe and the node
/// republishes the best valid tip rather than retrying the same block.
/// Operational failures (storage, UTXO commit, undo record, shutdown) are
/// transient and must not permanently mark a block invalid.
///
/// Kernel-backed script verification failures are classified Operational
/// because `bitcoinkernel` can reject a valid block depending on process
/// state (issue #618): the same block applies successfully after restart.
/// Treating these as Permanent would freeze the node at the tip and
/// invalidate a valid header subtree with no retry path. The native
/// interpreter path does not produce this spurious failure, so its
/// `ConsensusError::Script` remains Permanent.
pub(crate) fn is_permanent_apply_error(error: &ApplyError) -> bool {
    match error {
        ApplyError::ProofOfWork { .. }
        | ApplyError::TargetAboveLimit
        | ApplyError::NbitsNonRetargetMismatch { .. } => true,
        ApplyError::Consensus(error) => match error {
            bitcoin_rs_consensus::ConsensusError::PrevoutMatrixSize { .. }
            | bitcoin_rs_consensus::ConsensusError::Kernel(_)
            | bitcoin_rs_consensus::ConsensusError::Encoding(_) => false,
            bitcoin_rs_consensus::ConsensusError::Script { reason, .. }
                if reason.starts_with("kernel script verification failed:") =>
            {
                false
            }
            _ => true,
        },
        _ => false,
    }
}

/// Prepares consecutive blocks against one overlay and verifies all their input
/// scripts in a single dispatch.
///
/// Returns one proof per block, or nothing at all. There is no partial result
/// by design: a block must never be applied with its scripts skipped on the
/// strength of a neighbour.
///
/// Every reason to give up is silent and cheap, because the per-block path
/// behind this is complete and produces the real verdict in its documented
/// order. A header not yet in the tree, a block that does not extend its
/// predecessor, a prevout that does not resolve, or any failing check all
/// return nothing.
#[allow(clippy::too_many_lines)]
pub(super) fn prove_window<'a>(
    handles: &Chainstate,
    blocks: &[&'a Block],
    serialized: &[bytes::Bytes],
) -> Vec<ProvenApply<'a>> {
    if blocks.is_empty() || blocks.len() != serialized.len() {
        return Vec::new();
    }
    let Some(applied) = handles.applied_tip.load_full() else {
        return Vec::new();
    };

    // Context is captured before any block applies, because applying inserts
    // headers into the shared tree and would move median-time-past and softfork
    // state under the later blocks. Each apply re-derives all of it and
    // compares, so a captured value that turns out wrong costs the batch only.
    let context_started = quanta::Instant::now();
    let mut contexts = Vec::with_capacity(blocks.len());
    {
        let tree = handles.block_tree.read();
        let mut parent_id = applied.tip_id;
        let mut parent_hash = applied.hash;
        for (index, block) in blocks.iter().enumerate() {
            let hash = block.block_hash().0;
            if block.header.prev_blockhash.0 != parent_hash {
                return Vec::new();
            }
            let Some(height) = u32::try_from(index)
                .ok()
                .and_then(|offset| applied.height.checked_add(offset))
                .and_then(|height| height.checked_add(1))
            else {
                return Vec::new();
            };
            let softfork =
                bitcoin_rs_chain::softfork_state(&tree, handles.network, Some(parent_id), height);
            let cutoff = bitcoin_rs_consensus::locktime_cutoff(
                softfork.csv_active,
                tree.median_time_past_at(parent_id, MEDIAN_TIME_PAST_WINDOW)
                    .unwrap_or(0),
                block.header.time,
            );
            // The next block's context needs this one in the tree. Header-first
            // sync put it there; without it there is no window.
            let Some(node_id) = tree.lookup(hash) else {
                return Vec::new();
            };
            contexts.push(BlockValidationContext {
                hash,
                parent: parent_hash,
                height,
                flags: compute_verify_flags(handles.network, height, hash, softfork),
                locktime_cutoff: cutoff,
            });
            parent_id = node_id;
            parent_hash = hash;
        }
    }

    metrics::histogram!("node.window.context_seconds")
        .record(context_started.elapsed().as_secs_f64());

    // Parsing a block and planning its transactions depends on nothing but that
    // block, so the window does all of it at once. Only the overlay walk below
    // is order-dependent, and it is the cheaper half.
    let parse_started = quanta::Instant::now();
    let parsed: Vec<core::result::Result<_, ApplyError>> = blocks
        .par_iter()
        .zip(serialized.par_iter())
        .map(|(block, raw)| parse_block_for_apply(block, Some(raw.clone())))
        .collect();
    metrics::histogram!("node.window.parse_seconds").record(parse_started.elapsed().as_secs_f64());

    let prepare_started = quanta::Instant::now();
    let mut overlay = crate::window_overlay::WindowOverlay::new(handles.utxo.as_ref());
    let mut prepared = Vec::with_capacity(blocks.len());
    for ((block, parsed), context) in blocks.iter().zip(parsed).zip(&contexts) {
        let Ok((kernel_block, txids)) = parsed else {
            return Vec::new();
        };
        let tx_plan = plan_block_transactions(block, &txids);
        let facts = kernel_block.derive_facts(&block.txs, &txids);
        let view = bitcoin_rs_consensus::BlockView::from_facts(&block.txs, facts);
        let resolved = Arc::new(ResolvedUtxoView::resolve(&overlay, block, &tx_plan));
        if overlay
            .advance(
                block,
                view.txids(),
                context.height,
                tx_plan.same_block_spent_set(),
            )
            .is_err()
        {
            return Vec::new();
        }
        prepared.push(PreparedApply {
            kernel_block,
            view,
            tx_plan,
            resolved,
        });
    }

    metrics::histogram!("node.window.prepare_seconds")
        .record(prepare_started.elapsed().as_secs_f64());

    // Cheap structural checks before any script runs.
    //
    // Batching changed the cost of a bad body. The per-block path rejects a
    // broken merkle root or witness commitment before it verifies a single
    // script, but the window used to dispatch the whole batch first — so a peer
    // could send a body with the expected header and one altered witness
    // reserved value, keeping every txid intact, and force a full window of
    // script verification for a block that is rejected immediately either way.
    // Both checks below depend on nothing but the block, so the window runs
    // them before any script work. The Merkle verdict is already derived in
    // the one-pass parse, so this is a comparison, not a hash; a
    // witness-carrying block hashes its witness IDs exactly once below.
    for ((block, unit), context) in blocks.iter().zip(prepared.iter_mut()).zip(&contexts) {
        // The one-pass derivation already reduced these txids through the
        // production walker; comparing the stored root is the same verdict
        // without a second tree walk.
        if !unit.view.merkle_root_matches(block.header.merkle_root) {
            return Vec::new();
        }
        // BIP141 CheckWitnessMalleation window precheck. Under active SegWit a
        // block with witness data must carry a matching BIP141 commitment and a
        // 32-byte coinbase reserved nonce. The check consumes the view's cached
        // witness IDs so a block hashes its transactions as witness IDs exactly
        // once across the whole window. A commitment-less block without witness
        // data is valid and is not checked here.
        if context
            .flags
            .contains(bitcoin_rs_script::VerifyFlags::WITNESS)
            && unit.view.facts().has_witness()
        {
            let commitment_matches = {
                let wtxids = unit.view.witness_ids();
                bitcoin_rs_consensus::verify_block::block_witness_commitment_matches(block, wtxids)
            };
            if !commitment_matches {
                return Vec::new();
            }
        }
    }

    // One slot per input block, so a skipped unit leaves a hole rather than
    // shifting every later block onto the wrong prepared state.
    let mut skipped = vec![false; prepared.len()];
    // One dispatch for the whole window. The check units borrow their kernel
    // blocks, so they live and die inside this scope, before anything commits.
    {
        // Each block's checks are built from its own prepared state, so the
        // window builds them all at once. The overlay walk above already fixed
        // every prevout, which is what makes this independent per block.
        let checks_started = quanta::Instant::now();
        // Serial on purpose. Fanning this out measured worse on both axes:
        // 58.7s wall / 585.2s CPU with it serial against 64.2s / 613.1s
        // parallel, on the 0..150_000 replay. Each block's preparation is short
        // enough that the dispatch costs more than it distributes, which is the
        // same reason the script checks are batched across blocks rather than
        // split within one.
        let mut units = Vec::with_capacity(prepared.len());
        for (index, ((block, unit), context)) in blocks
            .iter()
            .zip(prepared.iter_mut())
            .zip(&contexts)
            .enumerate()
        {
            // The same predicate the single-block path applies, per block rather
            // than per window, because the anchor height can fall inside a
            // window. Without it the batch prepared and executed every unit
            // before the per-block decision was ever reached, so assume-valid
            // did nothing at all on the windowed path.
            if handles.scripts_verified_upstream(BlockProvenance::Network, context.height) {
                skipped[index] = true;
                continue;
            }
            let Ok(resolved) = resolve_block_prevouts(
                Arc::clone(&unit.resolved),
                block,
                &unit.tx_plan,
                context.height,
                unit.view.txids(),
            ) else {
                return Vec::new();
            };
            unit.view.set_resolved(resolved);
            match bitcoin_rs_consensus::verify_tx::prepare_block_script_checks(
                &mut unit.view,
                context.height,
                context.locktime_cutoff,
                context.flags,
                &unit.kernel_block,
            ) {
                Ok(checks) => units.push(checks),
                Err(_) => return Vec::new(),
            }
        }
        metrics::histogram!("node.window.checks_seconds")
            .record(checks_started.elapsed().as_secs_f64());
        let verify_started = quanta::Instant::now();
        let verdict = bitcoin_rs_consensus::verify_tx::verify_prepared_units(&units);
        metrics::histogram!("node.window.verify_seconds")
            .record(verify_started.elapsed().as_secs_f64());
        if verdict.is_err() {
            return Vec::new();
        }
        if !units.is_empty() {
            metrics::counter!("node.window.verify_success_total").increment(1);
        }
    }

    prepared
        .into_iter()
        .zip(contexts)
        .zip(skipped)
        .map(|((prepared, context), skipped)| {
            if skipped {
                ProvenApply::AssumeValidSkipped(prepared)
            } else {
                ProvenApply::Proven(BlockValidationProof { prepared, context })
            }
        })
        .collect()
}
