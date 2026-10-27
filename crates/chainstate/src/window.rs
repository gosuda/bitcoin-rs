//! Bounded script-proof windows, ordered prefix commits, and failure disposition.

use super::connect::{apply_committed_block_admitted, emit_journal_record};
use super::durable::{
    ConnectCommitFacts, commit_connect_head, stored_body_row, sync_appended_blocks,
};
use super::prepare::{parse_block_for_apply, plan_block_transactions, resolve_block_prevouts};
use super::{
    BlockProvenance, BlockValidationContext, BlockValidationProof, Chainstate, ConnectOutcome,
    PreparedApply, ProvenApply, ResolvedUtxoView, WindowApplyDisposition, WindowApplyError,
};
use crate::error::ApplyError;
use bitcoin_rs_primitives::{Block, Hash256};
use bitcoin_rs_storage::CommitRecords;
use rayon::prelude::*;
use std::sync::Arc;

/// Blocks per durable group commit on the windowed IBD path.
pub(super) const DURABLE_HEAD_GROUP_BLOCKS: usize = 64;

/// Serialized block bytes one group may hold before it must commit.
const DURABLE_HEAD_GROUP_MAX_BYTES: usize = 8 << 20;

/// How a committed block reaches its durable head and the published tip.
pub(super) enum PublishMode<'a> {
    Now,
    Grouped(&'a mut WindowGroup),
    /// Crash-recovery replay of a block whose durable batch already
    /// committed. The stored head receipt covers it, so nothing syncs and
    /// nothing re-commits: replay rebuilds the derived state the crash
    /// lost — coins, bookkeeping, journal tail — and publishes under the
    /// receipt the head already issued. Only the final replayed block takes
    /// the head's certified chain-transaction count; intermediate tips keep
    /// their reconstructed count so a progress checkpoint remains coherent.
    Replay {
        receipt: super::durable::DurableReceipt,
        certify_head: bool,
    },
}

/// One staged block awaiting its group's durable commit.
pub(super) struct PendingBlockCommit {
    /// Commit id 0 until the group's batch assigns the prefix id.
    pub outcome: ConnectOutcome,
    /// The block's encoded undo record, landed in the group's receipt.
    pub undo_record: bitcoin_rs_utxo::contract::UndoRecord,
    /// This block's parent; the group's first entry anchors the lineage
    /// fence.
    pub prev_hash: Hash256,
    /// The derived journal record, emitted at flush — after the batch, so
    /// the journal never leads the durable head.
    pub journal_record: super::connect::BuiltJournalRecord,
}

/// A bounded verified prefix staged for one durable group commit.
#[derive(Default)]
pub(super) struct WindowGroup {
    pending: Vec<PendingBlockCommit>,
    staged_bytes: usize,
}

impl WindowGroup {
    /// The chain view the next staged block builds on: the group's last
    /// staged tip, or `None` when the caller must read the published tip.
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

    pub(super) fn stage(&mut self, pending: PendingBlockCommit) {
        self.staged_bytes += pending.outcome.block_bytes.len();
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
    fn flush(
        &mut self,
        handles: &Chainstate,
        staged_block: Option<&Block>,
    ) -> core::result::Result<Vec<ConnectOutcome>, ApplyError> {
        let (first, last) = match (self.pending.first(), self.pending.last()) {
            (Some(first), Some(last)) => (first, last),
            _ => return Ok(Vec::new()),
        };
        let first_prev = first.prev_hash;
        // Staged-tip hook for the newest pending block: fires after the whole
        // prefix staged in memory and before the group's durable sync. Only
        // the last block is handed off; earlier pending blocks are its
        // ancestors and publish atomically in this same flush. The block is
        // borrowed from the caller's apply batch, which outlives the group.
        // The hook enqueues only; the batch, journal, and publication below
        // are unchanged, and a flush failure abandons the prefix unpublished.
        if let (Some(staged), Some(hook)) = (staged_block, handles.tip_staged.get()) {
            hook(&last.outcome.tip, staged);
        }
        let sync_started = quanta::Instant::now();
        sync_appended_blocks(handles)?;
        let group_sync_us = sync_started.elapsed().as_micros();
        let mut undo_rows = Vec::with_capacity(self.pending.len());
        let mut body_rows = Vec::with_capacity(self.pending.len());
        for pending in &self.pending {
            undo_rows.push((
                pending.outcome.height,
                pending.outcome.hash,
                pending.undo_record.as_bytes(),
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
            chain_tx_count_after: last.outcome.tip.chain_tx_count.to_wire(),
            undo_extent: Some((last.outcome.height, last.outcome.hash)),
        };
        let commit_started = quanta::Instant::now();
        let records = CommitRecords {
            undo_rows,
            body_rows,
        };
        let receipt = commit_connect_head(handles, &facts, &records)?;
        debug_assert!(
            self.pending
                .last()
                .is_some_and(|last| last.outcome.tip.chain_tx_count == receipt.chain_tx_count),
            "the batch certifies the last staged prefix count"
        );
        let group_blocks = self.pending.len();
        // Per-group decomposition is a development diagnostic
        // (`docs/observability.md`): it rides the tracing profile event, not
        // the metrics API.
        tracing::debug!(
            blocks = group_blocks,
            sync_us = group_sync_us,
            commit_us = commit_started.elapsed().as_micros(),
            "durable_head: group commit"
        );
        for pending in &mut self.pending {
            pending.outcome.commit_id = receipt.commit_id;
        }
        // The journal follows the receipt, block by block, before the
        // prefix publishes — the same derived-after-durable order as the
        // single-block path.
        for pending in &mut self.pending {
            emit_journal_record(
                handles,
                pending.journal_record.take(),
                pending.outcome.height,
            );
        }
        // The batch is the receipt; now publish the prefix in order. The
        // values are the ones the batch certified, so this tail is as
        // infallible as the single-block publication.
        self.staged_bytes = 0;
        let published = self
            .pending
            .drain(..)
            .map(|pending| {
                handles.publish_applied(&pending.outcome.tip, crate::events::HintKind::Connected);
                pending.outcome
            })
            .collect::<Vec<_>>();
        metrics::counter!("node.durable_head.group_flushes").increment(1);
        Ok(published)
    }

    /// Drops the staged prefix without committing it. Only for fatal
    /// dispositions, where the state is torn and recovery owns the
    /// reconciliation; the prefix was never published.
    fn abandon(&mut self) {
        self.pending.clear();
        self.staged_bytes = 0;
    }
}

#[derive(Default)]
struct ProvenWindow<'a, 'h> {
    proven: Vec<ProvenApply<'a>>,
    takes: Option<bitcoin_rs_consensus::WindowCacheTakes<'h>>,
    take_starts: Vec<usize>,
}

fn restore_uncommitted_takes(
    takes: Option<bitcoin_rs_consensus::WindowCacheTakes<'_>>,
    take_starts: &[usize],
    applied: usize,
) {
    if let Some(takes) = takes {
        takes.rollback_to(take_starts.get(applied).copied().unwrap_or(0));
    }
}

#[expect(clippy::result_large_err)]
pub(super) fn apply_window_admitted(
    handles: &Chainstate,
    blocks: &[&Block],
    serialized: &[bytes::Bytes],
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
    let window = prove_window(handles, blocks, serialized);
    let mut proven = window.proven.into_iter();
    let mut takes = window.takes;
    let take_starts = window.take_starts;
    let mut group = WindowGroup::default();
    let mut committed: Vec<ConnectOutcome> = Vec::with_capacity(blocks.len());
    for (block, raw) in blocks.iter().zip(serialized) {
        match apply_committed_block_admitted(
            handles,
            block,
            Some(raw.clone()),
            proven.next(),
            BlockProvenance::Network,
            PublishMode::Grouped(&mut group),
        ) {
            // The staged outcome sits in the group with commit id 0; the
            // flushed copy published below carries the group's id.
            Ok(_) => {}
            Err(source) => {
                let disposition = classify_apply_error(&source);
                if disposition == WindowApplyDisposition::Fatal {
                    // Torn or unreconcilable: the staged prefix was never
                    // published, and retrying it here would build on state
                    // recovery has to rebuild first.
                    restore_uncommitted_takes(takes.take(), &take_starts, committed.len());
                    group.abandon();
                    return Err(WindowApplyError {
                        applied: committed.len(),
                        committed,
                        source,
                        disposition: WindowApplyDisposition::Fatal,
                        invalidated: Box::default(),
                    });
                }
                // Only permanent failures invalidate: operational failures
                // (storage, UTXO commit, shutdown) leave the block retryable,
                // and a body-mutated failure poisons only the delivered body.
                let (invalidated, disposition) = if disposition == WindowApplyDisposition::Permanent
                {
                    invalidate_permanent_failure(handles, block.block_hash().0)
                } else {
                    (Box::default(), disposition)
                };
                // An invalidation that escalates to Fatal may have left the
                // tree partially mutated: flushing the staged prefix on top
                // of it would publish state recovery cannot certify. Abandon
                // the group and let restart-time recovery reconcile.
                if disposition == WindowApplyDisposition::Fatal {
                    restore_uncommitted_takes(takes.take(), &take_starts, committed.len());
                    group.abandon();
                    return Err(WindowApplyError {
                        applied: committed.len(),
                        committed,
                        source,
                        disposition: WindowApplyDisposition::Fatal,
                        invalidated,
                    });
                }
                // The prefix that committed in memory stays committed: flush
                // its durable group before reporting, so the durable head
                // and the published tip keep moving together. A flush
                // failure is the ambiguous-batch case: fatal, never retried.
                if let Err(error) = flush_group(&mut group, handles, &mut committed, blocks) {
                    restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
                    return Err(error);
                }
                restore_uncommitted_takes(takes.take(), &take_starts, committed.len());
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
            if let Err(error) = flush_group(&mut group, handles, &mut committed, blocks) {
                restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
                return Err(error);
            }
        }
    }
    if let Err(error) = flush_group(&mut group, handles, &mut committed, blocks) {
        restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
        return Err(error);
    }
    Ok(committed)
}

/// Flushes the group's staged prefix into `committed`. A flush failure is
/// the ambiguous-batch case — the durable head may or may not name it — so
/// the group is abandoned and the error is fatal, never retried.
#[expect(clippy::result_large_err)]
fn flush_group(
    group: &mut WindowGroup,
    handles: &Chainstate,
    committed: &mut Vec<ConnectOutcome>,
    blocks: &[&Block],
) -> core::result::Result<(), WindowApplyError> {
    // The staged prefix is a contiguous suffix starting at `committed.len()`,
    // so the newest staged block is borrowed straight from the caller's apply
    // batch — no clone in chainstate. Empty group: nothing staged, no hook.
    // Failure-prefix flush: the failing block was never staged, so the same
    // index still names the newest successfully staged block.
    let staged_block = if group.pending.is_empty() {
        None
    } else {
        blocks
            .get(committed.len() + group.pending.len() - 1)
            .copied()
    };
    match group.flush(handles, staged_block) {
        Ok(flushed) => {
            committed.extend(flushed);
            Ok(())
        }
        Err(flush_error) => {
            group.abandon();
            Err(WindowApplyError {
                applied: committed.len(),
                committed: std::mem::take(committed),
                source: flush_error,
                disposition: WindowApplyDisposition::Fatal,
                invalidated: Box::default(),
            })
        }
    }
}

/// Invalidates a permanently invalid block's subtree through the shared
/// chainstate operation, so the window caller can purge download state
/// without the frontier ever re-offering a descendant of that block.
fn invalidate_permanent_failure(
    handles: &Chainstate,
    hash: Hash256,
) -> (Box<[Hash256]>, WindowApplyDisposition) {
    match crate::reorg::invalidate_and_republish(handles, hash) {
        Ok(invalidated) => (invalidated, WindowApplyDisposition::Permanent),
        Err(crate::reorg::InvalidationError::UnknownBlock(_)) => {
            (Box::default(), WindowApplyDisposition::Permanent)
        }
        Err(invalidation) => {
            tracing::error!(
                %invalidation,
                "window subtree invalidation failed; requiring recovery"
            );
            let tree = handles.block_tree.read();
            handles.chain_tip.store(tree.tip());
            handles.reevaluate_assume_valid_with(&tree);
            drop(tree);
            (Box::default(), WindowApplyDisposition::Fatal)
        }
    }
}

/// Classifies an apply failure by what it proves about the header branch.
pub fn classify_apply_error(error: &ApplyError) -> WindowApplyDisposition {
    use WindowApplyDisposition::{BodyMutated, Fatal, Operational, Permanent};
    use bitcoin_rs_consensus::{ConsensusError, ScriptEngine};
    match error {
        ApplyError::UtxoCommit(_)
        | ApplyError::DurableHeadCommit(_)
        | ApplyError::DurableHeadLineage { .. }
        | ApplyError::DurableHeadGapUnrecoverable { .. } => Fatal,
        ApplyError::ProofOfWork { .. } | ApplyError::TargetAboveLimit
        // Deterministic contextual rejections: the header's branch can
        // never become valid under these rules, so the subtree is
        // invalidated rather than retried.
        | ApplyError::Chain(
            bitcoin_rs_chain::ChainError::BadVersion { .. }
            | bitcoin_rs_chain::ChainError::TimewarpAttack { .. }
            | bitcoin_rs_chain::ChainError::TimestampTooEarly { .. }
            | bitcoin_rs_chain::ChainError::NbitsMismatch { .. },
        ) => Permanent,
        ApplyError::Consensus(error) => match error {
            ConsensusError::MerkleRoot
            | ConsensusError::MerkleMutation
            // Inner Merkle nodes posing as transactions in a coinbase-less
            // body reach a valid header's root; the header is not at fault.
            | ConsensusError::SixtyFourByteMutation
            | ConsensusError::WitnessNonceSize
            | ConsensusError::WitnessCommitment
            | ConsensusError::UnexpectedWitness => BodyMutated,
            // An encoding refusal names the delivered bytes, not the
            // header's validity: the body is dropped and may be
            // re-fetched from another peer, so it does not invalidate the
            // subtree the way a consensus failure does.
            ConsensusError::Encoding(_)
            | ConsensusError::PrevoutMatrixSize { .. }
            | ConsensusError::PrevoutCount { .. }
            | ConsensusError::PrevoutMismatch { .. }
            | ConsensusError::UnsupportedEngine { .. }
            | ConsensusError::Kernel(_)
            | ConsensusError::Script {
                engine: ScriptEngine::Kernel,
                ..
            } => Operational,
            _ => Permanent,
        },
        _ => Operational,
    }
}

/// Prepares consecutive blocks against one overlay and verifies all their input
/// scripts in a single dispatch.
#[expect(clippy::too_many_lines)]
fn prove_window<'a, 'h>(
    handles: &'h Chainstate,
    blocks: &[&'a Block],
    serialized: &[bytes::Bytes],
) -> ProvenWindow<'a, 'h> {
    if blocks.is_empty() || blocks.len() != serialized.len() {
        return ProvenWindow::default();
    }
    let Some(applied) = handles.applied_tip.load_full() else {
        return ProvenWindow::default();
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
                return ProvenWindow::default();
            }
            let Some(height) = u32::try_from(index)
                .ok()
                .and_then(|offset| applied.height.checked_add(offset))
                .and_then(|height| height.checked_add(1))
            else {
                return ProvenWindow::default();
            };
            let softfork =
                bitcoin_rs_chain::softfork_state(&tree, handles.network, Some(parent_id), height);
            let cutoff = bitcoin_rs_consensus::locktime_cutoff(
                softfork.csv_active,
                tree.median_time_past_at(parent_id).unwrap_or(0),
                block.header.time,
            );
            // The next block's context needs this one in the tree. Header-first
            // sync put it there; without it there is no window.
            let Some(node_id) = tree.lookup(hash) else {
                return ProvenWindow::default();
            };
            contexts.push(BlockValidationContext {
                hash,
                parent: parent_hash,
                height,
                flags: bitcoin_rs_consensus::verify_flags(handles.network, height, hash, softfork),
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
        .map(|(block, raw)| {
            parse_block_for_apply(block, Some(raw.clone()), handles.validation_engine)
        })
        .collect();
    metrics::histogram!("node.window.parse_seconds").record(parse_started.elapsed().as_secs_f64());

    let prepare_started = quanta::Instant::now();
    let mut overlay = bitcoin_rs_utxo::WindowOverlay::new(
        handles.utxo.as_ref(),
        bitcoin_rs_consensus::MAX_SCRIPT_SIZE,
    );
    let mut prepared = Vec::with_capacity(blocks.len());
    for ((block, parsed), context) in blocks.iter().zip(parsed).zip(&contexts) {
        let Ok((script_source, facts)) = parsed else {
            return ProvenWindow::default();
        };
        let tx_plan = plan_block_transactions(block, facts.txids());
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
            return ProvenWindow::default();
        }
        prepared.push(PreparedApply {
            script_source,
            view,
            tx_plan,
            resolved,
        });
    }

    metrics::histogram!("node.window.prepare_seconds")
        .record(prepare_started.elapsed().as_secs_f64());

    // Cheap structural checks before any script runs.
    for ((block, unit), context) in blocks.iter().zip(prepared.iter_mut()).zip(&contexts) {
        // The one-pass derivation already reduced these txids through the
        // production walker; comparing the stored root is the same verdict
        // without a second tree walk.
        if !unit.view.merkle_root_matches(block.header.merkle_root) {
            return ProvenWindow::default();
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
                return ProvenWindow::default();
            }
        }
    }

    // Takes are transactional across the window: a failed proof rolls every
    // taken entry back, so blocks that never commit keep reusable positives.
    let mut takes = handles
        .script_cache
        .as_deref()
        .map(bitcoin_rs_consensus::WindowCacheTakes::new);
    let mut take_starts = Vec::with_capacity(prepared.len());
    // One slot per input block, so a skipped unit leaves a hole rather than
    // shifting every later block onto the wrong prepared state.
    let mut skipped = vec![false; prepared.len()];
    // One dispatch for the whole window. The check units borrow the selected
    // engine's parsed blocks, so they live and die inside this scope, before
    // anything commits.
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
            if let Some(takes) = takes.as_ref() {
                take_starts.push(takes.checkpoint());
            }
            // The same predicate the single-block path applies, per block rather
            // than per window, because the anchor height can fall inside a
            // window. Without it the batch prepared and executed every unit
            // before the per-block decision was ever reached, so assume-valid
            // did nothing at all on the windowed path.
            if handles.scripts_verified_upstream(
                BlockProvenance::Network,
                context.height,
                context.hash,
            ) {
                skipped[index] = true;
                continue;
            }
            let Ok(resolved) = resolve_block_prevouts(
                Arc::clone(&unit.resolved),
                &block.txs,
                &unit.tx_plan,
                context.height,
                unit.view.txids(),
            ) else {
                if let Some(takes) = takes.take() {
                    takes.rollback();
                }
                return ProvenWindow::default();
            };
            unit.view.set_resolved(resolved);
            // This window only feeds commits (`apply_window_admitted` below),
            // so its pre-proof consults the node-owned cache exactly like the
            // single-block commit path; the later commit reuses the proof and
            // never takes twice. `None` under the kernel engine. Takes are
            // logged across the window and rolled back when the proof fails.
            if let Ok(checks) = bitcoin_rs_consensus::verify_tx::prepare_block_script_checks(
                &mut unit.view,
                context.height,
                context.locktime_cutoff,
                context.flags,
                &unit.script_source,
                takes.as_mut(),
            ) {
                units.push(checks);
            } else {
                if let Some(takes) = takes.take() {
                    takes.rollback();
                }
                return ProvenWindow::default();
            }
        }
        let checks_us = checks_started.elapsed().as_micros();
        let verify_started = quanta::Instant::now();
        let verdict = bitcoin_rs_consensus::verify_tx::verify_prepared_units(&units);
        let verify_us = verify_started.elapsed();
        metrics::histogram!("node.window.verify_seconds").record(verify_us.as_secs_f64());
        // Window-stage decomposition is a development diagnostic
        // (`docs/observability.md`); only the verify hook stays on the
        // metrics API as the hot-path ledger requires.
        tracing::debug!(
            checks_us,
            verify_us = verify_us.as_micros(),
            units = units.len(),
            "prove_window: profile"
        );
        if verdict.is_err() {
            if let Some(takes) = takes.take() {
                takes.rollback();
            }
            return ProvenWindow::default();
        }
        if !units.is_empty() {
            metrics::counter!("node.window.verify_success_total").increment(1);
        }
    }

    let proven = prepared
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
        .collect();
    ProvenWindow {
        proven,
        takes,
        take_starts,
    }
}

#[cfg(test)]
mod cache_tests;
