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
use bitcoin_rs_primitives::{Block, BlockPayload, Hash256};
use bitcoin_rs_storage::CommitRecords;
use rayon::prelude::*;
use std::sync::Arc;

pub(super) const DURABLE_HEAD_GROUP_BLOCKS: usize = 64;

/// Serialized block bytes one group may hold before it must commit.
const DURABLE_HEAD_GROUP_MAX_BYTES: usize = 8 << 20;

pub(super) enum PublishMode<'a> {
    Now,
    Grouped(&'a mut WindowGroup),
    Replay {
        receipt: super::durable::DurableReceipt,
        certify_head: bool,
    },
}

pub(super) struct PendingBlockCommit {
    pub outcome: ConnectOutcome,
    pub undo_record: bitcoin_rs_utxo::contract::UndoRecord,
    pub prev_hash: Hash256,
    /// The derived journal record, emitted at flush — after the batch, so
    /// the journal never leads the durable head.
    pub journal_record: super::connect::BuiltJournalRecord,
}

#[derive(Default)]
pub(super) struct WindowGroup {
    pending: Vec<PendingBlockCommit>,
    staged_bytes: usize,
}

impl WindowGroup {
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

    fn should_flush(&self) -> bool {
        self.pending.len() >= DURABLE_HEAD_GROUP_BLOCKS
            || self.staged_bytes >= DURABLE_HEAD_GROUP_MAX_BYTES
    }

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
        tracing::debug!(
            blocks = group_blocks,
            sync_us = group_sync_us,
            commit_us = commit_started.elapsed().as_micros(),
            "durable_head: group commit"
        );
        for pending in &mut self.pending {
            pending.outcome.commit_id = receipt.commit_id;
        }
        for pending in &mut self.pending {
            emit_journal_record(
                handles,
                pending.journal_record.take(),
                pending.outcome.height,
            );
        }
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
    payloads: &[&BlockPayload],
) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
    let window = prove_window(handles, payloads);
    let mut proven = window.proven.into_iter();
    let mut takes = window.takes;
    let take_starts = window.take_starts;
    let mut group = WindowGroup::default();
    let mut committed: Vec<ConnectOutcome> = Vec::with_capacity(payloads.len());
    for &payload in payloads {
        let block = payload.block();
        match apply_committed_block_admitted(
            handles,
            payload,
            proven.next(),
            BlockProvenance::Network,
            PublishMode::Grouped(&mut group),
        ) {
            Ok(_) => {}
            Err(source) => {
                let disposition = classify_apply_error(&source);
                if disposition == WindowApplyDisposition::Fatal {
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
                let (invalidated, disposition) = if disposition == WindowApplyDisposition::Permanent
                {
                    invalidate_permanent_failure(handles, block.block_hash().0)
                } else {
                    (Box::default(), disposition)
                };
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
                if let Err(error) = flush_group(&mut group, handles, &mut committed, payloads) {
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
            if let Err(error) = flush_group(&mut group, handles, &mut committed, payloads) {
                restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
                return Err(error);
            }
        }
    }
    if let Err(error) = flush_group(&mut group, handles, &mut committed, payloads) {
        restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
        return Err(error);
    }
    Ok(committed)
}

/// Flushes the group's staged prefix into `committed`.
///
/// A flush failure is the ambiguous-batch case — the durable head may or may not name
/// it — so the group is abandoned and the error is fatal, never retried.
#[expect(clippy::result_large_err)]
fn flush_group(
    group: &mut WindowGroup,
    handles: &Chainstate,
    committed: &mut Vec<ConnectOutcome>,
    payloads: &[&BlockPayload],
) -> core::result::Result<(), WindowApplyError> {
    if group.pending.is_empty() {
        return Ok(());
    }
    let staged_block = if group.pending.is_empty() {
        None
    } else {
        payloads
            .get(committed.len() + group.pending.len() - 1)
            .map(|payload| payload.block())
    };
    let flush_started = quanta::Instant::now();
    let pending_blocks = group.pending.len();
    match group.flush(handles, staged_block) {
        Ok(flushed) => {
            let flush_wait_us = flush_started.elapsed().as_micros();
            tracing::debug!(blocks = flushed.len(), flush_wait_us, "window: group flush");
            committed.extend(flushed);
            Ok(())
        }
        Err(flush_error) => {
            let flush_wait_us = flush_started.elapsed().as_micros();
            tracing::debug!(
                blocks = pending_blocks,
                flush_wait_us,
                %flush_error,
                "window: group flush failed"
            );
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

fn invalidate_permanent_failure(
    handles: &Chainstate,
    hash: Hash256,
) -> (Box<[Hash256]>, WindowApplyDisposition) {
    match crate::reorg::invalidate_and_republish(handles, hash) {
        Ok(outcome) => (
            outcome.invalid.into_boxed_slice(),
            WindowApplyDisposition::Permanent,
        ),
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

pub fn classify_apply_error(error: &ApplyError) -> WindowApplyDisposition {
    use WindowApplyDisposition::{BodyMutated, Fatal, Operational, Permanent};
    use bitcoin_rs_consensus::{ConsensusError, ScriptEngine};
    match error {
        ApplyError::UtxoCommit(_)
        | ApplyError::DurableHeadCommit(_)
        | ApplyError::DurableHeadLineage { .. }
        | ApplyError::DurableHeadGapUnrecoverable { .. } => Fatal,
        ApplyError::ProofOfWork { .. }
        | ApplyError::TargetAboveLimit
        | ApplyError::Chain(
            bitcoin_rs_chain::ChainError::BadVersion { .. }
            | bitcoin_rs_chain::ChainError::TimewarpAttack { .. }
            | bitcoin_rs_chain::ChainError::TimestampTooEarly { .. }
            | bitcoin_rs_chain::ChainError::NbitsMismatch { .. },
        ) => Permanent,
        ApplyError::Consensus(error) => match error {
            ConsensusError::MerkleRoot
            | ConsensusError::MerkleMutation
            | ConsensusError::SixtyFourByteMutation
            | ConsensusError::WitnessNonceSize
            | ConsensusError::WitnessCommitment
            | ConsensusError::UnexpectedWitness => BodyMutated,
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

#[expect(clippy::too_many_lines)]
fn prove_window<'a, 'h>(
    handles: &'h Chainstate,
    payloads: &[&'a BlockPayload],
) -> ProvenWindow<'a, 'h> {
    if payloads.is_empty() {
        return ProvenWindow::default();
    }
    let Some(applied) = handles.applied_tip.load_full() else {
        return ProvenWindow::default();
    };

    let context_started = quanta::Instant::now();
    let mut contexts = Vec::with_capacity(payloads.len());
    {
        let tree = handles.block_tree.read();
        let mut parent_id = applied.tip_id;
        let mut parent_hash = applied.hash;
        for (index, &payload) in payloads.iter().enumerate() {
            let block = payload.block();
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

    let parse_started = quanta::Instant::now();
    let parsed: Vec<core::result::Result<_, ApplyError>> = payloads
        .par_iter()
        .copied()
        .map(|payload| parse_block_for_apply(payload, handles.validation_engine))
        .collect();
    metrics::histogram!("node.window.parse_seconds").record(parse_started.elapsed().as_secs_f64());

    let prepare_started = quanta::Instant::now();
    let mut overlay = bitcoin_rs_utxo::WindowOverlay::new(
        handles.utxo.as_ref(),
        bitcoin_rs_consensus::MAX_SCRIPT_SIZE,
    );
    let mut prepared = Vec::with_capacity(payloads.len());
    for ((&payload, parsed), context) in payloads.iter().zip(parsed).zip(&contexts) {
        let block = payload.block();
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

    for ((&payload, unit), context) in payloads.iter().zip(prepared.iter_mut()).zip(&contexts) {
        let block = payload.block();
        if !unit.view.merkle_root_matches(block.header.merkle_root) {
            return ProvenWindow::default();
        }
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

    let mut takes = handles
        .script_cache
        .as_deref()
        .map(bitcoin_rs_consensus::WindowCacheTakes::new);
    let mut take_starts = Vec::with_capacity(prepared.len());
    let mut skipped = vec![false; prepared.len()];
    {
        let checks_started = quanta::Instant::now();
        let mut units = Vec::with_capacity(prepared.len());
        for (index, ((&payload, unit), context)) in payloads
            .iter()
            .zip(prepared.iter_mut())
            .zip(&contexts)
            .enumerate()
        {
            let block = payload.block();
            if let Some(takes) = takes.as_ref() {
                take_starts.push(takes.checkpoint());
            }
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
