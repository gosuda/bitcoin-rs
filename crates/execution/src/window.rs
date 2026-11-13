use super::connect::{ApplyScope, apply_committed_block_admitted};
use super::durable::{stored_body_row, sync_appended_blocks};
use super::prepare::{parse_block_for_apply, plan_block_transactions, resolve_block_prevouts};
use super::{
    BlockProvenance, BlockValidationContext, BlockValidationProof, Chainstate, ConnectOutcome,
    PreparedApply, ProvenApply, ResolvedUtxoView, WindowApplyDisposition, WindowApplyError,
};
use crate::chain::NodeStatus;
use crate::error::ApplyError;
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Txid};
use rayon::prelude::*;
use std::sync::Arc;

pub(super) const DURABLE_HEAD_GROUP_BLOCKS: usize = 64;

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
    pub undo_record: bitcoin_rs_storage::utxo::contract::UndoRecord,
    pub prev_hash: Hash256,
    pub attestation: Option<bitcoin_rs_storage::ScriptAttestation>,
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
    ) -> core::result::Result<Option<(Arc<crate::chain::TipSnapshot>, u32)>, ApplyError> {
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
        workspace: Option<&mut super::workspace::WindowWorkspace>,
        staged_block: Option<&BlockImage>,
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

        let coin_delta = if let Some(workspace) = workspace {
            if !workspace.covers(self.pending.len()) {
                return Err(ApplyError::WindowWorkspaceIncomplete {
                    staged: self.pending.len(),
                    covered: workspace.unflushed_transitions(),
                });
            }
            workspace
                .build_flush_delta(self.pending.len())
                .map_err(ApplyError::UtxoCommit)?
        } else if self
            .pending
            .iter()
            .all(|pending| pending.outcome.height == 0)
        {
            bitcoin_rs_storage::WindowDelta::default()
        } else {
            return Err(ApplyError::WindowWorkspaceIncomplete {
                staged: self.pending.len(),
                covered: 0,
            });
        };

        let mut undo_rows = Vec::with_capacity(self.pending.len());
        let mut body_rows = Vec::with_capacity(self.pending.len());
        for pending in &self.pending {
            undo_rows.push((
                pending.outcome.height,
                pending.outcome.hash,
                bytes::Bytes::copy_from_slice(pending.undo_record.as_bytes()),
            ));
            if let Some(row) =
                stored_body_row(handles, pending.outcome.height, pending.outcome.hash)?
            {
                body_rows.push(row);
            }
        }

        let prior = handles
            .durable_head
            .load()
            .map_err(ApplyError::DurableHeadCommit)?;
        if let Some(head) = prior.as_ref() {
            if head.tip != first_prev {
                return Err(ApplyError::DurableHeadLineage {
                    head: head.tip,
                    prev: first_prev,
                });
            }
        }
        let next_head = bitcoin_rs_storage::DurableHead {
            assumeutxo: prior
                .as_ref()
                .map_or(crate::AssumeUtxoDiskStatus::Uninitialized, |head| {
                    head.assumeutxo
                }),
            commit_id: prior.as_ref().map_or(1, |head| head.commit_id + 1),
            height: last.outcome.height,
            tip: last.outcome.hash,
            chain_tx_count: last.outcome.tip.chain_tx_count.to_wire(),
            body_extent: handles
                .block_body_store
                .as_ref()
                .and_then(|store| store.append_cursor()),
            undo_extent: Some((last.outcome.height, last.outcome.hash)),
        };

        let commit_started = quanta::Instant::now();
        let receipt = handles
            .commit_authority
            .commit_prefix(bitcoin_rs_storage::AcceptedPrefix {
                expected_head: prior,
                next_head,
                undo_rows,
                body_rows,
                attestation: self
                    .pending
                    .iter()
                    .filter_map(|pending| pending.attestation)
                    .min(),
                coin_delta,
            })
            .map_err(|error| match error {
                bitcoin_rs_storage::CommitError::Storage(source) => {
                    ApplyError::DurableHeadCommit(source)
                }
                source @ (bitcoin_rs_storage::CommitError::AdmissionClosed
                | bitcoin_rs_storage::CommitError::PreconditionFailed) => {
                    ApplyError::DurableHeadCommit(bitcoin_rs_storage::StorageError::backend(
                        source.to_string(),
                    ))
                }
            })?;
        debug_assert!(
            self.pending.last().is_some_and(
                |last| last.outcome.tip.chain_tx_count.to_wire() == receipt.chain_tx_count()
            ),
            "the batch certifies the last staged prefix count"
        );
        let group_blocks = self.pending.len();
        tracing::debug!(
            blocks = group_blocks,
            sync_us = group_sync_us,
            commit_us = commit_started.elapsed().as_micros(),
            "durable_head: group commit"
        );
        Ok(self.finish_commit(handles, receipt.commit_id()))
    }

    fn finish_commit(&mut self, handles: &Chainstate, commit_id: u64) -> Vec<ConnectOutcome> {
        for pending in &mut self.pending {
            pending.outcome.commit_id = commit_id;
        }
        self.staged_bytes = 0;
        let published = self
            .pending
            .drain(..)
            .map(|pending| {
                handles.publish_applied(&pending.outcome.tip, crate::events::HintKind::Connected);
                pending.outcome
            })
            .collect();
        metrics::counter!("node.durable_head.group_flushes").increment(1);
        published
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
    workspace: Option<super::workspace::WindowWorkspace>,
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

fn admit_window_headers(handles: &Chainstate, payloads: &[&BlockImage]) {
    let mut tree = handles.block_tree.write();
    for payload in payloads {
        let header = payload.header();
        let hash = payload.block_hash().0;
        if tree.lookup(hash).is_some() {
            continue;
        }
        if tree.insert_header(header, NodeStatus::HeaderValid).is_err() {
            return;
        }
    }
}

fn proved_window<'a, 'h>(
    handles: &'h Chainstate,
    payloads: &[&'a BlockImage],
) -> core::result::Result<ProvenWindow<'a, 'h>, WindowApplyError> {
    prove_window(handles, payloads).map_err(|source| WindowApplyError {
        applied: 0,
        committed: Vec::new(),
        disposition: classify_apply_error(&source),
        source: Box::new(source),
        invalidated: Box::default(),
    })
}

pub(super) fn apply_window_admitted(
    handles: &Chainstate,
    payloads: &[&BlockImage],
) -> core::result::Result<Vec<ConnectOutcome>, WindowApplyError> {
    if payloads.len() > 1
        && handles.applied_tip.load_full().is_none()
        && payloads[0].block_hash().0 == handles.network.genesis_block_hash()
    {
        let mut committed = apply_window_admitted(handles, &payloads[..1])?;
        return match apply_window_admitted(handles, &payloads[1..]) {
            Ok(outcomes) => {
                committed.extend(outcomes);
                Ok(committed)
            }
            Err(mut error) => {
                committed.append(&mut error.committed);
                error.applied = committed.len();
                error.committed = committed;
                Err(error)
            }
        };
    }
    let mut window = proved_window(handles, payloads)?;
    if window.workspace.is_none() && !payloads.is_empty() {
        admit_window_headers(handles, payloads);
        window = proved_window(handles, payloads)?;
    }
    let covered = window.proven.len();
    let mut proven = window.proven.into_iter();
    let mut takes = window.takes;
    let take_starts = window.take_starts;
    let mut workspace = window.workspace;
    let mut group = WindowGroup::default();
    let mut committed: Vec<ConnectOutcome> = Vec::with_capacity(payloads.len());
    for (index, &payload) in payloads.iter().enumerate() {
        if workspace.is_some() && index >= covered {
            if let Err(error) = flush_group(
                &mut group,
                handles,
                workspace.as_mut(),
                &mut committed,
                payloads,
            ) {
                restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
                return Err(error);
            }
            restore_uncommitted_takes(takes.take(), &take_starts, committed.len());
            return match apply_window_admitted(handles, &payloads[index..]) {
                Ok(outcomes) => {
                    committed.extend(outcomes);
                    Ok(committed)
                }
                Err(mut error) => {
                    committed.append(&mut error.committed);
                    error.applied = committed.len();
                    error.committed = committed;
                    Err(error)
                }
            };
        }
        let block_hash = payload.block_hash().0;
        match apply_committed_block_admitted(
            handles,
            payload,
            proven.next(),
            ApplyScope {
                provenance: BlockProvenance::Network,
                staged: workspace.as_ref(),
            },
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
                        source: Box::new(source),
                        disposition: WindowApplyDisposition::Fatal,
                        invalidated: Box::default(),
                    });
                }
                let (invalidated, disposition) = if disposition == WindowApplyDisposition::Permanent
                {
                    invalidate_permanent_failure(handles, block_hash)
                } else {
                    (Box::default(), disposition)
                };
                if disposition == WindowApplyDisposition::Fatal {
                    restore_uncommitted_takes(takes.take(), &take_starts, committed.len());
                    group.abandon();
                    return Err(WindowApplyError {
                        applied: committed.len(),
                        committed,
                        source: Box::new(source),
                        disposition: WindowApplyDisposition::Fatal,
                        invalidated,
                    });
                }
                if let Err(error) = flush_group(
                    &mut group,
                    handles,
                    workspace.as_mut(),
                    &mut committed,
                    payloads,
                ) {
                    restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
                    return Err(error);
                }
                restore_uncommitted_takes(takes.take(), &take_starts, committed.len());
                return Err(WindowApplyError {
                    applied: committed.len(),
                    committed,
                    source: Box::new(source),
                    disposition,
                    invalidated,
                });
            }
        }
        if group.should_flush() {
            if let Err(error) = flush_group(
                &mut group,
                handles,
                workspace.as_mut(),
                &mut committed,
                payloads,
            ) {
                restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
                return Err(error);
            }
        }
    }
    if let Err(error) = flush_group(
        &mut group,
        handles,
        workspace.as_mut(),
        &mut committed,
        payloads,
    ) {
        restore_uncommitted_takes(takes.take(), &take_starts, error.applied);
        return Err(error);
    }
    Ok(committed)
}

/// Flushes the group's staged prefix into `committed`.
///
/// A flush failure is the ambiguous-batch case — the durable head may or may not name
/// it — so the group is abandoned and the error is fatal, never retried.
fn flush_group(
    group: &mut WindowGroup,
    handles: &Chainstate,
    workspace: Option<&mut super::workspace::WindowWorkspace>,
    committed: &mut Vec<ConnectOutcome>,
    payloads: &[&BlockImage],
) -> core::result::Result<(), WindowApplyError> {
    if group.pending.is_empty() {
        return Ok(());
    }

    let flush_started = quanta::Instant::now();
    let pending_blocks = group.pending.len();
    let staged_block = (committed.len() + pending_blocks)
        .checked_sub(1)
        .and_then(|idx| payloads.get(idx))
        .copied();
    match group.flush(handles, workspace, staged_block) {
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
                source: Box::new(flush_error),
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
    use WindowApplyDisposition::{Fatal, Operational, Permanent};
    match error {
        ApplyError::UtxoCommit(_)
        | ApplyError::DurableHeadCommit(_)
        | ApplyError::DurableHeadLineage { .. }
        | ApplyError::DurableHeadGapUnrecoverable { .. }
        | ApplyError::BlockBodyPersistence(_)
        | ApplyError::UndoPersistence(_)
        | ApplyError::WindowWorkspaceIncomplete { .. }
        | ApplyError::CoinStoreRead(_)
        | ApplyError::RecoveryCoinStats(_)
        | ApplyError::RecoveryPublication(_) => Fatal,
        ApplyError::ProofOfWork { .. }
        | ApplyError::BlockValueOverflow
        | ApplyError::BlockOutputsExceedInputs => Permanent,
        ApplyError::Chain(error) => classify_chain_error(error),
        ApplyError::Consensus(error) => classify_consensus_error(error),
        ApplyError::Shutdown
        | ApplyError::ConcurrentChainChange
        | ApplyError::ChainChangeGenerationOverflow
        | ApplyError::PrevHashMismatch { .. }
        | ApplyError::HeightOverflow(_)
        | ApplyError::VoutOverflow { .. }
        | ApplyError::TxidCountMismatch { .. }
        | ApplyError::UndoPrevoutMissing { .. }
        | ApplyError::UndoLoad(_)
        | ApplyError::DisconnectNotTip { .. }
        | ApplyError::DisconnectBodyMismatch { .. }
        | ApplyError::DisconnectOffDurableHead { .. }
        | ApplyError::CoinStatsRewind(_)
        | ApplyError::DisconnectBelowSnapshotBase { .. }
        | ApplyError::PruneDuringHistoricalValidation { .. }
        | ApplyError::ConnectPastHistoricalTarget { .. }
        | ApplyError::HistoricalTargetHashMismatch { .. } => Operational,
    }
}

fn classify_chain_error(error: &crate::chain::ChainError) -> WindowApplyDisposition {
    use WindowApplyDisposition::{Operational, Permanent};
    match error {
        crate::chain::ChainError::BadVersion { .. }
        | crate::chain::ChainError::TimewarpAttack { .. }
        | crate::chain::ChainError::TimestampTooEarly { .. }
        | crate::chain::ChainError::NbitsMismatch { .. } => Permanent,
        crate::chain::ChainError::NodeIdOverflow { .. }
        | crate::chain::ChainError::UnknownNode { .. }
        | crate::chain::ChainError::DuplicateHeader { .. }
        | crate::chain::ChainError::KnownInvalidHeader { .. }
        | crate::chain::ChainError::MissingParent { .. }
        | crate::chain::ChainError::InvalidParent { .. }
        | crate::chain::ChainError::NonContinuousHeader { .. }
        | crate::chain::ChainError::ZeroTarget { .. }
        | crate::chain::ChainError::TargetExceedsLimit { .. }
        | crate::chain::ChainError::TargetBitsOverflow { .. }
        | crate::chain::ChainError::InvalidPow { .. }
        | crate::chain::ChainError::ChainworkOverflow { .. }
        | crate::chain::ChainError::HeightOverflow { .. }
        | crate::chain::ChainError::NoCommonAncestor { .. }
        | crate::chain::ChainError::TimestampTooFarAhead { .. } => Operational,
    }
}

fn classify_consensus_error(
    error: &bitcoin_rs_consensus::ConsensusError,
) -> WindowApplyDisposition {
    use WindowApplyDisposition::{BodyMutated, Operational, Permanent};
    use bitcoin_rs_consensus::ConsensusError;
    match error {
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
        | ConsensusError::Kernel(_) => Operational,
        ConsensusError::EmptyInputs
        | ConsensusError::EmptyOutputs
        | ConsensusError::CoinbaseScriptSigSize { .. }
        | ConsensusError::NullPrevout { .. }
        | ConsensusError::DuplicateInput { .. }
        | ConsensusError::MissingPrevout { .. }
        | ConsensusError::OutputValueOverflow
        | ConsensusError::InputsLessThanOutputs { .. }
        | ConsensusError::Script { .. }
        | ConsensusError::SigopsLimit { .. }
        | ConsensusError::EmptyBlock
        | ConsensusError::MissingCoinbase
        | ConsensusError::ExtraCoinbase { .. }
        | ConsensusError::CoinbaseAmount { .. }
        | ConsensusError::BlockValueOverflow
        | ConsensusError::BlockWeight { .. }
        | ConsensusError::BlockBaseSize { .. }
        | ConsensusError::SignetSolution
        | ConsensusError::Bip { .. } => Permanent,
    }
}

fn window_contexts(
    handles: &Chainstate,
    applied: &crate::chain::TipSnapshot,
    payloads: &[&BlockImage],
) -> Vec<BlockValidationContext> {
    let tree = handles.block_tree.read();
    let mut contexts = Vec::with_capacity(payloads.len());
    let mut parent_id = applied.tip_id;
    let mut parent_hash = applied.hash;
    for (index, &payload) in payloads.iter().enumerate() {
        let header = payload.header();
        let hash = payload.block_hash().0;
        if header.prev_blockhash.0 != parent_hash {
            break;
        }
        let Some(height) = u32::try_from(index)
            .ok()
            .and_then(|offset| applied.height.checked_add(offset))
            .and_then(|height| height.checked_add(1))
        else {
            break;
        };
        let softfork =
            crate::chain::softfork_state(&tree, handles.network, Some(parent_id), height);
        let locktime_rule =
            bitcoin_rs_consensus::LocktimeRule::from_csv_active(softfork.csv_active);
        let cutoff = bitcoin_rs_consensus::locktime_cutoff(
            locktime_rule,
            tree.median_time_past_at(parent_id).unwrap_or(0),
            header.time,
        );
        let Some(node_id) = tree.lookup(hash) else {
            break;
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
    contexts
}

fn prepare_window<'a>(
    handles: &Chainstate,
    payloads: &[&'a BlockImage],
    contexts: &[BlockValidationContext],
) -> core::result::Result<
    Option<(Vec<PreparedApply<'a>>, super::workspace::WindowWorkspace)>,
    ApplyError,
> {
    #[cfg(test)]
    if prepare_fault::armed() {
        return Ok(None);
    }
    let parse_started = quanta::Instant::now();
    let parsed: Vec<core::result::Result<_, ApplyError>> = payloads
        .par_iter()
        .copied()
        .map(|payload| parse_block_for_apply(payload, handles.validation_engine))
        .collect();
    metrics::histogram!("node.window.parse_seconds").record(parse_started.elapsed().as_secs_f64());

    let prepare_started = quanta::Instant::now();
    let mut workspace =
        super::workspace::WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
    let mut window_txids: Vec<Txid> = parsed
        .iter()
        .filter_map(|parsed| parsed.as_ref().ok())
        .flat_map(|(_, facts)| facts.txids().iter().copied())
        .collect();
    window_txids.sort_unstable();
    window_txids.dedup();
    workspace
        .resolve_engine_presence(handles.coins.as_ref(), &window_txids)
        .map_err(ApplyError::CoinStoreRead)?;
    let mut prepared = Vec::with_capacity(payloads.len());
    for (index, ((&payload, parsed), context)) in
        payloads.iter().zip(parsed).zip(contexts).enumerate()
    {
        let Ok((script_source, facts)) = parsed else {
            return Ok(None);
        };
        let tx_plan = plan_block_transactions(payload, facts.txids());
        let view = bitcoin_rs_consensus::BlockView::from_image(payload, facts);
        let mut duplicates_visible = false;
        for txid in view.txids() {
            let present = workspace.has_live_outputs(*txid)
                || match workspace.resolved_engine_presence(*txid) {
                    Some(present) => present,
                    None => handles
                        .coins
                        .get(&bitcoin_rs_storage::CoinKey(txid.0.to_le_bytes()))
                        .map_err(ApplyError::CoinStoreRead)?
                        .is_some(),
                };
            if present {
                duplicates_visible = true;
                break;
            }
        }
        if index > 0
            && duplicates_visible
            && !bitcoin_rs_consensus::bip30::is_bip30_exception(context.height, context.hash)
        {
            break;
        }
        let mut external = Vec::new();
        for tx in (0..payload.tx_count()).map(|index| payload.tx(index)) {
            if tx.is_coinbase() {
                continue;
            }
            for input_index in 0..tx.input_count() {
                let previous_output = tx.input_outpoint(input_index);
                let is_same_block_spent = tx_plan
                    .same_block_spent
                    .as_ref()
                    .is_some_and(|set| set.contains(&previous_output));
                if !is_same_block_spent {
                    external.push(previous_output);
                }
            }
        }
        if let Err(source) = workspace.resolve_external_batch(handles.coins.as_ref(), &external) {
            return Err(match source {
                super::workspace::WindowReadError::Storage(source) => {
                    ApplyError::CoinStoreRead(source)
                }
                super::workspace::WindowReadError::Record(source) => ApplyError::UtxoCommit(source),
            });
        }
        let resolved = Arc::new(ResolvedUtxoView::resolve(&workspace, payload, &tx_plan));
        if workspace
            .advance(
                &payload.materialize(),
                view.txids(),
                context.height,
                tx_plan.same_block_spent_set(),
            )
            .is_err()
        {
            return Ok(None);
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
    Ok(Some((prepared, workspace)))
}

fn window_commitments_match(
    payloads: &[&BlockImage],
    prepared: &mut [PreparedApply<'_>],
    contexts: &[BlockValidationContext],
) -> bool {
    for ((&payload, unit), context) in payloads.iter().zip(prepared.iter_mut()).zip(contexts) {
        if !unit.view.merkle_root_matches(payload.header().merkle_root) {
            return false;
        }
        if context
            .flags
            .contains(bitcoin_rs_consensus::script::VerifyFlags::WITNESS)
            && unit.view.facts().has_witness()
        {
            let commitment_matches = {
                let wtxids = unit.view.witness_ids();
                bitcoin_rs_consensus::block_image_witness_commitment_matches(payload, wtxids)
            };
            if !commitment_matches {
                return false;
            }
        }
    }
    true
}

type WindowScriptProof<'h> = (
    Option<bitcoin_rs_consensus::WindowCacheTakes<'h>>,
    Vec<usize>,
    Vec<bool>,
);

fn prove_window_scripts<'a, 'h>(
    handles: &'h Chainstate,
    payloads: &[&'a BlockImage],
    prepared: &mut [PreparedApply<'a>],
    contexts: &[BlockValidationContext],
) -> Option<WindowScriptProof<'h>> {
    let mut takes = handles
        .script_cache
        .as_deref()
        .map(bitcoin_rs_consensus::WindowCacheTakes::new);
    let mut take_starts = Vec::with_capacity(prepared.len());
    let mut skipped = vec![false; prepared.len()];
    let checks_started = quanta::Instant::now();
    let mut units = Vec::with_capacity(prepared.len());
    for (index, ((&payload, unit), context)) in payloads
        .iter()
        .zip(prepared.iter_mut())
        .zip(contexts)
        .enumerate()
    {
        if let Some(takes) = takes.as_ref() {
            take_starts.push(takes.checkpoint());
        }
        if handles.scripts_verified_upstream(BlockProvenance::Network, context.height, context.hash)
        {
            skipped[index] = true;
            continue;
        }
        let Ok(resolved) = resolve_block_prevouts(
            Arc::clone(&unit.resolved),
            payload,
            &unit.tx_plan,
            context.height,
            unit.view.txids(),
        ) else {
            if let Some(takes) = takes.take() {
                takes.rollback();
            }
            return None;
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
            return None;
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
        return None;
    }
    if !units.is_empty() {
        metrics::counter!("node.window.verify_success_total").increment(1);
    }
    Some((takes, take_starts, skipped))
}

fn prove_window<'a, 'h>(
    handles: &'h Chainstate,
    payloads: &[&'a BlockImage],
) -> core::result::Result<ProvenWindow<'a, 'h>, ApplyError> {
    if payloads.is_empty() {
        return Ok(ProvenWindow::default());
    }
    let Some(applied) = handles.applied_tip.load_full() else {
        return Ok(ProvenWindow::default());
    };

    let context_started = quanta::Instant::now();
    let contexts = window_contexts(handles, &applied, payloads);
    if contexts.is_empty() {
        return Ok(ProvenWindow::default());
    }
    metrics::histogram!("node.window.context_seconds")
        .record(context_started.elapsed().as_secs_f64());

    let Some((mut prepared, workspace)) = prepare_window(handles, payloads, &contexts)? else {
        return Ok(ProvenWindow::default());
    };
    let (proven, takes, take_starts) =
        if window_commitments_match(payloads, &mut prepared, &contexts) {
            match prove_window_scripts(handles, payloads, &mut prepared, &contexts) {
                Some((takes, take_starts, skipped)) => {
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
                    (proven, takes, take_starts)
                }
                None => (
                    prepared.into_iter().map(ProvenApply::Unproven).collect(),
                    None,
                    Vec::new(),
                ),
            }
        } else {
            (
                prepared.into_iter().map(ProvenApply::Unproven).collect(),
                None,
                Vec::new(),
            )
        };
    Ok(ProvenWindow {
        proven,
        takes,
        take_starts,
        workspace: Some(workspace),
    })
}

#[cfg(test)]
mod cache_tests;

#[cfg(test)]
pub(crate) mod prepare_fault {
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn armed() -> bool {
        ARMED.with(Cell::get)
    }

    pub(crate) struct Armed(());

    impl Drop for Armed {
        fn drop(&mut self) {
            ARMED.with(|armed| armed.set(false));
        }
    }

    pub(crate) fn arm() -> Armed {
        ARMED.with(|armed| armed.set(true));
        Armed(())
    }
}

#[cfg(test)]
mod workspace_guard_tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use crate::chain::regtest_fixture::mined_regtest_child_at;
    use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
    use bitcoin_rs_storage::commit::AcceptedPrefix;
    use bitcoin_rs_storage::durable_head::DurableHead;
    use bitcoin_rs_storage::utxo::UtxoSet;
    use bitcoin_rs_storage::utxo::contract::UndoRecord;
    use bitcoin_rs_storage::{ColumnFamily, WindowDelta};

    use super::{PendingBlockCommit, WindowGroup};
    use crate::test_fixtures::{handles, seed_genesis};
    use crate::{ApplyError, Chainstate, ConnectOutcome, WindowApplyDisposition};

    fn commit_genesis_head(chain: &Chainstate) {
        let genesis = Network::Regtest.genesis_block();
        chain
            .commit_authority
            .commit_prefix(AcceptedPrefix {
                expected_head: None,
                next_head: DurableHead {
                    assumeutxo: crate::AssumeUtxoDiskStatus::Uninitialized,
                    commit_id: 1,
                    height: 0,
                    tip: Hash256::from(genesis.block_hash()),
                    chain_tx_count: 1,
                    body_extent: None,
                    undo_extent: None,
                },
                undo_rows: Vec::new(),
                body_rows: Vec::new(),
                attestation: None,
                coin_delta: WindowDelta::default(),
            })
            .expect("genesis head");
    }

    // CMT-02, CMT-03, SYNC-05, WIN-03
    #[test]
    fn cold_genesis_window_commits_child_with_its_coin() {
        let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis = Network::Regtest.genesis_block();
        let child = mined_regtest_child_at(genesis.block_hash(), 1).expect("mine child");
        let child_hash = child.block_hash().0;
        let child_key = bitcoin_rs_storage::CoinKey(child.txs[0].txid().0.to_le_bytes());
        let payloads = [
            BlockImage::from_local(genesis),
            BlockImage::from_local(child),
        ];

        let outcomes = chain
            .apply_window(&[&payloads[0], &payloads[1]])
            .expect("cold genesis window");

        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].height, 0);
        assert_eq!(outcomes[0].hash, Network::Regtest.genesis_block_hash());
        assert_eq!(outcomes[1].height, 1);
        assert_eq!(outcomes[1].hash, child_hash);
        assert!(outcomes[0].commit_id < outcomes[1].commit_id);
        let head = chain.durable_head.load().expect("head read").expect("head");
        assert_eq!(head.height, 1);
        assert_eq!(head.tip, child_hash);
        assert_eq!(head.commit_id, outcomes[1].commit_id);
        let applied = chain.applied_tip.load_full().expect("applied tip");
        assert_eq!(applied.height, 1);
        assert_eq!(applied.hash, child_hash);
        assert!(chain.coins.get(&child_key).expect("child coin").is_some());
        assert!(
            chain
                .commit_authority
                .store()
                .get(ColumnFamily::Coins, child_key.as_bytes())
                .expect("durable child coin")
                .is_some()
        );
    }

    // WIN-08, SYNC-04, CMT-03
    #[test]
    fn cold_genesis_window_reports_bootstrap_once_when_child_is_invalid() {
        let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash().0;
        let mut child = mined_regtest_child_at(genesis.block_hash(), 1).expect("mine child");
        child.txs[0].outputs[0].value =
            bitcoin_rs_consensus::primitives::Amount::from_sat(500_000_000_000);
        child.header.merkle_root =
            crate::chain::regtest_fixture::merkle_root(&child.txs).expect("merkle root");
        crate::chain::regtest_fixture::mine_block_to_declared_target(&mut child)
            .expect("remine invalid child");
        let child_key = bitcoin_rs_storage::CoinKey(child.txs[0].txid().0.to_le_bytes());
        let payloads = [
            BlockImage::from_local(genesis),
            BlockImage::from_local(child),
        ];

        let error = chain
            .apply_window(&[&payloads[0], &payloads[1]])
            .expect_err("invalid child");

        assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
        assert_eq!(error.applied, 1);
        assert_eq!(error.committed.len(), 1);
        assert_eq!(error.committed[0].height, 0);
        assert_eq!(error.committed[0].hash, genesis_hash);
        let head = chain.durable_head.load().expect("head read").expect("head");
        assert_eq!(head.height, 0);
        assert_eq!(head.tip, genesis_hash);
        assert_eq!(head.commit_id, error.committed[0].commit_id);
        let applied = chain.applied_tip.load_full().expect("applied tip");
        assert_eq!(applied.height, 0);
        assert_eq!(applied.hash, genesis_hash);
        assert!(chain.coins.get(&child_key).expect("child coin").is_none());
    }

    // CMT-02
    #[test]
    fn flush_refuses_a_staged_prefix_without_a_workspace() {
        let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        seed_genesis(&chain).expect("genesis tip");
        let genesis = Network::Regtest.genesis_block();
        commit_genesis_head(&chain);

        let b1 = mined_regtest_child_at(genesis.block_hash(), 1).expect("mine block 1");
        let b1_image = BlockImage::from_local(b1.clone());
        let tip = crate::connect::applied_header_tip(
            &chain,
            Hash256::from(b1.block_hash()),
            &b1_image,
            1,
        )
        .expect("header tip");

        let mut group = WindowGroup::default();
        group.stage(PendingBlockCommit {
            outcome: ConnectOutcome {
                tip: tip.clone(),
                commit_id: 0,
                height: 1,
                hash: tip.hash,
                txids: b1.txs.iter().map(|tx| tx.txid()).collect(),
                block_bytes: Default::default(),
                raw_txs: None,
            },
            undo_record: UndoRecord::new(Vec::new()),
            prev_hash: Hash256::from(genesis.block_hash()),
            attestation: None,
        });

        match group.flush(&chain, None, None) {
            Err(ApplyError::WindowWorkspaceIncomplete { .. }) => {}
            Err(other) => panic!("expected the missing-workspace refusal, got: {other}"),
            Ok(_) => {
                let head = chain
                    .durable_head
                    .load()
                    .expect("head read")
                    .expect("head row");
                panic!(
                    "a staged prefix with no window workspace committed head at height {} \
                     with an empty coin delta; the block's created coins never reached the engine",
                    head.height
                );
            }
        }
    }

    // CMT-02
    #[test]
    fn window_without_a_workspace_refuses_a_coin_less_commit() {
        let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        seed_genesis(&chain).expect("genesis tip");
        let genesis = Network::Regtest.genesis_block();
        commit_genesis_head(&chain);

        let b1 = mined_regtest_child_at(genesis.block_hash(), 1).expect("mine block 1");
        let b2 = mined_regtest_child_at(b1.block_hash(), 2).expect("mine block 2");
        let headers = [b1.header, b2.header];
        chain.admit_headers(&headers).expect("headers");
        let payloads = [BlockImage::from_local(b1), BlockImage::from_local(b2)];
        let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

        let error = {
            let _fault = super::prepare_fault::arm();
            match chain.apply_window(&payload_refs) {
                Ok(outcomes) => panic!(
                    "a window with no coin workspace committed head at height {}",
                    outcomes.last().map_or(0, |outcome| outcome.height)
                ),
                Err(error) => error,
            }
        };
        assert!(
            matches!(
                error.source.as_ref(),
                ApplyError::WindowWorkspaceIncomplete { .. }
            ),
            "expected the missing-workspace refusal, got: {error}"
        );
        assert_eq!(error.disposition, WindowApplyDisposition::Fatal);

        let head = chain
            .durable_head
            .load()
            .expect("head read")
            .expect("head row");
        assert_eq!(head.height, 0, "the refused prefix must not commit");
        let mut rows = chain
            .commit_authority
            .store()
            .iter_prefix(ColumnFamily::Coins, &[])
            .expect("coins scan");
        assert!(
            rows.next().is_none(),
            "no coin row of the refused prefix may reach the engine"
        );
    }
}
