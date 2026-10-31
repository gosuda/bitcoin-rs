//! Validated block connection and its ordered persistence/publication transaction.

#[cfg(test)]
mod tests;

use super::SameBlockSpentSet;
use super::durable::{
    ConnectCommitFacts, commit_connect_head, stored_body_row, sync_appended_blocks,
};
use super::prepare::{ScriptsRan, prepare_apply, verify_block_transactions};
use super::tx_count_delta_for;
use super::window::{PendingBlockCommit, PublishMode};
use super::{
    ApplyFinish, ApplyIntent, Bip68Context, BlockLocalUtxoView, BlockProvenance, BlockTxPlan,
    BlockValidationContext, Chainstate, ConnectOutcome, PreparedApply, ProvenApply,
    ResolvedUtxoView,
};
use crate::error::ApplyError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::node::NodeId;
use bitcoin_rs_consensus::{MAX_SCRIPT_SIZE, UtxoView};
use bitcoin_rs_primitives::{Block, BlockPayload, Hash256, Txid, consensus_bytes};
use bitcoin_rs_storage::{CommitRecords, ScriptAttestation};
use bitcoin_rs_utxo::contract::{
    BlockChangeError, BlockChangeInputs, BlockChanges, BlockValueTotals, UndoBatch, UndoRecord,
    build_block_changes,
};
use hashbrown::HashMap;
use std::sync::Arc;

pub(super) fn apply_committed_block_admitted<'b>(
    handles: &Chainstate,
    payload: &'b BlockPayload,
    proven: Option<ProvenApply<'b>>,
    provenance: BlockProvenance,
    publication: PublishMode<'_>,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    match apply_block_admitted(
        handles,
        payload,
        proven,
        provenance,
        ApplyIntent::Commit,
        publication,
    )? {
        ApplyFinish::Committed(outcome) => Ok(*outcome),
        ApplyFinish::Proposed => unreachable!("commit intent returns a committed tip"),
    }
}

#[derive(Default)]
struct ApplyTimings {
    block_rules: std::time::Duration,
    bip30_bip34: std::time::Duration,
    script_verify: std::time::Duration,
    utxo_commit: std::time::Duration,
    block_body_persist: std::time::Duration,
    block_tree_insert: std::time::Duration,
    coin_stats: std::time::Duration,
}

fn application_predecessor(
    handles: &Chainstate,
    block_hash: Hash256,
    prev_hash: Hash256,
    publication: &PublishMode<'_>,
) -> core::result::Result<(Option<Arc<TipSnapshot>>, u32), ApplyError> {
    match publication {
        PublishMode::Grouped(group) => match group.predecessor(prev_hash)? {
            Some((tip, height)) => Ok((Some(tip), height)),
            None => applied_predecessor(handles, block_hash, prev_hash),
        },
        PublishMode::Now | PublishMode::Replay { .. } => {
            applied_predecessor(handles, block_hash, prev_hash)
        }
    }
}

fn check_historical_target(
    handles: &Chainstate,
    height: u32,
    block_hash: Hash256,
) -> core::result::Result<(), ApplyError> {
    if let crate::assumeutxo::ChainstateRole::Historical {
        base_height,
        base_hash,
    } = handles.role()
    {
        if height > base_height {
            return Err(ApplyError::ConnectPastHistoricalTarget {
                height,
                base_height,
            });
        }
        if height == base_height && block_hash != base_hash {
            return Err(ApplyError::HistoricalTargetHashMismatch {
                base_height,
                expected: base_hash,
                found: block_hash,
            });
        }
    }
    Ok(())
}

fn check_contextual_header(
    handles: &Chainstate,
    block: &Block,
    height: u32,
    prior: Option<&TipSnapshot>,
    block_hash: Hash256,
) -> core::result::Result<(), ApplyError> {
    let contextual_header_started =
        tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let contextual_header_result = validate_contextual_block_header(handles, block, height, prior);
    tracing::debug!(
        height,
        %block_hash,
        contextual_header_us = contextual_header_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    contextual_header_result
}

fn prepare_journal_for_apply(
    handles: &Chainstate,
    height: u32,
    intent: ApplyIntent,
) -> core::result::Result<(), ApplyError> {
    if intent == ApplyIntent::Commit
        && let Some(journal) = handles.journal.read().clone()
    {
        let maintenance = {
            let mut journal = journal.lock();
            journal.prepare_for_apply()
        };
        if let Err(error) = maintenance {
            metrics::counter!("node.chainstate_journal.backpressure_total").increment(1);
            tracing::error!(height, %error, "chainstate journal backpressure stopped block apply");
            return Err(ApplyError::JournalBackpressure(Box::new(error)));
        }
    }
    Ok(())
}

fn check_self_pow(
    handles: &Chainstate,
    block: &Block,
    block_hash: Hash256,
    height: u32,
    intent: ApplyIntent,
) -> core::result::Result<(), ApplyError> {
    let pow_self_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let pow_self_result =
        bitcoin_rs_chain::header_sync::validate_pow(&block.header, block_hash, handles.network);
    tracing::debug!(
        height,
        %block_hash,
        pow_self_us = pow_self_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    match pow_self_result {
        Err(bitcoin_rs_chain::ChainError::TargetExceedsLimit { .. }) => {
            Err(ApplyError::TargetAboveLimit)
        }
        Err(_) if intent == ApplyIntent::Commit => {
            Err(ApplyError::ProofOfWork { hash: block_hash })
        }
        _ => Ok(()),
    }
}

struct ValidationContexts {
    validation: BlockValidationContext,
    softfork: bitcoin_rs_chain::SoftforkState,
    median_time_past: u32,
}

fn validation_contexts(
    handles: &Chainstate,
    block: &Block,
    height: u32,
    block_hash: Hash256,
    prior: Option<&TipSnapshot>,
) -> ValidationContexts {
    let (prev_median_time_past, softfork_state) = if let Some(tip) = prior {
        let tree = handles.block_tree.read();
        let mtp = tree.median_time_past_at(tip.tip_id).unwrap_or(0);
        let softfork_state =
            bitcoin_rs_chain::softfork_state(&tree, handles.network, Some(tip.tip_id), height);
        (mtp, softfork_state)
    } else {
        let tree = handles.block_tree.read();
        (
            0,
            bitcoin_rs_chain::softfork_state(&tree, handles.network, None, height),
        )
    };
    let locktime_rule = if softfork_state.csv_active {
        bitcoin_rs_consensus::LocktimeRule::MedianTimePast
    } else {
        bitcoin_rs_consensus::LocktimeRule::CandidateTime
    };
    let locktime_cutoff = bitcoin_rs_consensus::locktime_cutoff(
        locktime_rule,
        prev_median_time_past,
        block.header.time,
    );
    let verify_flags =
        bitcoin_rs_consensus::verify_flags(handles.network, height, block_hash, softfork_state);
    ValidationContexts {
        validation: BlockValidationContext {
            hash: block_hash,
            parent: block.header.prev_blockhash.0,
            height,
            flags: verify_flags,
            locktime_cutoff,
        },
        softfork: softfork_state,
        median_time_past: prev_median_time_past,
    }
}

fn prepare_block<'b>(
    handles: &Chainstate,
    payload: &'b BlockPayload,
    proven: Option<ProvenApply<'b>>,
    context: &BlockValidationContext,
) -> core::result::Result<(PreparedApply<'b>, bool), ApplyError> {
    match proven {
        Some(ProvenApply::Proven(proof)) if &proof.context == context => Ok((proof.prepared, true)),
        Some(ProvenApply::AssumeValidSkipped(prepared)) => Ok((prepared, false)),
        Some(ProvenApply::Proven(_)) | None => Ok((
            prepare_apply(payload, handles.utxo.as_ref(), handles.validation_engine)?,
            false,
        )),
    }
}

struct BlockRules<'a, 'b> {
    handles: &'a Chainstate,
    block: &'b Block,
    block_hash: Hash256,
    prev_hash: Hash256,
    context: &'b BlockValidationContext,
    softfork: bitcoin_rs_chain::SoftforkState,
    prior_tip_id: Option<NodeId>,
    intent: ApplyIntent,
}

impl BlockRules<'_, '_> {
    fn check(
        &self,
        view: &mut bitcoin_rs_consensus::BlockView<'_>,
        has_witness: bool,
        timings: &mut ApplyTimings,
    ) -> core::result::Result<(), ApplyError> {
        let needs_wtxids = self.softfork.segwit_active && has_witness;
        if needs_wtxids {
            view.witness_ids();
        }
        let block_rules_started = quanta::Instant::now();
        let block_rules_result = bitcoin_rs_consensus::verify_block_rules_precomputed(
            self.block,
            bitcoin_rs_consensus::BlockRuleContext {
                segwit_active: self.softfork.segwit_active,
            },
            view.facts(),
        );
        let block_rules_dur = block_rules_started.elapsed();
        metrics::histogram!("node.apply_block.block_rules_seconds")
            .record(block_rules_dur.as_secs_f64());
        timings.block_rules = block_rules_dur;
        block_rules_result?;
        if self.intent == ApplyIntent::Commit
            && let Some(challenge) = self.handles.network.signet_challenge()
        {
            bitcoin_rs_consensus::check_signet_block_solution(self.block, challenge)?;
        }
        check_block_finality(
            self.block,
            self.context.height,
            self.context.locktime_cutoff,
        )?;
        if self.intent == ApplyIntent::Commit {
            check_bip34(self.handles, self.block, self.context.height)?;
        }
        if self.intent == ApplyIntent::Commit
            && self.softfork.segwit_active
            && let Some(hook) = self.handles.pow_valid_block.get()
            && self
                .handles
                .applied_tip_snapshot()
                .is_some_and(|tip| tip.hash == self.prev_hash)
        {
            hook(self.block, self.block_hash, self.context.height);
        }
        let bip30_bip34_started = quanta::Instant::now();
        let bip30_bip34_result = check_bip30_and_bip34(
            self.handles,
            self.block,
            self.context.height,
            view.txids(),
            self.prior_tip_id,
        );
        let bip30_bip34_dur = bip30_bip34_started.elapsed();
        metrics::histogram!("node.apply_block.bip30_bip34_seconds")
            .record(bip30_bip34_dur.as_secs_f64());
        timings.bip30_bip34 = bip30_bip34_dur;
        bip30_bip34_result
    }
}

struct ScriptVerification<'a, 'b> {
    handles: &'a Chainstate,
    view: &'a mut bitcoin_rs_consensus::BlockView<'b>,
    tx_plan: &'a BlockTxPlan,
    resolved: &'a Arc<ResolvedUtxoView>,
    context: &'a BlockValidationContext,
    provenance: BlockProvenance,
    script_source: &'a bitcoin_rs_consensus::kernel::BlockScriptSource,
    transactions_proven: bool,
    intent: ApplyIntent,
}

impl ScriptVerification<'_, '_> {
    fn run(&mut self, timings: &mut ApplyTimings) -> core::result::Result<ScriptsRan, ApplyError> {
        let script_verify_started = quanta::Instant::now();
        let script_cache = if self.intent == ApplyIntent::Commit {
            self.handles.script_cache.as_deref()
        } else {
            None
        };
        let script_verify_result = if self.transactions_proven {
            Ok(ScriptsRan::Executed)
        } else {
            verify_block_transactions(
                self.handles,
                self.view,
                self.tx_plan,
                Arc::clone(self.resolved),
                self.context,
                self.provenance,
                self.script_source,
                script_cache,
            )
        };
        let script_verify_dur = script_verify_started.elapsed();
        metrics::histogram!("node.apply_block.script_verify_seconds")
            .record(script_verify_dur.as_secs_f64());
        timings.script_verify = script_verify_dur;
        tracing::debug!(
            height = self.context.height,
            %self.context.hash,
            script_verify_us = script_verify_dur.as_micros(),
            script_dispatch = if self.tx_plan.only_coinbase {
                "coinbase_only"
            } else if self.tx_plan.needs_local_utxo_overlay {
                "serial_overlay"
            } else {
                "parallel"
            },
            "apply_block: profile"
        );
        script_verify_result
    }
}

struct BudgetChecks<'a, 'b> {
    handles: &'a Chainstate,
    block: &'b Block,
    block_hash: Hash256,
    tx_plan: &'b BlockTxPlan,
    txids: &'b [Txid],
    resolved: Arc<ResolvedUtxoView>,
    context: &'b BlockValidationContext,
    median_time_past: u32,
    softfork: bitcoin_rs_chain::SoftforkState,
    previous_tip_id: Option<NodeId>,
}

impl BudgetChecks<'_, '_> {
    fn run(&self) -> core::result::Result<(), ApplyError> {
        check_block_sigops(
            self.block,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            self.context.height,
            self.context.flags,
        )?;

        let coinbase_maturity_started =
            tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
        let coinbase_maturity_result = check_coinbase_maturity(
            self.block,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            self.context.height,
        );
        tracing::debug!(
            height = self.context.height,
            %self.block_hash,
            coinbase_maturity_us = coinbase_maturity_started.map(|start| start.elapsed().as_micros()),
            "apply_block: profile"
        );
        coinbase_maturity_result?;
        let bip68_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
        let bip68_result = check_bip68_sequence_locks(
            self.handles,
            self.block,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            Bip68Context {
                validation: self.context,
                median_time_past: self.median_time_past,
                softfork_state: self.softfork,
                previous_tip_id: self.previous_tip_id,
            },
        );
        tracing::debug!(
            height = self.context.height,
            %self.block_hash,
            bip68_us = bip68_started.map(|start| start.elapsed().as_micros()),
            "apply_block: profile"
        );
        bip68_result
    }
}

struct ChangeRequest<'a, 'b> {
    handles: &'a Chainstate,
    block: &'b Block,
    block_hash: Hash256,
    height: u32,
    txids: &'a [Txid],
    tx_plan: &'a BlockTxPlan,
    resolved: &'a Arc<ResolvedUtxoView>,
}

fn build_block_changes_checked<'b>(
    request: &ChangeRequest<'_, 'b>,
) -> core::result::Result<
    (
        BlockChanges<&'b bitcoin_rs_primitives::TxOut>,
        UndoBatch,
        BlockValueTotals,
    ),
    ApplyError,
> {
    let same_block_spent = request.tx_plan.same_block_spent.as_ref();
    let same_block_spent_len = same_block_spent.map_or(0_usize, SameBlockSpentSet::len);
    let utxo_add_capacity = request
        .tx_plan
        .created_output_count
        .saturating_sub(same_block_spent_len);
    let utxo_remove_capacity = request
        .tx_plan
        .spent_input_count
        .saturating_sub(request.tx_plan.same_block_spent_input_count);

    let utxo_changes_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let utxo_changes_result = build_block_changes(
        &BlockChangeInputs {
            block: request.block,
            height: request.height,
            txids: request.txids,
            same_block_spent,
            add_capacity: utxo_add_capacity,
            remove_capacity: utxo_remove_capacity,
            overwritten: bitcoin_rs_consensus::bip30::is_bip30_exception(
                request.height,
                request.block_hash,
            )
            .then(|| request.handles.utxo.as_ref()),
            max_script_size: MAX_SCRIPT_SIZE,
        },
        request.resolved.as_ref(),
    );
    tracing::debug!(
        height = request.height,
        %request.block_hash,
        utxo_changes_us = utxo_changes_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    utxo_changes_result.map_err(|e| map_block_change_error(&e))
}

fn check_coinbase_value(
    handles: &Chainstate,
    height: u32,
    value_totals: &BlockValueTotals,
) -> core::result::Result<(), ApplyError> {
    if height > 0 {
        let fees = value_totals
            .fees()
            .ok_or(ApplyError::BlockOutputsExceedInputs)?;
        bitcoin_rs_consensus::verify_coinbase_amount(
            value_totals.coinbase_out,
            fees,
            height,
            handles.network.subsidy_halving_interval(),
        )?;
    }
    Ok(())
}

struct BlockOutcomeInputs<'a, 'b> {
    handles: &'a Chainstate,
    payload: &'b BlockPayload,
    block: &'b Block,
    block_hash: Hash256,
    height: u32,
    txids: Vec<Txid>,
    resolved: Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_script::VerifyFlags,
    undo: &'b UndoBatch,
    total_started: quanta::Instant,
}

struct PersistedPayload {
    undo_record: UndoRecord,
    tip: TipSnapshot,
    block_bytes: bytes::Bytes,
    block_connected_dur: std::time::Duration,
    coin_stats_height_delta: i64,
}

fn persist_payload(
    input: &BlockOutcomeInputs<'_, '_>,
    changes: &BlockChanges<&bitcoin_rs_primitives::TxOut>,
    timings: &mut ApplyTimings,
) -> core::result::Result<PersistedPayload, ApplyError> {
    let undo_persist_started = quanta::Instant::now();
    let undo_persist_result = bitcoin_rs_utxo::contract::persist_block_undo(
        input.handles.undo_store.as_ref(),
        input.height,
        input.block_hash,
        input.undo,
    )
    .map_err(ApplyError::UndoPersistence);
    metrics::histogram!("node.apply_block.undo_persist_seconds")
        .record(undo_persist_started.elapsed().as_secs_f64());
    let undo_record = undo_persist_result?;

    let block_bytes: bytes::Bytes = {
        let needs_body =
            input.handles.block_body_store.is_some() || input.handles.capture_block_bytes;
        if needs_body {
            input.payload.bytes().clone()
        } else {
            bytes::Bytes::new()
        }
    };

    let block_body_persist_started = quanta::Instant::now();
    let block_body_persist_result = match &input.handles.block_body_store {
        Some(store) => store
            .persist_block_body_value(input.height, input.block_hash, block_bytes.clone())
            .map_err(ApplyError::BlockBodyPersistence),
        None => Ok(()),
    };
    let block_body_persist_dur = block_body_persist_started.elapsed();
    metrics::histogram!("node.apply_block.block_body_persist_seconds")
        .record(block_body_persist_dur.as_secs_f64());
    timings.block_body_persist = block_body_persist_dur;
    block_body_persist_result?;

    let block_tree_insert_started = quanta::Instant::now();
    let tip = applied_header_tip(input.handles, input.block_hash, input.block, input.height)?;
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());
    timings.block_tree_insert = block_tree_insert_dur;

    let utxo_commit_started = quanta::Instant::now();
    let utxo_commit_result = bitcoin_rs_utxo::contract::commit_block_changes(
        &input.handles.utxo,
        changes,
        &input.block_hash,
    );
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    timings.utxo_commit = utxo_commit_dur;
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;
    let block_connected_dur = input.total_started.elapsed();
    let coin_stats_height_delta =
        i64::from(input.height) - i64::from(input.handles.coin_stats.snapshot().height);
    Ok(PersistedPayload {
        undo_record,
        tip,
        block_bytes,
        block_connected_dur,
        coin_stats_height_delta,
    })
}

fn finish_block_outcome(
    input: BlockOutcomeInputs<'_, '_>,
    persisted: PersistedPayload,
    timings: &mut ApplyTimings,
) -> (ConnectOutcome, UndoRecord, i64) {
    let handles = input.handles;
    debug_assert!(
        handles
            .block_tree
            .read()
            .node_by_hash(input.block_hash)
            .is_some(),
        "block {} is entering the record log with no block-tree node; \
         its header would be unrecoverable",
        input.block_hash.to_string_be()
    );
    let tx_count_delta = tx_count_delta_for(input.block);
    let coin_stats_started = quanta::Instant::now();
    handles
        .coin_stats
        .finish_block(input.height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    timings.coin_stats = coin_stats_dur;
    let total_dur = input.total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    emit_block_connected(
        input.block,
        &input.block_hash,
        input.height,
        &input.txids,
        &input.resolved,
        input.flags,
        persisted.block_connected_dur,
    );
    tracing::debug!(
        height = input.height,
        %input.block_hash,
        tx_count = input.block.txs.len(),
        block_rules_us = timings.block_rules.as_micros(),
        bip30_bip34_us = timings.bip30_bip34.as_micros(),
        script_verify_us = timings.script_verify.as_micros(),
        utxo_commit_us = timings.utxo_commit.as_micros(),
        block_body_persist_us = timings.block_body_persist.as_micros(),
        block_tree_insert_us = timings.block_tree_insert.as_micros(),
        coin_stats_us = timings.coin_stats.as_micros(),
        total_us = total_dur.as_micros(),
        "apply_block: profile"
    );
    let raw_txs = handles.capture_rawtx.then(|| {
        input
            .block
            .txs
            .iter()
            .map(consensus_bytes)
            .collect::<Vec<_>>()
    });
    let outcome = ConnectOutcome {
        tip: persisted.tip,
        commit_id: 0,
        height: input.height,
        hash: input.block_hash,
        txids: input.txids,
        block_bytes: persisted.block_bytes,
        raw_txs,
    };
    (
        outcome,
        persisted.undo_record,
        persisted.coin_stats_height_delta,
    )
}

struct Publication<'a, 'p, 'b> {
    handles: &'a Chainstate,
    block: &'b Block,
    outcome: ConnectOutcome,
    publication: PublishMode<'p>,
    undo: UndoBatch,
    changes: BlockChanges<&'b bitcoin_rs_primitives::TxOut>,
    undo_record: UndoRecord,
    attestation: Option<ScriptAttestation>,
    prev_hash: Hash256,
    coin_stats_height_delta: i64,
}

impl Publication<'_, '_, '_> {
    fn run(self) -> core::result::Result<ApplyFinish, ApplyError> {
        let Publication {
            handles,
            block,
            mut outcome,
            publication,
            undo,
            changes,
            undo_record,
            attestation,
            prev_hash,
            coin_stats_height_delta,
        } = self;
        let commit_id = match publication {
            PublishMode::Now => commit_now(
                handles,
                block,
                &mut outcome,
                &undo_record,
                attestation,
                prev_hash,
            )?,
            PublishMode::Replay {
                receipt,
                certify_head,
            } => {
                let commit_id = receipt.commit_id;
                if certify_head {
                    outcome.tip = receipt.certify(outcome.tip);
                }
                commit_id
            }
            PublishMode::Grouped(group) => {
                let journal_record = build_journal_record(
                    block,
                    outcome.height,
                    outcome.hash,
                    prev_hash,
                    &undo,
                    &changes,
                    coin_stats_height_delta,
                );
                group.stage(PendingBlockCommit {
                    outcome: outcome.clone(),
                    undo_record,
                    prev_hash,
                    journal_record,
                    attestation,
                });
                return Ok(ApplyFinish::Committed(Box::new(outcome)));
            }
        };
        emit_journal_record(
            handles,
            build_journal_record(
                block,
                outcome.height,
                outcome.hash,
                prev_hash,
                &undo,
                &changes,
                coin_stats_height_delta,
            ),
            outcome.height,
        );
        handles.publish_applied(&outcome.tip, crate::events::HintKind::Connected);
        outcome.commit_id = commit_id;
        Ok(ApplyFinish::Committed(Box::new(outcome)))
    }
}

struct BlockValidation<'a, 'b, 'c> {
    handles: &'a Chainstate,
    block: &'b Block,
    block_hash: Hash256,
    prev_hash: Hash256,
    context: &'c BlockValidationContext,
    softfork: bitcoin_rs_chain::SoftforkState,
    median_time_past: u32,
    prior_tip_id: Option<NodeId>,
    provenance: BlockProvenance,
    intent: ApplyIntent,
    transactions_proven: bool,
    prepared: PreparedApply<'b>,
}

type BlockValidationOutcome = (
    Vec<Txid>,
    BlockTxPlan,
    Arc<ResolvedUtxoView>,
    Option<ScriptAttestation>,
);

impl BlockValidation<'_, '_, '_> {
    fn run(
        self,
        timings: &mut ApplyTimings,
    ) -> core::result::Result<BlockValidationOutcome, ApplyError> {
        let PreparedApply {
            script_source,
            mut view,
            tx_plan,
            resolved,
        } = self.prepared;
        BlockRules {
            handles: self.handles,
            block: self.block,
            block_hash: self.block_hash,
            prev_hash: self.prev_hash,
            context: self.context,
            softfork: self.softfork,
            prior_tip_id: self.prior_tip_id,
            intent: self.intent,
        }
        .check(&mut view, tx_plan.has_witness, timings)?;

        let scripts_ran = ScriptVerification {
            handles: self.handles,
            view: &mut view,
            tx_plan: &tx_plan,
            resolved: &resolved,
            context: self.context,
            provenance: self.provenance,
            script_source: &script_source,
            transactions_proven: self.transactions_proven,
            intent: self.intent,
        }
        .run(timings)?;
        let attestation = match (self.provenance, scripts_ran) {
            (BlockProvenance::LocalReplay, _) => None,
            (_, ScriptsRan::Skipped) => Some(ScriptAttestation::AssumeValid),
            (_, ScriptsRan::Executed) => Some(ScriptAttestation::Full),
        };

        BudgetChecks {
            handles: self.handles,
            block: self.block,
            block_hash: self.block_hash,
            tx_plan: &tx_plan,
            txids: view.txids(),
            resolved: Arc::clone(&resolved),
            context: self.context,
            median_time_past: self.median_time_past,
            softfork: self.softfork,
            previous_tip_id: self.prior_tip_id,
        }
        .run()?;

        Ok((view.into_txids(), tx_plan, resolved, attestation))
    }
}

struct CommitRequest<'a, 'p, 'b> {
    handles: &'a Chainstate,
    payload: &'b BlockPayload,
    block: &'b Block,
    block_hash: Hash256,
    prev_hash: Hash256,
    height: u32,
    intent: ApplyIntent,
    flags: bitcoin_rs_script::VerifyFlags,
    txids: Vec<Txid>,
    resolved: Arc<ResolvedUtxoView>,
    tx_plan: BlockTxPlan,
    attestation: Option<ScriptAttestation>,
    publication: PublishMode<'p>,
    total_started: quanta::Instant,
}

fn commit_application(
    request: CommitRequest<'_, '_, '_>,
    timings: &mut ApplyTimings,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let CommitRequest {
        handles,
        payload,
        block,
        block_hash,
        prev_hash,
        height,
        intent,
        flags,
        txids,
        resolved,
        tx_plan,
        attestation,
        publication,
        total_started,
    } = request;
    let (changes, undo, value_totals) = build_block_changes_checked(&ChangeRequest {
        handles,
        block,
        block_hash,
        height,
        txids: &txids,
        tx_plan: &tx_plan,
        resolved: &resolved,
    })?;
    check_coinbase_value(handles, height, &value_totals)?;
    if intent == ApplyIntent::Propose {
        return Ok(ApplyFinish::Proposed);
    }

    let persist_input = BlockOutcomeInputs {
        handles,
        payload,
        block,
        block_hash,
        height,
        txids,
        resolved,
        flags,
        undo: &undo,
        total_started,
    };
    let persisted = persist_payload(&persist_input, &changes, timings)?;
    let (outcome, undo_record, coin_stats_height_delta) =
        finish_block_outcome(persist_input, persisted, timings);
    Publication {
        handles,
        block,
        outcome,
        publication,
        undo,
        changes,
        undo_record,
        attestation,
        prev_hash,
        coin_stats_height_delta,
    }
    .run()
}

fn commit_now(
    handles: &Chainstate,
    block: &Block,
    outcome: &mut ConnectOutcome,
    undo_record: &UndoRecord,
    attestation: Option<ScriptAttestation>,
    prev_hash: Hash256,
) -> core::result::Result<u64, ApplyError> {
    tracing::debug!(height = outcome.height, %outcome.hash, "apply_block: tail begin");
    if let Some(hook) = handles.tip_staged.get()
        && handles
            .applied_tip_snapshot()
            .is_some_and(|tip| tip.hash == prev_hash)
    {
        hook(&outcome.tip, block);
    }
    let durable_sync_started = quanta::Instant::now();
    sync_appended_blocks(handles)?;
    let durable_sync_us = durable_sync_started.elapsed().as_micros();
    let undo_rows = vec![(outcome.height, outcome.hash, undo_record.as_bytes())];
    let body_rows = stored_body_row(handles, outcome.height, outcome.hash)?
        .into_iter()
        .collect();
    let durable_commit_started = quanta::Instant::now();
    let receipt = commit_connect_head(
        handles,
        &ConnectCommitFacts {
            prev_hash,
            tip: outcome.hash,
            height: outcome.height,
            chain_tx_count_after: outcome.tip.chain_tx_count.to_wire(),
            undo_extent: Some((outcome.height, outcome.hash)),
        },
        &CommitRecords {
            undo_rows,
            body_rows,
            attestation,
        },
    )?;
    tracing::debug!(
        height = outcome.height,
        %outcome.hash,
        durable_sync_us,
        durable_commit_us = durable_commit_started.elapsed().as_micros(),
        "apply_block: publish profile"
    );
    outcome.tip = receipt.certify(outcome.tip.clone());
    Ok(receipt.commit_id)
}

pub(super) fn apply_block_admitted<'b>(
    handles: &Chainstate,
    payload: &'b BlockPayload,
    proven: Option<ProvenApply<'b>>,
    provenance: BlockProvenance,
    intent: ApplyIntent,
    publication: PublishMode<'_>,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let block = payload.block();
    let total_started = quanta::Instant::now();
    let block_hash = block.block_hash().0;
    let prev_hash = block.header.prev_blockhash.0;
    let (prior, height) = application_predecessor(handles, block_hash, prev_hash, &publication)?;
    check_historical_target(handles, height, block_hash)?;
    if !matches!(publication, PublishMode::Replay { .. }) {
        check_contextual_header(handles, block, height, prior.as_deref(), block_hash)?;
    }
    prepare_journal_for_apply(handles, height, intent)?;
    check_self_pow(handles, block, block_hash, height, intent)?;

    let ValidationContexts {
        validation,
        softfork,
        median_time_past,
    } = validation_contexts(handles, block, height, block_hash, prior.as_deref());
    let (prepared, transactions_proven) = prepare_block(handles, payload, proven, &validation)?;
    let mut timings = ApplyTimings::default();
    let (txids, tx_plan, resolved, attestation) = BlockValidation {
        handles,
        block,
        block_hash,
        prev_hash,
        context: &validation,
        softfork,
        median_time_past,
        prior_tip_id: prior.as_deref().map(|tip| tip.tip_id),
        provenance,
        intent,
        transactions_proven,
        prepared,
    }
    .run(&mut timings)?;
    commit_application(
        CommitRequest {
            handles,
            payload,
            block,
            block_hash,
            prev_hash,
            height,
            intent,
            flags: validation.flags,
            txids,
            resolved,
            tx_plan,
            attestation,
            publication,
            total_started,
        },
        &mut timings,
    )
}

fn emit_block_connected(
    block: &Block,
    block_hash: &Hash256,
    height: u32,
    txids: &[Txid],
    resolved: &Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_script::VerifyFlags,
    elapsed: std::time::Duration,
) {
    bitcoin_rs_consensus::trace::block_connected(move || {
        let mut view = BlockLocalUtxoView::new(Arc::clone(resolved), &block.txs, height, 0);
        let mut inputs: u32 = 0;
        let mut sigops: u64 = 0;
        for (index, tx) in block.txs.iter().enumerate() {
            inputs = inputs.saturating_add(u32::try_from(tx.inputs.len()).unwrap_or(u32::MAX));
            let mut prevouts = Vec::with_capacity(tx.inputs.len());
            for input in &tx.inputs {
                if let Some(output) = view.lookup(&input.previous_output) {
                    prevouts.push((input.previous_output, output));
                }
            }
            sigops = sigops.saturating_add(u64::from(
                bitcoin_rs_consensus::transaction_sigop_cost(tx, &prevouts, flags),
            ));
            if let Some(txid) = txids.get(index) {
                let _ = view.add_outputs(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    *txid,
                    tx.outputs.len(),
                );
            }
        }
        (
            block_hash.as_byte_array().as_ptr(),
            i32::try_from(height).unwrap_or(i32::MAX),
            u64::try_from(block.txs.len()).unwrap_or(u64::MAX),
            i32::try_from(inputs).unwrap_or(i32::MAX),
            i64::try_from(sigops).unwrap_or(i64::MAX),
            i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX),
        )
    });
}

fn check_block_sigops(
    block: &Block,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
    flags: bitcoin_rs_script::VerifyFlags,
) -> Result<(), ApplyError> {
    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, 0);
    let mut cost = 0_u32;
    for (index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        let prevouts: Vec<_> = tx
            .inputs
            .iter()
            .filter_map(|input| {
                view.lookup(&input.previous_output)
                    .map(|output| (input.previous_output, output))
            })
            .collect();
        cost = cost.saturating_add(bitcoin_rs_consensus::transaction_sigop_cost(
            tx, &prevouts, flags,
        ));
        if cost > bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST {
            return Err(bitcoin_rs_consensus::ConsensusError::SigopsLimit {
                cost,
                max: bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST,
            }
            .into());
        }
        if tx_plan.needs_local_utxo_overlay {
            view.spend_inputs(tx);
            view.add_outputs(index, *txid, tx.outputs.len())?;
        }
    }
    Ok(())
}

fn check_coinbase_maturity(
    block: &Block,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(block.txs.len(), txids.len());
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.needs_local_utxo_overlay {
        for tx in block.txs.iter().filter(|tx| !tx.is_coinbase()) {
            for input in &tx.inputs {
                let Some(entry) = resolved.lookup_meta(&input.previous_output) else {
                    continue;
                };
                bitcoin_rs_consensus::check_coinbase_maturity(
                    entry.coinbase,
                    entry.height,
                    height,
                )?;
            }
        }
        return Ok(());
    }

    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        if tx.is_coinbase() {
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        for input in &tx.inputs {
            let Some(entry) = view.lookup_meta(&input.previous_output) else {
                continue;
            };
            bitcoin_rs_consensus::check_coinbase_maturity(entry.coinbase, entry.height, height)?;
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &Chainstate,
    block: &Block,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    context: Bip68Context<'_>,
) -> core::result::Result<(), ApplyError> {
    if !context.softfork_state.csv_active
        || tx_plan.only_coinbase
        || !tx_plan.has_bip68_sequence_locks
    {
        return Ok(());
    }
    let height = context.validation.height;
    let mtp = context.median_time_past;
    debug_assert_eq!(block.txs.len(), txids.len());
    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = HashMap::new();
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        if tx.is_coinbase() {
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        if tx.version < 2 {
            view.spend_inputs(tx);
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        for tx_input in &tx.inputs {
            let sequence = tx_input.sequence;
            if sequence & bitcoin_rs_primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
                continue;
            }
            let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                continue;
            };
            let prevout_mtp = if bitcoin_rs_consensus::bip68::sequence_lock_is_time_based(
                sequence.to_consensus(),
            ) {
                prevout_median_time_past(
                    handles,
                    context,
                    entry.height,
                    &mut prevout_mtp_by_height,
                )?
            } else {
                0
            };
            bitcoin_rs_consensus::bip68::check_sequence_lock(
                tx.version,
                sequence.to_consensus(),
                entry.height,
                prevout_mtp,
                height,
                mtp,
            )?;
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
    }
    Ok(())
}

fn prevout_median_time_past(
    handles: &Chainstate,
    context: Bip68Context<'_>,
    entry_height: u32,
    cache: &mut HashMap<u32, u32>,
) -> core::result::Result<u32, ApplyError> {
    if entry_height == context.validation.height {
        return Ok(context.median_time_past);
    }
    if let Some(cached) = cache.get(&entry_height) {
        return Ok(*cached);
    }
    let Some(previous_tip_id) = context.previous_tip_id else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing previous tip for time-based sequence lock".to_owned(),
            },
        ));
    };
    let tree = handles.block_tree.read();
    let Some(prevout_mtp) = tree.median_time_past_before_height(previous_tip_id, entry_height)
    else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: format!(
                    "missing prevout ancestry at height {} for time-based sequence lock",
                    entry_height.saturating_sub(1)
                ),
            },
        ));
    };
    cache.insert(entry_height, prevout_mtp);
    Ok(prevout_mtp)
}

fn check_bip30_and_bip34(
    handles: &Chainstate,
    block: &Block,
    height: u32,
    txids: &[Txid],
    previous_tip_id: Option<NodeId>,
) -> core::result::Result<(), ApplyError> {
    let mut has_duplicate = false;
    if bitcoin_rs_chain::bip30_duplicate_scan_required(
        &handles.block_tree.read(),
        handles.network,
        height,
        previous_tip_id,
    ) {
        for txid in txids {
            if handles.utxo.has_live_outputs_for_txid(&txid.0) {
                has_duplicate = true;
                break;
            }
        }
    }
    let block_hash = block.block_hash().0;
    if has_duplicate {
        bitcoin_rs_consensus::bip30::check_duplicate_txid(height, block_hash)?;
    }
    check_bip34(handles, block, height)?;
    Ok(())
}

fn check_bip34(
    handles: &Chainstate,
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    if handles.network.is_bip34_active(height) {
        let coinbase = block
            .txs
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::EmptyBlock)?;
        let coinbase_input = coinbase
            .inputs
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)?;
        bitcoin_rs_consensus::bip34::check_bip34(height, &coinbase_input.script_sig)?;
    }
    Ok(())
}

fn check_block_finality(
    block: &Block,
    height: u32,
    locktime_cutoff: u32,
) -> core::result::Result<(), ApplyError> {
    for tx in &block.txs {
        if !bitcoin_rs_consensus::is_final_tx(tx, height, locktime_cutoff) {
            return Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip {
                    bip: "BIP113",
                    reason: format!(
                        "non-final transaction at height {height} locktime cutoff \
                         {locktime_cutoff}: locktime {}",
                        tx.lock_time,
                    ),
                },
            ));
        }
    }
    Ok(())
}

fn validate_contextual_block_header(
    handles: &Chainstate,
    block: &Block,
    height: u32,
    prior: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    if height == 0 {
        return Ok(());
    }
    let Some(prior) = prior else {
        return Err(ApplyError::Chain(
            bitcoin_rs_chain::ChainError::MissingParent {
                prev_hash: block.header.prev_blockhash.0,
            },
        ));
    };
    let tree = handles.block_tree.read();
    bitcoin_rs_chain::validate_contextual_header(
        &tree,
        prior.tip_id,
        &block.header,
        handles.network,
        bitcoin_rs_chain::current_unix_seconds(),
        bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
    )
    .map_err(ApplyError::Chain)
}

fn applied_predecessor(
    handles: &Chainstate,
    block_hash: bitcoin_rs_primitives::Hash256,
    prev_hash: bitcoin_rs_primitives::Hash256,
) -> core::result::Result<(Option<Arc<TipSnapshot>>, u32), ApplyError> {
    let prior = handles.applied_tip.load_full();
    let height = if let Some(tip) = prior.as_deref() {
        if tip.hash != prev_hash {
            return Err(ApplyError::PrevHashMismatch {
                tip: tip.hash,
                prev: prev_hash,
            });
        }
        tip.height
            .checked_add(1)
            .ok_or(ApplyError::HeightOverflow(tip.height))?
    } else {
        if block_hash != handles.network.genesis_block_hash() {
            return Err(ApplyError::Chain(
                bitcoin_rs_chain::ChainError::MissingParent { prev_hash },
            ));
        }
        0_u32
    };
    Ok((prior, height))
}

pub(super) fn applied_header_tip(
    handles: &Chainstate,
    block_hash: Hash256,
    block: &Block,
    height: u32,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let mut tree = handles.block_tree.write();
    let node_id = match tree.lookup(block_hash) {
        Some(node_id) => node_id,
        None => tree.insert_header(block.header, bitcoin_rs_chain::node::NodeStatus::Active)?,
    };
    let node = tree.node(node_id)?;
    if node.height != height {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "INTERNAL",
                reason: format!(
                    "block-tree height {} does not match applied height {height} for block {block_hash}",
                    node.height
                ),
            },
        ));
    }
    let parent_known = node
        .parent
        .and_then(|parent| tree.node(parent).ok())
        .is_some_and(|parent| parent.chain_tx_count.get().is_some());
    tree.record_applied_tx_count(node_id, tx_count_delta_for(block))?;
    let node = tree.node(node_id)?;
    if parent_known && node.chain_tx_count.get().is_none() {
        tracing::warn!(
            height,
            hash = %block_hash,
            "cumulative chain transaction count overflowed; marking it unknown"
        );
    }
    Ok(TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    })
}

fn map_block_change_error(error: &BlockChangeError) -> ApplyError {
    match error {
        BlockChangeError::BlockValueOverflow => ApplyError::BlockValueOverflow,
        BlockChangeError::VoutOverflow { txid } => ApplyError::VoutOverflow { txid: *txid },
        BlockChangeError::TxidCountMismatch {
            transactions,
            txids,
        } => ApplyError::TxidCountMismatch {
            transactions: *transactions,
            txids: *txids,
        },
        BlockChangeError::UndoPrevoutMissing { txid, vout } => ApplyError::UndoPrevoutMissing {
            txid: *txid,
            vout: *vout,
        },
    }
}

pub(super) type BuiltJournalRecord = Option<
    core::result::Result<
        bitcoin_rs_storage::chainstate_journal::JournalRecord,
        crate::journal::JournalDeltaError,
    >,
>;

fn build_journal_record(
    block: &Block,
    height: u32,
    block_hash: Hash256,
    prev_hash: Hash256,
    undo: &bitcoin_rs_utxo::contract::UndoBatch,
    changes: &bitcoin_rs_utxo::contract::BlockChanges<&'_ bitcoin_rs_primitives::TxOut>,
    coin_stats_height_delta: i64,
) -> BuiltJournalRecord {
    if height == 0 {
        return None;
    }
    let undo_coins =
        undo.restores()
            .iter()
            .map(|add| bitcoin_rs_storage::chainstate_journal::Coin {
                outpoint: add.outpoint,
                txout: add.txout.clone(),
                height: add.height,
                coinbase: add.coinbase,
            });
    let block_tx_count = tx_count_delta_for(block);
    let mut raw_header = [0u8; 80];
    let encoded = bitcoin_rs_primitives::consensus_bytes(&block.header);
    debug_assert_eq!(encoded.len(), 80, "header consensus encoding is 80 bytes");
    raw_header.copy_from_slice(&encoded);
    Some(
        crate::journal::mutations_for_block(changes, undo_coins).map(|mutations| {
            bitcoin_rs_storage::chainstate_journal::JournalRecord {
                height,
                block_hash: block_hash.to_le_bytes(),
                prev_hash: prev_hash.to_le_bytes(),
                block_tx_count,
                coin_stats_height_delta,
                raw_header,
                mutations,
            }
        }),
    )
}

pub(super) fn emit_journal_record(handles: &Chainstate, built: BuiltJournalRecord, height: u32) {
    let Some(journal) = handles.journal.read().clone() else {
        return;
    };
    let Some(record) = built else {
        return;
    };
    let mut journal = journal.lock();
    match record {
        Ok(record) => {
            if let Err(error) = journal.append(&record) {
                metrics::counter!("node.chainstate_journal.append_failures").increment(1);
                tracing::warn!(
                    height,
                    %error,
                    "chainstate journal append failed; recovery may fall back to full re-validation"
                );
            }
        }
        Err(error) => {
            journal.mark_append_gap(height);
            metrics::counter!("node.chainstate_journal.append_failures").increment(1);
            tracing::warn!(
                height,
                %error,
                "chainstate journal delta extraction failed; recovery may fall back to full re-validation"
            );
        }
    }
}
