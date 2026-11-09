//! Validated block connection and its ordered persistence/publication transaction.

#[cfg(test)]
mod tests;

use super::SameBlockSpentSet;
use super::prepare::{ScriptsRan, prepare_apply, verify_block_transactions};
use super::window::{PendingBlockCommit, PublishMode};
use super::{
    ApplyFinish, ApplyIntent, Bip68Context, BlockLocalUtxoView, BlockProvenance, BlockTxPlan,
    BlockValidationContext, Chainstate, ConnectOutcome, PreparedApply, ProvenApply,
    ResolvedUtxoView,
};
use crate::chain::TipSnapshot;
use crate::chain::node::NodeId;
use crate::error::ApplyError;
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Header, Txid};
use bitcoin_rs_consensus::{MAX_SCRIPT_SIZE, UtxoView};
use bitcoin_rs_storage::ScriptAttestation;
use bitcoin_rs_storage::utxo::contract::{
    BlockChangeError, BlockChangeInputs, BlockChanges, BlockValueTotals, CoinEntryError, UndoBatch,
    UndoRecord, build_block_changes, resolve_coin_entries,
};
use hashbrown::HashMap;
use std::sync::Arc;

/// The provenance inputs of one block apply.
///
/// `staged` is the coin view of the uncommitted window prefix; it is the only
/// path by which staged coins become visible to block rules.
#[derive(Clone, Copy)]
pub(super) struct ApplyScope<'a> {
    pub provenance: BlockProvenance,
    pub staged: Option<&'a super::workspace::WindowWorkspace>,
}

pub(super) fn apply_committed_block_admitted<'b>(
    handles: &Chainstate,
    payload: &'b BlockImage,
    proven: Option<ProvenApply<'b>>,
    scope: ApplyScope<'_>,
    publication: PublishMode<'_>,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    match apply_block_admitted(
        handles,
        payload,
        proven,
        scope,
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
    header: &Header,
    height: u32,
    prior: Option<&TipSnapshot>,
    block_hash: Hash256,
) -> core::result::Result<(), ApplyError> {
    let contextual_header_started =
        tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let contextual_header_result = validate_contextual_block_header(handles, header, height, prior);
    tracing::debug!(
        height,
        %block_hash,
        contextual_header_us = contextual_header_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    contextual_header_result
}

fn check_self_pow(
    handles: &Chainstate,
    header: &Header,
    block_hash: Hash256,
    height: u32,
    intent: ApplyIntent,
) -> core::result::Result<(), ApplyError> {
    if intent != ApplyIntent::Commit {
        return Ok(());
    }
    let pow_self_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let pow_self_result =
        crate::chain::header_sync::validate_pow(header, block_hash, handles.network);
    tracing::debug!(
        height,
        %block_hash,
        pow_self_us = pow_self_started.map(|start| start.elapsed().as_micros()),
        "apply_block: profile"
    );
    pow_self_result.map_err(|_| ApplyError::ProofOfWork { hash: block_hash })
}

struct ValidationContexts {
    validation: BlockValidationContext,
    softfork: crate::chain::SoftforkState,
    median_time_past: u32,
}

fn validation_contexts(
    handles: &Chainstate,
    header: &Header,
    height: u32,
    block_hash: Hash256,
    prior: Option<&TipSnapshot>,
) -> ValidationContexts {
    let (prev_median_time_past, softfork_state) = if let Some(tip) = prior {
        let tree = handles.block_tree.read();
        let mtp = tree.median_time_past_at(tip.tip_id).unwrap_or(0);
        let softfork_state =
            crate::chain::softfork_state(&tree, handles.network, Some(tip.tip_id), height);
        (mtp, softfork_state)
    } else {
        let tree = handles.block_tree.read();
        (
            0,
            crate::chain::softfork_state(&tree, handles.network, None, height),
        )
    };
    let locktime_rule =
        bitcoin_rs_consensus::LocktimeRule::from_csv_active(softfork_state.csv_active);
    let locktime_cutoff =
        bitcoin_rs_consensus::locktime_cutoff(locktime_rule, prev_median_time_past, header.time);
    let verify_flags =
        bitcoin_rs_consensus::verify_flags(handles.network, height, block_hash, softfork_state);
    ValidationContexts {
        validation: BlockValidationContext {
            hash: block_hash,
            parent: header.prev_blockhash.0,
            height,
            flags: verify_flags,
            locktime_cutoff,
        },
        softfork: softfork_state,
        median_time_past: prev_median_time_past,
    }
}

struct ChainstateUtxoSource<'a> {
    handles: &'a Chainstate,
    read_failure: core::cell::RefCell<Option<ApplyError>>,
}

impl<'a> ChainstateUtxoSource<'a> {
    fn new(handles: &'a Chainstate) -> Self {
        Self {
            handles,
            read_failure: core::cell::RefCell::new(None),
        }
    }

    fn into_result(self) -> core::result::Result<(), ApplyError> {
        match self.read_failure.into_inner() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn note_failure(&self, error: ApplyError) {
        let mut slot = self.read_failure.borrow_mut();
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}

impl bitcoin_rs_storage::utxo::contract::OutputSource for ChainstateUtxoSource<'_> {
    fn get_entry(
        &self,
        outpoint: &bitcoin_rs_consensus::primitives::OutPoint,
    ) -> Option<bitcoin_rs_storage::utxo::UtxoCoin> {
        self.get_entries(std::slice::from_ref(outpoint))
            .pop()
            .flatten()
    }

    fn get_entries(
        &self,
        outpoints: &[bitcoin_rs_consensus::primitives::OutPoint],
    ) -> Vec<Option<bitcoin_rs_storage::utxo::UtxoCoin>> {
        match resolve_coin_entries(&self.handles.coins, outpoints) {
            Ok(entries) => entries,
            Err(CoinEntryError::Read(source)) => {
                self.note_failure(ApplyError::CoinStoreRead(source));
                vec![None; outpoints.len()]
            }
            Err(CoinEntryError::Record(error)) => {
                self.note_failure(ApplyError::UtxoCommit(error));
                vec![None; outpoints.len()]
            }
        }
    }
}

fn prepare_block<'b>(
    handles: &Chainstate,
    payload: &'b BlockImage,
    proven: Option<ProvenApply<'b>>,
    context: &BlockValidationContext,
) -> core::result::Result<(PreparedApply<'b>, bool), ApplyError> {
    match proven {
        Some(ProvenApply::Proven(proof)) if &proof.context == context => Ok((proof.prepared, true)),
        Some(ProvenApply::AssumeValidSkipped(prepared)) => Ok((prepared, false)),
        Some(ProvenApply::Unproven(prepared)) => Ok((prepared, false)),
        Some(ProvenApply::Proven(proof)) => Ok((proof.prepared, false)),
        None => {
            let source = ChainstateUtxoSource::new(handles);
            let prepared = prepare_apply(
                payload,
                &source,
                handles.validation_engine,
                handles.prevout_charge.clone(),
            )?;
            source.into_result()?;
            Ok((prepared, false))
        }
    }
}

struct BlockRules<'a, 'b> {
    handles: &'a Chainstate,
    image: &'b BlockImage,
    block_hash: Hash256,
    prev_hash: Hash256,
    context: &'b BlockValidationContext,
    softfork: crate::chain::SoftforkState,
    prior_tip_id: Option<NodeId>,
    intent: ApplyIntent,
    scope: ApplyScope<'b>,
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
        let block_rules_result = bitcoin_rs_consensus::verify_block_image_rules(
            self.image,
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
            bitcoin_rs_consensus::check_signet_block_solution(self.image, challenge)?;
        }
        check_block_finality(
            self.image,
            self.context.height,
            self.context.locktime_cutoff,
        )?;
        if self.intent == ApplyIntent::Commit {
            check_bip34(self.handles, self.image, self.context.height)?;
        }
        if self.intent == ApplyIntent::Commit
            && self.softfork.segwit_active
            && let Some(hook) = self.handles.pow_valid_block.get()
            && self
                .handles
                .applied_tip_snapshot()
                .is_some_and(|tip| tip.hash == self.prev_hash)
        {
            hook(self.image, self.block_hash, self.context.height);
        }
        let bip30_bip34_started = quanta::Instant::now();
        let bip30_bip34_result = check_bip30_and_bip34(
            self.handles,
            self.image,
            self.context.height,
            view.txids(),
            self.prior_tip_id,
            self.scope,
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
    fn run(
        &mut self,
        timings: &mut ApplyTimings,
    ) -> core::result::Result<(ScriptsRan, Option<super::PrevoutHold>), ApplyError> {
        let script_verify_started = quanta::Instant::now();
        let script_cache = if self.intent == ApplyIntent::Commit {
            self.handles.script_cache.as_deref()
        } else {
            None
        };
        let script_verify_result = if self.transactions_proven {
            Ok((ScriptsRan::Executed, None))
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
    image: &'b BlockImage,
    block_hash: Hash256,
    tx_plan: &'b BlockTxPlan,
    txids: &'b [Txid],
    resolved: Arc<ResolvedUtxoView>,
    context: &'b BlockValidationContext,
    median_time_past: u32,
    softfork: crate::chain::SoftforkState,
    previous_tip_id: Option<NodeId>,
}

impl BudgetChecks<'_, '_> {
    fn run(&self) -> core::result::Result<(), ApplyError> {
        check_block_sigops(
            self.image,
            self.tx_plan,
            self.txids,
            Arc::clone(&self.resolved),
            self.context.height,
            self.context.flags,
        )?;

        let coinbase_maturity_started =
            tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
        let coinbase_maturity_result = check_coinbase_maturity(
            self.image,
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
            self.image,
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
    image: &'b BlockImage,
    block_hash: Hash256,
    height: u32,
    txids: &'a [Txid],
    tx_plan: &'a BlockTxPlan,
    resolved: &'a Arc<ResolvedUtxoView>,
}

fn build_block_changes_checked(
    request: &ChangeRequest<'_, '_>,
) -> core::result::Result<
    (
        BlockChanges<bitcoin_rs_consensus::primitives::TxOut>,
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
            block: request.image,
            height: request.height,
            txids: request.txids,
            same_block_spent,
            add_capacity: utxo_add_capacity,
            remove_capacity: utxo_remove_capacity,
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
    payload: &'b BlockImage,
    block_hash: Hash256,
    height: u32,
    txids: Vec<Txid>,
    resolved: Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
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
    timings: &mut ApplyTimings,
) -> core::result::Result<PersistedPayload, ApplyError> {
    let undo_encode_started = quanta::Instant::now();
    let undo_record = UndoRecord::new(bitcoin_rs_storage::utxo::contract::encode_undo_record(
        input.undo,
        input.block_hash,
    ));
    metrics::histogram!("node.apply_block.undo_persist_seconds")
        .record(undo_encode_started.elapsed().as_secs_f64());
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
    let tip = applied_header_tip(input.handles, input.block_hash, input.payload, input.height)?;
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());
    timings.block_tree_insert = block_tree_insert_dur;

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
    let tx_count_delta = u64::try_from(input.payload.tx_count()).unwrap_or(u64::MAX);
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
        input.payload,
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
        tx_count = input.payload.tx_count(),
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
        (0..input.payload.tx_count())
            .map(|index| input.payload.tx(index).span_bytes().to_vec())
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
        committed_facts: None,
    };
    (
        outcome,
        persisted.undo_record,
        persisted.coin_stats_height_delta,
    )
}

struct Publication<'a, 'p, 'b> {
    handles: &'a Chainstate,
    image: &'b BlockImage,

    outcome: ConnectOutcome,
    publication: PublishMode<'p>,
    undo: UndoBatch,
    changes: BlockChanges<bitcoin_rs_consensus::primitives::TxOut>,
    undo_record: UndoRecord,
    attestation: Option<ScriptAttestation>,
    prev_hash: Hash256,
    #[expect(dead_code)]
    coin_stats_height_delta: i64,
}

impl Publication<'_, '_, '_> {
    fn run(self) -> core::result::Result<ApplyFinish, ApplyError> {
        let Publication {
            handles,
            image,
            mut outcome,
            publication,
            undo,
            changes,
            undo_record,
            attestation,
            prev_hash,
            coin_stats_height_delta: _,
        } = self;
        match publication {
            PublishMode::Now => {
                return Err(ApplyError::DurableHeadCommit(
                    bitcoin_rs_storage::StorageError::InvalidOperation(
                        "single-block connect must route through connect_window",
                    ),
                ));
            }
            PublishMode::Replay {
                receipt,
                certify_head,
            } => {
                let prior = handles
                    .durable_head
                    .load()
                    .map_err(ApplyError::DurableHeadCommit)?
                    .ok_or(ApplyError::DurableHeadCommit(
                        bitcoin_rs_storage::StorageError::InvalidOperation(
                            "replay commit with no durable head",
                        ),
                    ))?;
                let prefix = bitcoin_rs_storage::AcceptedPrefix {
                    expected_head: Some(prior),
                    next_head: prior,
                    undo_rows: vec![(
                        outcome.height,
                        outcome.hash,
                        bytes::Bytes::copy_from_slice(undo_record.as_bytes()),
                    )],
                    body_rows: super::durable::stored_body_row(
                        handles,
                        outcome.height,
                        outcome.hash,
                    )?
                    .into_iter()
                    .collect(),
                    attestation: None,
                    coin_delta: replay_coin_delta(handles, &changes)?,
                };
                let commit_id = handles
                    .commit_authority
                    .commit_prefix(prefix)
                    .map_err(|error| match error {
                        bitcoin_rs_storage::CommitError::Storage(source) => {
                            ApplyError::DurableHeadCommit(source)
                        }
                        source @ (bitcoin_rs_storage::CommitError::AdmissionClosed
                        | bitcoin_rs_storage::CommitError::PreconditionFailed) => {
                            ApplyError::DurableHeadCommit(
                                bitcoin_rs_storage::StorageError::backend(source.to_string()),
                            )
                        }
                    })?
                    .commit_id();
                if certify_head {
                    outcome.tip = receipt.certify(outcome.tip);
                }
                outcome.commit_id = commit_id;
                outcome.committed_facts =
                    committed_facts_for_publish(handles, &outcome, image, &undo);
            }
            PublishMode::Grouped(group) => {
                outcome.committed_facts =
                    committed_facts_for_publish(handles, &outcome, image, &undo);
                group.stage(PendingBlockCommit {
                    outcome: outcome.clone(),
                    undo_record,
                    prev_hash,
                    attestation,
                });
                return Ok(ApplyFinish::Committed(Box::new(outcome)));
            }
        };

        handles.publish_applied(&outcome.tip, crate::events::HintKind::Connected);

        Ok(ApplyFinish::Committed(Box::new(outcome)))
    }
}

fn replay_coin_delta(
    handles: &Chainstate,
    changes: &BlockChanges<bitcoin_rs_consensus::primitives::TxOut>,
) -> Result<bitcoin_rs_storage::WindowDelta, ApplyError> {
    use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

    let mut adds_by_txid: HashMap<Hash256, Vec<_>> = HashMap::new();
    let mut removes_by_txid: HashMap<Hash256, Vec<u32>> = HashMap::new();
    for add in changes.adds() {
        adds_by_txid
            .entry(Hash256::from(add.outpoint.txid))
            .or_default()
            .push(add);
    }
    for spent in changes.spent_outpoints() {
        removes_by_txid
            .entry(Hash256::from(spent.txid))
            .or_default()
            .push(spent.vout);
    }
    let mut txids: Vec<Hash256> = adds_by_txid
        .keys()
        .chain(removes_by_txid.keys())
        .copied()
        .collect();
    txids.sort();
    txids.dedup();

    let mut delta = bitcoin_rs_storage::WindowDelta::default();
    for txid in txids {
        let key = bitcoin_rs_storage::CoinKey(txid.to_le_bytes());
        let mut outputs: Vec<OwnedUtxoOut> = match handles
            .coins
            .get(&key)
            .map_err(ApplyError::DurableHeadCommit)?
        {
            Some(bytes) => UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())
                .map_err(ApplyError::UtxoCommit)?
                .outputs()
                .map(|out| OwnedUtxoOut {
                    vout: out.vout,
                    value: out.value,
                    script_pubkey: out.script_pubkey.to_vec(),
                    coinbase: out.coinbase,
                    height: out.height,
                })
                .collect(),
            None => Vec::new(),
        };
        if let Some(removes) = removes_by_txid.get(&txid) {
            outputs.retain(|out| !removes.contains(&out.vout));
        }
        if let Some(adds) = adds_by_txid.get(&txid) {
            for add in adds {
                outputs.retain(|out| out.vout != add.outpoint.vout);
                outputs.push(OwnedUtxoOut {
                    vout: add.outpoint.vout,
                    value: add.txout.value.to_sat(),
                    script_pubkey: add.txout.script_pubkey.as_bytes().to_vec(),
                    coinbase: add.coinbase,
                    height: add.height,
                });
            }
        }
        outputs.sort_by_key(|out| out.vout);
        if outputs.is_empty() {
            delta.push_final(key, None);
            continue;
        }
        let record =
            UtxoRecord::from_owned_outputs(txid, &outputs).map_err(ApplyError::UtxoCommit)?;
        delta.push_final(key, Some(bytes::Bytes::copy_from_slice(record.bytes())));
    }
    Ok(delta)
}

fn committed_facts_for_publish(
    handles: &Chainstate,
    outcome: &ConnectOutcome,
    image: &BlockImage,
    undo: &UndoBatch,
) -> Option<Arc<bitcoin_rs_storage::CommittedFacts>> {
    if !handles.wants_committed_facts() {
        return None;
    }
    #[cfg(any(test, feature = "test-seam"))]
    handles
        .facts
        .builds
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    build_committed_facts(outcome, image, undo)
}

pub(crate) fn build_committed_facts(
    outcome: &ConnectOutcome,
    image: &BlockImage,
    undo: &UndoBatch,
) -> Option<std::sync::Arc<bitcoin_rs_storage::CommittedFacts>> {
    use bitcoin_rs_storage::{
        CommittedBlock, CommittedFacts, CreatedOutput, SpentPrevout, TxFacts,
    };
    use bytes::Bytes;
    use hashbrown::HashMap;

    let header: [u8; 80] = image.header_bytes();
    let block_hash = outcome.hash.to_le_bytes();
    let parent_hash = image.header().prev_blockhash.0.to_le_bytes();

    let mut prevout_map =
        HashMap::<([u8; 32], u32), (u64, Bytes, u32, bool)>::with_capacity(undo.restores().len());
    for add in undo.restores() {
        let txid = *add.outpoint.txid.as_bytes();
        let vout = add.outpoint.vout;
        prevout_map.insert(
            (txid, vout),
            (
                add.txout.value.to_sat(),
                Bytes::copy_from_slice(&add.txout.script_pubkey),
                add.height,
                add.coinbase,
            ),
        );
    }

    let tx_count = image.tx_count();
    let mut txs = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let tx = image.tx(i);
        let txid = *tx.txid().as_bytes();
        let offset = tx.layout().span().start();
        let len = tx.layout().span().len();

        let mut inputs = Vec::new();
        if !tx.is_coinbase() {
            for j in 0..tx.input_count() {
                let outpoint = tx.input_outpoint(j);
                let prev_txid = *outpoint.txid.as_bytes();
                let prev_vout = outpoint.vout;
                let (value, script, height, coinbase) =
                    prevout_map.get(&(prev_txid, prev_vout))?.clone();
                inputs.push(SpentPrevout {
                    txid: prev_txid,
                    vout: prev_vout,
                    value,
                    script,
                    height,
                    coinbase,
                });
            }
        }

        let output_count = tx.output_count();
        let mut outputs = Vec::with_capacity(output_count);
        for vout in 0..output_count {
            let vout_u32 = u32::try_from(vout).ok()?;
            let script = Bytes::copy_from_slice(tx.output_script(vout));
            let value = tx.output_value(vout).to_sat();
            outputs.push(CreatedOutput {
                vout: vout_u32,
                value,
                script: script.clone(),
            });
            prevout_map.insert(
                (txid, vout_u32),
                (value, script, outcome.height, tx.is_coinbase()),
            );
        }
        txs.push(TxFacts {
            txid,
            offset,
            len,
            inputs,
            outputs,
        });
    }

    let committed_block = CommittedBlock {
        height: outcome.height,
        hash: block_hash,
        parent_hash,
        header,
        txs,
    };

    Some(std::sync::Arc::new(CommittedFacts {
        commit_id: outcome.commit_id,
        blocks: vec![committed_block],
    }))
}

struct BlockValidation<'a, 'b, 'c> {
    handles: &'a Chainstate,
    image: &'b BlockImage,
    block_hash: Hash256,
    prev_hash: Hash256,
    context: &'c BlockValidationContext,
    softfork: crate::chain::SoftforkState,
    median_time_past: u32,
    prior_tip_id: Option<NodeId>,
    scope: ApplyScope<'c>,
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
            image: self.image,
            block_hash: self.block_hash,
            prev_hash: self.prev_hash,
            context: self.context,
            softfork: self.softfork,
            prior_tip_id: self.prior_tip_id,
            intent: self.intent,
            scope: self.scope,
        }
        .check(&mut view, tx_plan.has_witness, timings)?;

        let (scripts_ran, _view_hold) = ScriptVerification {
            handles: self.handles,
            view: &mut view,
            tx_plan: &tx_plan,
            resolved: &resolved,
            context: self.context,
            provenance: self.scope.provenance,
            script_source: &script_source,
            transactions_proven: self.transactions_proven,
            intent: self.intent,
        }
        .run(timings)?;
        let attestation = match (self.scope.provenance, scripts_ran) {
            (BlockProvenance::LocalReplay(_), _) => None,
            (_, ScriptsRan::Skipped) => Some(ScriptAttestation::AssumeValid),
            (_, ScriptsRan::Executed) => Some(ScriptAttestation::Full),
        };

        BudgetChecks {
            handles: self.handles,
            image: self.image,
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
    payload: &'b BlockImage,
    block_hash: Hash256,
    prev_hash: Hash256,
    height: u32,
    intent: ApplyIntent,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
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
        image: payload,
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
        block_hash,
        height,
        txids,
        resolved,
        flags,
        undo: &undo,
        total_started,
    };
    let persisted = persist_payload(&persist_input, timings)?;
    let (outcome, undo_record, coin_stats_height_delta) =
        finish_block_outcome(persist_input, persisted, timings);
    Publication {
        handles,
        image: payload,
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

pub(super) fn apply_block_admitted<'b>(
    handles: &Chainstate,
    payload: &'b BlockImage,
    proven: Option<ProvenApply<'b>>,
    scope: ApplyScope<'_>,
    intent: ApplyIntent,
    publication: PublishMode<'_>,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let header = payload.header();
    let total_started = quanta::Instant::now();
    let block_hash = payload.block_hash().0;
    let prev_hash = header.prev_blockhash.0;
    let (prior, height) = application_predecessor(handles, block_hash, prev_hash, &publication)?;
    check_historical_target(handles, height, block_hash)?;
    check_self_pow(handles, &header, block_hash, height, intent)?;
    if !matches!(publication, PublishMode::Replay { .. }) {
        check_contextual_header(handles, &header, height, prior.as_deref(), block_hash)?;
    }

    let ValidationContexts {
        validation,
        softfork,
        median_time_past,
    } = validation_contexts(handles, &header, height, block_hash, prior.as_deref());
    let (prepared, transactions_proven) = prepare_block(handles, payload, proven, &validation)?;
    let mut timings = ApplyTimings::default();
    let (txids, tx_plan, resolved, attestation) = BlockValidation {
        handles,
        image: payload,
        block_hash,
        prev_hash,
        context: &validation,
        softfork,
        median_time_past,
        prior_tip_id: prior.as_deref().map(|tip| tip.tip_id),
        scope,
        intent,
        transactions_proven,
        prepared,
    }
    .run(&mut timings)?;
    commit_application(
        CommitRequest {
            handles,
            payload,
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
    image: &BlockImage,
    block_hash: &Hash256,
    height: u32,
    txids: &[Txid],
    resolved: &Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
    elapsed: std::time::Duration,
) {
    bitcoin_rs_consensus::trace::block_connected(move || {
        let mut view = BlockLocalUtxoView::new(Arc::clone(resolved), image, height, 0);
        let mut inputs: u32 = 0;
        let mut sigops: u64 = 0;
        for index in 0..image.tx_count() {
            let tx = image.tx(index);
            inputs = inputs.saturating_add(u32::try_from(tx.input_count()).unwrap_or(u32::MAX));
            let mut prevouts = Vec::with_capacity(tx.input_count());
            for input_index in 0..tx.input_count() {
                let previous_output = tx.input_outpoint(input_index);
                if let Some(output) = view.lookup(&previous_output) {
                    prevouts.push((previous_output, output));
                }
            }
            sigops = sigops.saturating_add(u64::from(
                bitcoin_rs_consensus::transaction_sigop_cost_view(tx.into(), &prevouts, flags),
            ));
            if let Some(txid) = txids.get(index) {
                let _ = view.add_outputs(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    *txid,
                    tx.output_count(),
                );
            }
        }
        (
            block_hash.as_byte_array().as_ptr(),
            i32::try_from(height).unwrap_or(i32::MAX),
            u64::try_from(image.tx_count()).unwrap_or(u64::MAX),
            i32::try_from(inputs).unwrap_or(i32::MAX),
            i64::try_from(sigops).unwrap_or(i64::MAX),
            i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX),
        )
    });
}

fn check_block_sigops(
    image: &BlockImage,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
) -> Result<(), ApplyError> {
    let mut view = BlockLocalUtxoView::new(resolved, image, height, 0);
    let mut cost = 0_u32;
    for (index, txid) in txids.iter().enumerate() {
        let tx = image.tx(index);
        let prevouts: Vec<_> = (0..tx.input_count())
            .filter_map(|input_index| {
                let previous_output = tx.input_outpoint(input_index);
                view.lookup(&previous_output)
                    .map(|output| (previous_output, output))
            })
            .collect();
        cost = cost.saturating_add(bitcoin_rs_consensus::transaction_sigop_cost_view(
            tx.into(),
            &prevouts,
            flags,
        ));
        if cost > bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST {
            return Err(bitcoin_rs_consensus::ConsensusError::SigopsLimit {
                cost,
                max: bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST,
            }
            .into());
        }
        if tx_plan.needs_local_utxo_overlay {
            view.spend_inputs(&tx);
            view.add_outputs(
                u32::try_from(index).unwrap_or(u32::MAX),
                *txid,
                tx.output_count(),
            )?;
        }
    }
    Ok(())
}

fn check_coinbase_maturity(
    image: &BlockImage,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(image.tx_count(), txids.len());
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.needs_local_utxo_overlay {
        for index in 0..image.tx_count() {
            let tx = image.tx(index);
            if tx.is_coinbase() {
                continue;
            }
            for input_index in 0..tx.input_count() {
                let previous_output = tx.input_outpoint(input_index);
                let Some(entry) = resolved.lookup_meta(&previous_output) else {
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

    let mut view = BlockLocalUtxoView::new(resolved, image, height, tx_plan.overlay_capacity);
    for (tx_index, txid) in txids.iter().enumerate() {
        let tx = image.tx(tx_index);
        let tx_index_u32 = u32::try_from(tx_index).unwrap_or(u32::MAX);
        if tx.is_coinbase() {
            view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
            continue;
        }
        for input_index in 0..tx.input_count() {
            let previous_output = tx.input_outpoint(input_index);
            let Some(entry) = view.lookup_meta(&previous_output) else {
                continue;
            };
            bitcoin_rs_consensus::check_coinbase_maturity(entry.coinbase, entry.height, height)?;
        }
        view.spend_inputs(&tx);
        view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &Chainstate,
    image: &BlockImage,
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
    debug_assert_eq!(image.tx_count(), txids.len());
    let mut view = BlockLocalUtxoView::new(resolved, image, height, tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = HashMap::new();
    for (tx_index, txid) in txids.iter().enumerate() {
        let tx = image.tx(tx_index);
        let tx_index_u32 = u32::try_from(tx_index).unwrap_or(u32::MAX);
        if tx.is_coinbase() {
            view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
            continue;
        }
        if tx.version() < 2 {
            view.spend_inputs(&tx);
            view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
            continue;
        }
        for input_index in 0..tx.input_count() {
            let sequence = tx.input_sequence(input_index);
            if sequence.to_consensus()
                & bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG
                != 0
            {
                continue;
            }
            let previous_output = tx.input_outpoint(input_index);
            let Some(entry) = view.lookup_meta(&previous_output) else {
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
                tx.version(),
                sequence.to_consensus(),
                entry.height,
                prevout_mtp,
                height,
                mtp,
            )?;
        }
        view.spend_inputs(&tx);
        view.add_outputs(tx_index_u32, *txid, tx.output_count())?;
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
    image: &BlockImage,
    height: u32,
    txids: &[Txid],
    previous_tip_id: Option<NodeId>,
    scope: ApplyScope<'_>,
) -> core::result::Result<(), ApplyError> {
    let replay_exempt = matches!(
        scope.provenance,
        BlockProvenance::LocalReplay(_) | BlockProvenance::ColdReplay(_)
    );
    let mut has_duplicate = false;
    if !replay_exempt
        && crate::chain::bip30_duplicate_scan_required(
            &handles.block_tree.read(),
            handles.network,
            height,
            previous_tip_id,
        )
    {
        for txid in txids {
            let known = scope
                .staged
                .and_then(|workspace| workspace.coin_presence_before(*txid, height));
            let present = match known {
                Some(present) => present,
                None => {
                    let key = bitcoin_rs_storage::CoinKey(txid.0.to_le_bytes());
                    handles
                        .coins
                        .get(&key)
                        .map_err(ApplyError::CoinStoreRead)?
                        .is_some()
                }
            };
            if present {
                has_duplicate = true;
                break;
            }
        }
    }
    let block_hash = image.block_hash().0;
    if has_duplicate {
        bitcoin_rs_consensus::bip30::check_duplicate_txid(height, block_hash)?;
    }
    check_bip34(handles, image, height)?;
    Ok(())
}

fn check_bip34(
    handles: &Chainstate,
    image: &BlockImage,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    if handles.network.is_bip34_active(height) {
        if image.tx_count() == 0 {
            return Err(bitcoin_rs_consensus::ConsensusError::EmptyBlock.into());
        }
        let coinbase = image.tx(0);
        if coinbase.input_count() == 0 {
            return Err(bitcoin_rs_consensus::ConsensusError::MissingCoinbase.into());
        }
        bitcoin_rs_consensus::bip34::check_bip34(height, coinbase.input_script_sig(0))?;
    }
    Ok(())
}

fn check_block_finality(
    image: &BlockImage,
    height: u32,
    locktime_cutoff: u32,
) -> core::result::Result<(), ApplyError> {
    for index in 0..image.tx_count() {
        let tx = image.tx(index);
        if !bitcoin_rs_consensus::is_final_tx_view(tx.into(), height, locktime_cutoff) {
            return Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip {
                    bip: "BIP113",
                    reason: format!(
                        "non-final transaction at height {height} locktime cutoff \
                         {locktime_cutoff}: locktime {}",
                        tx.lock_time(),
                    ),
                },
            ));
        }
    }
    Ok(())
}

fn validate_contextual_block_header(
    handles: &Chainstate,
    header: &Header,
    height: u32,
    prior: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    if height == 0 {
        return Ok(());
    }
    let Some(prior) = prior else {
        return Err(ApplyError::Chain(crate::chain::ChainError::MissingParent {
            prev_hash: header.prev_blockhash.0,
        }));
    };
    let tree = handles.block_tree.read();
    crate::chain::validate_contextual_header(
        &tree,
        prior.tip_id,
        header,
        handles.network,
        crate::chain::current_unix_seconds(),
        crate::chain::HeaderValidationMode::LiveAdmission,
    )
    .map_err(ApplyError::Chain)
}

fn applied_predecessor(
    handles: &Chainstate,
    block_hash: bitcoin_rs_consensus::primitives::Hash256,
    prev_hash: bitcoin_rs_consensus::primitives::Hash256,
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
            return Err(ApplyError::Chain(crate::chain::ChainError::MissingParent {
                prev_hash,
            }));
        }
        0_u32
    };
    Ok((prior, height))
}

pub(super) fn applied_header_tip(
    handles: &Chainstate,
    block_hash: Hash256,
    image: &BlockImage,
    height: u32,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let mut tree = handles.block_tree.write();
    let node_id = match tree.lookup(block_hash) {
        Some(node_id) => node_id,
        None => tree.insert_header(image.header(), crate::chain::node::NodeStatus::Active)?,
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
    tree.record_applied_tx_count(node_id, u64::try_from(image.tx_count()).unwrap_or(u64::MAX))?;
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
