//! Validated block connection and its ordered persistence/publication transaction.

use super::ApplyFinish;
use super::ApplyIntent;
use super::Bip68Context;
use super::BlockLocalUtxoView;
use super::BlockProvenance;
use super::BlockTxPlan;
use super::BlockValidationContext;
use super::Chainstate;
use super::ConnectOutcome;
use super::PreparedApply;
use super::ProvenApply;
use super::ResolvedUtxoView;
use super::durable::{
    ConnectCommitFacts, commit_connect_head, stored_body_row, sync_appended_blocks,
};
use super::prepare::prepare_apply;
use super::prepare::verify_block_transactions;
use super::publication::certified_advance;
use super::publication::publish_connect;
use super::publication::tx_count_delta_for;
use super::scratch::ApplyScratch;
use super::window::{PendingBlockCommit, PublishMode};
use crate::error::ApplyError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::node::NodeId;
use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
use bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::consensus_bytes;
use bitcoin_rs_storage::CommitRecords;
use bitcoin_rs_utxo::contract::BlockChangeError;
use bitcoin_rs_utxo::contract::build_block_changes;
use bitcoin_rs_utxo::contract::is_coinbase_tx;
use hashbrown::HashMap;
use std::sync::Arc;

/// Applies one serialized block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
pub(super) fn apply_block_with_serialized_admitted(
    handles: &Chainstate,
    block: &Block,
    serialized: bytes::Bytes,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    apply_committed_block_admitted(
        handles,
        block,
        Some(serialized),
        None,
        BlockProvenance::Network,
        PublishMode::Now,
    )
}

/// Commit path. Callers reach this only through an admitted chain transition.
pub(super) fn apply_committed_block_admitted<'b>(
    handles: &Chainstate,
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    proven: Option<ProvenApply<'b>>,
    provenance: BlockProvenance,
    publication: PublishMode<'_>,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    match apply_block_admitted(
        handles,
        block,
        provided_serialized,
        proven,
        provenance,
        ApplyIntent::Commit,
        publication,
    )? {
        ApplyFinish::Committed(outcome) => Ok(outcome),
        ApplyFinish::Proposed => unreachable!("commit intent returns a committed tip"),
    }
}

/// Shared connect body for [`ApplyIntent::Commit`] and [`ApplyIntent::Propose`].
///
/// See `ARCH-07` in `docs/contracts/architecture.md`.
///
/// Kept separate from transition acquisition so a window can take both locks
/// once across its preparation and all of its ordered commits. Re-entering per
/// block would be two read guards on the same lock, which deadlocks against a
/// shutdown waiting on the write side, and would leave gaps in which another
/// applier could move the chain out from under prepared state.
#[allow(clippy::too_many_lines)]
pub(super) fn apply_block_admitted<'b>(
    handles: &Chainstate,
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    proven: Option<ProvenApply<'b>>,
    provenance: BlockProvenance,
    intent: ApplyIntent,
    publication: PublishMode<'_>,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let total_started = quanta::Instant::now();
    let block_hash = block.block_hash().0;
    let prev_hash = block.header.prev_blockhash.0;
    let (prior, height) = match &publication {
        PublishMode::Grouped(group) => match group.predecessor(prev_hash)? {
            Some((tip, height)) => (Some(tip), height),
            None => applied_predecessor(handles, block_hash, prev_hash)?,
        },
        PublishMode::Now | PublishMode::Replay { .. } => {
            applied_predecessor(handles, block_hash, prev_hash)?
        }
    };

    // Contextual header rules, shared with header admission: the difficulty
    // continuity, median-time-past, BIP94 timewarp, future-drift, and version
    // floors all come from the one gate, so a block whose header never passed
    // header sync cannot be connected and a direct `submitblock` cannot skip a
    // rule by relying on header-sync history. The gate runs before the first
    // mutation and before journal maintenance, so a contextually invalid block
    // reports its own rejection instead of the backpressure its maintenance
    // hit; the cost is that a block only the later self-PoW check rejects
    // still pays that maintenance first. A crash-recovery replay skips the
    // gate: its block already committed a durable head receipt, which
    // certifies the header passed every rule at first connect, and the
    // future-drift bound reads the wall clock, so re-running it after an
    // operator clock rollback would refuse a block the store already holds.
    let contextual_header_started = quanta::Instant::now();
    let mut contextual_header_dur = std::time::Duration::ZERO;
    if !matches!(publication, PublishMode::Replay { .. }) {
        let contextual_header_result =
            validate_contextual_block_header(handles, block, height, prior.as_deref());
        contextual_header_dur = contextual_header_started.elapsed();
        metrics::histogram!("node.apply_block.contextual_header_seconds")
            .record(contextual_header_dur.as_secs_f64());
        contextual_header_result?;
    }
    if intent == ApplyIntent::Commit
        && let Some(journal) = &handles.journal
    {
        let maintenance = {
            let mut journal = journal.lock();
            journal.prepare_for_apply()
        };
        if let Err(error) = maintenance {
            metrics::counter!("node.chainstate_journal.backpressure_total").increment(1);
            tracing::error!(height, %error, "chainstate journal backpressure stopped block apply");
            return Err(ApplyError::JournalBackpressure(error.to_string()));
        }
    }

    // Self-consistency PoW: the block header's hash must satisfy its
    // declared target. Contextual difficulty-adjustment validation
    // (verifying the declared target matches the network's expected
    // difficulty at this height) requires `BlockTree` state; it runs ahead of
    // this check so its rejections also precede journal maintenance. This
    // pass still runs before any structural check.
    let pow_self_started = quanta::Instant::now();
    let pow_self_result =
        bitcoin_rs_chain::header_sync::validate_pow(&block.header, block_hash, handles.network);
    let pow_self_dur = pow_self_started.elapsed();
    metrics::histogram!("node.apply_block.pow_self_consistency_seconds")
        .record(pow_self_dur.as_secs_f64());
    match pow_self_result {
        // Declared target above the network limit is refused for proposals too.
        Err(bitcoin_rs_chain::ChainError::TargetExceedsLimit { .. }) => {
            return Err(ApplyError::TargetAboveLimit);
        }
        // Proposals carry an unsolved header, so only commits refuse an unmet target.
        Err(_) if intent == ApplyIntent::Commit => {
            return Err(ApplyError::ProofOfWork { hash: block_hash });
        }
        _ => {}
    }

    let (prev_median_time_past, softfork_state) = if let Some(tip) = prior.as_deref() {
        let tree = handles.block_tree.read();
        let mtp = tree
            .median_time_past_at(tip.tip_id, MEDIAN_TIME_PAST_WINDOW)
            .unwrap_or(0);
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
    let locktime_cutoff = bitcoin_rs_consensus::locktime_cutoff(
        softfork_state.csv_active,
        prev_median_time_past,
        block.header.time,
    );
    let verify_flags =
        bitcoin_rs_consensus::verify_flags(handles.network, height, block_hash, softfork_state);
    let validation_context = BlockValidationContext {
        hash: block_hash,
        parent: prev_hash,
        height,
        flags: verify_flags,
        locktime_cutoff,
    };
    // Parse the block once with the kernel and take its txids. Core's
    // `CTransaction` hashes itself while deserializing with the SHA-256
    // implementation selected at runtime, so this one parse replaces the
    // scalar `compute_txid` pass *and* the per-transaction serialize/reparse
    // that script preparation used to perform.
    // A window prepares several blocks against one overlay and hands the result
    // back, so the kernel parse and the prevout resolution happen once. A proof
    // whose context no longer matches is discarded together with its prepared
    // view; the ordinary path rebuilds both from the live UTXO set.
    let (prepared, transactions_proven) = match proven {
        Some(ProvenApply::Proven(proof)) if proof.context == validation_context => {
            (proof.prepared, true)
        }
        Some(ProvenApply::AssumeValidSkipped(prepared)) => (prepared, false),
        Some(ProvenApply::Proven(_)) | None => (
            prepare_apply(block, provided_serialized.clone(), handles.utxo.as_ref())?,
            false,
        ),
    };
    let PreparedApply {
        kernel_block,
        mut view,
        tx_plan,
        resolved,
    } = prepared;

    let block_rules_started = quanta::Instant::now();
    // Witness IDs are needed only for a witness-carrying block under active
    // segwit; the view computes them once and the commitment check consumes
    // the cache, so witness-free blocks never serialize-and-hash for wtxids.
    // The native one-pass layout already carries them; this only fills the
    // kernel-build facts, which derive witness IDs lazily.
    let needs_wtxids = softfork_state.segwit_active && tx_plan.witness_presence.is_present();
    if needs_wtxids {
        view.witness_ids();
    }
    let block_rules_result = bitcoin_rs_consensus::verify_block_rules_precomputed(
        block,
        bitcoin_rs_consensus::BlockRuleContext {
            segwit_active: softfork_state.segwit_active,
        },
        view.facts(),
    );
    let block_rules_dur = block_rules_started.elapsed();
    metrics::histogram!("node.apply_block.block_rules_seconds")
        .record(block_rules_dur.as_secs_f64());
    block_rules_result?;
    // Contextual consensus checks (BIP30 + BIP34) using the resolved height.
    let bip30_bip34_started = quanta::Instant::now();
    let previous_tip_id = prior.as_deref().map(|tip| tip.tip_id);
    let bip30_bip34_result =
        check_bip30_and_bip34(handles, block, height, view.txids(), previous_tip_id);
    let bip30_bip34_dur = bip30_bip34_started.elapsed();
    metrics::histogram!("node.apply_block.bip30_bip34_seconds")
        .record(bip30_bip34_dur.as_secs_f64());
    bip30_bip34_result?;

    let script_verify_started = quanta::Instant::now();
    // A matching proof certifies exactly this transaction-validation slot.
    // Block rules and BIP30/BIP34 remain above it; coinbase maturity and BIP68
    // remain below it. Every other state uses the ordinary verifier.
    let script_verify_result = if transactions_proven {
        Ok(())
    } else {
        verify_block_transactions(
            handles,
            block,
            &mut view,
            &tx_plan,
            Arc::clone(&resolved),
            &validation_context,
            provenance,
            &kernel_block,
        )
    };
    let script_verify_dur = script_verify_started.elapsed();
    metrics::histogram!("node.apply_block.script_verify_seconds")
        .record(script_verify_dur.as_secs_f64());
    // Same duration split by dispatch path, so replay decompositions can
    // attribute time to the serial overlay walk vs the rayon fan-out.
    let script_verify_path = if tx_plan.only_coinbase {
        "node.apply_block.script_verify_coinbase_only_seconds"
    } else if tx_plan.needs_local_utxo_overlay {
        "node.apply_block.script_verify_serial_overlay_seconds"
    } else {
        "node.apply_block.script_verify_parallel_seconds"
    };
    metrics::histogram!(script_verify_path).record(script_verify_dur.as_secs_f64());
    script_verify_result?;

    let coinbase_maturity_started = quanta::Instant::now();
    let coinbase_maturity_result =
        check_coinbase_maturity(block, &tx_plan, view.txids(), Arc::clone(&resolved), height);
    let coinbase_maturity_dur = coinbase_maturity_started.elapsed();
    metrics::histogram!("node.apply_block.coinbase_maturity_seconds")
        .record(coinbase_maturity_dur.as_secs_f64());
    coinbase_maturity_result?;
    let bip68_started = quanta::Instant::now();
    let previous_tip_id = prior.as_deref().map(|tip| tip.tip_id);
    let bip68_result = check_bip68_sequence_locks(
        handles,
        block,
        &tx_plan,
        view.txids(),
        Arc::clone(&resolved),
        Bip68Context {
            validation: &validation_context,
            median_time_past: prev_median_time_past,
            softfork_state,
            previous_tip_id,
        },
    );
    let bip68_dur = bip68_started.elapsed();
    metrics::histogram!("node.apply_block.bip68_seconds").record(bip68_dur.as_secs_f64());
    bip68_result?;
    let wants_rawtx = handles.capture_rawtx;
    let (txids, scratch_capacities, same_block_spent, same_block_spent_input_count) =
        tx_plan.into_scratch_parts(view.into_txids());
    let scratch = ApplyScratch::from_prepared_parts(
        block,
        wants_rawtx,
        txids,
        scratch_capacities,
        same_block_spent,
        same_block_spent_input_count,
    );

    let utxo_changes_started = quanta::Instant::now();
    let (utxo_add_capacity, utxo_remove_capacity) = scratch.utxo_change_capacity();
    let (changes, undo, value_totals) = build_block_changes(
        block,
        height,
        scratch.txids(),
        scratch.same_block_spent(),
        utxo_add_capacity,
        utxo_remove_capacity,
        resolved.as_ref(),
        bitcoin_rs_consensus::bip30::is_bip30_exception(height, block_hash)
            .then(|| handles.utxo.as_ref()),
        MAX_SCRIPT_SIZE,
    )
    .map_err(|e| map_block_change_error(&e))?;
    let utxo_changes_dur = utxo_changes_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_changes_seconds")
        .record(utxo_changes_dur.as_secs_f64());

    // The last consensus gate, and the one that keeps a miner from creating
    // money. Nothing above bounds what the coinbase pays itself: block rules
    // check structure, and per-transaction verification exempts the coinbase
    // because it has no inputs to weigh its outputs against.
    //
    // Placed here because `build_block_changes` has just gathered the totals for
    // free, and still before `persist_undo` -- the first write of any kind --
    // so a rejected block leaves nothing behind. Genesis is skipped for the
    // same reason its transactions are not connected.
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

    if intent == ApplyIntent::Propose {
        return Ok(ApplyFinish::Proposed);
    }

    // Persist undo before the block body, the index, and the UTXO commit. All
    // three are derived state for a block that is about to apply; if the undo
    // record cannot be written the block must not apply at all, and leaving
    // body bytes or index rows behind for it would be worse than not starting.
    let undo_persist_started = quanta::Instant::now();
    let undo_persist_result = bitcoin_rs_utxo::contract::persist_block_undo(
        handles.undo_store.as_ref(),
        height,
        block_hash,
        &undo,
    )
    .map_err(ApplyError::UndoPersistence);
    metrics::histogram!("node.apply_block.undo_persist_seconds")
        .record(undo_persist_started.elapsed().as_secs_f64());
    let undo_record = undo_persist_result?;

    // Serialize the block lazily: only when a consumer actually needs the
    // full bytes. During IBD with pruning+txindex disabled this avoids a
    // full-block serialize on every apply.
    let block_bytes: bytes::Bytes = {
        let needs_body = handles.block_body_store.is_some() || handles.capture_block_bytes;
        if needs_body {
            // The preserved P2P wire payload is byte-identical to the canonical
            // block serialization: the decoder rejects every non-canonical
            // encoding, so a decoded block always re-serializes to its wire
            // bytes. The length guard keeps that invariant release-observable and
            // self-heals to a fresh serialize if it ever fails to hold, so a
            // future decoder change can never admit non-canonical bytes into the
            // block body store.
            match provided_serialized {
                Some(provided) if provided.len() == consensus_bytes(block).len() => {
                    #[cfg(debug_assertions)]
                    {
                        debug_assert_eq!(provided.as_ref(), consensus_bytes(block).as_slice(),);
                    }
                    provided
                }
                _ => bytes::Bytes::from(consensus_bytes(block)),
            }
        } else {
            // Nothing downstream reads `block_bytes` unless one of the consumers
            // above needs the full body, so skip the serialize entirely.
            bytes::Bytes::new()
        }
    };

    let block_body_persist_started = quanta::Instant::now();
    let block_body_persist_result = match &handles.block_body_store {
        Some(store) => store
            .persist_block_body_value(height, block_hash, block_bytes.clone())
            .map_err(ApplyError::BlockBodyPersistence),
        None => Ok(()),
    };
    let block_body_persist_dur = block_body_persist_started.elapsed();
    metrics::histogram!("node.apply_block.block_body_persist_seconds")
        .record(block_body_persist_dur.as_secs_f64());
    block_body_persist_result?;

    // Prove every fallible piece of block-tree bookkeeping before the first
    // UTXO mutation. Header resolution (inserting the header when header-first
    // sync has not seen it), the applied-height check, and the cumulative
    // transaction-count derivation can all fail; proving them here keeps every
    // rejection before the UTXO commit, so a failed block leaves no applied
    // outputs behind, and it leaves the publication tail infallible.
    let block_tree_insert_started = quanta::Instant::now();
    let tip = applied_header_tip(handles, block_hash, block, height)?;
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());

    let utxo_commit_started = quanta::Instant::now();
    let utxo_commit_result =
        bitcoin_rs_utxo::contract::commit_block_changes(&handles.utxo, &changes, &block_hash);
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;
    // Core's connect-block interval ends with the block's UTXO application
    // and bookkeeping (`UpdateCoins` per tx, undo write, `SetBestBlock`) at
    // the end of `ConnectBlock`; the durable `view.Flush()` runs afterwards
    // in `ConnectTip`. `commit_block` is the in-memory UTXO application, so
    // the probe's duration argument is captured here.
    let block_connected_dur = total_started.elapsed();
    // Capture before `finish_block` advances the listener's height: the
    // journal delta of this block is exactly (height - parent_height).
    let coin_stats_height_delta =
        i64::from(height) - i64::from(handles.coin_stats.snapshot().height);

    // Everything past the UTXO commit publishes values prepared above and
    // cannot fail: the tip snapshot was resolved from the tree before the
    // first write, so the publication tail is infallible.
    debug_assert!(
        handles.block_tree.read().node_by_hash(block_hash).is_some(),
        "block {} is entering the record log with no block-tree node; \
         its header would be unrecoverable",
        block_hash.to_string_be()
    );
    let tx_count_delta = tx_count_delta_for(block);
    let coin_stats_started = quanta::Instant::now();
    handles.coin_stats.finish_block(height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    let total_dur = total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    // Core fires `validation:block_connected` at the end of `ConnectBlock`,
    // after the block is connected. Everything below this point is
    // publication of an already-applied block, so this is the same commit
    // point. A grouped publish still counts as connected here: the block's
    // consensus state is applied to the chainstate before publication.
    emit_block_connected(
        block,
        &block_hash,
        height,
        scratch.txids(),
        &resolved,
        verify_flags,
        block_connected_dur,
    );
    tracing::debug!(
        height,
        %block_hash,
        tx_count = block.txs.len(),
        pow_self_us = pow_self_dur.as_micros(),
        contextual_header_us = contextual_header_dur.as_micros(),
        block_rules_us = block_rules_dur.as_micros(),
        bip30_bip34_us = bip30_bip34_dur.as_micros(),
        script_verify_us = script_verify_dur.as_micros(),
        coinbase_maturity_us = coinbase_maturity_dur.as_micros(),
        bip68_us = bip68_dur.as_micros(),
        utxo_commit_us = utxo_commit_dur.as_micros(),
        block_body_persist_us = block_body_persist_dur.as_micros(),
        block_tree_insert_us = block_tree_insert_dur.as_micros(),
        coin_stats_us = coin_stats_dur.as_micros(),
        total_us = total_dur.as_micros(),
        "apply_block: profile"
    );
    let (txids, raw_txs) = scratch.into_payloads();
    let mut outcome = ConnectOutcome {
        tip: tip.clone(),
        commit_id: 0,
        height,
        hash: block_hash,
        txids,
        block_bytes,
        raw_txs,
    };
    let (commit_id, chain_tx_count) = match publication {
        PublishMode::Now => {
            // RCV-02 steps 3–4: certify, then commit. `sync` makes the
            // appended body bytes, the blocks directory, and every deferred
            // index row durable; the durable-head batch then names them with
            // one `write_durable_if` receipt — head, undo record, and
            // locator row together. `Ok` is the receipt for the whole
            // prefix (`INV-06`: the head never names bytes that are not
            // already durable). An `Err` is not a rollback receipt: like a
            // `UtxoCommit` refusal it leaves the caller to reconcile
            // through recovery.
            let durable_sync_started = quanta::Instant::now();
            sync_appended_blocks(handles)?;
            metrics::histogram!("node.apply_block.durable_sync_seconds")
                .record(durable_sync_started.elapsed().as_secs_f64());
            let undo_rows = vec![(height, block_hash, undo_record.as_bytes())];
            let body_rows = stored_body_row(handles, height, block_hash)?
                .into_iter()
                .collect();
            let durable_commit_started = quanta::Instant::now();
            let chain_tx_count =
                certified_advance(handles.applied_chain_tx_count(), height, tx_count_delta);
            let commit_id = commit_connect_head(
                handles,
                &ConnectCommitFacts {
                    prev_hash,
                    tip: block_hash,
                    height,
                    chain_tx_count_after: chain_tx_count.to_wire(),
                    undo_extent: Some((height, block_hash)),
                },
                &CommitRecords {
                    undo_rows,
                    body_rows,
                },
            )?;
            metrics::histogram!("node.apply_block.durable_commit_seconds")
                .record(durable_commit_started.elapsed().as_secs_f64());
            (commit_id, chain_tx_count)
        }
        // The gap block's durable batch committed before the crash: the
        // stored head receipt covers its body, undo, and locator rows.
        // Replay redoes only what publication owed — the journal tail
        // and the coherent tip — and carries the receipt's commit id.
        PublishMode::Replay { commit_id } => (
            commit_id,
            certified_advance(handles.applied_chain_tx_count(), height, tx_count_delta),
        ),
        PublishMode::Grouped(group) => {
            // The window buffers the durable work: facts ride in the group
            // until its boundary, where one sync and one head batch commit
            // the whole verified prefix and the prefix publishes in order.
            let base = group
                .chain_tx_count_base()
                .unwrap_or_else(|| handles.applied_chain_tx_count());
            let journal_record = build_journal_record(
                block,
                height,
                block_hash,
                prev_hash,
                &undo,
                &changes,
                coin_stats_height_delta,
            );
            group.stage(PendingBlockCommit {
                outcome: outcome.clone(),
                undo_record,
                tx_count_delta,
                chain_tx_count_after: certified_advance(base, height, tx_count_delta),
                prev_hash,
                journal_record,
            });
            return Ok(ApplyFinish::Committed(outcome));
        }
    };
    // The journal may lag the durable head, never lead it. Fresh commits and
    // replayed receipts share publication; grouped commits publish later.
    emit_journal_record(
        handles,
        build_journal_record(
            block,
            height,
            block_hash,
            prev_hash,
            &undo,
            &changes,
            coin_stats_height_delta,
        ),
        height,
    );
    publish_connect(handles, &tip, chain_tx_count);
    outcome.commit_id = commit_id;
    Ok(ApplyFinish::Committed(outcome))
}

/// Accumulates Core's `validation:block_connected` payload facts and fires
/// the probe.
///
/// Core counts `nInputs` over every transaction and `nSigOpsCost` with
/// `GetTransactionSigOpCost` against the connect view (the same rules as
/// `bitcoin_rs_consensus::transaction_sigop_cost`), then fires the probe
/// after the block is connected. The per-transaction prevout resolution runs
/// inside `prepare`, so a build without the `usdt` feature — or a node with
/// no consumer attached — does none of it.
fn emit_block_connected(
    block: &Block,
    block_hash: &Hash256,
    height: u32,
    txids: &[Txid],
    resolved: &Arc<ResolvedUtxoView>,
    flags: bitcoin_rs_script::VerifyFlags,
    elapsed: std::time::Duration,
) {
    // `block_hash` borrows the caller's already-computed hash local, which
    // outlives this call: the probe argument must not point into a value the
    // prepare closure owns, because the generated macro fires only after the
    // closure has returned.
    bitcoin_rs_trace::block_connected(move || {
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

pub(super) fn check_coinbase_maturity(
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
        for tx in block.txs.iter().filter(|tx| !is_coinbase_tx(tx)) {
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
        if is_coinbase_tx(tx) {
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

pub(super) fn check_bip68_sequence_locks(
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
        if is_coinbase_tx(tx) {
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
            if sequence & bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
                continue;
            }
            let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                continue;
            };
            let prevout_mtp = if bitcoin_rs_consensus::bip68::sequence_lock_is_time_based(
                sequence.to_consensus(),
            ) {
                if entry.height == height {
                    // A same-block prevout uses the MTP before the block being connected.
                    mtp
                } else if let Some(cached) = prevout_mtp_by_height.get(&entry.height) {
                    *cached
                } else {
                    let Some(previous_tip_id) = context.previous_tip_id else {
                        // Time-based lock evaluated with no admitted tip to walk.
                        return Err(ApplyError::Consensus(
                            bitcoin_rs_consensus::ConsensusError::Bip {
                                bip: "BIP68",
                                reason: "missing previous tip for time-based sequence lock"
                                    .to_owned(),
                            },
                        ));
                    };
                    let tree = handles.block_tree.read();
                    let Some(prevout_mtp) =
                        tree.median_time_past_before_height(previous_tip_id, entry.height)
                    else {
                        // Prevout's ancestor is not on the previous tip's chain.
                        return Err(ApplyError::Consensus(
                            bitcoin_rs_consensus::ConsensusError::Bip {
                                bip: "BIP68",
                                reason: format!(
                                    "missing prevout ancestry at height {} for time-based sequence lock",
                                    entry.height.saturating_sub(1)
                                ),
                            },
                        ));
                    };
                    prevout_mtp_by_height.insert(entry.height, prevout_mtp);
                    prevout_mtp
                }
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

pub(super) fn check_bip30_and_bip34(
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
    bitcoin_rs_consensus::bip30::check_bip30(height, block_hash, has_duplicate)?;
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

/// Applies the shared contextual header gate to a block being connected.
///
/// PRE: `prior` is the applied predecessor of `block`, if it has one, and
/// `height` is that predecessor's child height.
///
/// POST: `Ok(())` only when
/// [`bitcoin_rs_chain::validate_contextual_header`] accepts the block's
/// header against its parent. A difficulty mismatch keeps its dedicated
/// [`ApplyError`] variant so the sync window still classifies it as a
/// permanent refusal.
///
/// INVARIANT: this operation adds no header rule of its own; header
/// admission and block connection share the one contextual implementation.
fn validate_contextual_block_header(
    handles: &Chainstate,
    block: &Block,
    height: u32,
    prior: Option<&TipSnapshot>,
) -> Result<(), ApplyError> {
    if height == 0 {
        // Genesis has no parent, so no contextual rule applies to it.
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
    )
    .map_err(|error| match error {
        bitcoin_rs_chain::ChainError::NbitsMismatch {
            actual,
            expected,
            height,
        } => ApplyError::NbitsNonRetargetMismatch {
            actual,
            expected,
            height,
        },
        error => ApplyError::Chain(error),
    })
}

pub(super) fn applied_predecessor(
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
    // No header check here: the shared contextual gate
    // (`validate_contextual_block_header`) ran at the top of this function, in
    // the same pre-mutation phase, so a rejection there leaves nothing behind.
    // A crash-recovery replay is exempt from the gate; its durable head
    // receipt certifies the header instead.
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
    tree.record_applied_tx_count(node_id, tx_count_delta_for(block))?;
    let node = tree.node(node_id)?;
    Ok(TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

/// Converts UTXO connect accounting errors into apply errors.
pub(super) fn map_block_change_error(error: &BlockChangeError) -> ApplyError {
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

/// The derived journal record for one connected block, or `None` when there
/// is nothing to derive (genesis never reaches this path; a disabled journal
/// derives nothing).
///
/// Pure: the caller decides when the record may reach the writer, which is
/// after the durable head batch — the journal may lag the head, never lead
/// it.
pub(super) type BuiltJournalRecord =
    Option<core::result::Result<bitcoin_rs_storage::chainstate_journal::JournalRecord, String>>;

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
        crate::journal::mutations_for_block(changes, undo_coins)
            .map(
                |mutations| bitcoin_rs_storage::chainstate_journal::JournalRecord {
                    height,
                    block_hash: block_hash.to_le_bytes(),
                    prev_hash: prev_hash.to_le_bytes(),
                    block_tx_count,
                    coin_stats_height_delta,
                    raw_header,
                    mutations,
                },
            )
            .map_err(|error| error.to_string()),
    )
}

/// Emits one built journal record, best-effort.
///
/// The journal is a recovery accelerator, not a consensus dependency: an
/// extraction failure records the append gap and an append failure warns,
/// and neither fails the block. Both run after the durable head batch, so a
/// failure here can only make the journal lag, never lead.
pub(super) fn emit_journal_record(handles: &Chainstate, built: BuiltJournalRecord, height: u32) {
    let Some(journal) = handles.journal.as_ref() else {
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
