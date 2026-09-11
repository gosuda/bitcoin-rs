//! Validated block connection and its ordered persistence/publication transaction.

use super::ApplyFinish;
use super::ApplyIntent;
use super::Bip68Context;
use super::BlockProvenance;
use super::BlockValidationContext;
use super::ChainChangeProof;
use super::Chainstate;
use super::ConnectOutcome;
use super::PreparedApply;
use super::ProvenApply;
use super::contextual::check_bip30_and_bip34;
use super::contextual::check_bip68_sequence_locks;
use super::contextual::check_coinbase_maturity_with_tx_plan;
use super::contextual::check_pow_limit_and_continuity;
use super::contextual::check_unseen_header_timestamp;
use super::contextual::compact_is_met_by;
use super::contextual::compute_verify_flags;
use super::prepare::prepare_apply;
use super::prepare::verify_block_transactions;
use super::publication::advance_chain_tx_count;
use super::publication::begin_applied_publication;
use super::publication::tx_count_delta_for;
use super::scratch::ApplyScratch;
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
use bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::consensus_bytes;
use bitcoin_rs_utxo::connect::BlockChangeError;
use bitcoin_rs_utxo::connect::build_block_changes;
use std::sync::Arc;

/// Applies one serialized block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
pub(super) fn apply_block_with_serialized_admitted(
    handles: &Chainstate,
    block: &Block,
    serialized: bytes::Bytes,
    proof: &ChainChangeProof<'_>,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    apply_committed_block_admitted(
        handles,
        block,
        Some(serialized),
        None,
        BlockProvenance::Network,
        proof,
    )
}

pub(super) fn apply_block_inner(
    handles: &Chainstate,
    block: &Block,
    provided_serialized: Option<bytes::Bytes>,
    provenance: BlockProvenance,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    let transition = handles.begin_transition()?;
    let result = apply_committed_block_admitted(
        handles,
        block,
        provided_serialized,
        None,
        provenance,
        transition.proof(),
    );
    if result.is_ok() {
        let _ = transition.finish();
    }
    result
}

/// Commit path: requires a [`ChainChangeProof`] so connect cannot run without
/// holding admission, the transition lock, and mempool generation.
pub(super) fn apply_committed_block_admitted<'b>(
    handles: &Chainstate,
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    proven: Option<ProvenApply<'b>>,
    provenance: BlockProvenance,
    _proof: &ChainChangeProof<'_>,
) -> core::result::Result<ConnectOutcome, ApplyError> {
    match apply_block_admitted(
        handles,
        block,
        provided_serialized,
        proven,
        provenance,
        ApplyIntent::Commit,
    )? {
        ApplyFinish::Committed(outcome) => Ok(outcome),
        ApplyFinish::Proposed => unreachable!("commit intent returns a committed tip"),
    }
}

/// Shared connect body for [`ApplyIntent::Commit`] and [`ApplyIntent::Propose`].
///
/// See `ARCH-07` in `docs/contracts/architecture.md`.
///
/// Split from [`apply_block_inner`] so a window can take both locks once across
/// its preparation and all of its ordered commits. Re-entering per block would
/// be two read guards on the same lock, which deadlocks against a shutdown
/// waiting on the write side, and would leave gaps in which another applier
/// could move the chain out from under prepared state.
#[allow(clippy::too_many_lines)]
pub(super) fn apply_block_admitted<'b>(
    handles: &Chainstate,
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    proven: Option<ProvenApply<'b>>,
    provenance: BlockProvenance,
    intent: ApplyIntent,
) -> core::result::Result<ApplyFinish, ApplyError> {
    let total_started = quanta::Instant::now();
    let block_hash = block.block_hash().0;
    let prev_hash = block.header.prev_blockhash.0;
    let (prior, height) = applied_predecessor(handles, block_hash, prev_hash)?;
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
    // declared target. This is the cheapest consensus gate; do it before
    // any structural checks. Contextual difficulty-adjustment validation
    // (verifying the declared target matches the network's expected
    // difficulty at this height) requires `BlockTree` state — deferred.
    let pow_self_started = quanta::Instant::now();
    let pow_self_result = if compact_is_met_by(block.header.bits, block_hash) {
        Ok(())
    } else {
        Err(())
    };
    let pow_self_dur = pow_self_started.elapsed();
    metrics::histogram!("node.apply_block.pow_self_consistency_seconds")
        .record(pow_self_dur.as_secs_f64());
    if intent == ApplyIntent::Commit && pow_self_result.is_err() {
        return Err(ApplyError::ProofOfWork { hash: block_hash });
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
    let verify_flags = compute_verify_flags(handles.network, height, block_hash, softfork_state);
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
    // Before any mutation. A header the tree has never seen skips header
    // sync's timestamp rules entirely, so this gate applies them itself; the
    // header insert in `applied_header_tip` below is part of the same
    // fallible preparation phase and still precedes the first write.
    check_unseen_header_timestamp(handles, block, block_hash)?;

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
    // PoW limit + DAA non-retarget continuity.
    let pow_limit_started = quanta::Instant::now();
    let pow_limit_result = check_pow_limit_and_continuity(handles, prior.as_deref(), block, height);
    let pow_limit_dur = pow_limit_started.elapsed();
    metrics::histogram!("node.apply_block.pow_limit_continuity_seconds")
        .record(pow_limit_dur.as_secs_f64());
    pow_limit_result?;

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
    let coinbase_maturity_result = check_coinbase_maturity_with_tx_plan(
        handles,
        block,
        &tx_plan,
        view.txids(),
        Arc::clone(&resolved),
        height,
    );
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
    let undo_record = bitcoin_rs_utxo::encode_undo(&undo, block_hash);
    let undo_persist_result = handles
        .undo_store
        .persist_undo(height, block_hash, &undo_record)
        .map_err(ApplyError::UndoPersistence);
    metrics::histogram!("node.apply_block.undo_persist_seconds")
        .record(undo_persist_started.elapsed().as_secs_f64());
    undo_persist_result?;

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
    let utxo_commit_result = handles.utxo.commit_borrowed_block(&changes, &block_hash);
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;

    // §2.3 linearization point for the chainstate journal (issue #230): the
    // in-memory UTXO commit above is the commit of record; everything the
    // journal needs to reconstruct this block's semantic delta is still
    // available here. Emit BEFORE `applied_tip.store` so any emission failure
    // records the append gap before the new tip becomes visible; the next apply
    // then stops in `prepare_for_apply` before mutating state. Successful
    // emissions advance the pending frontier, while `flush_to` advances the
    // durable head on the configured batch cadence. Emission remains
    // best-effort for the current block: a transient journal I/O failure is
    // §2.3 degraded-mode policy owns persistent failure) and must never fail
    // the block — the journal is a recovery accelerator, not a consensus
    // dependency. No fsync on this path; `flush_to` performs the §2.3
    // durability boundary on the batch cadence.
    if height > 0
        && let Some(journal) = &handles.journal
    {
        let mut journal = journal.lock();
        let undo_coins = undo
            .restores()
            .iter()
            .map(|add| crate::chainstate_journal::Coin {
                outpoint: add.outpoint,
                txout: add.txout.clone(),
                height: add.height,
                coinbase: add.coinbase,
            });
        let record = crate::chainstate_journal::journal_record_for_block(
            crate::chainstate_journal::BlockDeltaInputs {
                height,
                block_hash: block_hash.to_le_bytes(),
                prev_hash: prev_hash.to_le_bytes(),
                block_tx_count: tx_count_delta_for(block),
                // `finish_block` runs later in the publication tail, so the
                // listener still carries the parent height here: the delta of
                // this block is exactly (height - parent_height) — normally 1,
                // 0 for genesis (which never reaches this code path).
                coin_stats_height_delta: i64::from(height)
                    - i64::from(handles.coin_stats.snapshot().height),
                raw_header: {
                    let mut header_bytes = [0u8; 80];
                    let encoded = bitcoin_rs_primitives::consensus_bytes(&block.header);
                    debug_assert_eq!(encoded.len(), 80, "header consensus encoding is 80 bytes");
                    header_bytes.copy_from_slice(&encoded);
                    header_bytes
                },
            },
            &changes,
            undo_coins,
        );
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

    // Everything past the UTXO commit publishes values prepared above and
    // cannot fail: the tip snapshot was resolved from the tree before the
    // first write, so the publication tail is infallible.
    debug_assert!(
        handles.block_tree.read().node_by_hash(block_hash).is_some(),
        "block {} is entering the record log with no block-tree node; \
         its header would be unrecoverable",
        block_hash.to_string_be()
    );
    let mempool_evict_started = quanta::Instant::now();
    {
        let block_txids = scratch.txids();
        debug_assert_eq!(
            block_txids.len(),
            block.txs.len(),
            "block transactions and validated txids must stay aligned"
        );
        let block_txs: Vec<&Tx> = block.txs.iter().collect();
        handles.mempool_gateway.remove_for_block(
            AdmissionOrigin::Block,
            &block_txs,
            block_txids,
            height,
        );
    }
    let mempool_evict_dur = mempool_evict_started.elapsed();
    metrics::histogram!("node.apply_block.mempool_evict_seconds")
        .record(mempool_evict_dur.as_secs_f64());
    let tx_count_delta = tx_count_delta_for(block);
    let coin_stats_started = quanta::Instant::now();
    handles.coin_stats.finish_block(height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    let total_dur = total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    tracing::debug!(
        height,
        %block_hash,
        tx_count = block.txs.len(),
        pow_self_us = pow_self_dur.as_micros(),
        pow_limit_us = pow_limit_dur.as_micros(),
        block_rules_us = block_rules_dur.as_micros(),
        bip30_bip34_us = bip30_bip34_dur.as_micros(),
        script_verify_us = script_verify_dur.as_micros(),
        coinbase_maturity_us = coinbase_maturity_dur.as_micros(),
        bip68_us = bip68_dur.as_micros(),
        utxo_commit_us = utxo_commit_dur.as_micros(),
        block_body_persist_us = block_body_persist_dur.as_micros(),
        block_tree_insert_us = block_tree_insert_dur.as_micros(),
        mempool_evict_us = mempool_evict_dur.as_micros(),
        coin_stats_us = coin_stats_dur.as_micros(),
        total_us = total_dur.as_micros(),
        "apply_block: profile"
    );
    {
        let _publication = begin_applied_publication(handles);
        handles.applied_tip.store(Some(Arc::new(tip.clone())));
        handles
            .chain_events
            .record(crate::state::HintKind::Connected, tip.height, tip.hash);
        advance_chain_tx_count(handles, height, tx_count_delta_for(block));
    }
    let (txids, raw_txs) = scratch.into_payloads();
    Ok(ApplyFinish::Committed(ConnectOutcome {
        tip,
        height,
        hash: block_hash,
        txids,
        block_bytes,
        raw_txs,
    }))
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
    // No timestamp check here: `check_unseen_header_timestamp` ran just before
    // this call, in the same pre-mutation phase, and this whole function runs
    // before the first write so a rejection here leaves nothing behind.
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
        BlockChangeError::HeightOverflow(height) => ApplyError::HeightOverflow(*height),
        BlockChangeError::UndoPrevoutMissing { txid, vout } => ApplyError::UndoPrevoutMissing {
            txid: *txid,
            vout: *vout,
        },
    }
}
