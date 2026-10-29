//! Payload parsing, transaction planning, and resolved prevout preparation.

use super::SameBlockSpentSet;
use super::{
    BlockLocalUtxoView, BlockProvenance, BlockTxPlan, BlockValidationContext, ByteEquality,
    Chainstate, LOCAL_OVERLAY_TXID_SET_THRESHOLD, PreparedApply, ResolvedUtxoView,
};
use crate::error::ApplyError;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_primitives::{Block, BlockPayload, ConsensusEncode, OutPoint, Tx, TxOut, Txid};
use hashbrown::HashSet;
use rayon::prelude::*;
use std::sync::Arc;

/// Returns true iff `raw` is exactly the consensus serialization of `block`.
pub fn bytes_are_block(raw: &[u8], block: &Block) -> bool {
    let mut sink = ByteEquality {
        expected: raw,
        offset: 0,
        equal: true,
    };
    block.consensus_encode(&mut sink);
    sink.equal && sink.offset == raw.len()
}

/// Exactness is owned by the constructor: `from_raw` retains only bytes
/// that decoded, `from_local` retains its own single encode, and
/// `from_prefix` retains only the consumed prefix.
pub(super) fn parse_block_for_apply(
    payload: &BlockPayload,
    engine: bitcoin_rs_consensus::ValidationEngine,
) -> core::result::Result<
    (
        bitcoin_rs_consensus::kernel::BlockScriptSource,
        bitcoin_rs_consensus::BlockFacts,
    ),
    ApplyError,
> {
    let block = payload.block();
    let parsed = bitcoin_rs_consensus::kernel::BlockParse::parse(payload.bytes(), engine)
        .map_err(ApplyError::Consensus)?;
    if parsed.transaction_count() != block.txs.len() {
        return Err(ApplyError::TxidCountMismatch {
            transactions: block.txs.len(),
            txids: parsed.transaction_count(),
        });
    }
    parsed.into_parts(&block.txs).map_err(ApplyError::Consensus)
}

pub(super) fn prepare_apply<'b, S: bitcoin_rs_utxo::contract::OutputSource + ?Sized>(
    payload: &'b BlockPayload,
    source: &S,
    engine: bitcoin_rs_consensus::ValidationEngine,
) -> core::result::Result<PreparedApply<'b>, ApplyError> {
    let block = payload.block();
    let (script_source, facts) = parse_block_for_apply(payload, engine)?;
    let tx_plan = plan_block_transactions(block, facts.txids());
    let view = bitcoin_rs_consensus::BlockView::from_facts(&block.txs, facts);
    let resolved = Arc::new(ResolvedUtxoView::resolve(source, block, &tx_plan));
    Ok(PreparedApply {
        script_source,
        view,
        tx_plan,
        resolved,
    })
}

pub(super) fn plan_block_transactions(block: &Block, txids: &[Txid]) -> BlockTxPlan {
    let mut only_coinbase = true;
    let mut needs_local_utxo_overlay = false;
    let mut overlay_capacity = 0usize;
    let mut has_witness = false;
    let mut has_bip68_sequence_locks = false;
    let mut created_output_count = 0usize;
    let mut spent_input_count = 0usize;
    let mut same_block_spent: Option<SameBlockSpentSet> = None;
    let mut same_block_spent_input_count = 0usize;
    let mut created_txids: Option<HashSet<Txid>> = None;
    let mut spent_outpoints: Option<HashSet<OutPoint>> = None;
    let track_spent_conflicts = block.txs.len() > 2;
    let mut saw_non_coinbase = false;

    for (tx_index, (tx, txid)) in block.txs.iter().zip(txids.iter().copied()).enumerate() {
        let is_coinbase = tx.is_coinbase();
        let output_count = tx.outputs.len();
        only_coinbase &= is_coinbase;
        created_output_count = created_output_count.saturating_add(output_count);
        if is_coinbase {
            has_witness |= tx.inputs.iter().any(|input| !input.witness.is_empty());
            overlay_capacity = overlay_capacity.saturating_add(output_count);
        } else {
            let input_count = tx.inputs.len();
            for input in &tx.inputs {
                has_witness |= !input.witness.is_empty();
                let prior_txids = &txids[..tx_index];
                let spends_created_output = if prior_txids.len() <= LOCAL_OVERLAY_TXID_SET_THRESHOLD
                {
                    prior_txids.contains(&input.previous_output.txid)
                } else {
                    let created_txids = created_txids.get_or_insert_with(|| {
                        let mut set = HashSet::with_capacity(block.txs.len());
                        set.extend(prior_txids.iter().copied());
                        set
                    });
                    created_txids.contains(&input.previous_output.txid)
                };
                if spends_created_output {
                    same_block_spent
                        .get_or_insert_with(|| HashSet::with_capacity(input_count))
                        .insert(input.previous_output);
                    same_block_spent_input_count = same_block_spent_input_count.saturating_add(1);
                }
                let repeats_prior_spend = if track_spent_conflicts {
                    let spent_outpoints = spent_outpoints.get_or_insert_with(|| {
                        HashSet::with_capacity(input_count.max(block.txs.len()))
                    });
                    !spent_outpoints.insert(input.previous_output)
                } else {
                    saw_non_coinbase
                };
                needs_local_utxo_overlay |= spends_created_output || repeats_prior_spend;
            }
            saw_non_coinbase = true;
            if tx.version >= 2 {
                has_bip68_sequence_locks |= tx.inputs.iter().any(|input| {
                    input.sequence & bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_DISABLE_FLAG
                        == 0
                });
            }
            spent_input_count = spent_input_count.saturating_add(input_count);
            overlay_capacity =
                overlay_capacity.saturating_add(output_count.saturating_add(input_count));
        }
        if let Some(created_txids) = &mut created_txids {
            created_txids.insert(txid);
        }
    }

    BlockTxPlan {
        only_coinbase,
        needs_local_utxo_overlay,
        overlay_capacity,
        has_witness,
        has_bip68_sequence_locks,
        created_output_count,
        spent_input_count,
        same_block_spent,
        same_block_spent_input_count,
    }
}

pub(super) fn resolve_block_prevouts(
    resolved: Arc<ResolvedUtxoView>,
    txs: &[Tx],
    tx_plan: &BlockTxPlan,
    height: u32,
    txids: &[Txid],
) -> core::result::Result<Vec<Vec<Option<TxOut>>>, ApplyError> {
    if tx_plan.needs_local_utxo_overlay {
        let mut view = BlockLocalUtxoView::new(resolved, txs, height, tx_plan.overlay_capacity);
        let mut resolved = Vec::with_capacity(txs.len());
        for (tx_index, (tx, txid)) in (0_u32..).zip(txs.iter().zip(txids)) {
            if tx.is_coinbase() {
                resolved.push(Vec::new());
                view.add_outputs(tx_index, *txid, tx.outputs.len())?;
                continue;
            }
            let inputs = tx
                .inputs
                .iter()
                .map(|input| view.lookup(&input.previous_output))
                .collect();
            resolved.push(inputs);
            view.spend_inputs(tx);
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
        }
        Ok(resolved)
    } else {
        Ok(txs
            .iter()
            .map(|tx| {
                if tx.is_coinbase() {
                    return Vec::new();
                }
                tx.inputs
                    .iter()
                    .map(|input| resolved.lookup(&input.previous_output))
                    .collect()
            })
            .collect())
    }
}

fn run_non_script_checks_only(
    txs: &[Tx],
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    txids: &[Txid],
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_script::VerifyFlags,
) -> core::result::Result<(), ApplyError> {
    if !tx_plan.needs_local_utxo_overlay {
        txs.par_iter().try_for_each(|tx| {
            if tx.is_coinbase() {
                bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
                return Ok(());
            }
            bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
                tx,
                &*resolved,
                height,
                locktime_cutoff,
                flags,
            )
        })?;
        return Ok(());
    }
    let mut view = BlockLocalUtxoView::new(resolved, txs, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(txs.iter().zip(txids)) {
        if tx.is_coinbase() {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
            tx,
            &view,
            height,
            locktime_cutoff,
            flags,
        )?;
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
    }
    Ok(())
}

#[expect(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub(super) fn verify_block_transactions(
    handles: &Chainstate,
    view: &mut bitcoin_rs_consensus::BlockView<'_>,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    context: &BlockValidationContext,
    provenance: BlockProvenance,
    script_source: &bitcoin_rs_consensus::kernel::BlockScriptSource,
    script_cache: Option<&bitcoin_rs_consensus::ScriptExecutionCache>,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(view.txs().len(), view.txids().len());
    if tx_plan.only_coinbase {
        for tx in view.txs() {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
        }
        return Ok(());
    }
    let skip_scripts = handles.scripts_verified_upstream(provenance, context.height, context.hash);
    if skip_scripts {
        return run_non_script_checks_only(
            view.txs(),
            tx_plan,
            resolved,
            view.txids(),
            context.height,
            context.locktime_cutoff,
            context.flags,
        );
    }
    let resolution_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let resolution_result =
        resolve_block_prevouts(resolved, view.txs(), tx_plan, context.height, view.txids());
    tracing::debug!(
        height = context.height,
        script_resolution_us = resolution_started.map(|start| start.elapsed().as_micros()),
        "script_verify: profile"
    );
    let resolved = resolution_result?;
    view.set_resolved(resolved);
    let mut script_timings = bitcoin_rs_consensus::ScriptStageTimings::default();
    let script_input_result = bitcoin_rs_consensus::verify_block_input_scripts(
        view,
        context.height,
        context.locktime_cutoff,
        context.flags,
        &mut script_timings,
        script_source,
        script_cache,
    );
    tracing::debug!(
        height = context.height,
        script_prepare_us = (script_timings.prepare_seconds * 1_000_000.0) as u64,
        script_parallel_us = (script_timings.parallel_seconds * 1_000_000.0) as u64,
        "script_verify: profile"
    );
    script_input_result?;
    Ok(())
}
