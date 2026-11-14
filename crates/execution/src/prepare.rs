use super::SameBlockSpentSet;
use super::{
    BlockLocalUtxoView, BlockProvenance, BlockTxPlan, BlockValidationContext, ByteEquality,
    Chainstate, LOCAL_OVERLAY_TXID_SET_THRESHOLD, PreparedApply, ResolvedUtxoView,
};
use crate::error::ApplyError;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::primitives::{Block, BlockImage, ConsensusEncode, OutPoint, TxOut, Txid};
use hashbrown::HashSet;
use std::sync::Arc;

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
    payload: &BlockImage,
    engine: bitcoin_rs_consensus::ValidationEngine,
) -> core::result::Result<
    (
        bitcoin_rs_consensus::kernel::BlockScriptSource,
        bitcoin_rs_consensus::BlockFacts,
    ),
    ApplyError,
> {
    let facts = bitcoin_rs_consensus::BlockFacts::from_image(payload);
    match engine {
        bitcoin_rs_consensus::ValidationEngine::Native => Ok((
            bitcoin_rs_consensus::kernel::BlockScriptSource::Native,
            facts,
        )),
        bitcoin_rs_consensus::ValidationEngine::Kernel => {
            let parsed = bitcoin_rs_consensus::kernel::BlockParse::parse(payload.bytes(), engine)
                .map_err(ApplyError::Consensus)?;
            Ok((parsed.into_script_source(), facts))
        }
    }
}

pub(super) fn prepare_apply<'b, S: bitcoin_rs_storage::utxo::contract::OutputSource + ?Sized>(
    payload: &'b BlockImage,
    source: &S,
    engine: bitcoin_rs_consensus::ValidationEngine,
    charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
) -> core::result::Result<PreparedApply<'b>, ApplyError> {
    let (script_source, facts) = parse_block_for_apply(payload, engine)?;
    let tx_plan = plan_block_transactions(payload, facts.txids());
    let view = bitcoin_rs_consensus::BlockView::from_image(payload, facts);
    let resolved = Arc::new(ResolvedUtxoView::resolve_charged(
        source, payload, &tx_plan, charge,
    )?);
    Ok(PreparedApply {
        script_source,
        view,
        tx_plan,
        resolved,
    })
}

pub(super) fn plan_block_transactions(image: &BlockImage, txids: &[Txid]) -> BlockTxPlan {
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
    let tx_count = image.tx_count();
    let track_spent_conflicts = tx_count > 2;
    let mut saw_non_coinbase = false;

    for tx_index in 0..tx_count {
        let tx = image.tx(tx_index);
        let txid = txids[tx_index];
        let is_coinbase = tx.is_coinbase();
        let output_count = tx.output_count();
        only_coinbase &= is_coinbase;
        created_output_count = created_output_count.saturating_add(output_count);
        if is_coinbase {
            has_witness |= (0..tx.input_count()).any(|i| tx.witness_item_count(i) > 0);
            overlay_capacity = overlay_capacity.saturating_add(output_count);
        } else {
            let input_count = tx.input_count();
            for i in 0..input_count {
                has_witness |= tx.witness_item_count(i) > 0;
                let prevout = tx.input_outpoint(i);
                let prior_txids = &txids[..tx_index];
                let spends_created_output = if prior_txids.len() <= LOCAL_OVERLAY_TXID_SET_THRESHOLD
                {
                    prior_txids.contains(&prevout.txid)
                } else {
                    let created_txids = created_txids.get_or_insert_with(|| {
                        let mut set = HashSet::with_capacity(tx_count);
                        set.extend(prior_txids.iter().copied());
                        set
                    });
                    created_txids.contains(&prevout.txid)
                };
                if spends_created_output {
                    same_block_spent
                        .get_or_insert_with(|| HashSet::with_capacity(input_count))
                        .insert(prevout);
                    same_block_spent_input_count = same_block_spent_input_count.saturating_add(1);
                }
                let repeats_prior_spend = if track_spent_conflicts {
                    let spent_outpoints = spent_outpoints
                        .get_or_insert_with(|| HashSet::with_capacity(input_count.max(tx_count)));
                    !spent_outpoints.insert(prevout)
                } else {
                    saw_non_coinbase
                };
                needs_local_utxo_overlay |= spends_created_output || repeats_prior_spend;
            }
            saw_non_coinbase = true;
            has_bip68_sequence_locks |= tx_view_has_bip68_sequence_locks(&tx);
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

fn tx_view_has_bip68_sequence_locks(
    tx: &bitcoin_rs_consensus::primitives::TransactionView<'_>,
) -> bool {
    tx.version() >= 2
        && (0..tx.input_count()).any(|i| {
            tx.input_sequence(i).to_consensus()
                & bitcoin_rs_consensus::primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG
                == 0
        })
}

pub(super) fn resolve_block_prevouts(
    resolved: Arc<ResolvedUtxoView>,
    image: &BlockImage,
    tx_plan: &BlockTxPlan,
    height: u32,
    txids: &[Txid],
) -> core::result::Result<Vec<Vec<Option<TxOut>>>, ApplyError> {
    let tx_count = image.tx_count();
    if tx_plan.needs_local_utxo_overlay {
        let mut view = BlockLocalUtxoView::new(resolved, image, height, tx_plan.overlay_capacity);
        let mut resolved = Vec::with_capacity(tx_count);
        for (tx_index, &txid) in txids.iter().enumerate() {
            let tx = image.tx(tx_index);
            let tx_index_u32 =
                u32::try_from(tx_index).map_err(|_| ApplyError::VoutOverflow { txid })?;
            if tx.is_coinbase() {
                resolved.push(Vec::new());
                view.add_outputs(tx_index_u32, txid, tx.output_count())?;
                continue;
            }
            let inputs = (0..tx.input_count())
                .map(|i| view.lookup(&tx.input_outpoint(i)))
                .collect();
            resolved.push(inputs);
            view.spend_inputs(&tx);
            view.add_outputs(tx_index_u32, txid, tx.output_count())?;
        }
        Ok(resolved)
    } else {
        Ok((0..tx_count)
            .map(|tx_index| {
                let tx = image.tx(tx_index);
                if tx.is_coinbase() {
                    return Vec::new();
                }
                (0..tx.input_count())
                    .map(|i| resolved.lookup(&tx.input_outpoint(i)))
                    .collect()
            })
            .collect())
    }
}

fn run_non_script_checks_only(
    view: &bitcoin_rs_consensus::BlockView<'_>,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    txids: &[Txid],
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_consensus::script::VerifyFlags,
) -> core::result::Result<(), ApplyError> {
    let tx_count = view.tx_count();
    if !tx_plan.needs_local_utxo_overlay {
        for tx_index in 0..tx_count {
            let tx = view.tx_view(tx_index);
            if tx.is_coinbase() {
                continue;
            }
            bitcoin_rs_consensus::verify_tx::verify_transaction_non_script_view(
                tx,
                &*resolved,
                height,
                locktime_cutoff,
                flags,
            )?;
        }
        return Ok(());
    }
    let Some(image) = view.image() else {
        return Ok(());
    };
    let mut local_view = BlockLocalUtxoView::new(resolved, image, height, tx_plan.overlay_capacity);
    for (tx_index, &txid) in txids.iter().enumerate() {
        let tx = image.tx(tx_index);
        let tx_index_u32 =
            u32::try_from(tx_index).map_err(|_| ApplyError::VoutOverflow { txid })?;
        if tx.is_coinbase() {
            local_view.add_outputs(tx_index_u32, txid, tx.output_count())?;
            continue;
        }
        bitcoin_rs_consensus::verify_tx::verify_transaction_non_script_view(
            bitcoin_rs_consensus::primitives::TxView::View(tx),
            &local_view,
            height,
            locktime_cutoff,
            flags,
        )?;
        local_view.spend_inputs(&tx);
        local_view.add_outputs(tx_index_u32, txid, tx.output_count())?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScriptsRan {
    Executed,
    Skipped,
}

fn seconds_as_micros(seconds: f64) -> u128 {
    std::time::Duration::try_from_secs_f64(seconds).map_or(0_u128, |duration| duration.as_micros())
}

pub(super) fn verify_block_transactions(
    handles: &Chainstate,
    view: &mut bitcoin_rs_consensus::BlockView<'_>,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    context: &BlockValidationContext,
    provenance: BlockProvenance,
    script_source: &bitcoin_rs_consensus::kernel::BlockScriptSource,
    script_cache: Option<&bitcoin_rs_consensus::ScriptExecutionCache>,
) -> core::result::Result<(ScriptsRan, Option<super::PrevoutHold>), ApplyError> {
    debug_assert_eq!(view.tx_count(), view.txids().len());
    if tx_plan.only_coinbase {
        return Ok((ScriptsRan::Executed, None));
    }
    let skip_scripts = handles.scripts_verified_upstream(provenance, context.height, context.hash);
    if skip_scripts {
        run_non_script_checks_only(
            view,
            tx_plan,
            resolved,
            view.txids(),
            context.height,
            context.locktime_cutoff,
            context.flags,
        )?;
        return Ok((ScriptsRan::Skipped, None));
    }
    let resolution_started = tracing::enabled!(tracing::Level::DEBUG).then(quanta::Instant::now);
    let resolution_result = if let Some(image) = view.image() {
        resolve_block_prevouts(resolved, image, tx_plan, context.height, view.txids())
    } else {
        Ok(Vec::new())
    };
    tracing::debug!(
        height = context.height,
        script_resolution_us = resolution_started.map(|start| start.elapsed().as_micros()),
        "script_verify: profile"
    );
    let resolved = resolution_result?;
    let hold = super::PrevoutHold::charge(
        handles.prevout_charge.clone(),
        super::prevout_vec_bytes(&resolved),
    )?;
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
        script_prepare_us = seconds_as_micros(script_timings.prepare_seconds),
        script_parallel_us = seconds_as_micros(script_timings.parallel_seconds),
        "script_verify: profile"
    );
    script_input_result?;
    Ok((ScriptsRan::Executed, hold))
}
