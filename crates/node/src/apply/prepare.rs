//! Exact serialized-body validation, transaction planning, and resolved prevout preparation.

use super::BIP68_DISABLE_FLAG;
use super::BlockLocalUtxoView;
use super::BlockProvenance;
use super::BlockTxPlan;
use super::BlockValidationContext;
use super::ByteEquality;
use super::Chainstate;
use super::LOCAL_OVERLAY_TXID_SET_THRESHOLD;
use super::PreparedApply;
use super::ResolvedUtxoView;
use super::WitnessPresence;
use super::scratch::SameBlockSpentSet;
use crate::apply::error::ApplyError;
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::ConsensusEncode;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::TxOut;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::consensus_bytes;
use bitcoin_rs_utxo::is_coinbase_tx;
use hashbrown::HashSet;
use rayon::prelude::*;
use std::sync::Arc;

/// Returns true iff `raw` is exactly the consensus serialization of `block`.
pub(crate) fn bytes_are_block(raw: &[u8], block: &Block) -> bool {
    let mut sink = ByteEquality {
        expected: raw,
        offset: 0,
        equal: true,
    };
    block.consensus_encode(&mut sink);
    // `offset` accumulated every written byte, so a longer `raw` (trailing
    // bytes) fails here just as a shorter one fails in the sink.
    sink.equal && sink.offset == raw.len()
}

pub(super) fn parse_block_for_apply(
    block: &Block,
    provided_serialized: Option<bytes::Bytes>,
) -> core::result::Result<(bitcoin_rs_consensus::kernel::KernelBlock, Vec<Txid>), ApplyError> {
    // Preserved bytes must BE this block, not merely agree with it on
    // transaction count. In kernel builds the txids and the transactions that
    // script verification runs come from these bytes, while the witness
    // commitment check and the UTXO mutation use the decoded block. Changing a
    // witness does not change a txid, so a count check lets a caller pair a
    // block carrying an invalid witness with bytes carrying a valid one: the
    // scripts verify against the bytes and the invalid block gets applied.
    if let Some(raw) = provided_serialized.as_deref()
        && !bytes_are_block(raw, block)
    {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Kernel(
                "preserved bytes are not the serialization of the block they accompany".to_owned(),
            ),
        ));
    }
    #[cfg(feature = "kernel")]
    let (kernel_block, txids) = {
        let raw_block: bytes::Bytes =
            provided_serialized.unwrap_or_else(|| bytes::Bytes::from(consensus_bytes(block)));
        let kernel_block = bitcoin_rs_consensus::kernel::KernelBlock::parse(&raw_block)
            .map_err(ApplyError::Consensus)?;
        if kernel_block.transaction_count() != block.txs.len() {
            return Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Kernel(format!(
                    "kernel parsed {} transactions, decoder produced {}",
                    kernel_block.transaction_count(),
                    block.txs.len()
                )),
            ));
        }
        let txids = kernel_block.txids().map_err(ApplyError::Consensus)?;
        (kernel_block, txids)
    };
    // Without the kernel the checked borrowed layout is the one parse: it
    // derives the txids, witness IDs, weight, byte positions, and the
    // Merkle verdicts in a single pass, and the decoded block feeds only
    // the stages that mutate or verify against it. No second transaction
    // tree decode happens on this path.
    #[cfg(not(feature = "kernel"))]
    let (kernel_block, txids) = {
        let raw_block: bytes::Bytes =
            provided_serialized.unwrap_or_else(|| bytes::Bytes::from(consensus_bytes(block)));
        let kernel_block = bitcoin_rs_consensus::kernel::KernelBlock::parse(&raw_block)
            .map_err(ApplyError::Consensus)?;
        if kernel_block.transaction_count() != block.txs.len() {
            return Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Kernel(format!(
                    "layout parsed {} transactions, decoder produced {}",
                    kernel_block.transaction_count(),
                    block.txs.len()
                )),
            ));
        }
        let txids = kernel_block.txids().to_vec();
        (kernel_block, txids)
    };
    Ok((kernel_block, txids))
}

/// Parses a block and resolves the outputs it spends.
///
/// `source` is where prevouts come from. Every caller outside a window passes
/// the committed UTXO set; a window passes an overlay so a block can see
/// outputs an earlier block in the same window created.
pub(super) fn prepare_apply<'b, S: crate::window_overlay::OutputSource + ?Sized>(
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    source: &S,
) -> core::result::Result<PreparedApply<'b>, ApplyError> {
    let (kernel_block, txids) = parse_block_for_apply(block, provided_serialized)?;
    let tx_plan = plan_block_transactions(block, &txids);
    let facts = kernel_block.derive_facts(&block.txs, &txids);
    let view = bitcoin_rs_consensus::BlockView::from_facts(&block.txs, facts);
    let resolved = Arc::new(ResolvedUtxoView::resolve(source, block, &tx_plan));
    Ok(PreparedApply {
        kernel_block,
        view,
        tx_plan,
        resolved,
    })
}

/// Plans a block whose txids are already known.
///
/// Identities come from the parse-once view: the kernel parse hashes every
/// transaction on the way past using the SHA-256 implementation Core picks at
/// runtime, and the native build hashes each transaction once in
/// [`block_txids`]. Either way the plan borrows them instead of re-hashing
/// with a scalar implementation.
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
        let is_coinbase = is_coinbase_tx(tx);
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
                has_bip68_sequence_locks |= tx
                    .inputs
                    .iter()
                    .any(|input| input.sequence & BIP68_DISABLE_FLAG == 0);
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
        witness_presence: WitnessPresence::from_bool(has_witness),
        has_bip68_sequence_locks,
        created_output_count,
        spent_input_count,
        same_block_spent,
        same_block_spent_input_count,
    }
}

/// Resolves every transaction's prevouts serially in block order into an owned
/// `Vec<Vec<Option<TxOut>>>` (coinbase -> empty inner Vec). This is the only
/// order-sensitive step of full script verification: the overlay walk advances
/// a `BlockLocalUtxoView` so a later transaction sees outputs an earlier one
/// created (or spent) in the same block; the non-overlay case reads the
/// committed shared set directly.
pub(super) fn resolve_block_prevouts(
    resolved: Arc<ResolvedUtxoView>,
    block: &Block,
    tx_plan: &BlockTxPlan,
    height: u32,
    txids: &[Txid],
) -> core::result::Result<Vec<Vec<Option<TxOut>>>, ApplyError> {
    if tx_plan.needs_local_utxo_overlay {
        let mut view =
            BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
        let mut resolved = Vec::with_capacity(block.txs.len());
        for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
            if is_coinbase_tx(tx) {
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
        // Serial on purpose, for the same reason as `ResolvedUtxoView::resolve`:
        // each item is a hashmap hit plus a `TxOut` clone, which is cheaper than
        // handing the work to another thread. Pinned 3x medians on mainnet
        // 0..150_000, parallel and serial interleaved, serial winning every
        // round: 139.4s vs 125.4s overall, and this stage 6.9s vs 1.63s. The
        // fan-out was adding 5.3s of dispatch on top of 1.6s of work.
        Ok(block
            .txs
            .iter()
            .map(|tx| {
                if is_coinbase_tx(tx) {
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

#[allow(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
/// Runs every non-script transaction check for a block whose scripts are
/// verified upstream: assume-valid or local replay.
pub(super) fn run_non_script_checks_only(
    block: &Block,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    txids: &[Txid],
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_script::VerifyFlags,
) -> core::result::Result<(), ApplyError> {
    if !tx_plan.needs_local_utxo_overlay {
        block.txs.par_iter().try_for_each(|tx| {
            if is_coinbase_tx(tx) {
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
    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        if is_coinbase_tx(tx) {
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

#[allow(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub(super) fn verify_block_transactions(
    handles: &Chainstate,
    block: &Block,
    view: &mut bitcoin_rs_consensus::BlockView<'_>,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    context: &BlockValidationContext,
    provenance: BlockProvenance,
    kernel_block: &bitcoin_rs_consensus::kernel::KernelBlock,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(block.txs.len(), view.txids().len());
    if tx_plan.only_coinbase {
        for tx in &block.txs {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
        }
        return Ok(());
    }
    // The decision is owned by `scripts_verified_upstream`, which covers the
    // live assume-valid gate and locally validated crash-recovery replay.
    let skip_scripts = handles.scripts_verified_upstream(provenance, context.height);
    if skip_scripts {
        return run_non_script_checks_only(
            block,
            tx_plan,
            resolved,
            view.txids(),
            context.height,
            context.locktime_cutoff,
            context.flags,
        );
    }
    // Full-verify: resolve every transaction's prevouts serially in block order
    // into an owned `Vec<Vec<Option<TxOut>>>` (coinbase -> empty inner Vec), then
    // hand it to consensus, which runs the per-input script checks concurrently
    // and returns the first failure in block order. Resolution is the only
    // order-sensitive step: the overlay walk advances a `BlockLocalUtxoView` so a
    // later transaction sees outputs an earlier one created (or spent) in the same
    // block; the non-overlay case reads the committed shared set directly.
    let resolution_started = quanta::Instant::now();
    let resolution_result =
        resolve_block_prevouts(resolved, block, tx_plan, context.height, view.txids());
    let resolution_dur = resolution_started.elapsed();
    metrics::histogram!("node.apply_block.script_resolution_seconds")
        .record(resolution_dur.as_secs_f64());
    let resolved = resolution_result?;
    view.set_resolved(resolved);
    // preparation and parallel input-check fan-out internally and reports both
    // sub-stage durations back; record them here on the success and error paths
    // before propagating the verdict, mirroring the surrounding `*_result` idiom.
    let mut script_timings = bitcoin_rs_consensus::ScriptStageTimings::default();
    let script_input_result = bitcoin_rs_consensus::verify_block_input_scripts(
        view,
        context.height,
        context.locktime_cutoff,
        context.flags,
        &mut script_timings,
        kernel_block,
    );
    metrics::histogram!("node.apply_block.script_prepare_seconds")
        .record(script_timings.prepare_seconds);
    metrics::histogram!("node.apply_block.script_parallel_seconds")
        .record(script_timings.parallel_seconds);
    script_input_result?;
    tracing::debug!(
        height = context.height,
        script_resolution_us = resolution_dur.as_micros(),
        script_prepare_us = (script_timings.prepare_seconds * 1_000_000.0) as u64,
        script_parallel_us = (script_timings.parallel_seconds * 1_000_000.0) as u64,
        "script_verify: profile"
    );
    Ok(())
}
