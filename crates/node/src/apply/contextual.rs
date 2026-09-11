//! Contextual consensus checks against the admitted chain and resolved coins.

use super::BIP34_IMPLIES_BIP30_LIMIT;
use super::BIP68_DISABLE_FLAG;
use super::BIP68_MASK;
use super::BIP68_TIME_GRANULARITY_SECONDS;
use super::BIP68_TYPE_FLAG;
use super::Bip68Context;
use super::BlockLocalUtxoView;
use super::BlockTxPlan;
use super::COINBASE_MATURITY;
use super::Chainstate;
use super::ResolvedUtxoView;
use crate::apply::error::ApplyError;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_consensus::MEDIAN_TIME_PAST_WINDOW;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_utxo::LiveOutputMeta;
use bitcoin_rs_utxo::is_coinbase_tx;
use hashbrown::HashMap;
use std::sync::Arc;

/// Decodes a compact `bits` encoding into a 256-bit target with Core
/// `arith_uint256::SetCompact` semantics; the sign bit decodes to zero.
/// Node-local port: `bitcoin_rs_chain::header_sync` keeps its `pow` module
/// crate-private, and the header `PoW` gate here must match it exactly.
pub(super) fn compact_to_target(
    bits: impl Into<bitcoin_rs_primitives::CompactTarget>,
) -> ChainWork {
    let bits = bits.into().to_consensus();
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mut mantissa = u64::from(bits & 0x007f_ffff);
    let target = if exponent <= 3 {
        mantissa >>= 8 * (3 - exponent);
        ChainWork::from(mantissa)
    } else {
        let shift = 8 * (exponent - 3);
        if shift < 256 {
            ChainWork::from(mantissa) << shift
        } else {
            ChainWork::ZERO
        }
    };
    if mantissa != 0 && bits & 0x0080_0000 != 0 {
        ChainWork::ZERO
    } else {
        target
    }
}

/// Returns `true` when `hash`, read as a 256-bit little-endian integer, does
/// not exceed the decoded compact target.
pub(super) fn compact_is_met_by(
    bits: impl Into<bitcoin_rs_primitives::CompactTarget>,
    hash: Hash256,
) -> bool {
    let target = compact_to_target(bits);
    target != ChainWork::ZERO && ChainWork::from_le_bytes(hash.to_le_bytes()) <= target
}

/// Applies header-sync's timestamp rules to a header the tree has not seen.
///
/// A header already in the tree went through `accept_headers` and was checked
/// there. One that is not is about to be inserted by `applied_header_tip`, and
/// without this a caller handing `apply_block` a block directly could make one
/// with an invalid median-time-past or an absurd future timestamp the applied
/// consensus tip.
pub(super) fn check_unseen_header_timestamp(
    handles: &Chainstate,
    block: &Block,
    block_hash: Hash256,
) -> core::result::Result<(), ApplyError> {
    let tree = handles.block_tree.read();
    if tree.lookup(block_hash).is_some() {
        return Ok(());
    }
    bitcoin_rs_chain::validate_header_timestamp(
        &tree,
        &block.header,
        block_hash,
        bitcoin_rs_chain::current_unix_seconds(),
    )?;
    Ok(())
}

pub(super) fn check_coinbase_maturity_with_tx_plan(
    _handles: &Chainstate,
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
    // COINBASE_MATURITY: spent coinbase outputs must be at least 100 blocks deep.
    if !tx_plan.needs_local_utxo_overlay {
        for tx in block.txs.iter().filter(|tx| !is_coinbase_tx(tx)) {
            for input in &tx.inputs {
                let Some(entry) = resolved.lookup_meta(&input.previous_output) else {
                    continue;
                };
                check_coinbase_input_maturity(entry, height)?;
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
            check_coinbase_input_maturity(entry, height)?;
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
    }
    Ok(())
}

pub(super) fn check_coinbase_input_maturity(
    entry: LiveOutputMeta,
    height: u32,
) -> Result<(), ApplyError> {
    let depth = height.saturating_sub(entry.height);
    if entry.coinbase && depth < COINBASE_MATURITY {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "COINBASE_MATURITY",
                reason: format!(
                    "spent coinbase output created at height {} cannot be spent at height {} (depth {} < {})",
                    entry.height, height, depth, COINBASE_MATURITY,
                ),
            },
        ));
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
    if !context.softfork_state.csv_active {
        return Ok(());
    }
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.has_bip68_sequence_locks {
        return Ok(());
    }
    let height = context.validation.height;
    let mtp = context.median_time_past;

    debug_assert_eq!(block.txs.len(), txids.len());
    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = None;
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
            if sequence & BIP68_DISABLE_FLAG != 0 {
                continue;
            }
            let is_time_based = sequence & BIP68_TYPE_FLAG != 0;
            if is_time_based {
                let relative_intervals = sequence & BIP68_MASK;
                let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                    continue;
                };
                let prevout_mtp = if entry.height == height {
                    // A same-block prevout's coin time is the MTP of the block
                    // before the block being connected; the previous tip cannot
                    // contain an ancestor at the current block height yet.
                    mtp
                } else {
                    let cache = prevout_mtp_by_height.get_or_insert_with(HashMap::new);
                    if let Some(prevout_mtp) = cache.get(&entry.height) {
                        *prevout_mtp
                    } else {
                        let prevout_mtp =
                            bip68_prevout_mtp(handles, context.previous_tip_id, entry.height)?;
                        cache.insert(entry.height, prevout_mtp);
                        prevout_mtp
                    }
                };
                let earliest_time = prevout_mtp.saturating_add(
                    relative_intervals.saturating_mul(BIP68_TIME_GRANULARITY_SECONDS),
                );
                if mtp < earliest_time {
                    return Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip {
                            bip: "BIP68",
                            reason: format!(
                                "input sequence time-based lock unmet: prevout mtp {prevout_mtp} + {relative_intervals}*512s = {earliest_time} > current mtp {mtp}",
                            ),
                        },
                    ));
                }
                continue;
            }

            let relative_blocks = sequence & BIP68_MASK;
            let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                continue;
            };
            let earliest_height = entry.height.saturating_add(relative_blocks);
            if height < earliest_height {
                return Err(ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::Bip {
                        bip: "BIP68",
                        reason: format!(
                            "input sequence height-based lock unmet: prevout at height {} + {} blocks > current {}",
                            entry.height, relative_blocks, height
                        ),
                    },
                ));
            }
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
    }

    Ok(())
}

pub(super) fn bip68_prevout_mtp(
    handles: &Chainstate,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
    prevout_height: u32,
) -> core::result::Result<u32, ApplyError> {
    let tree = handles.block_tree.read();
    let Some(previous_tip_id) = previous_tip_id else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing previous tip for time-based sequence lock".to_owned(),
            },
        ));
    };
    let mtp_height = prevout_height.saturating_sub(1);
    let Some(prev_block_node) = tree.node_at_height_from(previous_tip_id, mtp_height) else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: format!(
                    "missing prevout ancestry at height {mtp_height} for time-based sequence lock"
                ),
            },
        ));
    };
    let Some(prevout_mtp) = tree.median_time_past_at(prev_block_node, MEDIAN_TIME_PAST_WINDOW)
    else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing prevout median-time-past for time-based sequence lock".to_owned(),
            },
        ));
    };
    Ok(prevout_mtp)
}

pub(super) fn check_bip30_and_bip34(
    handles: &Chainstate,
    block: &Block,
    height: u32,
    txids: &[Txid],
    previous_tip_id: Option<NodeId>,
) -> core::result::Result<(), ApplyError> {
    // BIP30: reject any txid that collides with an earlier transaction while
    // any output of the earlier transaction remains unspent, except at the
    // documented historical exception heights handled by `check_bip30`.
    let mut has_duplicate = false;
    if should_scan_bip30_duplicates(handles, height, previous_tip_id) {
        for txid in txids {
            if handles.utxo.has_live_outputs_for_txid(&txid.0) {
                has_duplicate = true;
                break;
            }
        }
    }
    let block_hash = block.block_hash().0;
    bitcoin_rs_consensus::bip30::check_bip30(height, block_hash, has_duplicate)?;

    // BIP34: when active for this network at `height`, the coinbase
    // scriptSig must start with the minimally-encoded height.
    if handles.network.is_bip34_active(height) {
        let coinbase = block
            .txs
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::EmptyBlock)?;
        // `verify_block_rules_precomputed` already pinned the first tx to
        // be the coinbase; relying on that here. `coinbase.inputs[0]`
        // is the synthetic prevout pointing at the impossible
        // outpoint; its `script_sig` carries the BIP34 height encoding.
        let coinbase_input = coinbase
            .inputs
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)?;
        bitcoin_rs_consensus::bip34::check_bip34(height, &coinbase_input.script_sig)?;
    }

    Ok(())
}

pub(super) fn should_scan_bip30_duplicates(
    handles: &Chainstate,
    height: u32,
    previous_tip_id: Option<NodeId>,
) -> bool {
    if height >= BIP34_IMPLIES_BIP30_LIMIT || !handles.network.is_bip34_active(height) {
        return true;
    }

    let Some(expected_activation_hash) = handles.network.bip34_activation_hash() else {
        return true;
    };
    let Some(previous_tip_id) = previous_tip_id else {
        return true;
    };

    let tree = handles.block_tree.read();
    let Some(activation_id) =
        tree.node_at_height_from(previous_tip_id, handles.network.bip34_activation_height())
    else {
        return true;
    };
    let Ok(activation_node) = tree.node(activation_id) else {
        return true;
    };

    activation_node.hash != expected_activation_hash
}

pub(super) fn check_pow_limit_and_continuity(
    handles: &Chainstate,
    prior: Option<&TipSnapshot>,
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    // PoW limit: declared target must not exceed network max_target.
    let declared = compact_to_target(block.header.bits);
    let max_target = handles.network.max_target();
    if declared > max_target {
        return Err(ApplyError::TargetAboveLimit);
    }

    // Genesis (height 0) has no parent; skip contextual DAA.
    if height == 0 {
        return Ok(());
    }

    let tree = handles.block_tree.read();
    let Some(parent_id) = prior.map(|tip| tip.tip_id) else {
        let prev_hash = block.header.prev_blockhash.0;
        return Err(ApplyError::Chain(
            bitcoin_rs_chain::ChainError::MissingParent { prev_hash },
        ));
    };
    bitcoin_rs_chain::header_sync::validate_header_nbits(
        &tree,
        parent_id,
        &block.header,
        handles.network,
    )
    .map_err(apply_nbits_error)
}

pub(super) fn apply_nbits_error(error: bitcoin_rs_chain::ChainError) -> ApplyError {
    match error {
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
    }
}

#[must_use]
pub(super) fn compute_verify_flags(
    network: Network,
    height: u32,
    block_hash: Hash256,
    softfork_state: bitcoin_rs_chain::SoftforkState,
) -> bitcoin_rs_script::VerifyFlags {
    use bitcoin_rs_script::VerifyFlags;

    // P2SH (BIP16) is enforced on every block except Core's single grandfathered
    // `consensus.BIP16Exception` (mainnet block 170060), keyed by block hash.
    let mut flags = VerifyFlags::NONE;
    if !network.is_bip16_p2sh_exception(block_hash) {
        flags = flags.union(VerifyFlags::P2SH);
    }
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if softfork_state.csv_active {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if softfork_state.segwit_active {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}
