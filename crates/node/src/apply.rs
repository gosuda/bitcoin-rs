//! Block-apply pipeline over shared node handles.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::{Network, OutPoint};
use bitcoin_rs_rpc::BlockRecord;
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::state::ApplyError;

/// Number of blocks after a coinbase that its outputs become spendable.
/// Consensus rule since Bitcoin v0.3.1; universal across networks.
const COINBASE_MATURITY: u32 = 100;
/// BIP68 sequence-bit masks.
const BIP68_DISABLE_FLAG: u32 = 0x8000_0000;
const BIP68_TYPE_FLAG: u32 = 0x0040_0000;
const BIP68_MASK: u32 = 0x0000_ffff;
const BIP68_TIME_GRANULARITY_SECONDS: u32 = 512;

/// Owned shared handle set needed by `apply_block` to perform a block apply.
pub struct ApplyHandles {
    /// Network consensus parameters.
    pub network: Network,
    /// Shared best-chain tip handle.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared best-applied-block tip handle.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<RwLock<BlockTree>>,
    /// Shared UTXO set.
    pub utxo: Arc<UtxoSet>,
    /// Shared mempool.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Shared block records exposed to RPC handlers.
    pub blocks: Arc<RwLock<Vec<BlockRecord>>>,
    /// Shared transaction map exposed to RPC handlers.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
}

/// Synthetically applies `block` as the next tip after consensus checks.
pub fn apply_block(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
) -> core::result::Result<TipSnapshot, ApplyError> {
    use bitcoin::hashes::Hash as _;

    let block_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
    let prev_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.header.prev_blockhash.as_byte_array());
    let prior = handles.chain_tip.load_full();
    let height = match prior.as_deref() {
        Some(tip) => {
            if tip.hash != prev_hash {
                return Err(ApplyError::PrevHashMismatch {
                    tip: tip.hash,
                    prev: prev_hash,
                });
            }
            tip.height
                .checked_add(1)
                .ok_or(ApplyError::HeightOverflow(tip.height))?
        }
        None => 0_u32,
    };

    // Self-consistency PoW: the block header's hash must satisfy its
    // declared target. This is the cheapest consensus gate; do it before
    // any structural checks. Contextual difficulty-adjustment validation
    // (verifying the declared target matches the network's expected
    // difficulty at this height) requires `BlockTree` state — deferred.
    let declared_target = block.header.target();
    if block.header.validate_pow(declared_target).is_err() {
        return Err(ApplyError::ProofOfWork { hash: block_hash });
    }

    let prev_tip_state = match prior.as_deref() {
        Some(tip) => {
            let mtp = handles
                .block_tree
                .read()
                .median_time_past_at(tip.tip_id, 11)
                .unwrap_or(0);
            bitcoin_rs_consensus::rust_path::TipState {
                height: Some(tip.height),
                block_hash: None,
                median_time_past: mtp,
            }
        }
        None => bitcoin_rs_consensus::rust_path::TipState {
            height: None,
            block_hash: None,
            median_time_past: 0,
        },
    };
    bitcoin_rs_consensus::verify_block::verify_block_rules_borrowed(block, &prev_tip_state)?;
    // Contextual consensus checks (BIP30 + BIP34) using the resolved height.
    check_bip30_and_bip34(handles, block, height)?;
    // PoW limit + DAA non-retarget continuity.
    check_pow_limit_and_continuity(handles, block, height)?;

    verify_block_transactions(handles, block, height, prev_tip_state.median_time_past)?;

    check_coinbase_maturity(handles, block, height)?;
    check_bip68_sequence_locks(handles, block, height, prev_tip_state.median_time_past)?;

    let changes = build_utxo_changes(block, height)?;
    handles
        .utxo
        .commit_block(&changes, &block_hash)
        .map_err(ApplyError::UtxoCommit)?;

    // Persist the header into the in-memory block tree after validation and
    // UTXO commit have succeeded. `BlockTree` publishes the canonical
    // best-tip snapshot as part of `insert_header`.
    insert_active_header(handles, block)?;

    let tip = handles
        .chain_tip
        .load_full()
        .map(|arc| (*arc).clone())
        .ok_or_else(|| {
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "INTERNAL",
                reason: format!(
                    "chain tip not published by BlockTree after insert_header for block {block_hash}"
                ),
            })
        })?;
    handles
        .blocks
        .write()
        .push(bitcoin_rs_rpc::BlockRecord::from_block(height, block));
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        let evicted_count = handles.mempool.write().remove_by_txid(&txid).len();
        tracing::debug!(%txid, evicted_count, "apply_block: evicted transaction from mempool");
        handles.transactions.write().insert(txid, tx.clone());
    }
    tracing::info!(
        height,
        %block_hash,
        tx_count = block.txdata.len(),
        utxo_adds = changes.add_count(),
        utxo_removes = changes.remove_count(),
        "apply_block: chain advance committed"
    );
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    Ok(tip)
}

fn insert_active_header(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
) -> core::result::Result<(), ApplyError> {
    handles
        .block_tree
        .write()
        .insert_header(block.header, bitcoin_rs_chain::node::NodeStatus::Active)?;
    Ok(())
}

fn verify_block_transactions(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    median_time_past: u32,
) -> core::result::Result<(), ApplyError> {
    // Per-tx script verification. The view borrows the UTXO set as it
    // stood BEFORE this block's outputs were committed — inputs in this
    // block can only spend outputs from earlier blocks. Coinbase txs have
    // no prevouts to verify here.
    let flags = compute_verify_flags(handles.network, height);
    let view = crate::utxo_view::UtxoSetView::new(Arc::clone(&handles.utxo));
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        bitcoin_rs_consensus::verify_transaction_borrowed_with_mtp(
            tx,
            &view,
            height,
            median_time_past,
            flags,
        )?;
    }
    Ok(())
}

pub(crate) fn check_coinbase_maturity(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // COINBASE_MATURITY: spent coinbase outputs must be at least 100 blocks deep.
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        for tx_input in &tx.input {
            let prev_outpoint = OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(
                    tx_input.previous_output.txid.as_byte_array(),
                ),
                tx_input.previous_output.vout,
            );
            let Some(entry) = handles.utxo.get_entry(&prev_outpoint) else {
                continue;
            };
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
        }
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    mtp: u32,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    if !handles.network.is_csv_active(height) {
        return Ok(());
    }

    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        if tx.version.0 < 2 {
            continue;
        }
        for tx_input in &tx.input {
            let sequence = tx_input.sequence.to_consensus_u32();
            if sequence & BIP68_DISABLE_FLAG != 0 {
                continue;
            }
            let is_time_based = sequence & BIP68_TYPE_FLAG != 0;
            if is_time_based {
                let relative_intervals = sequence & BIP68_MASK;
                let prev_outpoint = OutPoint::new(
                    bitcoin_rs_primitives::Hash256::from_le_bytes(
                        tx_input.previous_output.txid.as_byte_array(),
                    ),
                    tx_input.previous_output.vout,
                );
                let Some(entry) = handles.utxo.get_entry(&prev_outpoint) else {
                    continue;
                };
                let prevout_mtp = {
                    let tree = handles.block_tree.read();
                    let Some(chain_tip) = handles.chain_tip.load_full() else {
                        continue;
                    };
                    let Some(prev_block_node) =
                        tree.node_at_height_from(chain_tip.tip_id, entry.height)
                    else {
                        continue;
                    };
                    tree.median_time_past_at(prev_block_node, 11).unwrap_or(0)
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
            let prev_outpoint = OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(
                    tx_input.previous_output.txid.as_byte_array(),
                ),
                tx_input.previous_output.vout,
            );
            let Some(entry) = handles.utxo.get_entry(&prev_outpoint) else {
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
    }

    Ok(())
}

fn check_bip30_and_bip34(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // BIP30: best-effort — reject if any tx in the block re-uses an
    // outpoint that the UTXO set still considers live. The first vout
    // (index 0) lookup catches the common-case duplicate-coinbase
    // scenario that BIP30 was written to address. A proper any-vout
    // sweep needs an accessor on `UtxoSet` that walks all live outputs
    // for a given txid; see follow-up.
    let mut has_duplicate = false;
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        let outpoint = bitcoin_rs_primitives::OutPoint::new(
            bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array()),
            0,
        );
        if handles.utxo.get(&outpoint).is_some() {
            has_duplicate = true;
            break;
        }
    }
    bitcoin_rs_consensus::bip30::check_bip30(height, has_duplicate)?;

    // BIP34: when active for this network at `height`, the coinbase
    // scriptSig must start with the minimally-encoded height.
    if handles.network.is_bip34_active(height) {
        let coinbase = block
            .txdata
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::EmptyBlock)?;
        // `verify_block_rules_borrowed` already pinned the first tx to
        // be the coinbase; relying on that here. `coinbase.input[0]`
        // is the synthetic prevout pointing at the impossible
        // outpoint; its `script_sig` carries the BIP34 height encoding.
        let coinbase_input = coinbase
            .input
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)?;
        bitcoin_rs_consensus::bip34::check_bip34(height, coinbase_input.script_sig.as_script())?;
    }

    Ok(())
}

fn check_pow_limit_and_continuity(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    // PoW limit: declared target must not exceed network max_target.
    let target_be = block.header.target().to_be_bytes();
    let declared = bitcoin_rs_chain::node::ChainWork::from_be_bytes(target_be);
    let max_target = handles.network.max_target();
    if declared > max_target {
        return Err(ApplyError::TargetAboveLimit);
    }

    // nBits continuity: at non-retarget heights, must match the parent.
    // Genesis (height 0) has no parent; skip.
    if height == 0 {
        return Ok(());
    }
    let retarget_interval = handles.network.retarget_interval();
    let is_retarget = retarget_interval != 0 && height.is_multiple_of(retarget_interval);
    if is_retarget {
        return check_daa_retarget(handles, block, height, retarget_interval);
    }

    // Non-retarget: look up the parent header via the BlockTree.
    // The parent is the current chain_tip (which apply_block has already
    // verified equals block.header.prev_blockhash via the prev-hash check
    // upstream).
    let tree = handles.block_tree.read();
    let Some(parent_id) = handles.chain_tip.load_full().map(|tip| tip.tip_id) else {
        // No tip published yet — should not happen at height > 0 since
        // apply_block's prev-hash check would have rejected. Defensive.
        return Ok(());
    };
    let parent = tree.node(parent_id).map_err(ApplyError::Chain)?;
    if block.header.bits != parent.header.bits {
        return Err(ApplyError::NbitsNonRetargetMismatch {
            actual: block.header.bits.to_consensus(),
            expected: parent.header.bits.to_consensus(),
            height,
        });
    }
    Ok(())
}

fn check_daa_retarget(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    retarget_interval: u32,
) -> core::result::Result<(), ApplyError> {
    let prior_tip = handles.chain_tip.load_full();
    let Some(prior_tip) = prior_tip else {
        return Ok(());
    };

    let tree = handles.block_tree.read();
    let Some(anchor_height) = height.checked_sub(retarget_interval) else {
        return Ok(());
    };
    let Some(anchor_id) = tree.node_at_height_from(prior_tip.tip_id, anchor_height) else {
        return Ok(());
    };
    let Ok(anchor_node) = tree.node(anchor_id) else {
        return Ok(());
    };
    let Ok(prev_node) = tree.node(prior_tip.tip_id) else {
        return Ok(());
    };

    let actual_timespan = prev_node
        .header
        .time
        .saturating_sub(anchor_node.header.time);
    let expected_timespan = retarget_interval.saturating_mul(600);
    if expected_timespan == 0 {
        return Ok(());
    }

    let min_timespan = expected_timespan / 4;
    let max_timespan = expected_timespan.saturating_mul(4);
    let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);

    let prev_target_be = prev_node.header.target().to_be_bytes();
    let prev_target = bitcoin_rs_chain::node::ChainWork::from_be_bytes(prev_target_be);
    let actual_u256 = bitcoin_rs_chain::node::ChainWork::from(actual_clamped);
    let expected_u256 = bitcoin_rs_chain::node::ChainWork::from(expected_timespan);
    let max_target = handles.network.max_target();
    let quotient = prev_target / expected_u256;
    let remainder = prev_target % expected_u256;
    let Some(scaled_quotient) = quotient.checked_mul(actual_u256) else {
        return compare_retarget_bits(block, height, max_target);
    };
    let scaled_remainder = remainder.saturating_mul(actual_u256) / expected_u256;
    let new_target_raw = scaled_quotient.saturating_add(scaled_remainder);
    let new_target = new_target_raw.min(max_target);
    compare_retarget_bits(block, height, new_target)
}

fn compare_retarget_bits(
    block: &bitcoin::Block,
    height: u32,
    expected_target: bitcoin_rs_chain::node::ChainWork,
) -> core::result::Result<(), ApplyError> {
    let expected = bitcoin::Target::from_be_bytes(expected_target.to_be_bytes::<32>())
        .to_compact_lossy()
        .to_consensus();
    let actual = block.header.bits.to_consensus();

    if actual != expected {
        return Err(ApplyError::NbitsNonRetargetMismatch {
            actual,
            expected,
            height,
        });
    }

    Ok(())
}

fn build_utxo_changes(
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<BlockChanges, ApplyError> {
    use bitcoin::hashes::Hash as _;

    let mut changes = BlockChanges::default();
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        for (vout_idx, txout) in tx.output.iter().enumerate() {
            let outpoint = OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array()),
                u32::try_from(vout_idx).map_err(|_| ApplyError::HeightOverflow(height))?,
            );
            changes.add(UtxoAdd::new(
                outpoint,
                txout.clone(),
                tx.is_coinbase(),
                height,
            ));
        }

        if !tx.is_coinbase() {
            for tx_input in &tx.input {
                let previous_output = tx_input.previous_output;
                changes.remove(OutPoint::new(
                    bitcoin_rs_primitives::Hash256::from_le_bytes(
                        previous_output.txid.as_byte_array(),
                    ),
                    previous_output.vout,
                ));
            }
        }
    }
    Ok(changes)
}

#[must_use]
const fn compute_verify_flags(network: Network, height: u32) -> bitcoin_rs_script::VerifyFlags {
    use bitcoin_rs_script::VerifyFlags;

    // P2SH (BIP16) is effectively always-on for supported validation paths.
    let mut flags = VerifyFlags::P2SH;
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if network.is_csv_active(height) {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if network.is_segwit_active(height) {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}
