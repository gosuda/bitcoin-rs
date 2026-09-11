//! Shared contract-test fixture construction.

use super::super::*;
use super::BIP68_TEST_PREVOUT_HEIGHT;
use super::BIP68_TEST_PREVOUT_MTP;
use super::fixtures_behavior::apply_height_one_block;
use super::fixtures_behavior::block_with_transaction;
use super::fixtures_behavior::block_with_transactions;
use super::fixtures_behavior::fixture_txid;
use super::fixtures_behavior::interpolated_time;
use super::fixtures_behavior::target_to_compact_lossy;
use super::fixtures_behavior::tx_plan;
use super::fixtures_behavior::utxo_with_output;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::node::ChainWork;
use bitcoin_rs_chain::node::NodeStatus;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::TxIn;
use bitcoin_rs_script::script::push_data;
use bitcoin_rs_script::script::push_int;
use bitcoin_rs_utxo::BlockChanges;
use bitcoin_rs_utxo::UtxoAdd;
use bitcoin_rs_utxo::UtxoSet;
use std::sync::Arc;

/// Applies a height-1 regtest block whose only transaction is a coinbase
/// claiming `coinbase_value`.
#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn apply_coinbase_only_block(coinbase_value: u64) -> Result<TipSnapshot, ApplyError> {
    apply_height_one_block(vec![], coinbase_value)
}

pub(super) fn coinbase_transaction_with_height(height: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(push_int(i64::from(height))),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

pub(super) fn block_with_pow_header(
    prev_blockhash: BlockHash,
    bits: u32,
    time: u32,
    nonce: u32,
) -> Block {
    Block {
        header: pow_header(prev_blockhash, bits, time, nonce),
        txs: Vec::new(),
    }
}

pub(super) fn pow_header(prev_blockhash: BlockHash, bits: u32, time: u32, nonce: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(bits),
        nonce,
    }
}

pub(super) fn seed_pow_chain(
    handles: &Chainstate,
    bits: u32,
    anchor_time: u32,
    tip_time: u32,
    tip_height: u32,
) -> Result<BlockHash, Box<dyn std::error::Error>> {
    let headers: Vec<_> = (0..=tip_height)
        .map(|height| {
            (
                bits,
                interpolated_time(anchor_time, tip_time, height, tip_height),
            )
        })
        .collect();
    seed_pow_chain_with_headers(handles, &headers)
}

pub(super) fn seed_pow_period_with_tip_bits(
    handles: &Chainstate,
    period_bits: u32,
    tip_bits: u32,
    anchor_time: u32,
    tip_time: u32,
    tip_height: u32,
) -> Result<BlockHash, Box<dyn std::error::Error>> {
    let headers: Vec<_> = (0..=tip_height)
        .map(|height| {
            let bits = if height == tip_height {
                tip_bits
            } else {
                period_bits
            };
            (
                bits,
                interpolated_time(anchor_time, tip_time, height, tip_height),
            )
        })
        .collect();
    seed_pow_chain_with_headers(handles, &headers)
}

pub(super) fn seed_pow_chain_with_headers(
    handles: &Chainstate,
    headers: &[(u32, u32)],
) -> Result<BlockHash, Box<dyn std::error::Error>> {
    let mut tree = handles.block_tree.write();
    let mut parent = None;
    let mut prev_hash = BlockHash::default();
    for (height, &(bits, time)) in headers.iter().enumerate() {
        let height = u32::try_from(height)?;
        let header = pow_header(prev_hash, bits, time, height);
        prev_hash = header.compute_hash();
        parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
    }
    handles.chain_tip.store(tree.tip());
    Ok(prev_hash)
}

pub(super) fn seed_known_bip34_activation_chain(
    handles: &Chainstate,
    network: Network,
) -> Result<NodeId, Box<dyn std::error::Error>> {
    let activation_height = network.bip34_activation_height();
    let expected_hash = network
        .bip34_activation_hash()
        .ok_or_else(|| std::io::Error::other("network has no fixed BIP34 activation hash"))?;
    let mut tree = handles.block_tree.write();
    let mut parent = None;
    let mut prev_hash = BlockHash::default();
    let mut activation_id = None;
    for height in 0..=activation_height.saturating_add(1) {
        let header = pow_header(prev_hash, 0x207f_ffff, height, height);
        let node_id = tree.insert_node(parent, header, NodeStatus::Active)?;
        if height == activation_height {
            activation_id = Some(node_id);
        }
        parent = Some(node_id);
        prev_hash = BlockHash::from(tree.node(node_id)?.hash);
    }
    let activation_id =
        activation_id.ok_or_else(|| std::io::Error::other("missing activation node"))?;
    tree.node_mut(activation_id)?.hash = expected_hash;
    handles.chain_tip.store(tree.tip());
    parent.ok_or_else(|| std::io::Error::other("missing previous tip").into())
}

/// `OP_RETURN <data>` output script.
pub(super) fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut script = vec![0x6a_u8];
    script.extend_from_slice(&push_data(data));
    script
}

/// Merkle root over the block's txids: pairwise double-SHA256 over the
/// little-endian id bytes, duplicating the last leaf on odd widths.
pub(super) fn txids_merkle_root(block: &Block) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    merkle_root_bytes(&mut leaves).map(|bytes| Hash256::from_le_bytes(&bytes))
}

pub(super) fn scaled_pow_limit_bits(handles: &Chainstate, divisor: u64) -> u32 {
    target_to_compact_lossy(handles.network.max_target() / ChainWork::from(divisor))
}

pub(super) fn pow_limit_bits(handles: &Chainstate) -> u32 {
    target_to_compact_lossy(handles.network.max_target())
}

pub(super) fn spending_transaction_to_script(
    previous_output: OutPoint,
    sequence: u32,
    script_pubkey: Vec<u8>,
) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(script_pubkey),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

pub(super) fn op_true_script() -> Vec<u8> {
    vec![0x51]
}

pub(super) fn seed_block_tree_for_bip68_time(
    handles: &Chainstate,
) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
    seed_block_tree_for_bip68_time_at_height(handles, BIP68_TEST_PREVOUT_HEIGHT)
}

pub(super) fn seed_block_tree_for_bip68_time_at_height(
    handles: &Chainstate,
    tip_height: u32,
) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
    let mut tree = handles.block_tree.write();
    let mut parent = None;
    let mut tip = None;
    for height in 0..=tip_height {
        let header = Header {
            version: 1,
            prev_blockhash: parent
                .and_then(|id| tree.node(id).ok().map(|node| BlockHash::from(node.hash)))
                .unwrap_or_else(BlockHash::default),
            merkle_root: Hash256::default(),
            time: BIP68_TEST_PREVOUT_MTP,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        };
        let id = tree.insert_node(parent, header, NodeStatus::Active)?;
        parent = Some(id);
        tip = Some(id);
    }
    match tip {
        Some(tip) => Ok(tip),
        None => Err(ApplyError::HeightOverflow(0)),
    }
}

pub(super) fn assert_bip_error(error: &ApplyError, bip: &str) {
    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, .. }) if *actual == bip
    ));
}

pub(super) fn assert_bip_error_reason_contains(error: &ApplyError, bip: &str, needle: &str) {
    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, reason })
            if *actual == bip && reason.contains(needle)
    ));
}

pub(super) fn duplicate_spend_block()
-> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x64), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let first_spend = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
    let second_spend = spending_transaction_to_script(base_prevout, u32::MAX - 1, op_true_script());
    let block = block_with_transactions(vec![first_spend, second_spend]);
    let plan = tx_plan(&block);
    Ok((block, plan, utxo))
}

pub(super) fn bad_script_spend_block()
-> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x65), 0);
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        base_prevout,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x87]),
        },
        false,
        1,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

    let mut script_sig = push_int(7);
    script_sig.extend_from_slice(&push_int(8));
    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: base_prevout,
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(op_true_script()),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let block = block_with_transaction(spend);
    let plan = tx_plan(&block);
    Ok((block, plan, utxo))
}
