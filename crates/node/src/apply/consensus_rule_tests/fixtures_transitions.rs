//! Shared contract-test fixture construction.

use super::super::*;
use super::MapBodyStore;
use super::ReorgBodyLoadingFixture;
use super::apply_handles_without_tx_index;
use super::coinbase_transaction;
use super::fixtures_behavior::apply_handles_for_network;
use super::mined_block_with_prev_hash_and_transactions;
use bitcoin_rs_chain::node::NodeStatus;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::UtxoSet;
use compact_str::CompactString;
use std::sync::Arc;

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn one_block_window_fixture(
    utxo: Arc<UtxoSet>,
    txdata: Vec<Tx>,
    assume_valid_height: u32,
) -> Result<(Chainstate, Block, bytes::Bytes), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut handles = apply_handles_for_network(Network::Regtest, utxo);
    handles.assume_valid_height = assume_valid_height;
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;
    let block_hash = Hash256::from(block.block_hash());
    applied_header_tip(&handles, block_hash, &block, 1)?;
    let raw = bytes::Bytes::from(consensus_bytes(&block));
    Ok((handles, block, raw))
}

pub(super) fn reorg_body_loading_fixture()
-> Result<ReorgBodyLoadingFixture, Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    let body_arc = Arc::clone(&bodies);
    let body_handle: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> = body_arc;
    handles.block_body_store = Some(body_handle);

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let losing = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let raw = bytes::Bytes::from(consensus_bytes(&losing));
    let applied = handles
        .apply_block_with_serialized(&losing, raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((applied.height, applied.hash), raw.to_vec());

    let win_one = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let win_two = mined_block_with_prev_hash_and_transactions(
        win_one.block_hash(),
        vec![coinbase_transaction(3)],
    )?;
    let target = {
        let mut tree = handles.block_tree.write();
        let mut last = None;
        for (height, block) in [(1_u32, &win_one), (2_u32, &win_two)] {
            let hash = Hash256::from(block.block_hash());
            last = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
            bodies
                .bodies
                .write()
                .insert((height, hash), consensus_bytes(block));
        }
        last.ok_or_else(|| anyhow::anyhow!("no winning branch built"))?
    };

    Ok(ReorgBodyLoadingFixture {
        handles,
        utxo,
        bodies,
        target,
        losing,
        applied,
    })
}

pub(super) fn assert_reorg_load_failure_preserved_state(
    handles: &Chainstate,
    utxo: &UtxoSet,
    losing: &Block,
    applied: &TipSnapshot,
    tree_tip_before: Option<(bitcoin_rs_chain::NodeId, u32, Hash256)>,
    utxo_len_before: usize,
) {
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        Some((applied.tip_id, applied.height, applied.hash)),
        "body loading failure must not move the applied tip"
    );
    assert_eq!(
        handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        tree_tip_before,
        "body loading failure must not change the active header index"
    );
    assert_eq!(
        utxo.len(),
        utxo_len_before,
        "body loading failure must not change UTXO cardinality"
    );
    assert!(
        utxo.has_live_outputs_for_txid(&Hash256::from(losing.txs[0].txid())),
        "body loading failure must leave the applied branch coin live"
    );
}

pub(super) fn disconnect_followed(
    handles: &Chainstate,
    followers: &crate::chain_effects::ChainFollowers,
    block: &Block,
) -> core::result::Result<TipSnapshot, crate::DisconnectError> {
    Ok(followers.apply_disconnect(handles, block)?.parent_tip)
}

pub(super) fn generation_unavailable() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from("not wired in this test"))
}
