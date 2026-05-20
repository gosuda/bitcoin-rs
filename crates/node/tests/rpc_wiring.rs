//! Integration test: `NodeState`'s source-of-truth handles share pointer
//! identity with the `rpc::Context` constructed from them.
//!
//! The pointer-identity invariant is the contract that future
//! validation-pipeline commits rely on — when the import pipeline
//! writes to `NodeState`'s `chain_tip`, RPC handlers must observe the
//! update without any additional plumbing.

use std::sync::Arc;

use anyhow::Result;
use bitcoin_rs_node::{Config, state::NodeState};
use bitcoin_rs_rpc::Context;
use bitcoin_rs_utxo::UtxoSet;
use tempfile::tempdir;

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn rpc_context_shares_arc_identity_with_node_state() -> Result<()> {
    let dir = tempdir()?;
    let mut config = Config::default();
    config.data_dir = dir.path().join("node");
    let state = NodeState::open(config)?;

    let chain_tip = state.chain_tip();
    let applied_tip = state.applied_tip();
    let mempool = state.mempool();
    let blocks = state.blocks();
    let transactions = state.transactions();
    let utxo = Arc::new(UtxoSet::new());
    let coin_stats = state.coin_stats();
    let filter_index = state.filter_index();
    let network = state.network();
    let chain_network = state.config().network;
    let mining_template_id = state.mining_template_id();
    let peers = state.peers();
    let block_tree = state.block_tree();
    let inbound_blocks_sender = state.inbound_blocks_sender();
    let p2p_outbound = Some(state.p2p_outbound_sender());
    let banned = Arc::new(parking_lot::RwLock::new(hashbrown::HashSet::new()));
    let added_nodes = Arc::new(parking_lot::RwLock::new(Vec::new()));
    let tx_index = state.tx_index();
    let ctx = Context::from_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&mempool),
        Arc::clone(&blocks),
        Arc::clone(&transactions),
        Arc::clone(&utxo),
        Arc::clone(&coin_stats),
        Arc::clone(&filter_index),
        Arc::clone(&network),
        Arc::clone(&mining_template_id),
        Arc::clone(&peers),
        Arc::clone(&block_tree),
        chain_network,
        Some(inbound_blocks_sender),
        p2p_outbound,
        Arc::clone(&banned),
        Arc::clone(&added_nodes),
        Some(Arc::clone(&tx_index)),
    );

    assert!(
        Arc::ptr_eq(&ctx.chain_tip, &chain_tip),
        "chain_tip must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.applied_tip, &applied_tip),
        "applied_tip must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.mempool, &mempool),
        "mempool must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.blocks, &blocks),
        "blocks must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.transactions, &transactions),
        "transactions must share identity"
    );
    assert!(Arc::ptr_eq(&ctx.utxo, &utxo), "utxo must share identity");
    assert!(
        Arc::ptr_eq(&ctx.coin_stats, &coin_stats),
        "coin_stats must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.filter_index, &filter_index),
        "filter_index must share identity"
    );
    assert!(ctx.indexer.is_some(), "indexer handle must be wired");
    assert!(
        Arc::ptr_eq(&ctx.network, &network),
        "network must share identity"
    );
    assert_eq!(
        ctx.chain_network,
        state.config().network,
        "chain_network must match"
    );
    assert!(
        Arc::ptr_eq(&ctx.mining_template_id, &mining_template_id),
        "mining_template_id must share identity"
    );
    assert!(Arc::ptr_eq(&ctx.peers, &peers), "peers must share identity");
    assert!(
        Arc::ptr_eq(&ctx.block_tree, &block_tree),
        "block_tree must share identity"
    );
    assert!(
        ctx.inbound_blocks_sender.is_some(),
        "inbound_blocks_sender must be Some"
    );
    assert!(
        ctx.p2p_outbound_sender.is_some(),
        "p2p_outbound_sender must be Some"
    );

    Ok(())
}
