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
use tempfile::tempdir;

#[test]
fn rpc_context_shares_arc_identity_with_node_state() -> Result<()> {
    let dir = tempdir()?;
    let mut config = Config::default();
    config.data_dir = dir.path().join("node");
    let state = NodeState::open(config)?;

    let chain_tip = state.chain_tip();
    let mempool = state.mempool();
    let blocks = state.blocks();
    let transactions = state.transactions();
    let network = state.network();
    let mining_template_id = state.mining_template_id();

    let ctx = Context::from_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&mempool),
        Arc::clone(&blocks),
        Arc::clone(&transactions),
        Arc::clone(&network),
        Arc::clone(&mining_template_id),
    );

    assert!(
        Arc::ptr_eq(&ctx.chain_tip, &chain_tip),
        "chain_tip must share identity"
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
    assert!(
        Arc::ptr_eq(&ctx.network, &network),
        "network must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.mining_template_id, &mining_template_id),
        "mining_template_id must share identity"
    );

    Ok(())
}
