use super::*;

#[test]
fn partial_reorg_readmits_only_still_disconnected_transactions()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    let tip = main
        .last()
        .ok_or_else(|| std::io::Error::other("empty chain"))?;
    let spend_txid = tip.txs[1].txid();
    // A competing branch rooted at block 50 with four more blocks of
    // work: switching to it disconnects the 51-block suffix (including
    // the matured spend) while the spent coin itself stays live below
    // the fork point, and the 105th fork body contradicts its own
    // header merkle root, so the connect dies permanently mid-walk.
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree.write();
    let mut fork_parent = tree
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork_blocks = Vec::new();
    for height in 51..=105_u32 {
        let mut coinbase = coinbase_transaction(height);
        // Distinguish the branch: same-height coinbases on both chains
        // must not carry identical txids, or the fork headers collide.
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
        fork_prev = block.block_hash();
        fork_blocks.push(block);
    }
    let fork_target = fork_parent;
    drop(tree);
    let mut corrupt = fork_blocks[fork_blocks.len() - 1].clone();
    corrupt.txs[0].outputs[0].value = Amount::from_sat(2);
    let last = fork_blocks.len() - 1;
    fork_blocks[last] = corrupt;
    for block in &fork_blocks {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }
    let connected_count = std::rc::Rc::new(std::cell::Cell::new(0_usize));
    let counter = std::rc::Rc::clone(&connected_count);

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |hash| bodies.get(&hash).cloned(),
        move |_hash| counter.set(counter.get() + 1),
    );

    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                disconnected: 51,
                connected: 54,
                ..
            })
        ),
        "the walk must report its exact committed prefixes, got {outcome:?}"
    );
    assert_eq!(
        connected_count.get(),
        54,
        "only the committed connect prefix is retired to the caller"
    );
    let connected_tip = Hash256::from_le_bytes(fork_blocks[53].block_hash().as_bytes());
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(connected_tip),
        "the successful connected prefix is the final active chain"
    );
    // MPL-04: the valid connected prefix reopens only after re-admission.
    assert!(handles.mempool_gateway.stable_generation().is_some());
    let mempool = handles.mempool.read();
    assert_eq!(
        mempool.len(),
        1,
        "exactly the still-off-chain tx is readmitted"
    );
    assert!(
        mempool.contains_txid(&spend_txid),
        "the disconnected matured spend stays eligible"
    );
    assert_eq!(
        mempool.sequence_number(),
        1,
        "reconsideration runs exactly once for the partial switch"
    );
    let reconnected_txid = fork_blocks[0].txs[0].txid();
    let reconnected_in_pool = mempool.contains_txid(&reconnected_txid);
    assert!(
        !reconnected_in_pool,
        "reconnected-block transactions are confirmed, never readmitted"
    );
    Ok(())
}

#[test]
fn fatal_disconnect_readmits_nothing() -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (mut handles, main, mut bodies) = matured_chain(101)?;
    let tip = main
        .last()
        .ok_or_else(|| std::io::Error::other("empty chain"))?;
    let spend_txid = tip.txs[1].txid();
    // The in-flight marker can never be cleared, so the very first
    // disconnect dies fatal after rolling back cleanly. The wrapper keeps
    // the real records; only the disarm fails.
    let real_store = Arc::clone(&handles.undo_store);
    handles.undo_store = Arc::new(DisarmFailsUndoStore { inner: real_store });
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree.write();
    let mut fork_parent = tree
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork_blocks = Vec::new();
    for height in 51..=52_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
        fork_prev = block.block_hash();
        fork_blocks.push(block);
    }
    let fork_target = fork_parent;
    drop(tree);
    for block in &fork_blocks {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );

    assert!(
        matches!(outcome, Err(crate::reorg::ReorgError::Fatal(_))),
        "a stuck disconnect marker is fatal, got {outcome:?}"
    );
    assert!(
        handles.mempool.read().is_empty(),
        "a fatal disconnect must never reconsider disconnected transactions"
    );
    assert_eq!(handles.mempool.read().sequence_number(), 0);
    // MPL-04: a stuck marker must keep all later chain changes fenced.
    assert!(handles.mempool_gateway.stable_generation().is_none());
    assert!(handles.begin_transition().is_err());
    let spend_in_pool = handles.mempool.read().contains_txid(&spend_txid);
    assert!(
        !spend_in_pool,
        "the off-chain matured spend must not be readmitted after a fatal disconnect"
    );
    Ok(())
}
