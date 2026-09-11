use super::*;

#[test]
fn permanent_connect_failure_through_switch_to_branch_invalidates_subtree()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    // Build a competing fork rooted at block 50. The first fork block has a
    // corrupted body (coinbase value changed → txid changed → merkle root
    // mismatch), so the connect dies permanently on the very first block.
    // A descendant header extends the invalid subtree so the test proves
    // the whole subtree is invalidated, not just the failed block.
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
    let invalid_id = tree
        .lookup(Hash256::from_le_bytes(
            fork_blocks[0].block_hash().as_bytes(),
        ))
        .ok_or_else(|| std::io::Error::other("missing invalid fork node"))?;
    let descendant_id = tree
        .lookup(Hash256::from_le_bytes(
            fork_blocks[1].block_hash().as_bytes(),
        ))
        .ok_or_else(|| std::io::Error::other("missing descendant fork node"))?;
    drop(tree);

    // Corrupt the first fork block's body: change the coinbase value so
    // the txid no longer matches the header's merkle root. This is a
    // permanent consensus failure (MerkleRoot), which the classifier
    // marks as permanent and invalidates the subtree.
    let mut corrupt = fork_blocks[0].clone();
    corrupt.txs[0].outputs[0].value = Amount::from_sat(2);
    fork_blocks[0] = corrupt;
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

    let Err(crate::reorg::ReorgError::ConnectFailed {
        disconnected,
        connected,
        invalidated,
        ..
    }) = outcome
    else {
        panic!("permanent connect failure must return ConnectFailed");
    };
    assert_eq!(
        disconnected, 51,
        "the full disconnect prefix must be reported"
    );
    assert_eq!(
        connected, 0,
        "nothing connected before the permanent failure"
    );
    // The invalidated subtree must contain both the failed block and its
    // descendant, so the caller can purge every bounded carrier.
    let invalid_hash = Hash256::from_le_bytes(fork_blocks[0].block_hash().as_bytes());
    let descendant_hash = Hash256::from_le_bytes(fork_blocks[1].block_hash().as_bytes());
    assert!(
        invalidated.contains(&invalid_hash),
        "the failed block must be in the invalidated set: {invalidated:?}"
    );
    assert!(
        invalidated.contains(&descendant_hash),
        "the descendant must be in the invalidated set: {invalidated:?}"
    );
    // The block tree must mark the entire subtree Invalid.
    {
        let tree = handles.block_tree.read();
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
    }
    // The applied tip must be back at the fork root (block 50), the
    // successful disconnect prefix.
    let fork_root_id_hash = Hash256::from_le_bytes(fork_root_hash.as_bytes());
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(fork_root_id_hash),
        "the applied tip must be the fork root after disconnecting back to it"
    );
    Ok(())
}
