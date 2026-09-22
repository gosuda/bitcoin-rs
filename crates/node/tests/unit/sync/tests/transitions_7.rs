use super::*;

#[test]
fn mutated_connect_body_through_switch_to_branch_preserves_subtree()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    // Build a competing fork rooted at block 50. The first fork block has a
    // corrupted body (coinbase value changed → txid changed → merkle root
    // mismatch), so the connect stops on the first body. The descendant
    // header must remain eligible for a later delivery of the correct body.
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree().write();
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
    // body mutation (MerkleRoot), which must not invalidate the subtree.
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
        disposition,
        invalidated,
        ..
    }) = outcome
    else {
        panic!("mutated connect body must return ConnectFailed");
    };
    assert_eq!(
        disconnected, 51,
        "the full disconnect prefix must be reported"
    );
    assert_eq!(connected, 0, "nothing connected before the body mutation");
    assert_eq!(
        disposition,
        bitcoin_rs_chainstate::WindowApplyDisposition::BodyMutated
    );
    assert!(
        invalidated.is_empty(),
        "body mutation cannot poison headers"
    );
    // Both headers remain valid and may be retried with another body.
    {
        let tree = handles.block_tree().read();
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::HeaderValid);
        assert_eq!(tree.node(descendant_id)?.status, NodeStatus::HeaderValid);
    }
    // The applied tip must be back at the fork root (block 50), the
    // successful disconnect prefix.
    let fork_root_id_hash = Hash256::from_le_bytes(fork_root_hash.as_bytes());
    assert_eq!(
        handles.applied_tip().load_full().map(|tip| tip.hash),
        Some(fork_root_id_hash),
        "the applied tip must be the fork root after disconnecting back to it"
    );
    Ok(())
}
