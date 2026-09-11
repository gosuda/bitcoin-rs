use super::*;

#[test]
fn branch_switch_rejects_a_body_for_another_header_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
    let applied_before = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let utxo_len_before = sync.handles.utxo.len();

    let genesis = Network::Regtest.genesis_block();
    let genesis_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
    let mut target_coinbase = coinbase_transaction(1);
    target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let target = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![target_coinbase]);
    let target_id = sync.handles.block_tree.write().insert_node(
        Some(genesis_id),
        target.header,
        NodeStatus::HeaderValid,
    )?;
    let mut wrong_coinbase = coinbase_transaction(1);
    wrong_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let wrong = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![wrong_coinbase]);
    let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
    let wrong_hash = Hash256::from_le_bytes(wrong.block_hash().as_bytes());
    assert_ne!(target_hash, wrong_hash);
    let connected = std::cell::Cell::new(false);

    let outcome = crate::reorg::switch_to_branch(
        &sync.handles,
        &sync.followers,
        target_id,
        |hash| {
            let block = if hash == target_hash {
                wrong.clone()
            } else {
                main[0].clone()
            };
            let serialized = bytes::Bytes::from(consensus_bytes(&block));
            Some((block, serialized))
        },
        |_| connected.set(true),
    );

    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyHashMismatch {
                expected,
                actual,
                height: 1,
            }) if expected == target_hash && actual == wrong_hash
        ),
        "the wrong sibling body must retain its typed mismatch, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().as_deref(),
        Some(applied_before.as_ref())
    );
    assert_eq!(sync.handles.utxo.len(), utxo_len_before);
    assert!(!connected.get());
    Ok(())
}

#[test]
fn branch_switch_rejects_mismatched_preserved_bytes_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
    let applied_before = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let utxo_len_before = sync.handles.utxo.len();

    let genesis = Network::Regtest.genesis_block();
    let genesis_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
    let mut target_coinbase = coinbase_transaction(1);
    target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let target = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![target_coinbase]);
    let target_id = sync.handles.block_tree.write().insert_node(
        Some(genesis_id),
        target.header,
        NodeStatus::HeaderValid,
    )?;
    let mut wrong_coinbase = coinbase_transaction(1);
    wrong_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let wrong = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![wrong_coinbase]);
    let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
    let wrong_bytes = bytes::Bytes::from(consensus_bytes(&wrong));
    let connected = std::cell::Cell::new(false);

    let outcome = crate::reorg::switch_to_branch(
        &sync.handles,
        &sync.followers,
        target_id,
        |hash| {
            if hash == target_hash {
                return Some((target.clone(), wrong_bytes.clone()));
            }
            let block = main[0].clone();
            let serialized = bytes::Bytes::from(consensus_bytes(&block));
            Some((block, serialized))
        },
        |_| connected.set(true),
    );

    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyBytesMismatch { hash, height: 1 })
                if hash == target_hash
        ),
        "mismatched preserved bytes must retain their typed error, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().as_deref(),
        Some(applied_before.as_ref())
    );
    assert_eq!(sync.handles.utxo.len(), utxo_len_before);
    assert!(!connected.get());
    Ok(())
}

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
