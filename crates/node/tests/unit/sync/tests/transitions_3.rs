use super::*;

#[test]
fn branch_switch_retires_only_the_connected_prefix_after_connect_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (handles, main, mut bodies) = matured_chain(101)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();
    let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());

    let fork_root_hash = main[99].block_hash();
    let mut fork_parent = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork = Vec::new();
    for height in 101..=102_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let mut block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = crate::sync::fixture_insert_header_node(
            &handles,
            fork_parent,
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        if height == 102 {
            block.txs[0].outputs[0].value = Amount::from_sat(2);
        }
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        fork.push(block);
    }

    let mut retired = Vec::new();
    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &followers,
        fork_parent,
        |hash| bodies.get(&hash).cloned(),
        |hash| retired.push(hash),
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                stopped_at: 101,
                connected: 1,
                ref disposition,
                ref invalidated,
                ..
            }) if *disposition == bitcoin_rs_chainstate::WindowApplyDisposition::BodyMutated
                && invalidated.is_empty()
        ),
        "the mutated second body must fail as BodyMutated after one committed connect, \
         got {outcome:?}"
    );

    let tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("partial switch did not publish a tip"))?;
    assert_eq!(
        tip.hash,
        Hash256::from_le_bytes(fork[0].block_hash().as_bytes()),
        "the valid prefix must remain committed"
    );
    let first = Hash256::from_le_bytes(fork[0].block_hash().as_bytes());
    let failed = Hash256::from_le_bytes(fork[1].block_hash().as_bytes());
    assert_eq!(
        retired,
        vec![first],
        "only the connected prefix body retires"
    );
    assert!(
        bodies.contains_key(&failed) && bodies.contains_key(&main_tip_hash),
        "the failed and disconnected bodies stay staged for a later switch"
    );
    assert_ne!(
        handles
            .block_tree()
            .read()
            .node_by_hash(failed)
            .map(|node| node.status),
        Some(NodeStatus::Invalid),
        "a mutated body must not invalidate the header subtree"
    );
    Ok(())
}

#[test]
fn permanent_reorg_failure_invalidates_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let (handles, main, mut bodies) = matured_chain(101)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();

    let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());
    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let invalid = mined_block_with_prev_hash(fork_root_hash, 101, Vec::new());
    let invalid_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        invalid.header,
        NodeStatus::HeaderValid,
    )?;
    let descendant =
        mined_block_with_prev_hash(invalid.block_hash(), 102, vec![coinbase_transaction(102)]);
    let descendant_id = crate::sync::fixture_insert_header_node(
        &handles,
        invalid_id,
        descendant.header,
        NodeStatus::HeaderValid,
    )?;
    for block in [&invalid, &descendant] {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            ((*block).clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &followers,
        descendant_id,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );
    assert!(
        matches!(
            &outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                disposition: bitcoin_rs_chainstate::WindowApplyDisposition::Permanent,
                invalidated,
                ..
            }) if invalidated.len() == 2
        ),
        "an empty-block connect must fail Permanent and report the invalidated subtree, \
         got {outcome:?}"
    );

    {
        let tree = handles.block_tree().read();
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
        assert_eq!(
            tree.tip().map(|tip| tip.hash),
            Some(main_tip_hash),
            "the valid main branch must win after subtree invalidation"
        );
    }
    // Rejecting the invalid branch must still allow the selected valid main
    // branch to reconnect through ordinary forward apply.
    handles.apply_block(&main[100], None)?;
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(main_tip_hash)
    );
    Ok(())
}

#[test]
fn branch_switch_rejects_a_body_for_another_header_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (handles, main, mut bodies) = matured_chain(101)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();
    let applied_before = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let utxo_len_before = handles.utxo().len();

    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut target_coinbase = coinbase_transaction(101);
    target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let target = mined_block_with_prev_hash(fork_root_hash, 101, vec![target_coinbase]);
    let target_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        target.header,
        NodeStatus::HeaderValid,
    )?;
    let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
    let mut wrong_coinbase = coinbase_transaction(101);
    wrong_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let wrong = mined_block_with_prev_hash(fork_root_hash, 101, vec![wrong_coinbase]);
    let wrong_bytes = bytes::Bytes::from(consensus_bytes(&wrong));
    // The staged body names another header's hash: the plan must refuse
    // before touching chainstate.
    bodies.insert(target_hash, (wrong, wrong_bytes));

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &followers,
        target_id,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyHashMismatch { height: 101, .. })
        ),
        "a body keyed for another header must refuse before mutation, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_before.hash),
        "a pre-mutation refusal must leave the applied tip untouched"
    );
    assert_eq!(
        handles.utxo().len(),
        utxo_len_before,
        "a pre-mutation refusal must leave the UTXO set untouched"
    );
    Ok(())
}

#[test]
fn branch_switch_rejects_mismatched_preserved_bytes_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (handles, main, mut bodies) = matured_chain(101)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();
    let applied_before = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let utxo_len_before = handles.utxo().len();

    let fork_root_hash = main[99].block_hash();
    let fork_root_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut target_coinbase = coinbase_transaction(101);
    target_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let target = mined_block_with_prev_hash(fork_root_hash, 101, vec![target_coinbase]);
    let target_id = crate::sync::fixture_insert_header_node(
        &handles,
        fork_root_id,
        target.header,
        NodeStatus::HeaderValid,
    )?;
    let target_hash = Hash256::from_le_bytes(target.block_hash().as_bytes());
    let mut wrong_coinbase = coinbase_transaction(101);
    wrong_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let wrong = mined_block_with_prev_hash(fork_root_hash, 101, vec![wrong_coinbase]);
    // The staged block names the planned hash but its preserved bytes
    // serialize a different block — the reorg plan must refuse before
    // touching chainstate.
    let wrong_bytes = bytes::Bytes::from(consensus_bytes(&wrong));
    bodies.insert(target_hash, (target, wrong_bytes));

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &followers,
        target_id,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyBytesMismatch { height: 101, .. })
        ),
        "mismatched preserved bytes must refuse before mutation, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_before.hash),
        "a pre-mutation refusal must leave the applied tip untouched"
    );
    assert_eq!(
        handles.utxo().len(),
        utxo_len_before,
        "a pre-mutation refusal must leave the UTXO set untouched"
    );
    Ok(())
}
