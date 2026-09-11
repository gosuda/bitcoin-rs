use super::*;

#[test]
fn branch_switch_retires_only_the_connected_prefix_after_connect_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, Script};
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
    stage_body(&sync, &main[0]);

    let genesis = Network::Regtest.genesis_block();
    let genesis_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
    let mut fork_parent = genesis_id;
    let mut fork_prev = genesis.block_hash();
    let mut fork = Vec::new();
    for height in 1..=2_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let mut block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = sync.handles.block_tree.write().insert_node(
            Some(fork_parent),
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        if height == 2 {
            block.txs[0].outputs[0].value = Amount::from_sat(2);
        }
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let bytes = consensus_bytes(&block).len();
        stage_body(&sync, &block);
        sync.download_window
            .lock()
            .mark_received(hash, bytes, Instant::now());
        fork.push(block);
    }
    let outcome = crate::reorg::switch_to_branch(
        &sync.handles,
        &sync.followers,
        fork_parent,
        |hash| sync.block_stager.lock().staged_body(hash),
        |hash| sync.retire_applied_reorg_body(hash),
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::ConnectFailed { stopped_at: 1, .. })
        ),
        "the mutated second body must fail after one committed connect, got {outcome:?}"
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
    assert!(!sync.block_stager.lock().contains(&first));
    assert!(sync.block_stager.lock().contains(&failed));
    assert_eq!(
        sync.download_window.lock().received_len(),
        1,
        "only the failed block may retain download accounting"
    );
    Ok(())
}

#[test]
fn permanent_reorg_failure_invalidates_descendants_and_purges_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
    stage_body(&sync, &main[0]);

    let main_hash = Hash256::from_le_bytes(main[0].block_hash().as_bytes());
    let genesis = Network::Regtest.genesis_block();
    let genesis_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
    let invalid = mined_block_with_prev_hash(genesis.block_hash(), 1, Vec::new());
    let invalid_id = sync.handles.block_tree.write().insert_node(
        Some(genesis_id),
        invalid.header,
        NodeStatus::HeaderValid,
    )?;
    let descendant =
        mined_block_with_prev_hash(invalid.block_hash(), 2, vec![coinbase_transaction(2)]);
    let descendant_id = sync.handles.block_tree.write().insert_node(
        Some(invalid_id),
        descendant.header,
        NodeStatus::HeaderValid,
    )?;
    let invalid_hash = Hash256::from_le_bytes(invalid.block_hash().as_bytes());
    let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
    for block in [&invalid, &descendant] {
        stage_body(&sync, block);
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let bytes = consensus_bytes(block).len();
        sync.download_window
            .lock()
            .mark_received(hash, bytes, Instant::now());
    }

    sync.switch_branch_if_outweighed();

    {
        let tree = sync.handles.block_tree.read();
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
        assert_eq!(
            tree.tip().map(|tip| tip.hash),
            Some(main_hash),
            "the valid main branch must win after subtree invalidation"
        );
    }
    let stager = sync.block_stager.lock();
    assert!(stager.contains(&main_hash));
    assert!(!stager.contains(&invalid_hash));
    assert!(!stager.contains(&descendant_hash));
    drop(stager);
    assert_eq!(sync.download_window.lock().received_len(), 0);
    // MPL-04: rejecting the invalid branch must still allow the selected
    // valid main branch to reconnect through ordinary forward apply.
    assert!(sync.handles.mempool_gateway.stable_generation().is_some());
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
    assert_eq!(
        sync.handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(main_hash)
    );
    assert!(sync.handles.mempool_gateway.stable_generation().is_some());
    Ok(())
}

/// Generation settlement: MPL-04 in docs/contracts/mempool-mutations.md.
/// Prefix and body ownership: docs/solutions/architecture-patterns/node-reorg-execution-design.md.
#[test]
fn operational_reorg_failure_preserves_branch_and_retries_without_restart()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (mut sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));
    stage_body(&sync, &main[0]);
    let fail_once_store = Arc::new(FailOnceBodyStore::new(1));
    sync.handles.block_body_store = Some(fail_once_store);

    let genesis = Network::Regtest.genesis_block();
    let genesis_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing genesis node"))?;
    let mut fork_coinbase = coinbase_transaction(1);
    fork_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
    let fork = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![fork_coinbase]);
    let fork_id = sync.handles.block_tree.write().insert_node(
        Some(genesis_id),
        fork.header,
        NodeStatus::HeaderValid,
    )?;
    let descendant =
        mined_block_with_prev_hash(fork.block_hash(), 2, vec![coinbase_transaction(2)]);
    let descendant_id = sync.handles.block_tree.write().insert_node(
        Some(fork_id),
        descendant.header,
        NodeStatus::HeaderValid,
    )?;
    let fork_hash = Hash256::from_le_bytes(fork.block_hash().as_bytes());
    let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
    for block in [&fork, &descendant] {
        stage_body(&sync, block);
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let bytes = consensus_bytes(block).len();
        sync.download_window
            .lock()
            .mark_received(hash, bytes, Instant::now());
    }

    let outcome = crate::reorg::switch_to_branch(
        &sync.handles,
        &sync.followers,
        descendant_id,
        |hash| sync.block_stager.lock().staged_body(hash),
        |hash| sync.retire_applied_reorg_body(hash),
    );
    assert!(
        matches!(
            &outcome,
            Err(crate::reorg::ReorgError::ConnectFailed {
                disconnected: 1,
                connected: 0,
                source,
                ..
            }) if matches!(source.as_ref(), crate::ApplyError::BlockBodyPersistence(_))
        ),
        "the body-store refusal must follow a committed disconnect, got {outcome:?}"
    );
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(Hash256::from_le_bytes(genesis.block_hash().as_bytes())),
        "a refused pre-UTXO connect leaves the fork point as the committed tip"
    );

    {
        let tree = sync.handles.block_tree.read();
        assert_ne!(tree.node(fork_id)?.status, NodeStatus::Invalid);
        assert_ne!(tree.node(descendant_id)?.status, NodeStatus::Invalid);
        assert_eq!(tree.tip().map(|tip| tip.tip_id), Some(descendant_id));
    }
    let stager = sync.block_stager.lock();
    assert!(stager.contains(&fork_hash));
    assert!(stager.contains(&descendant_hash));
    drop(stager);
    assert_eq!(sync.download_window.lock().received_len(), 2);
    // MPL-04: a known committed prefix must finish its generation, so a
    // transient pre-UTXO refusal cannot wedge admission and later applies.
    assert!(
        sync.handles.mempool_gateway.stable_generation().is_some(),
        "admission must reopen after the clean connect refusal"
    );

    crate::reorg::switch_to_branch(
        &sync.handles,
        &sync.followers,
        descendant_id,
        |hash| sync.block_stager.lock().staged_body(hash),
        |hash| sync.retire_applied_reorg_body(hash),
    )?;
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.hash),
        Some(descendant_hash),
        "retrying the same reorg must reach the target without restarting"
    );
    assert!(sync.handles.mempool_gateway.stable_generation().is_some());
    assert!(!sync.block_stager.lock().contains(&fork_hash));
    assert!(!sync.block_stager.lock().contains(&descendant_hash));
    assert_eq!(sync.download_window.lock().received_len(), 0);
    Ok(())
}

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
fn tick_skips_getheaders_when_header_tip_matches_peer_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let applied_snapshot = {
        let tree = block_tree.read();
        let chain_tip = sync
            .handles
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
        let node_id = tree
            .node_at_height_from(chain_tip.tip_id, 1)
            .ok_or_else(|| std::io::Error::other("missing height one node"))?;
        let node = tree.node(node_id)?;
        TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    applied_tip.store(Some(Arc::new(applied_snapshot)));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 3));

    sync.tick();

    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[1..]);
    assert!(rx.try_recv().is_err());
    Ok(())
}
