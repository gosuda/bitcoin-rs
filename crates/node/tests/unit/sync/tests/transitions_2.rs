use super::*;

/// A branch switch must resolve every disconnect and connect body from the
/// staged-body callback alone when no durable block-body store is installed.
#[test]
fn branch_switch_uses_staged_bodies_without_durable_store() -> Result<(), Box<dyn std::error::Error>>
{
    use bitcoin_rs_primitives::Script;
    let (handles, main, mut bodies) = matured_chain(101)?;
    assert!(
        handles.block_body_store().is_none(),
        "fixture must not fall back to durable body storage"
    );
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();

    // Fork rooted one below the tip: three blocks of work outweigh the
    // main chain's one-block lead.
    let fork_root_hash = main[99].block_hash();
    let mut fork_parent = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork = Vec::new();
    for height in 101..=103_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = crate::sync::fixture_insert_header_node(
            &handles,
            fork_parent,
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        fork.push(block);
    }
    let fork_tip = fork_parent;
    let main_tip_hash = Hash256::from_le_bytes(main[100].block_hash().as_bytes());

    // The staged-body callback is the only body source: every connect on
    // both walks resolves from it. `connected_body` fires once per connect;
    // like `BlockStager` entries, retired bodies stay readable so a later
    // switch can still disconnect the blocks it just connected.
    let staged = &bodies;
    let mut retired = Vec::new();
    crate::reorg::switch_to_branch(
        &handles,
        &followers,
        fork_tip,
        |hash| staged.get(&hash).cloned(),
        |hash| retired.push(hash),
    )?;
    let tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("branch switch did not publish a tip"))?;
    assert_eq!(
        tip.hash,
        Hash256::from_le_bytes(fork[2].block_hash().as_bytes()),
        "the switch must reach the fork tip using staged bodies alone"
    );
    assert_eq!(
        retired.len(),
        3,
        "every connected body retires once, in connect order"
    );

    // The reverse switch resolves all disconnect and connect bodies from
    // the same bounded staging, without durable storage or fixture lookup.
    let main_target = handles
        .block_tree()
        .read()
        .lookup(main_tip_hash)
        .ok_or_else(|| std::io::Error::other("missing original branch tip"))?;
    crate::reorg::switch_to_branch(
        &handles,
        &followers,
        main_target,
        |hash| staged.get(&hash).cloned(),
        |hash| retired.push(hash),
    )?;
    let restored = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("reverse switch did not publish a tip"))?;
    assert_eq!(
        restored.hash, main_tip_hash,
        "bounded staging must supply the reverse branch switch without durable storage"
    );
    assert_eq!(
        retired.len(),
        4,
        "the reconnected main body retires as well"
    );
    Ok(())
}

/// When a competing connect lands between a reorg plan and its transition,
/// the switch must replan on the moved applied tip and still reach its
/// target.
#[test]
fn branch_switch_replans_after_a_competing_connect_before_transition()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (handles, main, mut bodies) = matured_chain(101)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let applied_tip = handles.applied_tip_reader();

    let fork_root_hash = main[99].block_hash();
    let mut fork_parent = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork = Vec::new();
    for height in 101..=103_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = crate::sync::fixture_insert_header_node(
            &handles,
            fork_parent,
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        fork.push(block);
    }

    let main_tip_id = handles
        .block_tree()
        .read()
        .lookup(Hash256::from_le_bytes(main[100].block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing main branch tip"))?;
    let mut racing_coinbase = coinbase_transaction(102);
    racing_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let racing = mined_block_with_prev_hash(main[100].block_hash(), 102, vec![racing_coinbase]);
    crate::sync::fixture_insert_header_node(
        &handles,
        main_tip_id,
        racing.header,
        NodeStatus::HeaderValid,
    )?;
    // The competing connect's body must be resolvable when the replanned
    // walk disconnects it.
    bodies.insert(
        Hash256::from_le_bytes(racing.block_hash().as_bytes()),
        (racing.clone(), bytes::Bytes::from(consensus_bytes(&racing))),
    );

    let (preloaded_tx, preloaded_rx) = std::sync::mpsc::sync_channel(0);
    let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let handles = &handles;
        let bodies = &bodies;
        let worker = scope.spawn(move || {
            let mut paused = false;
            crate::reorg::switch_to_branch(
                handles,
                &followers,
                fork_parent,
                |hash| {
                    let body = bodies.get(&hash).cloned();
                    if !paused {
                        paused = true;
                        assert!(preloaded_tx.send(()).is_ok());
                        assert!(continue_rx.recv().is_ok());
                    }
                    body
                },
                |_| {},
            )
        });
        preloaded_rx.recv().map_err(|_| {
            std::io::Error::other("branch switch did not pause after preloading began")
        })?;
        handles.apply_block(&racing, None)?;
        continue_tx
            .send(())
            .map_err(|_| std::io::Error::other("branch switch stopped before replanning"))?;
        worker
            .join()
            .map_err(|_| std::io::Error::other("branch switch worker panicked"))??;
        Ok(())
    })?;

    let tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("branch switch did not publish a tip"))?;
    assert_eq!(
        tip.hash,
        Hash256::from_le_bytes(fork[2].block_hash().as_bytes()),
        "the locked replan must absorb the competing connect and still reach the target"
    );
    Ok(())
}
