use super::*;

#[test]
fn tick_fetches_reorg_fork_announced_by_at_tip_peer() -> Result<(), Box<dyn std::error::Error>> {
    // Contract proof: P2P-03 (docs/contracts/p2p-wire.md) — the reorg
    // edge of the branch-aware credit. A winning fork announced at tip
    // re-selects the tree's best chain during acceptance, and the
    // announcing peer must earn credit against that POST-reselection
    // chain. A filter that credited only headers on the pre-insert tip
    // would leave the peer ineligible and no fork body would be fetched.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let losing1 = test_header(genesis.compute_hash(), 1);
    let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
    let losing2 = test_header(losing1.compute_hash(), 2);
    let losing2_id = tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
    let applied = {
        let node = tree.node(losing2_id)?;
        TipSnapshot {
            tip_id: losing2_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };

    let winning1 = test_header(genesis.compute_hash(), 101);
    let winning2 = test_header(winning1.compute_hash(), 102);
    let winning3 = test_header(winning2.compute_hash(), 103);
    let expected: Vec<Hash256> = [&winning1, &winning2, &winning3]
        .iter()
        .map(|header| header.compute_hash().into())
        .collect();

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(applied)));
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let sync = BlockSync::for_test(
        apply_handles(chain_tip, Arc::clone(&applied_tip), Arc::clone(&block_tree)),
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    // The peer's handshake height equals the applied height: it
    // connected at the losing tip, and only the fork announcement it
    // delivers demonstrates anything beyond that.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 2));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![winning1, winning2, winning3],
        source: Some(current_source(&peers, addr)),
    })?;

    sync.tick();

    // The winning fork's actual tip height is 3 (the fixture's 101..103
    // only seed merkle/time bytes; tree heights derive from parents).
    assert_eq!(
        peers.infos()[0].best_known_height,
        3,
        "the announced winning fork must earn credit on the reselected best chain"
    );
    let first = rx
        .try_recv()
        .map_err(|_| std::io::Error::other("no getdata sent for the announced fork"))?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    let requested = inventory
        .into_iter()
        .map(|item| match item {
            Inventory::WitnessBlock(hash) => Ok(Hash256::from_le_bytes(hash.as_byte_array())),
            _ => Err(std::io::Error::other("expected witness block inventory")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        requested, expected,
        "the reorg connect set must be requested after the common ancestor"
    );
    Ok(())
}

#[test]
fn retargeting_pending_requests_drops_losing_branch_hashes()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = genesis_header();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let genesis_tip = {
        let node = tree.node(genesis_id)?;
        TipSnapshot {
            tip_id: genesis_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };

    let losing1 = test_header(genesis.compute_hash(), 1);
    let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
    let losing2 = test_header(losing1.compute_hash(), 2);
    let losing2_id = tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
    let losing_tip = {
        let node = tree.node(losing2_id)?;
        TipSnapshot {
            tip_id: losing2_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let losing_hashes = vec![losing1.compute_hash(), losing2.compute_hash()];

    let winning1 = test_header(genesis.compute_hash(), 101);
    let winning1_id = tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
    let winning2 = test_header(winning1.compute_hash(), 102);
    let winning2_id = tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
    let winning3 = test_header(winning2.compute_hash(), 103);
    let winning3_id = tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
    let winning_tip = {
        let node = tree.node(winning3_id)?;
        TipSnapshot {
            tip_id: winning3_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let winning_hashes = vec![
        winning1.compute_hash(),
        winning2.compute_hash(),
        winning3.compute_hash(),
    ];

    let chain_tip = Arc::new(ArcSwapOption::empty());
    chain_tip.store(Some(Arc::new(losing_tip)));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(genesis_tip)));
    let block_tree = Arc::new(RwLock::new(tree));
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let sync = BlockSync::for_test(
        apply_handles(Arc::clone(&chain_tip), Arc::clone(&applied_tip), block_tree),
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    let peer = SocketAddr::from(([127, 0, 0, 1], 18_461));
    let (tx, rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(tx));
    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing genesis applied tip"))?;
    let initial = chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing losing chain tip"))?;

    assert!(
        sync.send_getdata_for_pending_blocks(peer, false, 100, &initial, &applied)
            .sent
    );
    assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, losing_hashes);

    chain_tip.store(Some(Arc::new(winning_tip)));
    let retargeted = chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing winning chain tip"))?;
    assert!(
        sync.send_getdata_for_pending_blocks(peer, false, 100, &retargeted, &applied)
            .sent
    );
    let requested = witness_block_inventory(next_getdata(&rx)?)?;
    assert_eq!(requested, winning_hashes);
    assert!(
        requested.iter().all(|hash| !losing_hashes.contains(hash)),
        "retargeted requests must not retain hashes from the losing branch"
    );
    assert_eq!(
        sync.download_window.lock().pending_len(),
        winning_hashes.len(),
        "retargeting must release losing-branch pending capacity"
    );
    Ok(())
}

#[test]
fn outweighed_branch_target_accepts_shorter_higher_work_branch()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::CompactTarget;
    let genesis = genesis_header();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let main1 = test_header(genesis.compute_hash(), 1);
    let main1_id = tree.insert_node(Some(genesis_id), main1, NodeStatus::HeaderValid)?;
    let main2 = test_header(main1.compute_hash(), 2);
    let main2_id = tree.insert_node(Some(main1_id), main2, NodeStatus::HeaderValid)?;
    let applied = {
        let node = tree.node(main2_id)?;
        TipSnapshot {
            tip_id: main2_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };

    let mut high_work = test_header(genesis.compute_hash(), 101);
    high_work.bits = CompactTarget::from_consensus(0x2000_ffff);
    high_work.nonce = 0;
    while !pow_met(
        high_work.bits.to_consensus(),
        Hash256::from(high_work.compute_hash()),
    ) {
        high_work.nonce = high_work.nonce.wrapping_add(1);
    }
    let high_work_id = tree.insert_node(Some(genesis_id), high_work, NodeStatus::HeaderValid)?;
    let winning = tree
        .tip()
        .ok_or_else(|| std::io::Error::other("missing higher-work tip"))?;
    assert_eq!(winning.tip_id, high_work_id);
    assert!(winning.height < applied.height);
    assert!(winning.chainwork > applied.chainwork);

    let chain_tip = tree.tip_handle();
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(applied)));
    let block_tree = Arc::new(RwLock::new(tree));
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let sync = BlockSync::for_test(
        apply_handles(chain_tip, applied_tip, block_tree),
        Arc::new(PeerTable::new()),
        Arc::new(Mutex::new(inbound_headers_rx_raw)),
        Arc::new(Mutex::new(inbound_blocks_rx_raw)),
    );

    assert_eq!(sync.outweighed_branch_target(), Some(high_work_id));
    Ok(())
}

// One no-store lifecycle must prove both accounting retirement and bounded
// staging body resolution; splitting it would stop exercising their handoff.
#[allow(clippy::too_many_lines)]
#[test]
fn branch_switch_uses_staged_bodies_without_durable_store() -> Result<(), Box<dyn std::error::Error>>
{
    use bitcoin_rs_primitives::Script;
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(2)?;
    sync.ensure_genesis_tip();
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_blocks: 3,
            ..super::super::default_sync_budget()
        },
    );
    for block in &main {
        stage_body(&sync, block);
    }
    assert_eq!(sync.apply_buffered_blocks(None), (2, 0));
    assert!(
        sync.handles.block_body_store.is_none(),
        "fixture must not fall back to durable body storage"
    );
    for block in &main {
        stage_body(&sync, block);
    }

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
    for height in 1..=3_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = sync.handles.block_tree.write().insert_node(
            Some(fork_parent),
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        fork.push(block);
    }
    let fork_tip = sync
        .handles
        .block_tree
        .read()
        .tip()
        .ok_or_else(|| std::io::Error::other("fork tip was not published"))?;
    sync.handles.chain_tip.store(Some(fork_tip));
    assert_eq!(sync.block_stager.lock().received_len(), 2);
    assert_eq!(sync.download_window.lock().received_len(), 0);

    let stage_received = |block: &Block| {
        stage_body(&sync, block);
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let bytes = consensus_bytes(block).len();
        sync.download_window
            .lock()
            .mark_received(hash, bytes, Instant::now());
        hash
    };

    let first_hash = stage_received(&fork[0]);
    assert_eq!(sync.block_stager.lock().received_len(), 3);
    assert_eq!(
        sync.outweighed_branch_target(),
        Some(fork_parent),
        "the full fork tip must select the initial branch switch"
    );
    sync.switch_branch_if_outweighed();
    let first_tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("branch prefix did not publish a tip"))?;
    assert_eq!(first_tip.height, 1);
    assert_eq!(first_tip.hash, first_hash);
    assert_eq!(sync.block_stager.lock().received_len(), 2);
    assert_eq!(sync.download_window.lock().received_len(), 0);

    for (index, block) in fork.iter().enumerate().skip(1) {
        let hash = stage_received(block);
        assert_eq!(
            sync.block_stager.lock().received_len(),
            3,
            "the tiny stager has room for one suffix body"
        );
        assert_eq!(
            sync.apply_buffered_blocks(None),
            (1, 0),
            "the committed prefix must turn the remaining fork into forward apply"
        );
        let tip = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("forward suffix did not publish a tip"))?;
        assert_eq!(tip.height, u32::try_from(index + 1)?);
        assert_eq!(tip.hash, hash);
        assert_eq!(sync.block_stager.lock().received_len(), 2);
        assert_eq!(sync.download_window.lock().received_len(), 0);
    }

    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_blocks: 5,
            ..super::super::default_sync_budget()
        },
    );
    for block in &fork {
        stage_body(&sync, block);
    }
    for block in &main {
        stage_body(&sync, block);
    }
    assert_eq!(
        sync.block_stager.lock().received_len(),
        5,
        "bounded staging must contain every reverse-switch plan body"
    );
    // The reverse switch must resolve all five disconnect and connect bodies from
    // the bounded stager, without durable storage or fixture-vector lookup.
    let explicit_body = |hash: Hash256| sync.block_stager.lock().staged_body(hash);
    let main_target = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(main[1].block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing original branch tip"))?;
    crate::reorg::switch_to_branch(
        &sync.handles,
        &sync.followers,
        main_target,
        explicit_body,
        |hash| {
            sync.retire_applied_reorg_body(hash);
        },
    )?;
    let restored = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("reverse switch did not publish a tip"))?;
    assert_eq!(
        restored.hash,
        Hash256::from_le_bytes(main[1].block_hash().as_bytes()),
        "bounded staging must supply the reverse branch switch without durable storage"
    );
    assert_eq!(
        sync.block_stager.lock().received_len(),
        3,
        "only connected bodies retire from bounded staging after the reverse switch"
    );
    Ok(())
}

#[test]
fn branch_switch_replans_after_a_competing_connect_before_transition()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(2)?;
    sync.ensure_genesis_tip();
    for block in &main {
        stage_body(&sync, block);
    }
    assert_eq!(sync.apply_buffered_blocks(None), (2, 0));
    for block in &main {
        stage_body(&sync, block);
    }

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
    for height in 1..=3_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = sync.handles.block_tree.write().insert_node(
            Some(fork_parent),
            block.header,
            NodeStatus::HeaderValid,
        )?;
        fork_prev = block.block_hash();
        stage_body(&sync, &block);
        fork.push(block);
    }

    let main_tip_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(main[1].block_hash().as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing main branch tip"))?;
    let mut racing_coinbase = coinbase_transaction(3);
    racing_coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(3));
    let racing = mined_block_with_prev_hash(main[1].block_hash(), 3, vec![racing_coinbase]);
    stage_body(&sync, &racing);
    sync.handles.block_tree.write().insert_node(
        Some(main_tip_id),
        racing.header,
        NodeStatus::HeaderValid,
    )?;

    let (preloaded_tx, preloaded_rx) = std::sync::mpsc::sync_channel(0);
    let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let sync = &sync;
        let worker = scope.spawn(move || {
            let mut paused = false;
            crate::reorg::switch_to_branch(
                &sync.handles,
                &sync.followers,
                fork_parent,
                |hash| {
                    let body = sync.block_stager.lock().staged_body(hash);
                    if !paused {
                        paused = true;
                        assert!(preloaded_tx.send(()).is_ok());
                        assert!(continue_rx.recv().is_ok());
                    }
                    body
                },
                |hash| sync.retire_applied_reorg_body(hash),
            )
        });
        preloaded_rx.recv().map_err(|_| {
            std::io::Error::other("branch switch did not pause after preloading began")
        })?;
        sync.handles.apply_block(&racing)?;
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
