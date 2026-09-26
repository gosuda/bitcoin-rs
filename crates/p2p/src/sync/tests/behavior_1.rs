use super::*;

// SYNC-FRONTIER-01: the documented contracts of outweighed_branch_target
// and send_getdata_for_pending_blocks require ancestry, not equal heights.
// Independent oracle: crates/chain/src/reorg.rs::plan_reorg, unchanged by
// this optimization. Compare actual emitted hashes, not only batch sizes.
#[test]
fn indexed_sync_frontiers_match_parent_plans() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let root = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
    let mut main = vec![root];
    for tag in 1..=12 {
        let parent = *main.last().ok_or("missing main parent")?;
        let header = test_header(BlockHash::from(tree.node(parent)?.hash), tag);
        main.push(tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?);
    }
    let mut fork = vec![main[2]];
    for tag in 101..=106 {
        let parent = *fork.last().ok_or("missing fork parent")?;
        let header = test_header(BlockHash::from(tree.node(parent)?.hash), tag);
        fork.push(tree.insert_node(Some(parent), header, NodeStatus::HeaderValid)?);
    }
    let foreign_header = test_header(BlockHash::from(Hash256::from_le_bytes(&[0; 32])), 200);
    let foreign = tree.insert_node(None, foreign_header, NodeStatus::HeaderValid)?;
    let endpoints = [root, main[2], main[6], main[12], fork[2], fork[6], foreign];
    let snapshots = endpoints
        .iter()
        .map(|&tip_id| {
            let node = tree.node(tip_id)?;
            Ok(TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
                chain_tx_count: node.chain_tx_count,
            })
        })
        .collect::<Result<Vec<_>, bitcoin_rs_chain::ChainError>>()?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        ..
    } = SyncHarness::new(tree);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8_333));
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    // Repeat the same matrix after public node_mut invalidates the index,
    // without changing any node. Cached and parent-walk answers must agree.
    for tainted in [false, true] {
        if tainted {
            let mut tree = block_tree.write();
            let _ = tree.node_mut(main[12])?;
        }
        for applied in &snapshots {
            for target in &snapshots {
                check_sync_frontier_pair(&sync, &rx, addr, applied, target)?;
            }
        }
    }
    Ok(())
}

// SYNC-FRONTIER-01: an invalidated height index must preserve the
// unchanged parent-plan result even when public node_mut leaves a gap.
#[test]
fn request_frontier_retains_parent_plan_on_height_gaps() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let root = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
    let root_hash = tree.node(root)?.hash;
    let header = test_header(BlockHash::from(root_hash), 1);
    let child = tree.insert_node(Some(root), header, NodeStatus::HeaderValid)?;
    tree.node_mut(child)?.height = 2;
    let plan = bitcoin_rs_chain::plan_reorg(&tree, root, child)?;
    let [first] = plan.connect.as_slice() else {
        return Err("expected one connect node".into());
    };
    assert_eq!(
        BlockSync::first_connect_height(&tree, root_hash, child),
        Some(tree.node(*first)?.height),
    );
    Ok(())
}

#[test]
fn fork_getdata_starts_at_common_ancestor_child() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = genesis_header();
    let mut tree = BlockTree::new();
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
            chain_tx_count: node.chain_tx_count,
        }
    };

    let winning1 = test_header(genesis.compute_hash(), 101);
    let winning1_id = tree.insert_node(Some(genesis_id), winning1, NodeStatus::HeaderValid)?;
    let winning2 = test_header(winning1.compute_hash(), 102);
    let winning2_id = tree.insert_node(Some(winning1_id), winning2, NodeStatus::HeaderValid)?;
    let winning3 = test_header(winning2.compute_hash(), 103);
    tree.insert_node(Some(winning2_id), winning3, NodeStatus::HeaderValid)?;
    let expected = vec![
        winning1.compute_hash(),
        winning2.compute_hash(),
        winning3.compute_hash(),
    ];

    let SyncHarness {
        sync,
        peers,
        block_tree: _,
        applied_tip,
        inbound_headers_tx: _inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(applied)));
    let peer = SocketAddr::from(([127, 0, 0, 1], 18_460));
    let (tx, rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(tx));

    assert!(
        sync.send_getdata_for_pending_blocks(
            current_source(&sync.peer_table, peer),
            false,
            100,
            &test_frontier(&sync),
            Instant::now()
        )
        .sent
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&rx)?)?,
        expected,
        "the fork request must begin immediately after the common ancestor"
    );
    Ok(())
}

/// Builds a live-tip race: the applied tip sits two deep on a losing
/// branch while a heavier three-block branch heads the tree. Winning
/// bodies are real mined blocks so they pass the binding gate when staged.
fn pending_reorg_fixture()
-> Result<(SyncHarness, TipSnapshot, Vec<Block>), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis_header(), NodeStatus::HeaderValid)?;
    let losing1 = test_header(genesis_header().compute_hash(), 1);
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
            chain_tx_count: node.chain_tx_count,
        }
    };

    let mut winning = Vec::new();
    let mut parent = genesis_id;
    let mut prev = genesis_header().compute_hash();
    for tag in 101..=103_u32 {
        let block = mined_block_with_prev_hash(prev, tag, vec![coinbase_transaction(tag)]);
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        prev = block.block_hash();
        winning.push(block);
    }

    let harness = SyncHarness::new(tree);
    harness.applied_tip.store(Some(Arc::new(applied.clone())));
    Ok((harness, applied, winning))
}

// SYNC-FRONTIER-01: while a heavier branch is pending, the apply-side
// frontier is the first connect node above the common ancestor — not the
// winner-branch node at `applied_height + 1`.
#[test]
fn pending_reorg_frontier_is_first_connect_node() -> Result<(), Box<dyn std::error::Error>> {
    let (harness, _applied, winning) = pending_reorg_fixture()?;
    let first_connect = Hash256::from(winning[0].block_hash());
    assert_eq!(
        harness.sync.next_expected_block(),
        Some((1, first_connect)),
        "the connect frontier must name the winner's first block, not the winner at applied+1"
    );
    Ok(())
}

// A winning-branch body staged above the fork must wait for the branch
// switch instead of churning through the extension commit: its parent lies
// on the winning branch — never on the applied tip — so the commit could
// never consume it and would restore-drop and re-request it every tick.
#[test]
fn apply_buffered_blocks_waits_for_pending_reorg() -> Result<(), Box<dyn std::error::Error>> {
    let (harness, applied, winning) = pending_reorg_fixture()?;
    let sync = &harness.sync;
    let head = &winning[2];
    let head_hash = Hash256::from(head.block_hash());

    sync.buffer_received_block_chunk(
        &mut vec![crate::InboundBlock::from_decoded(head.clone())],
        Some(head_hash),
    );
    assert!(sync.scheduler.lock().stager.contains(&head_hash));

    let first_connect = Hash256::from(winning[0].block_hash());
    assert_eq!(sync.apply_buffered_blocks(Some(first_connect)), (0, 0));
    assert!(
        sync.scheduler.lock().stager.contains(&head_hash),
        "an uncommittable winner body must stay staged for the branch switch"
    );
    assert_eq!(
        sync.chain
            .applied_tip()
            .load_full()
            .ok_or("missing applied tip")?
            .hash,
        applied.hash,
        "the losing applied tip must not be displaced by the extension path"
    );
    Ok(())
}

#[test]
fn tick_does_not_resend_same_getheaders_while_pending() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));

    sync.tick();
    let first = rx.try_recv()?;
    if !matches!(first, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first getheaders").into());
    }

    sync.tick();
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn inbound_headers_response_releases_getheaders_gate() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    let chain_tip = block_tree.read().tip_handle();
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));

    sync.tick();
    let first = rx.try_recv()?;
    if !matches!(first, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first getheaders").into());
    }

    let header = test_header(genesis.compute_hash(), 1);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![header],
        source: Some(current_source(&peers, addr)),

        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();
    let second = rx.try_recv()?;
    if !matches!(second, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected second getheaders after response").into());
    }
    let accepted_tip = chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing accepted header tip"))?;
    assert_eq!(accepted_tip.height, 1);
    assert_ne!(accepted_tip.tip_id, genesis_id);
    Ok(())
}

#[test]
fn unconnecting_headers_retain_gate_and_pace_retry() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    let chain_tip = block_tree.read().tip_handle();
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));

    sync.tick();
    let first = rx.try_recv()?;
    if !matches!(first, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first getheaders").into());
    }

    // An unconnecting batch is not a valid answer, so the request stays
    // registered. The live gate paces the retry instead of letting the same
    // locator be replayed at round-trip pace against a peer that already said
    // it cannot serve the ancestry.
    let orphan_prev = BlockHash(Hash256::from_le_bytes(&[0x11; 32]));
    let orphan = test_header(orphan_prev, 5);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan],
        source: Some(current_source(&peers, addr)),

        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();
    assert!(
        rx.try_recv().is_err(),
        "a retained gate must not replay getheaders"
    );
    let tip = chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing header tip"))?;
    assert_eq!(tip.tip_id, genesis_id, "orphan header must not advance tip");
    Ok(())
}

#[test]
fn orphan_headers_keep_source_peer_connected() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        sync,
        inbound_headers_tx,
        peers,
        ..
    } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let _rx = connect_peer(&peers, synthetic_peer(peer_addr, 8));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![test_header(
            BlockHash(Hash256::from_le_bytes(&[0x11; 32])),
            1,
        )],
        source: Some(current_source(&peers, peer_addr)),

        wire_response: true,
        body_fetch_owned: false,
    })?;

    sync.tick();

    assert!(
        peers.is_connected(peer_addr),
        "orphan announcements are not evidence of a bad peer"
    );
    assert!(
        peers.is_connected(peer_addr),
        "orphan announcements must not revoke the peer lease"
    );
    Ok(())
}

#[test]
fn tick_bounded_request_peer_selection_skips_inflight_saturated_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 4,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let first_rx = connect_peer(&peers, synthetic_peer(first_addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(first_inventory) = first_rx.try_recv()? else {
        return Err(std::io::Error::other("expected first peer getdata").into());
    };
    assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
    let first_headers = first_rx.try_recv()?;
    if !matches!(first_headers, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first peer getheaders").into());
    }

    let second_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let second_rx = connect_peer(&peers, synthetic_peer(second_addr, 100));

    sync.tick();

    let Message::GetData(second_inventory) = second_rx.try_recv()? else {
        return Err(std::io::Error::other("expected second peer getdata").into());
    };
    assert_eq!(witness_block_inventory(second_inventory)?, expected[2..4]);
    while let Ok(message) = second_rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(std::io::Error::other(
                "a saturated prefix must not receive additional getdata",
            )
            .into());
        }
    }
    // The in-flight getheaders gate suppresses a duplicate header request to
    // the original sync peer, so it receives no further messages.
    assert!(first_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            pending_timeout_override: Some(Duration::ZERO),
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let stale_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let stale_rx = connect_peer(&peers, synthetic_peer(stale_addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(first_inventory) = stale_rx.try_recv()? else {
        return Err(std::io::Error::other("expected stale peer getdata").into());
    };
    assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
    let stale_headers = stale_rx.try_recv()?;
    if !matches!(stale_headers, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected stale peer getheaders").into());
    }

    let healthy_rx = connect_peer(&peers, synthetic_peer(healthy_addr, 100));

    sync.tick();

    let Message::GetData(retry_inventory) = healthy_rx.try_recv()? else {
        return Err(std::io::Error::other("expected healthy peer retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
    while let Ok(message) = healthy_rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(std::io::Error::other(
                "healthy peer must not receive another getdata request",
            )
            .into());
        }
    }
    while let Ok(message) = stale_rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(
                std::io::Error::other("stale peer should not receive retry getdata").into(),
            );
        }
    }
    Ok(())
}
