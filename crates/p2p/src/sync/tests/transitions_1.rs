use super::*;

#[test]
fn tick_sends_getdata_for_headers_above_applied_tip() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    let mut expected = Vec::new();

    for height in 1_u32..=3 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        expected.push(BlockHash::from(tree.node(tip_id)?.hash));
    }

    let SyncHarness {
        sync,
        peers,
        block_tree,
        applied_tip,
        inbound_headers_tx: _inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
    } = SyncHarness::new(tree);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(inventory.len(), 3);
    let requested = inventory
        .into_iter()
        .map(|item| match item {
            // Wire seam: Inventory payloads stay bitcoin::; convert to native.
            Inventory::WitnessBlock(hash) => {
                Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
            }
            _ => Err(std::io::Error::other("expected witness block inventory")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(requested, expected);

    let second = rx.try_recv()?;
    if !matches!(second, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders").into());
    }
    Ok(())
}

#[test]
fn tick_fetches_new_tip_headers_from_at_tip_peers() -> Result<(), Box<dyn std::error::Error>> {
    // Contract proof: P2P-03 (docs/contracts/p2p-wire.md).
    // Regression test for the #617 shape: once a node has caught up, no
    // connected peer has a handshake-time start_height above its applied
    // height — every peer connected while the node was at or below the
    // tip. When a new header then extends the tip (a sendheaders
    // announcement), the announcing peer demonstrably has the block, so
    // its demonstrated best-known height must keep it request-eligible
    // and tick must fetch the missing body instead of skipping every
    // peer for a stale handshake snapshot.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    for height in 1_u32..=2 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
    }
    // Applied frontier at height 2; header 3 arrives later, below.
    let applied = {
        let node = tree.node(tip_id)?;
        TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let announced_header = test_header(BlockHash::from(tree.node(tip_id)?.hash), 3);
    let expected = announced_header.compute_hash();

    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(applied)));
    // The peer's handshake height equals the applied height: it connected
    // while the node was at the tip, before the new block existed.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 2));

    // The peer announces the new tip header; drain accepts it and must
    // record the demonstrated height on the peer.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![announced_header],
        source: Some(current_source(&peers, addr)),
    })?;

    sync.tick();

    let first = rx
        .try_recv()
        .map_err(|_| std::io::Error::other("no getdata sent for the new tip header"))?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(
        inventory.len(),
        1,
        "only the unapplied new block is requested"
    );
    match &inventory[0] {
        Inventory::WitnessBlock(hash) => {
            assert_eq!(
                Hash256::from_le_bytes(hash.as_byte_array()),
                expected.into()
            );
        }
        _ => return Err(std::io::Error::other("expected witness block inventory").into()),
    }
    Ok(())
}

#[test]
fn repeated_at_tip_extensions_keep_one_owned_frontier() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, applied_tip, blocks, inbound_blocks) = sync_with_mined_chain(8)?;
    let genesis_hash = Network::Regtest.genesis_block_hash();
    let genesis_tip = {
        let tree = sync.chain.block_tree().read();
        let id = tree.lookup(genesis_hash).ok_or("missing genesis")?;
        let node = tree.node(id)?;
        TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    sync.chain.chain_tip().store(Some(Arc::new(genesis_tip)));
    let addr = test_addr(9_740, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 0));
    let source = current_source(&peers, addr);

    for (index, block) in blocks.into_iter().enumerate() {
        let hash = Hash256::from(block.block_hash());
        let announced = {
            let tree = sync.chain.block_tree().read();
            let id = tree.lookup(hash).ok_or("missing announced block")?;
            let node = tree.node(id)?;
            TipSnapshot {
                tip_id: id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        sync.chain
            .chain_tip()
            .store(Some(Arc::new(announced.clone())));
        assert!(peers.note_announced_tip(source, hash, Some(i32::try_from(announced.height)?),));

        sync.tick();
        assert_eq!(
            witness_block_inventory(next_getdata(&rx)?)?,
            vec![block.block_hash()]
        );
        assert_eq!(
            sync.frontier_state.lock().window.pending_owner(&hash),
            Some(source),
            "the current connection must own the frontier body request"
        );
        assert!(peers.is_current(source));
        let mut inbound = crate::InboundBlock::from_decoded(block);
        inbound.source = Some(source);
        inbound_blocks.send(inbound)?;
        sync.tick();
        let applied = applied_tip.load_full().ok_or("missing applied tip")?;
        assert_eq!(applied.height, u32::try_from(index + 1)?);
        assert_eq!(applied.hash, hash);
    }
    Ok(())
}

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

    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(applied)));
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
fn losing_fork_credit_survives_winner_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    // Contract proof: P2P-03 (docs/contracts/p2p-wire.md). Peer A's
    // accepted fork is initially losing, peer B later extends it so the
    // fork wins, and B then disconnects. A must retain the accepted tip
    // evidence and remain eligible for the bodies it demonstrated.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let losing1 = test_header(genesis.compute_hash(), 1);
    let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
    let losing2 = test_header(losing1.compute_hash(), 2);
    tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
    let genesis_node = tree.node(genesis_id)?;
    let applied = TipSnapshot {
        tip_id: genesis_id,
        height: genesis_node.height,
        chainwork: genesis_node.chainwork,
        hash: genesis_node.hash,
    };

    let fork1 = test_header(genesis.compute_hash(), 101);
    let fork2 = test_header(fork1.compute_hash(), 102);
    let fork3 = test_header(fork2.compute_hash(), 103);
    let expected = [fork1, fork2, fork3];
    let expected_hashes: Vec<Hash256> = expected
        .iter()
        .map(|header| header.compute_hash().into())
        .collect();

    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx: _inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(applied)));

    let peer_a = test_addr(8333, 0)?;
    let peer_b = test_addr(8333, 1)?;
    let rx_a = connect_peer(&peers, synthetic_peer(peer_a, 0));
    let _rx_b = connect_peer(&peers, synthetic_peer(peer_b, 0));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork1, fork2],
        source: Some(current_source(&peers, peer_a)),
    })?;
    sync.drain_inbound_headers();
    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer_a)
            .ok_or("peer A info missing")?
            .best_known_height,
        0,
        "a losing fork must not receive scalar credit yet"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork3],
        source: Some(current_source(&peers, peer_b)),
    })?;
    sync.drain_inbound_headers();
    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer_a)
            .ok_or("peer A info missing after reorg")?
            .best_known_height,
        2,
        "peer A's retained fork tip must be credited after the fork wins"
    );
    assert!(peers.disconnect_source(current_source(&peers, peer_b)));

    sync.tick();

    let requested = next_getdata(&rx_a)?
        .into_iter()
        .map(|item| match item {
            Inventory::WitnessBlock(hash) => Ok(Hash256::from_le_bytes(hash.as_byte_array())),
            _ => Err(std::io::Error::other("expected witness block inventory")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        requested,
        expected_hashes[..2],
        "the surviving peer must serve the bodies it demonstrated"
    );
    Ok(())
}

#[test]
fn header_progress_from_another_peer_supersedes_pending_request()
-> Result<(), Box<dyn std::error::Error>> {
    // A pending getheaders is a question about one locator tip: progress
    // admitted from any peer moves the tip, so the pending gate must not
    // suppress the follow-up question about the new tip.
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let addr_a = test_addr(9_751, 0)?;
    let addr_b = test_addr(9_751, 1)?;
    let rx_a = connect_peer(&peers, eligible_peer(addr_a, 8));
    let rx_b = connect_peer(&peers, eligible_peer(addr_b, 9));

    // Tick 1: at tip, so the plan extends the header chain — one
    // getheaders to the best candidate (B's higher demonstrated height).
    sync.tick();
    let drain_getheaders = |rx: &crossbeam_channel::Receiver<Message>| {
        let mut requests = Vec::new();
        while let Ok(message) = rx.try_recv() {
            if let Message::GetHeaders(request) = message {
                requests.push(request);
            }
        }
        requests
    };
    let first: Vec<_> = [drain_getheaders(&rx_a), drain_getheaders(&rx_b)].concat();
    assert_eq!(first.len(), 1, "exactly one getheaders must be armed");
    assert!(
        sync.frontier_state.lock().header_request.is_some(),
        "the pending gate must be armed before progress lands"
    );

    // Header progress attributed to the OTHER peer (A, not the request
    // owner) is admitted and moves the chain tip; B's pending survives
    // (a nonempty batch retires only its own source's request).
    let next_header = test_header(genesis.compute_hash(), 1);
    let next_hash = next_header.compute_hash();
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![next_header],
        source: Some(current_source(&peers, addr_a)),
    })?;
    sync.tick();
    assert!(
        sync.frontier_state.lock().header_request.is_some(),
        "the non-owner batch must leave the pending request armed"
    );
    let _ = drain_getheaders(&rx_a);
    let _ = drain_getheaders(&rx_b);

    // The node applies the admitted block, so the next tick extends the
    // header chain (at tip) rather than probing a missing frontier.
    let applied = {
        let tree = sync.chain.block_tree().read();
        let tip_id = tree
            .lookup(next_hash.into())
            .ok_or("admitted header missing from the block tree")?;
        let node = tree.node(tip_id)?;
        TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    sync.chain.applied_tip().store(Some(Arc::new(applied)));

    // Tick 3: the follow-up question is about the NEW locator tip, so the
    // still-live pending request for the old tip must not gate it.
    sync.tick();
    let second: Vec<_> = [drain_getheaders(&rx_a), drain_getheaders(&rx_b)].concat();
    assert!(
        !second.is_empty(),
        "a getheaders for the new tip must not be gated by the old pending"
    );
    assert!(
        second.iter().any(|request| {
            request
                .locator_hashes
                .first()
                .map(|hash| Hash256::from_le_bytes(hash.as_byte_array()))
                == Some(next_hash.into())
        }),
        "the follow-up locator must be anchored at the new header tip"
    );
    Ok(())
}
