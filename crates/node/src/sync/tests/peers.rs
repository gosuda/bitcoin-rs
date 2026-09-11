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

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(applied)));
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
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

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(applied)));
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let sync = BlockSync::for_test(
        apply_handles(chain_tip, Arc::clone(&applied_tip), block_tree),
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    let peer = SocketAddr::from(([127, 0, 0, 1], 18_460));
    let (tx, rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(tx));
    let chain_tip = sync
        .handles
        .chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing winning chain tip"))?;
    let applied_tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing losing applied tip"))?;

    assert!(
        sync.send_getdata_for_pending_blocks(peer, false, 100, &chain_tip, &applied_tip)
            .sent
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&rx)?)?,
        expected,
        "the fork request must begin immediately after the common ancestor"
    );
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

#[test]
fn tick_does_not_resend_same_getheaders_while_pending() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
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
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
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
fn rejected_matching_peer_headers_release_gate_and_retry_immediately()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));

    sync.tick();
    let first = rx.try_recv()?;
    if !matches!(first, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first getheaders").into());
    }

    // A syntactically valid response consumes the matching request even when
    // acceptance rejects its headers. Otherwise one bad response stalls sync.
    let orphan_prev = BlockHash(Hash256::from_le_bytes(&[0x11; 32]));
    let orphan = test_header(orphan_prev, 5);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan],
        source: Some(current_source(&peers, addr)),
    })?;
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    assert!(rx.try_recv().is_err());
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
            ..super::super::default_sync_budget()
        },
    );
    let first_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let first_rx = connect_peer(&peers, synthetic_peer(first_addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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
            pending_timeout: Duration::ZERO,
            ..super::super::default_sync_budget()
        },
    );
    let stale_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let stale_rx = connect_peer(&peers, synthetic_peer(stale_addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
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

#[test]
fn tick_allows_demoted_peer_when_it_is_the_only_eligible_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(first_inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected first getdata").into());
    };
    assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
    let headers = rx.try_recv()?;
    if !matches!(headers, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders").into());
    }

    sync.tick();

    let Message::GetData(retry_inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
    Ok(())
}

#[test]
fn tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    let mut expected = Vec::new();
    let batch_size = 16_u32;

    for height in 1_u32..=batch_size + 4 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        if height <= batch_size {
            expected.push(BlockHash::from(tree.node(tip_id)?.hash));
        }
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::super::SyncBudget {
            getdata_batch_limit: usize::try_from(batch_size)?,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
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
    Ok(())
}

#[test]
fn successful_getdata_send_marks_requested_blocks_pending() -> Result<(), Box<dyn std::error::Error>>
{
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected);

    let window = sync.download_window.lock();
    assert_eq!(window.pending_len(), expected.len());
    for hash in expected {
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(hash.as_bytes());
        assert!(window.contains_pending(&hash));
    }
    Ok(())
}

#[test]
fn tick_limits_inflight_per_peer() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(5)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_peer_inflight: 2,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(inventory.len(), 2);
    let _headers = rx.try_recv()?;

    sync.tick();

    // Peer inflight budget is saturated and the in-flight getheaders gate
    // suppresses a duplicate header request, so the second tick is silent.
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_falls_back_to_single_deep_peer_below_fanout_threshold()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    let mut rxs = Vec::new();
    for idx in 0..super::super::MIN_PEERS_FOR_FANOUT - 1 {
        let addr = test_addr(9021, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rxs[0].try_recv()? else {
        return Err(std::io::Error::other("expected deep getdata for highest peer").into());
    };
    // The tracked window remains single-owner. Idle eligible alternates
    // receive only the same bounded frontier prefix for the one-shot race.
    assert_eq!(witness_block_inventory(inventory)?, expected);
    for rx in &rxs[1..] {
        assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
    }
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET
    );
    Ok(())
}
