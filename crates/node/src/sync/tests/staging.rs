use super::*;

#[test]
fn second_tick_does_not_re_request_already_pending_blocks() -> Result<(), Box<dyn std::error::Error>>
{
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;

    for height in 1_u32..=3 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
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
    if !matches!(first, Message::GetData(_)) {
        return Err(std::io::Error::other("expected first tick getdata").into());
    }
    let second = rx.try_recv()?;
    if !matches!(second, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first tick getheaders").into());
    }

    sync.tick();

    // The in-flight getheaders gate suppresses a duplicate header request,
    // and already-pending blocks are not re-requested, so the second tick
    // emits no outbound messages.
    match rx.try_recv() {
        Ok(Message::GetData(_)) => {
            Err(std::io::Error::other("second tick re-requested pending blocks").into())
        }
        Ok(Message::GetHeaders(_)) => {
            Err(std::io::Error::other("second tick resent in-flight getheaders").into())
        }
        Ok(_) => Err(std::io::Error::other("unexpected extra message after second tick").into()),
        Err(crossbeam_channel::TryRecvError::Empty) => Ok(()),
        Err(crossbeam_channel::TryRecvError::Disconnected) => {
            Err(std::io::Error::other("outbound channel disconnected").into())
        }
    }
}

#[test]
fn drain_inbound_blocks_prunes_stale_received_blocks_without_new_arrivals()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
    let block = Network::Regtest.genesis_block();
    let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_bytes());
    let received_at = Instant::now()
        .checked_sub(super::super::RECEIVED_BLOCK_TIMEOUT + Duration::from_secs(1))
        .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let staged = sync
        .block_stager
        .lock()
        .insert(hash, None, block, serialized, received_at);
    let super::super::StagedBlock::Memory { bytes, .. } = staged else {
        return Err(std::io::Error::other("test block should stage in memory").into());
    };
    sync.download_window
        .lock()
        .mark_received(hash, bytes, Instant::now());

    sync.drain_inbound_blocks();

    assert_eq!(sync.block_stager.lock().received_len(), 0);
    assert_eq!(sync.download_window.lock().received_len(), 0);
    Ok(())
}

#[test]
fn tick_respects_pending_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_bytes: 256 * 1024,
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
    assert_eq!(inventory.len(), 1);
    assert_eq!(sync.download_window.lock().pending_len(), 1);
    Ok(())
}

#[test]
fn tick_caps_requests_at_staged_byte_headroom() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    let slot = 256 * 1024;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_bytes: 3 * slot,
            ..super::super::default_sync_budget()
        },
    );
    // Two of three staging slots already occupied: the staged-byte gate is
    // still open, but only one more estimated block fits.
    {
        let mut window = sync.download_window.lock();
        let now = Instant::now();
        window.mark_received(Hash256::from_le_bytes(&[0xEE; 32]), slot, now);
        window.mark_received(Hash256::from_le_bytes(&[0xEF; 32]), slot, now);
    }
    let addr = test_addr(9270, 0)?;
    let rx = connect_peer(&peers, eligible_peer(addr, 200));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected headroom-clamped getdata").into());
    };
    // A gate-open burst must not over-request past staging headroom.
    assert_eq!(witness_block_inventory(inventory)?, expected[..1]);
    if !matches!(rx.try_recv()?, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders").into());
    }

    sync.tick();

    // The in-flight request consumed the last slot: no further requests
    // until staged blocks apply.
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn()
-> Result<(), Box<dyn std::error::Error>> {
    // The recorded live-collapse construction (scaled 8x down): the
    // default one-minute timeouts never fire inside the test, so the only
    // thing that can stop the second wave is the count clamp itself.
    let (sync, _peers, expected, rxs, _blocks_tx) =
        staged_count_wedge(wedge_budget(super::super::PENDING_TIMEOUT))?;

    // Tick 2: the healthy deliveries stage; staged (14) + pending (2) sit
    // exactly at the count budget (16). The byte gates are unbounded here
    // (KB-scale blocks), so requests stop only if count overflow is
    // request backpressure.
    sync.tick();

    {
        let window = sync.download_window.lock();
        assert_eq!(window.received_len(), 14);
        assert_eq!(window.pending_len(), 2);
        for front in &expected[..2] {
            assert!(
                window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())),
                "stalled front stripe must stay pending, not churn through retry"
            );
        }
    }

    // Tick 3: stability. Pre-fix this is where the second wave was
    // requested, delivered past RECEIVED_BLOCK_BUDGET, evicted the oldest
    // staged blocks (nearest the frozen front) and snapped the window
    // back into self-sustaining re-request churn.
    sync.tick();

    for rx in &rxs {
        assert_no_getdata(rx)?;
    }
    let stager = sync.block_stager.lock();
    assert_eq!(stager.received_len(), 14, "no evictions may occur");
    for height in 3..=16_u32 {
        let hash = Hash256::from_le_bytes(expected[usize::try_from(height)? - 1].as_bytes());
        assert!(
            stager.contains(&hash),
            "every delivered block must remain staged (height {height})"
        );
    }
    assert_eq!(sync.download_window.lock().pending_len(), 2);
    Ok(())
}

#[test]
fn cold_start_stall_hedges_front_without_reassigning_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = super::super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(super::super::PENDING_TIMEOUT)
    };
    let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
    let owner = test_addr(9320, 0)?;
    let alternate = test_addr(9320, 1)?;

    // The alternate peer connected at height zero. Its accepted header
    // announcement proves the active front, which must make it a hedge
    // candidate even though the handshake snapshot remains at zero.
    let alternate_lease = peers
        .lease(alternate)
        .ok_or_else(|| std::io::Error::other("alternate peer lease missing"))?;
    let mut alternate_info = peers
        .infos()
        .into_iter()
        .find(|info| info.addr == alternate)
        .ok_or_else(|| std::io::Error::other("alternate peer info missing"))?;
    alternate_info.start_height = 0;
    alternate_info.best_known_height = 0;
    assert!(peers.publish_info(alternate, &alternate_lease, alternate_info));
    assert!(peers.note_announced_tip(
        current_source(&peers, alternate),
        Hash256::from_le_bytes(expected[0].as_bytes()),
        Some(1),
    ));

    // The first drain builds the asymmetric wedge and starts the episode.
    sync.tick();
    assert_eq!(sync.download_window.lock().pending_len(), 2);
    std::thread::sleep(Duration::from_millis(150));
    sync.tick();

    assert!(
        peers.is_connected(owner),
        "a cold-start hedge must not disconnect the pending owner"
    );
    let mut hedged = Vec::new();
    for rx in &rxs[1..] {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                hedged.extend(witness_block_inventory(inventory)?);
            }
        }
    }
    assert_eq!(hedged, expected[..1]);
    assert_eq!(sync.download_window.lock().pending_len(), 2);

    // The confirmed front hash is not duplicated again on later ticks.
    std::thread::sleep(Duration::from_millis(50));
    sync.tick();
    for rx in &rxs[1..] {
        assert_no_getdata(rx)?;
    }
    Ok(())
}

#[test]
fn far_behind_duplicate_of_applied_block_is_not_staged() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(64)?;
    let peer = test_addr(9321, 0)?;
    let rx = connect_peer(&peers, eligible_peer(peer, 100));

    sync.tick();
    let requested = next_getdata(&rx)?;
    assert_eq!(
        witness_block_inventory(requested)?,
        blocks.iter().map(Block::block_hash).collect::<Vec<_>>()
    );
    for block in &blocks {
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
    }
    sync.tick();
    assert_eq!(
        applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height,
        64
    );
    let stale_hash = Hash256::from_le_bytes(blocks[0].block_hash().as_bytes());
    assert!(
        !sync.download_window.lock().contains_pending(&stale_hash),
        "the replay must be unsolicited after its request was applied"
    );

    blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
        blocks[0].clone(),
    ))?;
    sync.tick();

    assert!(!sync.block_stager.lock().contains(&stale_hash));
    let window = sync.download_window.lock();
    assert_eq!(window.pending_len(), 0);
    assert_eq!(window.received_len(), 0);
    assert!(!window.contains_pending(&stale_hash));
    Ok(())
}

#[test]
fn received_only_state_uses_scan_path_without_duplicate_request()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let received_hash = Hash256::from_le_bytes(expected[1].as_bytes());
    {
        let mut window = sync.download_window.lock();
        let needs_height = window.mark_received(received_hash, 80, Instant::now());
        assert!(needs_height);
        window.update_received_height(&received_hash, 2);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 3));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(
        witness_block_inventory(inventory)?,
        alloc::vec![expected[0], expected[2]]
    );
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_retries_expired_pending_before_new_heights() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(5)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 2,
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(first) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected first getdata").into());
    };
    assert_eq!(witness_block_inventory(first)?, expected[..2]);
    let _headers = rx.try_recv()?;

    sync.tick();

    let Message::GetData(second) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected retry getdata").into());
    };
    assert_eq!(witness_block_inventory(second)?, expected[..2]);
    Ok(())
}

#[test]
fn stager_evicts_same_height_fork_before_expected_hash() -> Result<(), Box<dyn std::error::Error>> {
    let expected_hash = Hash256::from_le_bytes(&[0x11; 32]);
    let fork_hash = Hash256::from_le_bytes(&[0x22; 32]);
    let mut stager = super::super::BlockStager::new(super::super::SyncBudget {
        max_received_blocks: 1,
        max_received_bytes: usize::MAX,
        ..super::super::default_sync_budget()
    });
    let now = Instant::now();
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));

    let super::super::StagedBlock::Memory { dropped, .. } = stager.insert(
        fork_hash,
        Some(expected_hash),
        block.clone(),
        serialized.clone(),
        now,
    ) else {
        return Err(std::io::Error::other("fork block should stage").into());
    };
    assert!(dropped.is_empty());

    let super::super::StagedBlock::Memory { dropped, .. } =
        stager.insert(expected_hash, Some(expected_hash), block, serialized, now)
    else {
        return Err(std::io::Error::other("expected block should stage").into());
    };
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].hash, fork_hash);
    assert_eq!(stager.received_len(), 1);
    assert!(stager.contains(&expected_hash));
    Ok(())
}

#[test]
fn oversized_received_block_releases_pending_budget_for_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block = mined_block_with_prev_hash(
        genesis.block_hash(),
        1,
        vec![coinbase_transaction(1), transaction(0x41)],
    );
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block_id = tree.insert_node(Some(genesis_id), block.header, NodeStatus::HeaderValid)?;
    let expected_hash = BlockHash::from(tree.node(block_id)?.hash);

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
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
            max_received_bytes: 1,
            max_peer_inflight: 1,
            getdata_batch_limit: 1,
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
    assert_eq!(
        witness_block_inventory(inventory)?,
        alloc::vec![expected_hash]
    );
    let _headers = rx.try_recv()?;
    assert_eq!(sync.download_window.lock().pending_len(), 1);

    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block))?;
    sync.drain_inbound_blocks();

    {
        let window = sync.download_window.lock();
        assert_eq!(window.pending_len(), 0);
        assert_eq!(window.pending_bytes(), 0);
    }

    sync.tick();

    let Message::GetData(retry) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
    Ok(())
}

#[test]
fn staging_byte_exhaustion_backpressures_requests_then_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let block1_hash = block1.block_hash();
    let block2_hash = block2.block_hash();
    let block3_hash = block3.block_hash();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    let block2_id = tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
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
    // Staging byte budget that exactly one staged block exhausts.
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_bytes: consensus_bytes(&block2).len(),
            getdata_batch_limit: 2,
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
    assert_eq!(
        witness_block_inventory(inventory)?,
        alloc::vec![block1_hash, block2_hash]
    );
    let _headers = rx.try_recv()?;

    // Deliver only the successor: it stages (waiting on block1) and
    // exactly exhausts the staging byte budget.
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2.clone()))?;
    sync.drain_inbound_blocks();
    assert_eq!(
        sync.block_stager.lock().received_bytes(),
        consensus_bytes(&block2).len()
    );

    // Exhausted staging degrades to backpressure: the next tick requests
    // nothing further (block3 stays unrequested) and the staged block is
    // not dropped for re-download.
    sync.tick();
    assert!(rx.try_recv().is_err());
    assert_eq!(sync.block_stager.lock().received_len(), 1);

    // The window-front block arrives: the stager admits it past the
    // exhausted budget (expected-block exemption), apply drains both, and
    // request capacity returns for block3.
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block1))?;
    sync.tick();

    let applied_height = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
        .height;
    assert_eq!(applied_height, 2);
    assert_eq!(sync.block_stager.lock().received_len(), 0);
    let Message::GetData(recovered) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected recovery getdata").into());
    };
    assert_eq!(
        witness_block_inventory(recovered)?,
        alloc::vec![block3_hash]
    );
    Ok(())
}

#[test]
fn staging_byte_exhaustion_blocks_all_requests() -> Result<(), Box<dyn std::error::Error>> {
    let ExhaustionFixture {
        sync,
        stalled_rx,
        healthy_rx,
        ..
    } = staging_exhaustion_fixture()?;

    // While the staged bytes are exhausted no getdata is issued at all —
    // the gate is checked before expired-pending retry, so even though
    // block1's pending entry is already expired (zero pending timeout)
    // neither peer is asked for anything.
    sync.tick();
    while let Ok(message) = stalled_rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(std::io::Error::other(
                "exhausted staging must not request from the stalled peer",
            )
            .into());
        }
    }
    while let Ok(message) = healthy_rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(std::io::Error::other(
                "exhausted staging must not request getdata from the healthy peer",
            )
            .into());
        }
    }
    assert_eq!(sync.block_stager.lock().received_len(), 1);
    Ok(())
}

#[test]
fn staging_byte_exhaustion_recovers_via_staged_block_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let ExhaustionFixture {
        sync,
        stalled_rx,
        healthy_rx,
        block1_hash,
        block2_hash,
        ..
    } = staging_exhaustion_fixture()?;

    // Drain the first tick's messages before testing recovery.
    sync.tick();
    while stalled_rx.try_recv().is_ok() {}

    // Let the staged successor outlive its received timeout, then tick:
    // prune_expired drops it, drop_received_for_retry releases its bytes
    // (gate reopens), and expire_pending re-queues the stalled frontier
    // height-first toward the healthy peer.
    std::thread::sleep(Duration::from_millis(125));
    sync.tick();

    assert_eq!(sync.block_stager.lock().received_len(), 0);
    {
        let window = sync.download_window.lock();
        assert_eq!(window.received_len(), 0);
        assert!(window.has_request_capacity());
        assert!(window.contains_pending(&Hash256::from_le_bytes(block1_hash.as_bytes())));
    }
    let Message::GetData(retry) = healthy_rx.try_recv()? else {
        return Err(std::io::Error::other("expected healthy peer retry getdata").into());
    };
    assert_eq!(
        witness_block_inventory(retry)?,
        alloc::vec![block1_hash, block2_hash]
    );
    while let Ok(message) = stalled_rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(
                std::io::Error::other("stalled peer should not receive retry getdata").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn drain_inbound_blocks_keeps_oversized_burst_within_received_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = deterministic_proxy_fixture()?;
    let max_received_blocks = 2;
    install_budget(
        &fixture.sync,
        super::super::SyncBudget {
            max_received_blocks,
            max_received_bytes: usize::MAX,
            ..super::super::default_sync_budget()
        },
    );

    for block in fixture.blocks[1..6].iter().rev() {
        fixture
            .inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
    }

    fixture.sync.drain_inbound_blocks();

    assert!(
        fixture.sync.block_stager.lock().received_len() <= max_received_blocks,
        "block stager must enforce received block count budget"
    );
    assert!(
        fixture.sync.download_window.lock().received_len() <= max_received_blocks,
        "download window must mirror received block count budget"
    );
    assert!(
        fixture.applied_tip.load_full().is_none(),
        "missing next expected block should prevent out-of-order apply"
    );
    Ok(())
}
