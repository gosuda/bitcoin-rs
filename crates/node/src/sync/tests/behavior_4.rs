use super::*;

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
fn tick_fills_mixed_retry_and_new_height_batch() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 3,
            max_pending_bytes: 3 * 256 * 1024,
            max_peer_inflight: 3,
            getdata_batch_limit: 3,
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
    assert_eq!(witness_block_inventory(first)?, expected[..3]);
    let _headers = rx.try_recv()?;
    sync.download_window
        .lock()
        .mark_applied(&Hash256::from_le_bytes(expected[0].as_bytes()));

    sync.tick();

    let Message::GetData(second) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected mixed retry getdata").into());
    };
    assert_eq!(
        witness_block_inventory(second)?,
        vec![expected[1], expected[2], expected[3]]
    );
    Ok(())
}

#[test]
fn tick_applies_contiguous_blocks_before_requesting_more() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let child = test_header(genesis.block_hash(), 1);
    let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
    let expected = BlockHash::from(tree.node(child_id)?.hash);

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
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(genesis))?;

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, alloc::vec![expected]);
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
fn deterministic_initial_sync_proxy_reports_pipeline_budgets()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = TestRecorder::default();
    metrics::with_local_recorder(&recorder, || {
        let fixture = deterministic_proxy_fixture()?;
        let DeterministicProxyFixture {
            sync,
            applied_tip,
            block_tree,
            inbound_blocks_tx,
            outbound_rx,
            blocks,
        } = fixture;

        sync.tick();

        assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        let Message::GetData(inventory) = outbound_rx.try_recv()? else {
            return Err(std::io::Error::other("expected proxy getdata").into());
        };
        let pending_count = inventory.len();
        assert_eq!(pending_count, DETERMINISTIC_PROXY_BLOCKS);
        assert_gauge(&recorder, "node.sync.pending_blocks", pending_count);
        assert_metric_absent(&recorder, "node.sync.received_blocks");
        assert_metric_absent(&recorder, "node.sync.received_bytes");
        let _headers = outbound_rx.try_recv()?;

        for block in blocks[1..].iter().rev() {
            inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
        }
        sync.drain_inbound_blocks();
        let (received_count, peak_staged_bytes) = {
            let stager = sync.block_stager.lock();
            (stager.received_len(), stager.received_bytes())
        };
        assert_eq!(received_count, DETERMINISTIC_PROXY_BLOCKS.saturating_sub(1));
        assert!(peak_staged_bytes > 0);
        assert_gauge(&recorder, "node.sync.received_blocks", received_count);
        assert_gauge(&recorder, "node.sync.received_bytes", peak_staged_bytes);

        inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            blocks[0].clone(),
        ))?;
        let apply_started = quanta::Instant::now();
        sync.drain_inbound_blocks();
        let apply_elapsed = apply_started.elapsed();
        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("proxy apply did not publish tip"))?
            .height;
        assert_eq!(applied_height, DETERMINISTIC_PROXY_TIP_HEIGHT);
        assert_eq!(sync.block_stager.lock().received_len(), 0);
        assert_eq!(sync.download_window.lock().pending_len(), 0);
        assert_histogram(&recorder, "node.sync.apply_buffered_blocks_seconds");

        println!(
            "deterministic_sync_apply_proxy peak_staged_bytes={peak_staged_bytes} pending_count={pending_count} received_count={received_count} contiguous_apply_latency_us={}",
            apply_elapsed.as_micros(),
        );
        Ok(())
    })
}
