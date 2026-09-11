use super::*;

#[test]
fn unsolicited_stale_block_retries_from_resolved_header_height()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block1_hash = block1.block_hash();
    let expected_hash = block2.block_hash();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
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
            getdata_batch_limit: 2,
            received_timeout: Duration::ZERO,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(initial) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected initial getdata").into());
    };
    assert_eq!(
        witness_block_inventory(initial)?,
        alloc::vec![block1_hash, expected_hash]
    );
    let _headers = rx.try_recv()?;
    {
        let mut window = sync.download_window.lock();
        window.mark_applied(&Hash256::from_le_bytes(block1_hash.as_bytes()));
        window.mark_applied(&Hash256::from_le_bytes(expected_hash.as_bytes()));
    }

    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
    sync.drain_inbound_blocks();

    assert_eq!(sync.block_stager.lock().received_len(), 0);
    assert_eq!(sync.download_window.lock().received_len(), 0);

    sync.tick();

    let Message::GetData(retry) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected height-2 retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
    Ok(())
}

#[test]
fn applied_ancestry_lookup_uses_active_index_only_for_applied_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let main1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let main2 = mined_block_with_prev_hash(main1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let main3 = mined_block_with_prev_hash(main2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let main4 = mined_block_with_prev_hash(main3.block_hash(), 4, vec![coinbase_transaction(4)]);
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let main1_id = tree.insert_node(Some(genesis_id), main1.header, NodeStatus::HeaderValid)?;
    let main2_id = tree.insert_node(Some(main1_id), main2.header, NodeStatus::HeaderValid)?;
    let applied_tip = tree
        .tip()
        .ok_or_else(|| std::io::Error::other("main tip was not published"))?;
    let main3_id = tree.insert_node(Some(main2_id), main3.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(main3_id), main4.header, NodeStatus::HeaderValid)?;
    let active_tip = tree
        .tip()
        .ok_or_else(|| std::io::Error::other("extended main tip was not published"))?;

    assert_eq!(
        BlockSync::indexed_applied_ancestry_tip(&tree, &applied_tip),
        Some(active_tip.tip_id),
        "an applied prefix must use the indexed active tip"
    );

    let mut fork_parent = genesis_id;
    let mut fork_prev = genesis.block_hash();
    for height in 1_u32..=5 {
        let fork = mined_block_with_prev_hash(
            fork_prev,
            height.saturating_add(100),
            vec![coinbase_transaction(height.saturating_add(100))],
        );
        fork_prev = fork.block_hash();
        fork_parent = tree.insert_node(Some(fork_parent), fork.header, NodeStatus::HeaderValid)?;
    }
    assert_ne!(
        tree.tip()
            .ok_or_else(|| std::io::Error::other("fork tip was not published"))?
            .tip_id,
        active_tip.tip_id
    );
    assert_eq!(
        BlockSync::indexed_applied_ancestry_tip(&tree, &applied_tip),
        None,
        "an applied tip outside the active header chain must retain side-chain bodies"
    );
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

/// A recorded Fatal settlement halts further apply attempts: staged blocks
/// stay queued, no new transition starts, and the latched tick reports
/// idle instead of churning an `AlreadyActive` refusal every round.
#[test]
fn fatal_settlement_halts_further_apply_attempts() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    stage_body(&sync, &main[0]);
    let staged = sync.block_stager.lock().received_len();
    assert!(
        staged > 0,
        "the staged block must be queued before the halt"
    );
    assert!(
        !sync.apply_halted.load(std::sync::atomic::Ordering::SeqCst),
        "a fresh sync object must not start halted"
    );
    sync.note_fatal_settlement(0, &crate::apply::error::ApplyError::BlockValueOverflow);
    assert_eq!(
        sync.apply_buffered_blocks(None),
        (0, 0),
        "a halted sync must not start another transition"
    );
    assert_eq!(
        sync.block_stager.lock().received_len(),
        staged,
        "halted ticks must preserve staged blocks for recreation"
    );
    Ok(())
}

#[test]
fn permanent_forward_failure_purges_invalid_blocks_without_retry()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Amount;
    let (sync, _peers, applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    sync.ensure_genesis_tip();
    stage_body(&sync, &main[0]);
    assert_eq!(sync.apply_buffered_blocks(None), (1, 0));

    let main_hash = main[0].block_hash();
    let bad = mined_block_with_prev_hash(main_hash, 2, vec![coinbase_transaction(2)]);
    // The value change alters the txid, so the staged body contradicts the
    // header's merkle root: a permanent consensus failure.
    let mut bad_body = bad.clone();
    bad_body.txs[0].outputs[0].value = Amount::from_sat(2);
    let descendant = mined_block_with_prev_hash(bad.block_hash(), 3, vec![coinbase_transaction(3)]);
    {
        let mut tree = sync.handles.block_tree.write();
        let main_id = tree
            .lookup(Hash256::from_le_bytes(main_hash.as_bytes()))
            .ok_or_else(|| std::io::Error::other("missing applied main block"))?;
        let bad_id = tree.insert_node(Some(main_id), bad.header, NodeStatus::HeaderValid)?;
        tree.insert_node(Some(bad_id), descendant.header, NodeStatus::HeaderValid)?;
    }
    stage_body(&sync, &bad_body);
    stage_body(&sync, &descendant);

    assert_eq!(
        sync.apply_buffered_blocks(None),
        (0, 1),
        "the permanent failure must stop the window with nothing committed"
    );
    let bad_hash = Hash256::from_le_bytes(bad.block_hash().as_bytes());
    let descendant_hash = Hash256::from_le_bytes(descendant.block_hash().as_bytes());
    assert!(!sync.block_stager.lock().contains(&bad_hash));
    let descendant_staged = sync.block_stager.lock().contains(&descendant_hash);
    assert!(
        !descendant_staged,
        "invalid descendants must be purged from bounded staging"
    );
    assert_eq!(
        sync.apply_buffered_blocks(None),
        (0, 0),
        "the frontier must not cycle: nothing re-offers the invalidated blocks"
    );
    assert_eq!(applied_tip.load_full().map(|tip| tip.height), Some(1));
    Ok(())
}
