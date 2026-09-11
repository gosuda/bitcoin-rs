use super::*;

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

#[test]
fn apply_cache_miss_populates_and_then_hits() -> Result<(), Box<dyn std::error::Error>> {
    // 8 block bodies available as headers, but only the first three staged
    // this round. A small pending budget caps the cached horizon at 5.
    let fixture = apply_cache_fixture(8, 0)?;
    install_budget(
        &fixture.sync,
        super::super::SyncBudget {
            max_pending_blocks: 5,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 64,
            max_received_bytes: usize::MAX,
            ..super::super::default_sync_budget()
        },
    );
    assert!(
        cache_snapshot(&fixture.sync).is_none(),
        "cache starts empty so the first apply round is a miss"
    );

    for block in &fixture.blocks[..3] {
        stage_body(&fixture.sync, block);
    }
    let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!((applied, failed), (3, 0), "three staged bodies apply");
    assert_eq!(
        fixture.applied_tip.load_full().map(|tip| tip.height),
        Some(3)
    );

    // Miss path populated the cache with the full 5-block horizon, then the
    // post-apply advance moved the offset past the three applied blocks.
    let cache = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
    assert_eq!(
        cache.hashes.len(),
        5,
        "horizon capped at max_pending_blocks"
    );
    assert_eq!(cache.offset, 3, "advance moved offset past applied blocks");
    assert_eq!(cache.applied_tip_height, 3);
    assert_eq!(
        cache.applied_tip_hash,
        Hash256::from_le_bytes(fixture.blocks[2].block_hash().as_bytes())
    );
    assert_eq!(
        cache.chain_tip_hash,
        fixture
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?
            .hash
    );
    let cached_suffix = cache.hashes[cache.offset..].to_vec();

    // Stage block #4: this round must be a cache HIT (validity keys match the
    // advanced cache), draining from the retained suffix rather than re-walking.
    stage_body(&fixture.sync, &fixture.blocks[3]);
    let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!(
        (applied, failed),
        (1, 0),
        "fourth body applies on the hit path"
    );
    assert_eq!(
        fixture.applied_tip.load_full().map(|tip| tip.height),
        Some(4)
    );
    let cache = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("hit path dropped the apply cache"))?;
    assert_eq!(
        cache.offset, 4,
        "hit path advanced offset within the same run"
    );
    assert_eq!(
        cached_suffix.first().copied(),
        Some(Hash256::from_le_bytes(
            fixture.blocks[3].block_hash().as_bytes()
        )),
        "fourth applied block was already present in the populated horizon"
    );
    Ok(())
}

#[test]
fn apply_cache_invalidated_on_failed_apply() -> Result<(), Box<dyn std::error::Error>> {
    // Fail persisting height 2 so the second apply in the batch fails after
    // the first succeeds, exercising the failed-apply invalidation branch.
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
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
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let mut handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let fail_once_store = Arc::new(FailOnceBodyStore::new(2));
    handles.block_body_store = Some(fail_once_store);
    let sync = BlockSync::for_test(handles, peers, inbound_headers_rx, inbound_blocks_rx);
    sync.ensure_genesis_tip();

    for block in [&block1, &block2, &block3] {
        stage_body(&sync, block);
    }
    let (applied, failed) = sync.apply_buffered_blocks(None);
    assert_eq!(applied, 1, "height 1 applies before the height 2 failure");
    assert_eq!(failed, 1, "height 2 persistence failure aborts the batch");
    assert!(
        cache_snapshot(&sync).is_none(),
        "a failed apply must invalidate the populated cache"
    );
    Ok(())
}

#[test]
fn apply_cache_horizon_capped_by_pending_budget() -> Result<(), Box<dyn std::error::Error>> {
    // 12 header-backed bodies available, pending budget capped at 4. Stage a
    // single body: the populated horizon must not exceed the budget even
    // though far more headers are available above the applied tip.
    let fixture = apply_cache_fixture(12, 0)?;
    let cap = 4;
    install_budget(
        &fixture.sync,
        super::super::SyncBudget {
            max_pending_blocks: cap,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 64,
            max_received_bytes: usize::MAX,
            ..super::super::default_sync_budget()
        },
    );

    stage_body(&fixture.sync, &fixture.blocks[0]);
    let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!((applied, failed), (1, 0));
    let cache = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
    assert_eq!(
        cache.hashes.len(),
        cap,
        "horizon must be capped at max_pending_blocks even with more headers available"
    );
    // The cached run begins at applied_tip + 1 (height 1) and stays contiguous.
    assert_eq!(
        cache.hashes[0],
        Hash256::from_le_bytes(fixture.blocks[0].block_hash().as_bytes())
    );
    assert_eq!(
        cache.hashes[cap - 1],
        Hash256::from_le_bytes(fixture.blocks[cap - 1].block_hash().as_bytes())
    );
    Ok(())
}

#[test]
fn on_peer_ready_clears_same_address_header_state_for_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture { sync, .. } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    *sync.pending_getheaders.lock() = Some(super::super::PendingHeaderRequest {
        peer_addr,
        locator_tip_hash: Hash256::default(),
        target_height: 1,
        requested_at: Instant::now(),
    });
    register_info(&sync.peer_table, synthetic_peer(peer_addr, 1));
    let source = current_source(&sync.peer_table, peer_addr);
    sync.on_peer_ready(source);
    assert!(
        sync.pending_getheaders.lock().is_none(),
        "replacement readiness must drop address-scoped header state"
    );
    Ok(())
}

#[test]
fn on_peer_ready_ignores_stale_predecessor_source() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture { sync, .. } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let (stale_tx, _stale_rx) = unbounded::<Message>();
    let stale = PeerLease::new(stale_tx);
    sync.peer_table.register(peer_addr, stale.clone());
    register_info(&sync.peer_table, synthetic_peer(peer_addr, 2));
    *sync.pending_getheaders.lock() = Some(super::super::PendingHeaderRequest {
        peer_addr,
        locator_tip_hash: Hash256::default(),
        target_height: 1,
        requested_at: Instant::now(),
    });
    sync.on_peer_ready(stale.source(peer_addr));
    assert!(
        sync.pending_getheaders.lock().is_some(),
        "stale predecessor must not clear the replacement's header state"
    );
    Ok(())
}

#[test]
fn far_future_matching_peer_retries_without_peer_blame() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let (tx, rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peers.register(peer_addr, lease.clone());
    peers.publish_info(peer_addr, &lease, synthetic_peer(peer_addr, 8));
    let tip_before = sync
        .handles
        .chain_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing genesis tip"))?;

    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![far_future_header(genesis.compute_hash(), 1)?],
        source: Some(current_source(&peers, peer_addr)),
    })?;
    sync.tick();

    assert_eq!(
        sync.handles.chain_tip.load_full().as_deref(),
        Some(tip_before.as_ref())
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    assert!(rx.try_recv().is_err());
    assert!(
        !lease.is_cancelled(),
        "local-clock rejection must not cancel the peer lease"
    );
    assert!(peers.is_connected(peer_addr));
    assert!(peers.is_connected(peer_addr));
    assert!(
        !sync
            .download_window
            .lock()
            .peer_in_staller_cooldown(peer_addr, Instant::now()),
        "local-clock rejection must not blame the peer"
    );
    Ok(())
}

/// Mines `depth` regtest blocks on genesis and applies them. Block 1's
/// coinbase pays the full subsidy, and the tip block carries a matured
/// spend of that coin paying a fee far above min-relay, so a reorg that
/// disconnects the chain has a real readmission candidate. Returns the
/// handles, the blocks, and their serialized bodies for the reorg body
/// loader.
#[allow(clippy::type_complexity)]
#[test]
fn tick_sorts_out_of_order_peers_before_requesting_blocks() -> Result<(), Box<dyn std::error::Error>>
{
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let low_addr = test_addr(9500, 0)?;
    let high_addr = test_addr(9500, 1)?;
    let low_rx = connect_peer(&peers, synthetic_peer(low_addr, 2));
    let high_rx = connect_peer(&peers, synthetic_peer(high_addr, 8));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = high_rx.try_recv()? else {
        return Err(std::io::Error::other("expected high peer getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected);
    assert!(matches!(high_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(low_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn same_address_registration_clears_getheaders_gate_and_routes_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
        },
    );
    let addr = test_addr(9501, 0)?;
    let old_rx = connect_peer(&peers, synthetic_peer(addr, 8));
    sync.tick();
    assert!(matches!(old_rx.try_recv()?, Message::GetHeaders(_)));

    let (new_tx, new_rx) = unbounded::<Message>();
    let new_lease = PeerLease::new(new_tx);
    peers.register(addr, new_lease.clone());
    peers.publish_info(addr, &new_lease, synthetic_peer(addr, 8));
    sync.tick();

    assert!(old_rx.try_recv().is_err());
    assert!(matches!(new_rx.try_recv()?, Message::GetHeaders(_)));
    Ok(())
}

#[test]
fn tick_uses_highest_peer_for_headers_when_request_capacity_is_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
        },
    );
    let low_rx = connect_peer(&peers, synthetic_peer(test_addr(9502, 0)?, 5));
    let high_rx = connect_peer(&peers, synthetic_peer(test_addr(9502, 1)?, 9));

    sync.tick();

    assert!(matches!(high_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(low_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_bounded_request_peer_selection_preserves_equal_height_order()
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
    let first_rx = connect_peer(&peers, synthetic_peer(test_addr(9503, 0)?, 100));
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    assert_eq!(
        witness_block_inventory(match first_rx.try_recv()? {
            Message::GetData(inventory) => inventory,
            _ => return Err(std::io::Error::other("expected first getdata").into()),
        })?,
        expected[..2]
    );
    let _ = first_rx.try_recv()?;

    let second_rx = connect_peer(&peers, synthetic_peer(test_addr(9503, 1)?, 100));
    sync.tick();
    assert_eq!(
        witness_block_inventory(match second_rx.try_recv()? {
            Message::GetData(inventory) => inventory,
            _ => return Err(std::io::Error::other("expected second getdata").into()),
        })?,
        expected[2..4]
    );
    Ok(())
}
