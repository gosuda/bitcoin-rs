use super::*;

#[test]
fn tick_fanout_distributes_window_front_first_across_eligible_peers()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    let mut rxs = Vec::new();
    for idx in 0..super::super::MIN_PEERS_FOR_FANOUT {
        let addr = test_addr(9001, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    // Effective fan-out stripe (mirrors `effective_peer_inflight`).
    let cap = super::super::PENDING_BUDGET
        .div_ceil(super::super::MIN_PEERS_FOR_FANOUT)
        .clamp(
            super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
            super::super::PEER_INFLIGHT_BUDGET,
        );
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata for every eligible peer").into());
        };
        // Window-front-first and capped: peers are scanned highest-first,
        // each taking the next `cap` in-order heights — fan-out changes
        // who is asked, never what order the window wants.
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * cap..(idx + 1) * cap]
        );
        if idx == 0 {
            if !matches!(rx.try_recv()?, Message::GetHeaders(_)) {
                return Err(std::io::Error::other("expected getheaders for header peer").into());
            }
        }
        assert!(rx.try_recv().is_err(), "no peer may exceed the fan-out cap");
    }
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET,
        "fan-out must fill the deep window"
    );
    Ok(())
}

#[test]
fn wedged_window_expires_stalled_front_and_rerequests_through_count_clamp()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, expected, rxs, _blocks_tx) =
        staged_count_wedge(wedge_budget(Duration::from_millis(250)))?;

    // Tick 2: wedge — staged + pending at the count budget, scan limit
    // zero, the stalled front still pending.
    sync.tick();
    assert_eq!(sync.download_window.lock().pending_len(), 2);

    // Past the pending timeout the wedge must process its own deadlines:
    // the expired front credits the scan-limit count headroom, the
    // request path expires it (U5 chain through the new clamps' pending
    // terms), soft demotion keeps the staller out, and a healthy peer is
    // asked for the front stripe — all without the received-prune
    // discarding a single staged block into re-download.
    std::thread::sleep(Duration::from_millis(300));
    sync.tick();

    assert_no_getdata(&rxs[0])?;
    let mut rerequested = Vec::new();
    for rx in &rxs[1..] {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                rerequested.extend(witness_block_inventory(inventory)?);
            }
        }
    }
    assert_eq!(
        rerequested,
        expected[..2],
        "the stalled front stripe must be re-requested from a healthy peer"
    );
    assert_eq!(
        sync.block_stager.lock().received_len(),
        14,
        "staged progress must survive the wedge"
    );
    {
        let window = sync.download_window.lock();
        assert_eq!(window.pending_len(), 2);
        for front in &expected[..2] {
            assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
        }
    }
    Ok(())
}

#[test]
fn common_prefix_winner_takes_over_deep_window() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(16)?;
    let owner = test_addr(9321, 0)?;
    let alternate = test_addr(9321, 1)?;
    let owner_rx = connect_peer(&peers, eligible_peer(owner, 200));
    let alternate_rx = connect_peer(&peers, eligible_peer(alternate, 100));

    sync.tick();
    assert_eq!(
        witness_block_inventory(next_getdata(&owner_rx)?)?,
        blocks.iter().map(Block::block_hash).collect::<Vec<_>>()
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&alternate_rx)?)?,
        blocks[..8]
            .iter()
            .map(Block::block_hash)
            .collect::<Vec<_>>()
    );

    for block in &blocks[..4] {
        let mut inbound = bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(current_source(&peers, alternate));
        blocks_tx.send(inbound)?;
    }
    sync.tick();

    assert_eq!(
        sync.download_window.lock().preferred_peer(),
        Some(alternate)
    );
    assert!(
        sync.download_window
            .lock()
            .peer_in_staller_cooldown(owner, Instant::now())
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&alternate_rx)?)?,
        blocks[4..]
            .iter()
            .map(Block::block_hash)
            .collect::<Vec<_>>()
    );
    assert!(peers.is_connected(owner));
    sync.download_window
        .lock()
        .mark_peer_unresponsive(alternate, Instant::now());
    sync.tick();
    assert_eq!(
        sync.download_window.lock().preferred_peer(),
        Some(alternate),
        "a temporary soft block skips the winner without erasing its election"
    );
    Ok(())
}

#[test]
fn byte_wedged_window_recovers_via_staller_disconnect_before_received_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    // RE-ADV-1 byte-denominated R+P wedge: staged bytes + the stalled
    // front's estimated bytes exhaust the staging byte headroom, so the
    // request gate is closed while the gate itself (`staged_bytes_
    // exhausted`) is still open. Both 1-minute timeouts are live
    // defaults here — pre-U7 the received-prune was the only recovery;
    // now the staller disconnect frees the wedge in well under a second.
    let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(2)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            // One initial-estimate slot (the pending front) plus the
            // delivered successor: byte headroom is exactly zero once
            // both are accounted.
            max_received_bytes: 256 * 1024 + consensus_bytes(&blocks[1]).len(),
            // Phase 1: arming reads the staged-count fraction, not
            // request capacity, so the single staged successor must be
            // >= half the count window (2 / 2 = 1) for the episode to
            // arm. The byte clamp still closes the request gate (the
            // wedge under test); the count budget only sizes the arming
            // bar to this two-block construction.
            max_received_blocks: 2,
            getdata_batch_limit: 2,
            stall_timeout_initial: Duration::from_millis(100),
            ..super::super::default_sync_budget()
        },
    );
    let staller = test_addr(9430, 0)?;
    let honest = test_addr(9430, 1)?;
    let staller_rx = connect_peer(&peers, synthetic_peer(staller, 200));
    let honest_rx = connect_peer(&peers, synthetic_peer(honest, 100));

    // Cold-start disarm: this byte-wedge construction depends on the
    // pristine 256KiB initial block-size estimate, so the cadence EWMA
    // is seeded directly instead of via two real front deliveries (the
    // real sampling path is pinned by the window tests). 50ms keeps the
    // decay floor at the injected 100ms initial threshold.
    sync.download_window
        .lock()
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let Message::GetData(inventory) = staller_rx.try_recv()? else {
        return Err(std::io::Error::other("expected staller getdata").into());
    };
    assert_eq!(
        witness_block_inventory(inventory)?,
        alloc::vec![blocks[0].block_hash(), blocks[1].block_hash()]
    );

    // The successor stages; byte headroom hits zero (R + P at the byte
    // budget) with the front still pending to the staller.
    blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
        blocks[1].clone(),
    ))?;
    sync.tick();
    {
        let window = sync.download_window.lock();
        assert!(!window.has_request_capacity());
        assert_eq!(window.stalling_peer().map(|(addr, _)| addr), Some(staller));
    }
    assert!(honest_rx.try_recv().is_err());

    // Fire: the staller's disconnect releases its pending bytes, which
    // reopens exactly enough headroom to re-request the front from the
    // honest peer — with the staged successor untouched (the 1-minute
    // prune never ran).
    std::thread::sleep(Duration::from_millis(150));
    sync.tick();
    assert!(!peers.is_connected(staller));
    assert_eq!(
        sync.block_stager.lock().received_len(),
        1,
        "recovery must not discard staged progress (prune-free)"
    );
    let Message::GetData(retry) = honest_rx.try_recv()? else {
        return Err(std::io::Error::other("expected honest peer front retry").into());
    };
    assert_eq!(
        witness_block_inventory(retry)?,
        alloc::vec![blocks[0].block_hash()]
    );

    blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
        blocks[0].clone(),
    ))?;
    sync.tick();
    // The re-request narrowed the expected-apply cache to the front, so
    // the staged successor drains on the following tick's tree walk.
    sync.tick();
    let applied_height = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
        .height;
    assert_eq!(applied_height, 2, "the byte wedge must fully recover");
    Ok(())
}

#[test]
fn single_peer_can_fill_default_pending_window() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 300));

    let mut requested = Vec::new();
    let ticks = super::super::PENDING_BUDGET / super::super::GETDATA_BATCH_SIZE;
    assert_eq!(
        ticks, 1,
        "default getdata batch should fill the pending window in one tick"
    );
    for tick in 0..ticks {
        sync.tick();
        if tick == 0 {
            assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
        }
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        requested.extend(witness_block_inventory(inventory)?);
        let _headers = rx.try_recv()?;
    }

    assert_eq!(requested, expected);
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET
    );
    Ok(())
}

#[test]
fn tick_preserves_partial_window_order_across_pending_gap() -> Result<(), Box<dyn std::error::Error>>
{
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(5)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 4,
            max_pending_bytes: 4 * 256 * 1024,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
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
    assert_eq!(witness_block_inventory(first)?, expected[..4]);
    let _headers = rx.try_recv()?;
    {
        let mut window = sync.download_window.lock();
        window.mark_applied(&Hash256::from_le_bytes(expected[0].as_bytes()));
        window.drop_for_retry(&Hash256::from_le_bytes(expected[1].as_bytes()));
    }

    sync.tick();

    let Message::GetData(second) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected gap-filling getdata").into());
    };
    assert_eq!(
        witness_block_inventory(second)?,
        vec![expected[1], expected[4]]
    );
    assert_eq!(sync.download_window.lock().pending_len(), 4);
    Ok(())
}

#[test]
fn batch_drain_restores_unapplied_tail_after_mid_batch_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let block2_hash = Hash256::from_le_bytes(block2.block_hash().as_bytes());
    let block3_hash = Hash256::from_le_bytes(block3.block_hash().as_bytes());

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
    let mut handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let fail_once_store = Arc::new(FailOnceBodyStore::new(2));
    handles.block_body_store = Some(fail_once_store.clone());
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block3))?;
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2.clone()))?;
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block1))?;
    sync.tick();

    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "height 1 should apply before the fail-once height 2 body persistence error"
    );
    assert_eq!(sync.block_stager.lock().received_len(), 1);
    assert_eq!(sync.download_window.lock().received_len(), 1);
    assert!(
        !sync.block_stager.lock().contains(&block2_hash),
        "failed block should be dropped for retry rather than restored"
    );
    assert!(
        sync.block_stager.lock().contains(&block3_hash),
        "tail block must be restored after the mid-batch failure"
    );
    // The mid-batch failure must hand the gateway generation back so the
    // retry can begin a new transition. Leaving it odd refused every
    // later apply at the gate with the same "clean shutdown has begun"
    // text and no log line — the silent tip wedge observed live on the
    // explorer node (issue #618 post-#657 field report). The committed
    // prefix is per-block atomic and no authoritative UTXO mutation
    // occurred for the failed block, so the even generation is safe to
    // restore.
    assert!(
        sync.handles.mempool_gateway.stable_generation().is_some(),
        "generation must be even after mid-batch failure so the retry can begin"
    );

    // The retry actually applies: the re-sent block 2 (the fail-once
    // body store succeeds on its second attempt) must advance the tip
    // past the failed height instead of being refused at the gate.
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
    sync.tick();

    let retry_height = applied_tip.load_full().map(|tip| tip.height);
    assert!(
        retry_height.is_some_and(|height| height >= 2),
        "retry must advance past the failed height, got {retry_height:?}"
    );
    assert!(
        sync.handles.mempool_gateway.stable_generation().is_some(),
        "generation must stay even after the retry"
    );
    assert!(fail_once_store.persisted_height(1));
    Ok(())
}

#[test]
fn settle_window_failure_finish_failure_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
    let transition = sync.handles.begin_transition()?;
    // Force a different odd generation so the CAS in finish fails.
    sync.handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation().wrapping_add(2));
    let error = crate::apply::WindowApplyError {
        applied: 0,
        committed: Vec::new(),
        source: crate::apply::error::ApplyError::BlockValueOverflow,
        disposition: crate::apply::WindowApplyDisposition::Operational,
        invalidated: Box::default(),
    };

    let error = super::super::settle_window_failure(transition, error);

    assert_eq!(
        error.disposition,
        crate::apply::WindowApplyDisposition::Fatal,
        "finish failure must be classified Fatal"
    );
    assert!(
        matches!(
            error.source,
            crate::apply::error::ApplyError::BlockValueOverflow
        ),
        "original source must be preserved, not overwritten by the finish error"
    );
    assert_eq!(
        sync.handles.mempool_gateway.stable_generation(),
        None,
        "generation must stay odd after a failed finish"
    );
    Ok(())
}

#[test]
fn settle_window_success_finish_failure_is_fatal() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
    let transition = sync.handles.begin_transition()?;
    // Force a different odd generation so the CAS in finish fails.
    sync.handles
        .mempool_gateway
        .force_chain_generation(transition.proof().odd_generation().wrapping_add(2));
    let applied = 2_usize;
    let committed: Vec<crate::apply::ConnectOutcome> = Vec::new();

    let error = match super::super::settle_window_success(transition, applied, committed) {
        Err(error) => error,
        Ok(_) => panic!("finish failure must return Err, got Ok"),
    };

    assert_eq!(
        error.disposition,
        crate::apply::WindowApplyDisposition::Fatal,
        "success-path finish failure must be classified Fatal"
    );
    assert_eq!(error.applied, applied, "applied count must be preserved");
    assert!(
        error.committed.is_empty(),
        "committed outcomes must be preserved"
    );
    assert_eq!(
        sync.handles.mempool_gateway.stable_generation(),
        None,
        "generation must stay odd after a failed finish"
    );
    Ok(())
}

#[test]
fn restore_split_pins_off_by_one() {
    // Full-chunk stop: nothing refused, restore from the next chunk head.
    // The old formula (chunk_start + stopped + 1) returned 5 here.
    assert_eq!(super::super::restore_split(2, 2, 2), 4);
    // Mid-chunk stop: the refused block is dropped, tail starts after it.
    assert_eq!(super::super::restore_split(2, 1, 2), 4);
    // Empty chunk boundary.
    assert_eq!(super::super::restore_split(0, 0, 0), 0);
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
fn apply_cache_invalidated_on_chain_tip_move() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = apply_cache_fixture(4, 0)?;
    install_budget(
        &fixture.sync,
        super::super::SyncBudget {
            max_pending_blocks: 4,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 64,
            max_received_bytes: usize::MAX,
            ..super::super::default_sync_budget()
        },
    );

    // Round 1: stage one body, miss populates the cache, advance retains it
    // with the original chain-tip hash as a validity key.
    stage_body(&fixture.sync, &fixture.blocks[0]);
    let (applied, _failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!(applied, 1);
    let cache = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("miss did not populate apply cache"))?;
    let original_chain_tip_hash = cache.chain_tip_hash;
    assert_eq!(cache.offset, 1);

    // Move the chain tip: publish a snapshot whose hash differs from the one
    // the cache was keyed against (a reorg replaces the active-chain tip).
    let moved_tip = {
        let current = fixture
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?;
        let mut hash_bytes = current.hash.to_le_bytes();
        hash_bytes[0] ^= 0xff;
        TipSnapshot {
            tip_id: current.tip_id,
            height: current.height,
            chainwork: current.chainwork,
            hash: Hash256::from_le_bytes(&hash_bytes),
        }
    };
    fixture.chain_tip.store(Some(Arc::new(moved_tip)));
    assert_ne!(
        fixture
            .chain_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing chain tip"))?
            .hash,
        original_chain_tip_hash,
        "chain tip must move for this test to be meaningful"
    );

    // The decisive probe: with the tip moved, the stale entry must be
    // rejected by its validity keys BEFORE any repopulation can mask a
    // broken eviction (a later apply round always rekeys the cache, so
    // asserting on the post-apply snapshot alone is vacuous).
    assert!(
        fixture.sync.drain_cached_expected_blocks(1).is_none(),
        "stale cache keyed to the old chain tip must not serve a drain"
    );

    // Round 2: stage the next body. The miss recomputes the run against the
    // new tip and repopulates the cache keyed to the moved tip's hash.
    stage_body(&fixture.sync, &fixture.blocks[1]);
    let _ = fixture.sync.apply_buffered_blocks(None);
    let after = cache_snapshot(&fixture.sync)
        .ok_or_else(|| std::io::Error::other("miss did not repopulate apply cache"))?;
    assert_ne!(
        after.chain_tip_hash, original_chain_tip_hash,
        "repopulated cache must be keyed to the moved tip"
    );
    Ok(())
}

#[test]
fn window_failure_applies_prefix_and_restores_suffix() -> Result<(), Box<dyn std::error::Error>> {
    // Blocks now apply in windows, so a mid-window failure has to split the
    // chunk three ways: the prefix committed, the one block that failed, and
    // an untouched suffix that must go back on the stager. Getting that
    // split wrong is invisible to the (applied, failed) counts alone, so
    // this asserts the stager contents too.
    let fixture = apply_cache_fixture(4, 0)?;

    // Corrupt the second body without touching its header: the stager keys
    // on the header hash, so this still drains as the expected block, and
    // apply rejects it on the merkle root. A body that changed its own hash
    // would never be drained and the window would never see it.
    let mut corrupted = fixture.blocks[1].clone();
    corrupted.txs.push(coinbase_transaction(99));
    assert_eq!(
        corrupted.block_hash(),
        fixture.blocks[1].block_hash(),
        "corruption must not move the header hash or the drain never sees it"
    );

    stage_body(&fixture.sync, &fixture.blocks[0]);
    stage_body(&fixture.sync, &corrupted);
    stage_body(&fixture.sync, &fixture.blocks[2]);
    stage_body(&fixture.sync, &fixture.blocks[3]);

    let (applied, failed) = fixture.sync.apply_buffered_blocks(None);
    assert_eq!(
        (applied, failed),
        (1, 1),
        "only the block before the corrupt one commits"
    );
    assert_eq!(
        fixture.applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "the chain stops at the last good block"
    );

    // The merkle-root rejection is a permanent consensus failure, so the
    // window invalidated the corrupted block and its (never-attempted)
    // descendants while the transition was held. They can never become
    // applicable, so instead of returning to the stager they are purged
    // from it: the frontier must not cycle on invalidated blocks.
    let restored = fixture.sync.block_stager.lock().received_len();
    assert_eq!(
        restored, 0,
        "invalidated blocks and their descendants are purged, not restored"
    );
    Ok(())
}
