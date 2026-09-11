use super::*;

#[test]
fn invalid_nbits_headers_disconnect_source_and_rotate_getheaders()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let invalid_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let other_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let (invalid_tx, invalid_rx) = unbounded::<Message>();
    let (other_tx, other_rx) = unbounded::<Message>();

    // Seed only the invalid peer so the first tick routes a GetHeaders to
    // it and arms the pending gate against its address.
    let invalid_lease = bitcoin_rs_p2p::PeerLease::new(invalid_tx);
    peers.register(invalid_peer, invalid_lease.clone());
    peers.publish_info(
        invalid_peer,
        &invalid_lease,
        synthetic_peer(invalid_peer, 9),
    );

    sync.tick();
    assert!(
        matches!(invalid_rx.try_recv()?, Message::GetHeaders(_)),
        "the first getheaders must target the invalid peer"
    );
    assert!(
        sync.pending_getheaders
            .lock()
            .is_some_and(|request| request.peer_addr == invalid_peer),
        "a pending getheaders must name the invalid peer before its batch arrives"
    );

    // Deliver the attributed invalid batch while the gate is still armed
    // against the invalid peer. No other selectable peer remains, so this
    // tick cannot re-arm the gate against a different address: the only way
    // `pending_getheaders` ends up clear is the peer-fault cleanup.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
        source: Some(current_source(&peers, invalid_peer)),
    })?;
    sync.tick();

    assert!(
        sync.pending_getheaders.lock().is_none(),
        "an attributed invalid-header fault must release the pending getheaders gate"
    );
    assert!(
        !peers.is_connected(invalid_peer),
        "invalid header source must be removed from peer selection"
    );
    assert!(
        !peers.is_connected(invalid_peer),
        "invalid header source must lose its outbound lease"
    );

    // Re-introduce a healthy peer; the next getheaders must rotate to it.
    let other_lease = bitcoin_rs_p2p::PeerLease::new(other_tx);
    peers.register(other_peer, other_lease.clone());
    peers.publish_info(other_peer, &other_lease, synthetic_peer(other_peer, 8));
    sync.tick();
    assert!(
        peers.is_connected(other_peer),
        "healthy peer must remain eligible for rotation"
    );
    assert!(
        peers.is_connected(other_peer),
        "healthy peer must retain its outbound lease"
    );
    assert!(
        invalid_rx.try_recv().is_err(),
        "the invalid peer must not receive another getheaders"
    );
    assert!(
        matches!(other_rx.try_recv()?, Message::GetHeaders(_)),
        "the next getheaders must rotate to the remaining peer"
    );
    Ok(())
}

#[test]
fn unattributed_invalid_headers_do_not_disconnect_any_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let _rx = connect_peer(&peers, synthetic_peer(peer_addr, 8));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
        source: None,
    })?;

    sync.tick();

    assert!(
        peers.is_connected(peer_addr),
        "local injection must not identify an arbitrary peer as faulty"
    );
    assert!(
        peers.is_connected(peer_addr),
        "local injection must preserve peer outbound leases"
    );
    Ok(())
}

#[test]
fn disconnected_outbound_channel_does_not_mark_blocks_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    register_info(&peers, synthetic_peer(addr, 100));
    let (tx, rx) = unbounded::<Message>();
    drop(rx);
    peers.register(addr, bitcoin_rs_p2p::PeerLease::new(tx));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    assert_eq!(sync.download_window.lock().pending_len(), 0);
    Ok(())
}

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
fn stall_eviction_does_not_disconnect_replacement_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = super::super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(super::super::PENDING_TIMEOUT)
    };
    let (sync, peers, _expected, _rxs, _blocks_tx) = staged_count_wedge(budget)?;
    let staller = test_addr(9320, 0)?;
    sync.download_window
        .lock()
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let applied_tip = sync
        .handles
        .applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let next_apply_height = applied_tip
        .height
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("applied height overflow"))?;
    let (replacement_tx, _replacement_rx) = unbounded::<Message>();
    let replacement = PeerLease::new(replacement_tx);
    let evicted = sync.select_and_evict_window_peer(|window| {
        let selected = window.observe_stall(
            next_apply_height,
            false,
            Instant::now() + Duration::from_millis(150),
        );
        peers.register(staller, replacement.clone());
        peers.publish_info(staller, &replacement, eligible_peer(staller, 200));
        selected
    });

    assert_eq!(evicted, None);
    assert!(peers.is_connected(staller));
    assert!(!replacement.is_cancelled());
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
