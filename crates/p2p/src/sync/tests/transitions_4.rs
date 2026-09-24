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
    let invalid_lease = crate::PeerLease::new(invalid_tx);
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
        sync.scheduler
            .lock()
            .header_request
            .is_some_and(|request| request.source.addr == invalid_peer),
        "a pending getheaders must name the invalid peer before its batch arrives"
    );

    // Deliver the attributed invalid batch while the gate is still armed
    // against the invalid peer. No other selectable peer remains, so this
    // tick cannot re-arm the gate against a different address — and the
    // batch is marked a non-response so the wire-response consume cannot
    // clear it either: the only way the header request ends up clear is
    // the peer-fault cleanup.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![nbits_mismatch_header(genesis.compute_hash(), 1)],
        source: Some(current_source(&peers, invalid_peer)),

        wire_response: false,
        body_fetch_owned: false,
    })?;
    sync.tick();

    assert!(
        sync.scheduler.lock().header_request.is_none(),
        "an attributed invalid-header fault must release the pending header request"
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
    let other_lease = crate::PeerLease::new(other_tx);
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

        wire_response: true,
        body_fetch_owned: false,
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
    peers.register(addr, crate::PeerLease::new(tx));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    assert_eq!(sync.scheduler.lock().window.pending_len(), 0);
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
            synthetic_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
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
        sync.scheduler.lock().window.pending_len(),
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
    assert_eq!(sync.scheduler.lock().window.pending_len(), 2);

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
        sync.scheduler.lock().stager.received_len(),
        14,
        "staged progress must survive the wedge"
    );
    {
        let scheduler = sync.scheduler.lock();
        let window = &scheduler.window;
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
    let owner_rx = connect_peer(&peers, synthetic_peer(owner, 200));
    let alternate_rx = connect_peer(&peers, synthetic_peer(alternate, 100));

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
        let mut inbound = crate::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(current_source(&peers, alternate));
        blocks_tx.send(inbound)?;
    }
    sync.tick();

    assert_eq!(
        sync.scheduler.lock().window.preferred_peer(),
        Some(current_source(&peers, alternate))
    );
    assert!(
        sync.scheduler
            .lock()
            .window
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
    sync.scheduler
        .lock()
        .window
        .mark_peer_unresponsive(alternate, Instant::now());
    sync.tick();
    assert_eq!(
        sync.scheduler.lock().window.preferred_peer(),
        Some(current_source(&peers, alternate)),
        "a temporary soft block skips the winner without erasing its election"
    );
    Ok(())
}

/// RC2: a same-address reconnect neither inherits its dead predecessor's
/// deep-window election nor loses its own in-flight work when its
/// readiness is reported.
#[test]
fn same_address_reconnect_does_not_inherit_stalled_inflight()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(16)?;
    let owner = test_addr(9322, 0)?;
    let winner = test_addr(9322, 1)?;
    let owner_rx = connect_peer(&peers, synthetic_peer(owner, 200));
    let winner_rx = connect_peer(&peers, synthetic_peer(winner, 100));
    sync.tick();
    let _ = next_getdata(&owner_rx)?;
    let _ = next_getdata(&winner_rx)?;
    let predecessor = current_source(&peers, winner);
    for block in &blocks[..4] {
        let mut inbound = crate::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(predecessor);
        blocks_tx.send(inbound)?;
    }
    sync.tick();
    let _ = next_getdata(&winner_rx)?;
    let pending_owner = |hash: &BlockHash| {
        sync.scheduler
            .lock()
            .window
            .pending_owner(&Hash256::from_le_bytes(hash.as_bytes()))
    };
    assert!(sync.scheduler.lock().window.preferred_peer().is_some());
    assert!(
        blocks[4..]
            .iter()
            .any(|block| pending_owner(&block.block_hash()) == Some(predecessor)),
        "the elected winner must hold the deep window in flight"
    );

    let (replacement_tx, replacement_rx) = unbounded::<Message>();
    let lease = PeerLease::new(replacement_tx);
    peers.register(winner, lease.clone());
    peers.publish_info(winner, &lease, synthetic_peer(winner, 100));
    let replacement = lease.source(winner);
    sync.on_peer_ready(replacement);
    assert!(
        sync.scheduler.lock().window.preferred_peer().is_none(),
        "the dead connection's election must not pass to its replacement"
    );
    sync.tick();

    let rerequested = witness_block_inventory(next_getdata(&replacement_rx)?)?;
    assert!(!rerequested.is_empty());
    for hash in &rerequested {
        assert_eq!(pending_owner(hash), Some(replacement));
    }

    sync.on_peer_ready(replacement);
    for hash in &rerequested {
        assert_eq!(
            pending_owner(hash),
            Some(replacement),
            "readiness must not release the replacement's own in-flight work"
        );
    }
    sync.tick();
    for hash in &rerequested {
        assert_eq!(pending_owner(hash), Some(replacement));
    }
    Ok(())
}

#[test]
fn stall_eviction_does_not_disconnect_replacement_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = super::super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(Duration::from_mins(1))
    };
    let (sync, peers, _expected, _rxs, _blocks_tx) = staged_count_wedge(budget)?;
    let staller = test_addr(9320, 0)?;
    sync.scheduler
        .lock()
        .window
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let applied_tip = sync
        .chain
        .applied_tip()
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let next_apply_height = applied_tip
        .height
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("applied height overflow"))?;
    let selected = {
        let mut scheduler = sync.scheduler.lock();
        let tree = sync.chain.block_tree().read();
        let state = &mut *scheduler;
        let active = state.window.active_downloading_peers();
        match state.window.observe_blocked(
            crate::download_window::BlockedContext {
                next_apply_height: Some(next_apply_height),
                frontier_hash: None,
                apply_side_busy: false,
                active_downloading_peers: active,
            },
            &state.stager,
            &tree,
            Instant::now() + Duration::from_millis(150),
        ) {
            crate::download_window::BlockedDecision::Blame {
                owner,
                reason: crate::download_window::BlameReason::Staller,
            } => Some(owner),
            _ => None,
        }
    };
    let (replacement_tx, _replacement_rx) = unbounded::<Message>();
    let replacement = PeerLease::new(replacement_tx);
    peers.register(staller, replacement.clone());
    peers.publish_info(staller, &replacement, synthetic_peer(staller, 200));
    // The convicted owner is the predecessor's source: the replacement at
    // the same address must not be blamed for it.
    let evicted = selected.is_some_and(|owner| sync.peer_table.disconnect_source(owner));

    assert!(selected.is_some());
    assert!(!evicted);
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
            ..super::super::default_sync_budget(Network::Regtest)
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
    sync.scheduler
        .lock()
        .window
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let Message::GetData(inventory) = staller_rx.try_recv()? else {
        return Err(std::io::Error::other("expected staller getdata").into());
    };
    assert_eq!(
        witness_block_inventory(inventory)?,
        std::vec![blocks[0].block_hash(), blocks[1].block_hash()]
    );

    // The successor stages; byte headroom hits zero (R + P at the byte
    // budget) with the front still pending to the staller.
    blocks_tx.send(crate::InboundBlock::from_decoded(blocks[1].clone()))?;
    sync.tick();
    {
        let scheduler = sync.scheduler.lock();
        assert!(!scheduler.window.has_request_capacity(&scheduler.stager));
        assert_eq!(
            scheduler.window.stalling_peer().map(|(addr, _)| addr),
            Some(staller)
        );
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
        sync.scheduler.lock().stager.received_len(),
        1,
        "recovery must not discard staged progress (prune-free)"
    );
    let Message::GetData(retry) = honest_rx.try_recv()? else {
        return Err(std::io::Error::other("expected honest peer front retry").into());
    };
    assert_eq!(
        witness_block_inventory(retry)?,
        std::vec![blocks[0].block_hash()]
    );

    blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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
