use super::*;

/// A recorded Fatal settlement halts further apply attempts: staged blocks
/// stay queued, no new transition starts, and the latched tick reports
/// idle instead of churning an `AlreadyActive` refusal every round.
#[test]
fn fatal_settlement_halts_further_apply_attempts() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _applied_tip, main, _blocks_tx) = sync_with_mined_chain(1)?;
    stage_body(&sync, &main[0]);
    let staged = sync.scheduler.lock().stager.received_len();
    assert!(
        staged > 0,
        "the staged block must be queued before the halt"
    );
    assert!(
        !sync.apply_halted.load(std::sync::atomic::Ordering::SeqCst),
        "a fresh sync object must not start halted"
    );
    sync.note_fatal_settlement(0, &std::io::Error::other("scripted fatal settlement"));
    assert_eq!(
        sync.apply_buffered_blocks(None),
        (0, 0),
        "a halted sync must not start another transition"
    );
    assert_eq!(
        sync.scheduler.lock().stager.received_len(),
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
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );

    for block in fixture.blocks[1..6].iter().rev() {
        fixture
            .inbound_blocks_tx
            .send(crate::InboundBlock::from_decoded(block.clone()))?;
    }

    fixture.sync.drain_inbound_blocks(Instant::now());

    assert!(
        fixture.sync.scheduler.lock().stager.received_len() <= max_received_blocks,
        "block stager must enforce received block count budget"
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
            ..super::super::default_sync_budget(Network::Regtest)
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
            ..super::super::default_sync_budget(Network::Regtest)
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
fn on_peer_ready_sweeps_dead_predecessor_header_request() -> Result<(), Box<dyn std::error::Error>>
{
    let HeaderSyncFixture { sync, .. } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    sync.scheduler.lock().header_request = Some(super::super::PendingHeaderRequest {
        source: crate::PeerSource::for_test(peer_addr),
        locator_tip_hash: Hash256::default(),
        target_height: 1,
        requested_at: Instant::now(),
        answered: false,
    });
    register_info(&sync.peer_table, synthetic_peer(peer_addr, 1));
    let source = current_source(&sync.peer_table, peer_addr);
    sync.on_peer_ready(source);
    assert!(
        sync.scheduler.lock().header_request.is_none(),
        "replacement readiness must release the dead predecessor's request"
    );
    Ok(())
}

#[test]
fn on_peer_ready_sweep_releases_dead_owned_requests_only() -> Result<(), Box<dyn std::error::Error>>
{
    let HeaderSyncFixture { sync, .. } = header_sync_with_genesis()?;
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let (stale_tx, _stale_rx) = unbounded::<Message>();
    let stale = PeerLease::new(stale_tx);
    sync.peer_table.register(peer_addr, stale.clone());
    register_info(&sync.peer_table, synthetic_peer(peer_addr, 2));
    let replacement = current_source(&sync.peer_table, peer_addr);
    sync.scheduler.lock().header_request = Some(super::super::PendingHeaderRequest {
        source: replacement,
        locator_tip_hash: Hash256::default(),
        target_height: 1,
        requested_at: Instant::now(),
        answered: false,
    });
    sync.on_peer_ready(stale.source(peer_addr));
    sync.on_peer_ready(replacement);
    assert!(
        sync.scheduler
            .lock()
            .header_request
            .is_some_and(|request| request.source == replacement),
        "neither a stale callback nor the sweep may release the live connection's request"
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
        .chain
        .chain_tip()
        .ok_or_else(|| std::io::Error::other("missing genesis tip"))?;

    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![far_future_header(genesis.compute_hash(), 1)?],
        source: Some(current_source(&peers, peer_addr)),

        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();

    assert_eq!(sync.chain.chain_tip().as_deref(), Some(tip_before.as_ref()));
    // The batch was answered, so the gate is retained and its deadline moved:
    // the same locator is not replayed, and expiry cannot later blame a peer
    // that did respond.
    assert!(
        rx.try_recv().is_err(),
        "an answered request must not be replayed at round-trip pace"
    );
    assert!(
        !lease.is_cancelled(),
        "local-clock rejection must not cancel the peer lease"
    );
    assert!(peers.is_connected(peer_addr));
    assert!(peers.is_connected(peer_addr));
    assert!(
        !sync
            .scheduler
            .lock()
            .window
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

    assert_applied_genesis(&applied_tip, &block_tree)?;
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
            ..super::super::default_sync_budget(Network::Regtest)
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
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    // Peers that may not serve block bodies: the tick's only job here is the
    // header request, and it must still go to the highest peer.
    let low_rx = connect_peer(&peers, ineligible_peer(test_addr(9502, 0)?, 5));
    let high_rx = connect_peer(&peers, ineligible_peer(test_addr(9502, 1)?, 9));

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
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let first_rx = connect_peer(&peers, synthetic_peer(test_addr(9503, 0)?, 100));
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
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

/// Mines `count` regtest headers chained from `start_prev`, heights starting
/// at `first_height`.
fn chained_headers(
    start_prev: BlockHash,
    first_height: u32,
    count: usize,
) -> Result<Vec<Header>, Box<dyn std::error::Error>> {
    let mut out = Vec::with_capacity(count);
    let mut prev = start_prev;
    for index in 0..count {
        let height = first_height.saturating_add(u32::try_from(index)?);
        let mut header = test_header(prev, height);
        // `test_header` mines version 1, which regtest rejects from height 500
        // (BIP 34) and again from height 1251 (BIP 66 requires version 3), so a
        // full page has to carry a modern version throughout.
        header.version = if height >= 1251 { 4 } else { 3 };
        while !pow_met(
            header.bits.to_consensus(),
            Hash256::from(header.compute_hash()),
        ) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        prev = header.compute_hash();
        out.push(header);
    }
    Ok(out)
}

/// Delivers `headers` to `sync` as a wire answer from `source`.
fn deliver_headers(
    tx: &crossbeam_channel::Sender<InboundHeaders>,
    headers: Vec<Header>,
    source: PeerSource,
) -> Result<(), Box<dyn std::error::Error>> {
    tx.send(InboundHeaders {
        headers,
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    Ok(())
}

/// The locator anchors a `getheaders` carries, as raw consensus bytes, or
/// `None` for another message.
fn locator_of(message: &Message) -> Option<Vec<[u8; 32]>> {
    match message {
        Message::GetHeaders(request) => Some(
            request
                .locator_hashes
                .iter()
                .map(|hash| *hash.as_byte_array())
                .collect(),
        ),
        _ => None,
    }
}

/// The first `getheaders` locator on `rx`, or `None` if none is queued.
fn next_locator(rx: &crossbeam_channel::Receiver<Message>) -> Option<Vec<[u8; 32]>> {
    rx.try_iter().find_map(|message| locator_of(&message))
}

/// The wire encoding of a fixture block hash, for locator comparisons.
fn wire_hash(hash: BlockHash) -> [u8; 32] {
    *Hash256::from(hash).as_byte_array()
}

#[test]
fn accepted_full_header_batch_continues_from_last_header() -> Result<(), Box<dyn std::error::Error>>
{
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let page = super::super::MAX_HEADERS_RESULTS;
    let addr = test_addr(9100, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::try_from(page + 10)?));

    sync.tick();
    assert!(
        next_locator(&rx).is_some(),
        "the first tick must ask for headers"
    );

    let batch = chained_headers(genesis.compute_hash(), 1, page)?;
    deliver_headers(&inbound_headers_tx, batch, current_source(&peers, addr))?;
    sync.tick();

    let held = sync
        .chain
        .block_tree()
        .tip()
        .map(|tip| *tip.hash.as_byte_array());
    assert!(
        held.is_some_and(|hash| hash != *Hash256::from(genesis.compute_hash()).as_byte_array()),
        "a full page must move the header tip"
    );
    let locator = next_locator(&rx).ok_or("a full page must be continued")?;
    assert_eq!(
        locator.first().copied(),
        held,
        "the continuation must anchor on the deepest header the page left us with"
    );
    assert!(
        next_locator(&rx).is_none(),
        "exactly one continuation may follow a full page"
    );
    Ok(())
}

#[test]
fn known_full_header_batch_continues_from_last_header() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let page = super::super::MAX_HEADERS_RESULTS;
    let addr = test_addr(9110, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::try_from(page + 10)?));

    sync.tick();
    assert!(next_locator(&rx).is_some());

    let batch = chained_headers(genesis.compute_hash(), 1, page)?;
    let last = batch[page - 1].compute_hash();
    let source = current_source(&peers, addr);
    // Two deliveries admit every header of the page, so the third takes the
    // known-batch branch, which skips the transition lock entirely.
    for round in 0..3 {
        deliver_headers(&inbound_headers_tx, batch.clone(), source)?;
        sync.tick();
        let locator = next_locator(&rx).ok_or_else(|| {
            format!("full page round {round} must be continued, accepted or known")
        })?;
        assert!(!locator.is_empty(), "a continuation carries a locator");
        if round == 2 {
            assert_eq!(
                locator.first().copied(),
                Some(wire_hash(last)),
                "the known-page continuation anchors on the page's last header"
            );
        }
    }
    Ok(())
}

#[test]
fn unconnecting_headers_leave_request_pending() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        sync,
        inbound_headers_tx,
        peers,
        ..
    } = header_sync_with_genesis()?;
    let addr = test_addr(9120, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));
    let now = Instant::now();

    sync.tick_at(now);
    assert!(next_locator(&rx).is_some(), "the first tick must ask");
    assert!(
        sync.scheduler.lock().header_request.is_some(),
        "the request must be registered before the answer"
    );

    // A batch whose parent the tree never saw is not an answer to anything.
    let orphan_prev = BlockHash(Hash256::from_le_bytes(&[0x22; 32]));
    deliver_headers(
        &inbound_headers_tx,
        vec![test_header(orphan_prev, 9)],
        current_source(&peers, addr),
    )?;
    sync.tick_at(now);

    assert!(
        sync.scheduler
            .lock()
            .header_request
            .is_some_and(|request| request.source == current_source(&peers, addr)),
        "an unconnecting batch must not consume the request it failed to answer"
    );
    Ok(())
}

#[test]
fn expired_request_marks_disconnects_and_switches_rank() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        sync,
        inbound_headers_tx: _inbound_headers_tx,
        peers,
        ..
    } = header_sync_with_genesis()?;
    // Equal advertised heights, so the first-wins tie breaks toward `a` and the
    // penalty alone can move the pick to `b`.
    let a = test_addr(9130, 0)?;
    let b = test_addr(9130, 1)?;
    let a_rx = connect_peer(&peers, synthetic_peer(a, 8));
    let b_rx = connect_peer(&peers, synthetic_peer(b, 8));
    let t0 = Instant::now();
    let expired_at = t0 + super::super::HEADER_REQUEST_TIMEOUT;

    sync.tick_at(t0);
    assert!(
        next_locator(&a_rx).is_some(),
        "the first-wins tie must pick `a`"
    );
    assert!(next_locator(&b_rx).is_none());

    sync.tick_at(expired_at);

    assert!(
        !peers.is_connected(a),
        "a timed-out header peer is rotated away while a fallback exists"
    );
    assert!(
        sync.scheduler
            .lock()
            .window
            .peer_in_staller_cooldown(a, expired_at),
        "expiry must mark the timed-out connection unresponsive"
    );
    assert!(
        sync.scheduler
            .lock()
            .header_request
            .is_some_and(|request| request.source == current_source(&peers, b)),
        "the gate must move to the fallback connection, never stay on the timed-out one"
    );
    assert!(
        next_locator(&b_rx).is_some(),
        "the fallback peer must be asked in the very tick that rotates"
    );
    Ok(())
}

#[test]
fn answered_request_does_not_penalize() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let addr = test_addr(9140, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));
    let t0 = Instant::now();

    sync.tick_at(t0);
    assert!(next_locator(&rx).is_some());

    deliver_headers(
        &inbound_headers_tx,
        chained_headers(genesis.compute_hash(), 1, 1)?,
        current_source(&peers, addr),
    )?;
    sync.tick_at(t0 + Duration::from_millis(1));

    assert!(
        sync.scheduler.lock().header_penalties.is_empty(),
        "a real answer must not leave a timeout penalty behind"
    );
    assert!(
        peers.is_connected(addr),
        "an answered request must never rotate the peer away"
    );
    Ok(())
}

#[test]
fn replacement_source_does_not_inherit_header_penalty() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        sync,
        inbound_headers_tx: _inbound_headers_tx,
        peers,
        ..
    } = header_sync_with_genesis()?;
    let addr = test_addr(9150, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));
    let t0 = Instant::now();
    let old_source = current_source(&peers, addr);

    sync.tick_at(t0);
    assert!(next_locator(&rx).is_some());
    // One peer only, so expiry clears and penalises without disconnecting.
    sync.tick_at(t0 + super::super::HEADER_REQUEST_TIMEOUT);
    assert!(
        sync.scheduler
            .lock()
            .header_penalties
            .contains_key(&old_source),
        "the timed-out connection must carry its own penalty"
    );

    // A same-address replacement is a different connection and starts clean.
    let _replacement_rx = connect_peer(&peers, synthetic_peer(addr, 8));
    let replacement = current_source(&peers, addr);
    assert_ne!(old_source, replacement, "the lease identity must change");
    sync.on_peer_ready(replacement);

    let scheduler = sync.scheduler.lock();
    assert!(
        !scheduler.header_penalties.contains_key(&replacement),
        "a replacement must never inherit its predecessor's penalty"
    );
    assert!(
        !scheduler.header_penalties.contains_key(&old_source),
        "the released connection keeps no penalty record"
    );
    drop(scheduler);
    assert!(peers.is_connected(addr));
    Ok(())
}

/// A connection that answered with a batch this node could not use keeps its
/// gate only until the re-armed deadline. Ageing out then ends the pacing:
/// it proves no silence, so the answering peer must keep its connection and
/// its rank.
///
/// PRE: `a` owns the live header request and answers it with a far-future
///   timestamp batch (`TimestampTooFarAhead`, rejected without blame); `b` is
///   an equal peer so the rotation guard has a fallback.
/// POST: at the re-armed deadline the gate retires with no penalty, no
///   unresponsive mark, and no disconnect; only a fresh unanswered ask may
///   stand in its place.
/// INVARIANT: expiry blames silence only. A peer that answered — even
///   unusably — never loses its connection or its rank to a timeout.
#[test]
fn answered_request_expires_without_blame() -> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    } = header_sync_with_genesis()?;
    let a = test_addr(9160, 0)?;
    let b = test_addr(9160, 1)?;
    let a_rx = connect_peer(&peers, synthetic_peer(a, 8));
    let _b_rx = connect_peer(&peers, synthetic_peer(b, 8));
    let t0 = Instant::now();

    sync.tick_at(t0);
    assert!(next_locator(&a_rx).is_some(), "the first tick must ask `a`");

    deliver_headers(
        &inbound_headers_tx,
        vec![far_future_header(genesis.compute_hash(), 1)?],
        current_source(&peers, a),
    )?;
    let answered_at = t0 + Duration::from_millis(1);
    sync.tick_at(answered_at);
    assert!(
        sync.scheduler.lock().header_request.is_some(),
        "an answered request keeps its gate to pace the retry",
    );

    let expiry = answered_at + super::super::HEADER_REQUEST_TIMEOUT;
    sync.tick_at(expiry);

    let scheduler = sync.scheduler.lock();
    let retired = scheduler
        .header_request
        .as_ref()
        .is_none_or(|request| !request.answered && request.requested_at >= expiry);
    assert!(
        retired,
        "the answered gate must retire; only a fresh unanswered ask may stand",
    );
    assert!(
        scheduler.header_penalties.is_empty(),
        "an answered request must never earn a timeout penalty",
    );
    drop(scheduler);
    assert!(
        peers.is_connected(a),
        "expiry must not disconnect a peer that answered",
    );
    assert!(
        !sync
            .scheduler
            .lock()
            .window
            .peer_in_staller_cooldown(a, expiry),
        "expiry must not mark an answering peer unresponsive",
    );
    Ok(())
}
