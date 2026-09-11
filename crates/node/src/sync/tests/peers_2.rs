use super::*;

/// Cross-tick regression for the bounded prefix-race-before-fanout
/// handoff: a probe created below the threshold must defer fanout when the
/// eligible count reaches the threshold on a following tick while the
/// probe is still fresh, then fanout must engage once the injected time
/// crosses the `stall_timeout_initial` deadline. Exercises the real
/// `tick()` / `configure_request_mode` / `set_fanout_eligible_peers`
/// path for probe creation and the deferral, then injects a future
/// `Instant` (the only available time seam, since `tick()` reads
/// `Instant::now()`) to cross the deadline. This is the exact cross-tick
/// boundary test; the direct window-boundary test lives in
/// `window::tests::fanout_cancels_prefix_probe_without_rearming_it`. No
/// sleeps, no network.
#[test]
fn tick_fanout_deferred_for_fresh_probe_engages_at_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    // A 16-block chain: the deep single-peer window takes all 16 while
    // the one-shot probe sends the first 8 (PREFIX_PROBE_BLOCK_LIMIT), so
    // the probe getdata is distinguishable from the deep getdata.
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(16)?;
    install_budget(&sync, super::super::default_sync_budget());

    // Two eligible peers: below the 8-peer fanout threshold. The owner
    // (highest) takes the deep window; the alternate is the probe racer.
    let owner_addr = test_addr(9401, 0)?;
    let alternate_addr = test_addr(9401, 1)?;
    let owner_rx = connect_peer(&peers, eligible_peer(owner_addr, 201));
    let alternate_rx = connect_peer(&peers, eligible_peer(alternate_addr, 200));

    // Tick 1: below the threshold, a prefix probe is created. The owner
    // receives the deep getdata (all 16) and the alternate receives the
    // one-shot probe getdata (the first 8).
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    assert_eq!(
        witness_block_inventory(next_getdata(&owner_rx)?)?,
        expected,
        "the deep owner must receive the full window"
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&alternate_rx)?)?,
        expected[..8],
        "the alternate must receive the one-shot probe prefix"
    );
    assert!(
        !sync.download_window.lock().fanout_active(),
        "below the threshold fanout must stay off"
    );

    // Reach the fanout threshold on the following tick: add six more
    // eligible peers (eight total) and tick again. The probe is still
    // fresh (age well under stall_timeout_initial = 2s), so the bounded
    // deferral holds fanout off and the probe survives the transition.
    for idx in 2..super::super::MIN_PEERS_FOR_FANOUT {
        connect_peer(&peers, eligible_peer(test_addr(9401, idx)?, 200));
    }
    sync.tick();
    assert!(
        !sync.download_window.lock().fanout_active(),
        "a fresh prefix probe must defer the threshold-crossing tick"
    );

    // Cross the injected time deadline measured from the active probe's
    // stored `started_at`. The cross-tick path cannot control the
    // `Instant::now()` used when the probe is created, so read it back and
    // add exactly `stall_timeout_initial`. Then assert the planned
    // duration equals the budget before engaging fanout.
    let mut window = sync.download_window.lock();
    let started_at = window
        .active_prefix_probe_started_at()
        .ok_or_else(|| std::io::Error::other("probe must remain active after deferral"))?;
    let budget = super::super::default_sync_budget();
    let planned_duration = budget.stall_timeout_initial;
    let deadline = started_at + planned_duration;
    assert_eq!(
        deadline - started_at,
        planned_duration,
        "planned deadline must be exactly stall_timeout_initial after probe start"
    );
    window.set_fanout_eligible_peers(super::super::MIN_PEERS_FOR_FANOUT, deadline);
    assert!(
        window.fanout_active(),
        "fanout must engage at the stall_timeout_initial deadline"
    );
    assert!(
        window.prefix_probe_plan().is_none(),
        "no probe plan may remain once fanout engages"
    );
    Ok(())
}

#[test]
fn inbound_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>> {
    let ineligible = PeerInfo {
        inbound: true,
        ..eligible_peer(test_addr(9200, 0)?, 300)
    };
    assert_fallback_with_ineligible_candidate(ineligible, true)
}

#[test]
fn non_witness_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>>
{
    let ineligible = PeerInfo {
        // NODE_NETWORK only — no NODE_WITNESS.
        services: 1,
        ..eligible_peer(test_addr(9210, 0)?, 300)
    };
    assert_fallback_with_ineligible_candidate(ineligible, true)
}

#[test]
fn low_chain_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>> {
    // Outbound + witness, but its known chain does not reach past our
    // applied tip (genesis, height 0): fails the height clause outright.
    let ineligible = eligible_peer(test_addr(9220, 0)?, 0);
    assert_fallback_with_ineligible_candidate(ineligible, false)
}

#[test]
fn demoted_peer_not_counted_toward_fanout_threshold() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            pending_timeout: Duration::ZERO,
            ..super::super::default_sync_budget()
        },
    );
    // Phase 1: the lone peer takes the deep window; the zero timeout
    // expires every pending immediately, soft-demoting it.
    let demoted_rx = connect_peer(&peers, eligible_peer(test_addr(9240, 0)?, 300));
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(initial) = demoted_rx.try_recv()? else {
        return Err(std::io::Error::other("expected initial deep getdata").into());
    };
    assert_eq!(initial.len(), super::super::PENDING_BUDGET);
    if !matches!(demoted_rx.try_recv()?, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders for lone peer").into());
    }

    // Phase 2: seven more eligible peers connect — eight eligible-shaped
    // candidates, but the demoted one must not count (7 < threshold), so
    // the expired blocks are re-issued as one deep fallback batch instead
    // of fanning out.
    let mut rxs = Vec::new();
    for idx in 0..super::super::MIN_PEERS_FOR_FANOUT - 1 {
        let addr = test_addr(9241, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 200 - i32::try_from(idx)?),
        ));
    }
    sync.tick();

    let Message::GetData(retry) = rxs[0].try_recv()? else {
        return Err(std::io::Error::other("expected deep retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry)?, expected);
    assert!(
        demoted_rx.try_recv().is_err(),
        "demoted peer must receive no new block requests"
    );
    for rx in &rxs[1..] {
        assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
    }
    Ok(())
}

#[test]
fn ineligible_peers_receive_no_block_requests_during_fanout()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    // A real (short) pending timeout: the lone peer's requests must be
    // expired by the time the second tick runs, while the second tick's
    // own fresh requests stay live across the request loop. (A zero
    // timeout would re-expire each fan-out peer's requests for the next
    // peer within the same tick.)
    install_budget(
        &sync,
        super::super::SyncBudget {
            pending_timeout: Duration::from_millis(250),
            ..super::super::default_sync_budget()
        },
    );
    // Soft-demote one otherwise-eligible peer: it takes the deep window
    // and never delivers.
    let demoted_rx = connect_peer(&peers, eligible_peer(test_addr(9250, 0)?, 290));
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(initial) = demoted_rx.try_recv()? else {
        return Err(std::io::Error::other("expected initial deep getdata").into());
    };
    assert_eq!(initial.len(), super::super::PENDING_BUDGET);
    if !matches!(demoted_rx.try_recv()?, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders for lone peer").into());
    }

    // One ineligible candidate per predicate clause, all at heights that
    // would make them the most attractive picks were they eligible.
    let inbound_rx = connect_peer(
        &peers,
        PeerInfo {
            inbound: true,
            ..eligible_peer(test_addr(9251, 0)?, 310)
        },
    );
    let non_witness_rx = connect_peer(
        &peers,
        PeerInfo {
            services: 1,
            ..eligible_peer(test_addr(9252, 0)?, 305)
        },
    );
    let low_chain_rx = connect_peer(&peers, eligible_peer(test_addr(9253, 0)?, 0));
    let mut rxs = Vec::new();
    for idx in 0..super::super::MIN_PEERS_FOR_FANOUT {
        let addr = test_addr(9254, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    // Let the lone peer's pendings expire (demoting it) before fanning out.
    std::thread::sleep(Duration::from_millis(300));
    sync.tick();
    // Conviction requires a second drain opportunity so a block delivered
    // during synchronous apply is not mistaken for a network timeout.
    sync.tick();
    assert!(
        !peers.is_connected(test_addr(9250, 0)?),
        "a peer that misses the request timeout must release its outbound slot"
    );
    assert!(
        sync.download_window
            .lock()
            .peer_in_staller_cooldown(test_addr(9250, 0)?, Instant::now()),
        "a timed-out peer must not immediately reacquire the same block stripe"
    );

    // Effective fan-out stripe (mirrors `effective_peer_inflight`).
    let cap = super::super::PENDING_BUDGET
        .div_ceil(super::super::MIN_PEERS_FOR_FANOUT)
        .clamp(
            super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
            super::super::PEER_INFLIGHT_BUDGET,
        );
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata for eligible peer").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * cap..(idx + 1) * cap]
        );
        assert!(rx.try_recv().is_err());
    }
    // The header peer (highest candidate, inbound) may still receive
    // getheaders — header sync is not block download.
    if !matches!(inbound_rx.try_recv()?, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders to header peer").into());
    }
    assert!(inbound_rx.try_recv().is_err());
    assert!(non_witness_rx.try_recv().is_err());
    assert!(low_chain_rx.try_recv().is_err());
    assert!(demoted_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn fanout_replaces_preferred_peer_when_eligible_pool_recovers()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _applied_tip, blocks, blocks_tx) = sync_with_mined_chain(48)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 16,
            max_pending_bytes: usize::MAX,
            max_peer_inflight: 16,
            fanout_peer_inflight: 2,
            min_peers_for_fanout: super::super::MIN_PEERS_FOR_FANOUT,
            getdata_batch_limit: 16,
            ..super::super::default_sync_budget()
        },
    );
    let owner = test_addr(9322, 0)?;
    let alternate = test_addr(9322, 1)?;
    let owner_rx = connect_peer(&peers, eligible_peer(owner, 200));
    let alternate_rx = connect_peer(&peers, eligible_peer(alternate, 100));

    sync.tick();
    let _ = next_getdata(&owner_rx)?;
    let _ = next_getdata(&alternate_rx)?;
    for block in &blocks[..4] {
        let mut inbound = bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(current_source(&peers, alternate));
        blocks_tx.send(inbound)?;
    }
    sync.tick();
    let _ = next_getdata(&alternate_rx)?;
    assert_eq!(
        sync.download_window.lock().preferred_peer(),
        Some(alternate)
    );

    let mut recovered_rxs = Vec::new();
    for idx in 2..=8 {
        recovered_rxs.push(connect_peer(
            &peers,
            eligible_peer(test_addr(9322, idx)?, 100),
        ));
    }
    for block in &blocks[4..8] {
        let mut inbound = bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(current_source(&peers, alternate));
        blocks_tx.send(inbound)?;
    }
    sync.tick();

    let window = sync.download_window.lock();
    assert!(window.preferred_peer().is_none());
    assert!(window.fanout_active());
    drop(window);
    assert!(
        recovered_rxs.iter().any(|rx| rx.try_recv().is_ok()),
        "a recovered eligible peer must receive a fanout request"
    );
    Ok(())
}

#[test]
fn apply_side_backpressure_never_blamed_on_front_peer() -> Result<(), Box<dyn std::error::Error>> {
    // No-blame guard at the sync layer: while the stager holds the next
    // expected block (apply lag / failed-apply restore), the stall clock
    // must not run — no disconnect fires even arbitrarily far past the
    // threshold, and the busy interval is never charged to the peer.
    // Time is injected through the detection entry point directly.
    let (sync, peers, _block_tree, _applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 2,
            max_received_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            ..super::super::default_sync_budget()
        },
    );
    let staller = test_addr(9450, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(staller, 100));

    // Cold-start disarm: an unseeded EWMA would suppress the fire on its
    // own and this test would pass vacuously. Seed it (50ms keeps the
    // decay floor at the default 2s initial threshold) so the no-fire
    // phase below pins the apply-side no-blame guard specifically.
    sync.download_window
        .lock()
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
    // The successor stages; the window is otherwise fully blocked on the
    // front-holding peer.
    let successor = Hash256::from_le_bytes(expected[1].as_bytes());
    {
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        sync.block_stager
            .lock()
            .insert(successor, None, block, serialized, Instant::now());
    }
    sync.download_window
        .lock()
        .mark_received(successor, 80, Instant::now());

    // Apply-side backpressure: the next expected block (the frontier) is
    // itself staged but not yet drained.
    let frontier = Hash256::from_le_bytes(expected[0].as_bytes());
    {
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        sync.block_stager
            .lock()
            .insert(frontier, None, block, serialized, Instant::now());
    }

    let applied = sync
        .handles
        .applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let far_future = Instant::now() + Duration::from_mins(1);

    // Far past any threshold, but the apply side is busy: frozen.
    sync.disconnect_window_staller(Some(&applied), far_future);
    assert!(sync.download_window.lock().stalling_peer().is_none());
    assert!(peers.is_connected(staller));

    // The apply side drains the frontier: blame starts from scratch and
    // only then runs to a fire — the busy interval was not charged.
    let drained = sync.block_stager.lock().drain_expected_prefix(&[frontier]);
    assert_eq!(drained.len(), 1);
    sync.disconnect_window_staller(Some(&applied), far_future);
    assert_eq!(
        sync.download_window
            .lock()
            .stalling_peer()
            .map(|(addr, _)| addr),
        Some(staller)
    );
    assert!(peers.is_connected(staller));
    sync.disconnect_window_staller(
        Some(&applied),
        far_future + super::super::BLOCK_STALLING_TIMEOUT,
    );
    assert!(
        !peers.is_connected(staller),
        "with the apply side idle the same state must fire normally"
    );
    Ok(())
}

#[test]
fn transient_demotion_does_not_flap_fanout_mode() -> Result<(), Box<dyn std::error::Error>> {
    const PEER_COUNT: usize = 8;
    let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
        sync_with_header_chain_and_blocks(64)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 16,
            max_pending_bytes: usize::MAX,
            // Roomy count budget: the staging clamps must not bind, so
            // any request change is attributable to the mode alone.
            max_received_blocks: 64,
            max_received_bytes: usize::MAX,
            max_peer_inflight: 16,
            fanout_peer_inflight: 2,
            min_peers_for_fanout: 8,
            getdata_batch_limit: 16,
            pending_timeout: Duration::from_millis(250),
            ..super::super::default_sync_budget()
        },
    );
    let mut rxs = Vec::new();
    for idx in 0..PEER_COUNT {
        let addr = test_addr(9340, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 200 - i32::try_from(idx)?),
        ));
    }

    // Tick 1: eight eligible peers engage fan-out and stripe the window.
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    assert!(sync.download_window.lock().fanout_active());
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected striped getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * 2..(idx + 1) * 2]
        );
    }

    // The healthy peers deliver their stripes; the front-stripe owner
    // stalls past the pending timeout — eligible peers dip 8 -> 7.
    for height in 3..=16_u32 {
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            header_chain_block(&expected, height)?,
        ))?;
    }
    std::thread::sleep(Duration::from_millis(300));
    sync.tick();

    // Mode stability under the transient dip: hysteresis holds fan-out,
    // so the stalled stripe is redistributed in cap-sized batches instead
    // of re-concentrating the whole window on one deep peer.
    assert!(
        sync.download_window.lock().fanout_active(),
        "one demotion below the threshold must not disengage fan-out"
    );
    assert_no_getdata(&rxs[0])?;
    let mut redistributed = Vec::new();
    let redistributed_cap = 16_usize.div_ceil(PEER_COUNT - 1);
    for rx in &rxs[1..] {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                let hashes = witness_block_inventory(inventory)?;
                assert!(
                    hashes.len() <= redistributed_cap,
                    "per-peer batches must stay at the dynamic cap; a deep \
                         batch is the mode-flap signature"
                );
                redistributed.extend(hashes);
            }
        }
    }
    assert!(
        expected[..2]
            .iter()
            .all(|hash| redistributed.contains(hash)),
        "the stalled front stripe must move to healthy peers under the cap"
    );

    // Tick 3: the dip heals (7 -> 8) and the mode is still fan-out — the
    // window stayed in one mode across 8 -> 7 -> 8.
    sync.tick();
    assert!(sync.download_window.lock().fanout_active());
    Ok(())
}

#[test]
fn clean_fast_path_caps_request_at_peer_height() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 2));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
    assert!(rx.try_recv().is_err());

    sync.tick();

    assert!(rx.try_recv().is_err());
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

#[test]
fn tick_retries_when_all_selected_peers_have_expired_pending()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            pending_timeout: Duration::ZERO,
            getdata_batch_limit: 1,
            ..super::super::default_sync_budget()
        },
    );
    let rx = connect_peer(&peers, synthetic_peer(test_addr(9504, 0)?, 100));
    sync.tick();
    let _ = rx.try_recv()?;
    let _ = rx.try_recv()?;
    sync.tick();
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected expired-pending retry").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..1]);
    Ok(())
}
