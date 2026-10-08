use super::*;

#[test]
fn tick_caps_requests_at_staged_byte_headroom() -> TestResult {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    let slot = 256 * 1024;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_bytes: 3 * slot,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    {
        let mut scheduler = sync.scheduler.lock();
        let now = Instant::now();
        for seed in [0xEE, 0xEF] {
            let block = padded_block_exact(slot, seed);
            let serialized = bytes::Bytes::from(consensus_bytes(&block));
            scheduler.stager.insert(
                Hash256::from_le_bytes(&[seed; 32]),
                None,
                block,
                serialized,
                None,
                now,
            );
        }
    }
    let addr = test_addr(9270, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 200));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    assert_eq!(witness_block_inventory(next_getdata(&rx)?)?, expected[..1]);

    sync.tick();

    assert_no_getdata(&rx)?;
    Ok(())
}

#[test]
fn stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn() -> TestResult {
    // The recorded live-collapse construction (scaled 8x down): the
    // default one-minute timeouts never fire inside the test, so the only
    // thing that can stop the second wave is the count clamp itself.
    let (sync, _peers, expected, rxs, _blocks_tx) =
        staged_count_wedge(wedge_budget(Duration::from_mins(1)))?;

    sync.tick();

    {
        let scheduler = sync.scheduler.lock();
        assert_eq!(scheduler.stager.received_len(), 14);
        assert_eq!(scheduler.window.pending_len(), 2);
        for front in &expected[..2] {
            assert!(
                scheduler
                    .window
                    .contains_pending(&Hash256::from_le_bytes(front.as_bytes())),
                "stalled front stripe must stay pending, not churn through retry"
            );
        }
    }

    sync.tick();

    for rx in &rxs {
        assert_no_getdata(rx)?;
    }
    let scheduler = sync.scheduler.lock();
    let stager = &scheduler.stager;
    assert_eq!(stager.received_len(), 14, "no evictions may occur");
    for height in 3..=16_u32 {
        let hash = Hash256::from_le_bytes(expected[usize::try_from(height)? - 1].as_bytes());
        assert!(
            stager.contains(&hash),
            "every delivered block must remain staged (height {height})"
        );
    }
    assert_eq!(scheduler.window.pending_len(), 2);
    Ok(())
}

#[test]
fn cold_start_stall_hedges_front_without_reassigning_owner() -> TestResult {
    let budget = super::super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(Duration::from_mins(1))
    };
    let ((sync, peers, _block_tree, _applied_tip, expected), _blocks_tx) =
        sync_with_header_chain_and_blocks(64)?;
    install_budget(&sync, budget);
    let mut rxs = Vec::new();
    for idx in 0..budget.min_peers_for_fanout {
        let addr = test_addr(9320, idx)?;
        rxs.push(connect_peer(
            &peers,
            synthetic_peer(addr, 200 - i32::try_from(idx)?),
        ));
    }
    let owner = test_addr(9320, 0)?;
    let alternate = test_addr(9320, 1)?;

    sync.tick();
    assert_eq!(sync.scheduler.lock().window.pending_len(), 16);
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected a striped getdata per peer").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * 2..(idx + 1) * 2]
        );
    }

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
    sync.tick();
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
    assert_eq!(
        sync.scheduler
            .lock()
            .window
            .pending_owner(&Hash256::from_le_bytes(expected[0].as_bytes())),
        Some(current_source(&peers, owner)),
        "the hedge must not reassign the front's owner"
    );

    std::thread::sleep(Duration::from_millis(50));
    sync.tick();
    for rx in &rxs[1..] {
        assert_no_getdata(rx)?;
    }
    Ok(())
}

#[test]
fn fanout_replaces_preferred_peer_when_eligible_pool_recovers() -> TestResult {
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
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let owner = test_addr(9322, 0)?;
    let alternate = test_addr(9322, 1)?;
    let owner_rx = connect_peer(&peers, synthetic_peer(owner, 200));
    let alternate_rx = connect_peer(&peers, synthetic_peer(alternate, 100));

    sync.tick();
    let _ = next_getdata(&owner_rx)?;
    let _ = next_getdata(&alternate_rx)?;
    for block in &blocks[..4] {
        let mut inbound = crate::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(current_source(&peers, alternate));
        blocks_tx.send(inbound)?;
    }
    sync.tick();
    let _ = next_getdata(&alternate_rx)?;
    assert_eq!(
        sync.scheduler.lock().window.preferred_peer(),
        Some(current_source(&peers, alternate))
    );

    let mut recovered_rxs = Vec::new();
    for idx in 2..=8 {
        recovered_rxs.push(connect_peer(
            &peers,
            synthetic_peer(test_addr(9322, idx)?, 100),
        ));
    }
    for block in &blocks[4..8] {
        let mut inbound = crate::InboundBlock::from_decoded(block.clone());
        inbound.source = Some(current_source(&peers, alternate));
        blocks_tx.send(inbound)?;
    }
    sync.tick();

    let scheduler = sync.scheduler.lock();

    let window = &scheduler.window;
    assert!(window.preferred_peer().is_none());
    assert!(window.fanout_active());
    drop(scheduler);
    assert!(
        recovered_rxs.iter().any(|rx| rx.try_recv().is_ok()),
        "a recovered eligible peer must receive a fanout request"
    );
    Ok(())
}

#[test]
fn applied_ancestry_lookup_uses_active_index_only_for_applied_prefix() -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let main1 = regtest_fixture::mined_block_with_prev_hash(
        genesis.block_hash(),
        1,
        vec![regtest_fixture::coinbase(1)],
    )
    .or_fail("regtest fixture block");
    let main2 = regtest_fixture::mined_block_with_prev_hash(
        main1.block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    let main3 = regtest_fixture::mined_block_with_prev_hash(
        main2.block_hash(),
        3,
        vec![regtest_fixture::coinbase(3)],
    )
    .or_fail("regtest fixture block");
    let main4 = regtest_fixture::mined_block_with_prev_hash(
        main3.block_hash(),
        4,
        vec![regtest_fixture::coinbase(4)],
    )
    .or_fail("regtest fixture block");
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
        let fork = regtest_fixture::mined_block_with_prev_hash(
            fork_prev,
            height.saturating_add(100),
            vec![regtest_fixture::coinbase(height.saturating_add(100))],
        )
        .or_fail("regtest fixture block");
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
fn apply_side_backpressure_never_blamed_on_front_peer() -> TestResult {
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
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let staller = test_addr(9450, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(staller, 100));

    sync.scheduler
        .lock()
        .window
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
    let successor = Hash256::from_le_bytes(expected[1].as_bytes());
    {
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        sync.scheduler.lock().stager.insert(
            successor,
            None,
            block,
            serialized,
            None,
            Instant::now(),
        );
    }
    sync.scheduler
        .lock()
        .window
        .mark_received_from(successor, 80, None, Instant::now());

    let frontier = Hash256::from_le_bytes(expected[0].as_bytes());
    {
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        sync.scheduler.lock().stager.insert(
            frontier,
            None,
            block,
            serialized,
            None,
            Instant::now(),
        );
    }

    let far_future = Instant::now() + Duration::from_mins(1);

    sync.reconcile_window_recovery(&sync.observe_chain_frontier(), far_future);
    assert!(sync.scheduler.lock().window.stalling_peer().is_none());
    assert!(peers.is_connected(staller));

    let drained = sync
        .scheduler
        .lock()
        .stager
        .drain_expected_prefix(&[frontier]);
    assert_eq!(drained.len(), 1);
    sync.reconcile_window_recovery(&sync.observe_chain_frontier(), far_future);
    assert_eq!(
        sync.scheduler
            .lock()
            .window
            .stalling_peer()
            .map(|(addr, _)| addr),
        Some(staller)
    );
    assert!(peers.is_connected(staller));
    sync.reconcile_window_recovery(
        &sync.observe_chain_frontier(),
        far_future + super::super::BLOCK_STALLING_TIMEOUT,
    );
    assert!(
        !peers.is_connected(staller),
        "with the apply side idle the same state must fire normally"
    );
    Ok(())
}

#[test]
fn staged_frontier_stuck_past_bound_escalates_without_blame() -> TestResult {
    // Issue #1091 regression: a well-formed next-expected body staged but
    // never applied used to hold `apply_side_busy` (and with it stall
    // conviction, pending-timeout conviction, and the cold-front hedge)
    // forever. The 60s staged-body prune does not rescue the window — it
    // expires the body, the re-request re-delivers it, and the fresh insert
    // re-stamps its received_at, re-arming the suppression. The bound must
    // therefore key on the stuck frontier: past two received_timeouts the
    // staged body is evicted for refetch, no peer is blamed, and with the
    // body absent the unsuppressed stall path engages again. Time is
    // injected through the detection entry point directly.
    let (sync, peers, _block_tree, _applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 2,
            max_received_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let staller = test_addr(9470, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(staller, 100));

    sync.scheduler
        .lock()
        .window
        .seed_front_cadence_for_test(50, Instant::now());

    sync.tick();
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);

    let frontier = Hash256::from_le_bytes(expected[0].as_bytes());
    let successor = Hash256::from_le_bytes(expected[1].as_bytes());
    for hash in [frontier, successor] {
        let block = Network::Regtest.genesis_block();
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        sync.scheduler
            .lock()
            .stager
            .insert(hash, None, block, serialized, None, Instant::now());
    }
    let staged_at = Instant::now();
    sync.scheduler.lock().window.mark_received_from(
        frontier,
        80,
        Some(current_source(&peers, staller)),
        staged_at,
    );
    sync.scheduler
        .lock()
        .window
        .mark_received_from(successor, 80, None, staged_at);

    let bound = super::super::default_sync_budget(Network::Regtest)
        .received_timeout
        .saturating_mul(2);
    let start = Instant::now();

    sync.reconcile_window_recovery(&sync.observe_chain_frontier(), start);
    sync.reconcile_window_recovery(
        &sync.observe_chain_frontier(),
        bound
            .checked_sub(Duration::from_secs(1))
            .map_or(start, |just_below| start + just_below),
    );
    assert!(
        sync.scheduler.lock().stager.contains(&frontier),
        "below the bound the staged frontier must stay put"
    );
    assert!(peers.is_connected(staller));
    assert!(sync.scheduler.lock().window.stalling_peer().is_none());

    sync.reconcile_window_recovery(
        &sync.observe_chain_frontier(),
        start + bound + Duration::from_secs(1),
    );
    assert!(
        !sync.scheduler.lock().stager.contains(&frontier),
        "past the bound the stuck staged frontier must be evicted for refetch"
    );
    assert!(
        peers.is_connected(staller),
        "the apply-side escalation must never blame or disconnect the front peer"
    );
    assert!(sync.scheduler.lock().window.stalling_peer().is_none());

    sync.tick();
    let requeued = witness_block_inventory(next_getdata(&rx)?)?;
    assert!(
        requeued.contains(&expected[0]),
        "the escalation must requeue the evicted frontier for refetch, got {requeued:?}"
    );

    sync.reconcile_window_recovery(
        &sync.observe_chain_frontier(),
        start + bound + Duration::from_secs(1) + super::super::BLOCK_STALLING_TIMEOUT,
    );
    assert_eq!(
        sync.scheduler
            .lock()
            .window
            .stalling_peer()
            .map(|(addr, _)| addr),
        Some(staller)
    );
    sync.reconcile_window_recovery(
        &sync.observe_chain_frontier(),
        start + bound + Duration::from_secs(1) + super::super::BLOCK_STALLING_TIMEOUT * 2,
    );
    assert!(
        !peers.is_connected(staller),
        "after the escalation a genuinely stalling peer must be convictable"
    );
    Ok(())
}

#[test]
fn transient_demotion_does_not_flap_fanout_mode() -> TestResult {
    const PEER_COUNT: usize = 8;
    let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
        sync_with_header_chain_and_blocks(64)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 16,
            max_pending_bytes: usize::MAX,
            max_received_blocks: 64,
            max_received_bytes: usize::MAX,
            max_peer_inflight: 16,
            fanout_peer_inflight: 2,
            min_peers_for_fanout: 8,
            getdata_batch_limit: 16,
            ..super::super::default_sync_budget(Network::Regtest)
        }
        .with_pending_timeout_override(Duration::from_millis(250)),
    );
    let mut rxs = Vec::new();
    for idx in 0..PEER_COUNT {
        let addr = test_addr(9340, idx)?;
        rxs.push(connect_peer(
            &peers,
            synthetic_peer(addr, 200 - i32::try_from(idx)?),
        ));
    }

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
    assert!(sync.scheduler.lock().window.fanout_active());
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected striped getdata").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * 2..(idx + 1) * 2]
        );
    }

    for height in 3..=16_u32 {
        blocks_tx.send(crate::InboundBlock::from_decoded(header_chain_block(
            &expected, height,
        )?))?;
    }
    std::thread::sleep(Duration::from_millis(300));
    sync.tick();

    assert!(
        sync.scheduler.lock().window.fanout_active(),
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

    sync.tick();
    assert!(sync.scheduler.lock().window.fanout_active());
    Ok(())
}

/// Builds a regtest block whose serialized size is exactly `size` bytes by
/// padding the coinbase-style transaction's output script.
fn padded_block_exact(size: usize, seed: u8) -> Block {
    let mut block = regtest_fixture::mined_block_with_prev_hash(
        BlockHash(Hash256::from_le_bytes(&[seed; 32])),
        1,
        vec![super::transaction(seed)],
    )
    .or_fail("regtest fixture block");
    block.txs[0].outputs[0].script_pubkey = Vec::new().into();
    let prefix_growth = |len: usize| match len {
        0..=252 => 0,
        253..=0xffff => 2,
        _ => 4,
    };
    let wanted = size - consensus_bytes(&block).len();
    let script_len = wanted - prefix_growth(wanted - prefix_growth(wanted));
    block.txs[0].outputs[0].script_pubkey = vec![0_u8; script_len].into();
    assert_eq!(consensus_bytes(&block).len(), size);
    block
}
