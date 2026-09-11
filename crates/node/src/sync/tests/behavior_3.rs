use super::*;

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
