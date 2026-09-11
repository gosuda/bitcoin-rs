use super::*;

#[test]
fn losing_fork_credit_survives_winner_disconnect() -> Result<(), Box<dyn std::error::Error>> {
    // Contract proof: P2P-03 (docs/contracts/p2p-wire.md). Peer A's
    // accepted fork is initially losing, peer B later extends it so the
    // fork wins, and B then disconnects. A must retain the accepted tip
    // evidence and remain eligible for the bodies it demonstrated.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let losing1 = test_header(genesis.compute_hash(), 1);
    let losing1_id = tree.insert_node(Some(genesis_id), losing1, NodeStatus::HeaderValid)?;
    let losing2 = test_header(losing1.compute_hash(), 2);
    tree.insert_node(Some(losing1_id), losing2, NodeStatus::HeaderValid)?;
    let genesis_node = tree.node(genesis_id)?;
    let applied = TipSnapshot {
        tip_id: genesis_id,
        height: genesis_node.height,
        chainwork: genesis_node.chainwork,
        hash: genesis_node.hash,
    };

    let fork1 = test_header(genesis.compute_hash(), 101);
    let fork2 = test_header(fork1.compute_hash(), 102);
    let fork3 = test_header(fork2.compute_hash(), 103);
    let expected = [fork1, fork2, fork3];
    let expected_hashes: Vec<Hash256> = expected
        .iter()
        .map(|header| header.compute_hash().into())
        .collect();

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    applied_tip.store(Some(Arc::new(applied)));
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let sync = BlockSync::for_test(
        apply_handles(chain_tip, Arc::clone(&applied_tip), Arc::clone(&block_tree)),
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    let peer_a = test_addr(8333, 0)?;
    let peer_b = test_addr(8333, 1)?;
    let rx_a = connect_peer(&peers, synthetic_peer(peer_a, 0));
    let _rx_b = connect_peer(&peers, synthetic_peer(peer_b, 0));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork1, fork2],
        source: Some(current_source(&peers, peer_a)),
    })?;
    sync.drain_inbound_headers();
    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer_a)
            .ok_or("peer A info missing")?
            .best_known_height,
        0,
        "a losing fork must not receive scalar credit yet"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork3],
        source: Some(current_source(&peers, peer_b)),
    })?;
    sync.drain_inbound_headers();
    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer_a)
            .ok_or("peer A info missing after reorg")?
            .best_known_height,
        2,
        "peer A's retained fork tip must be credited after the fork wins"
    );
    assert!(peers.disconnect_source(current_source(&peers, peer_b)));

    sync.tick();

    let requested = next_getdata(&rx_a)?
        .into_iter()
        .map(|item| match item {
            Inventory::WitnessBlock(hash) => Ok(Hash256::from_le_bytes(hash.as_byte_array())),
            _ => Err(std::io::Error::other("expected witness block inventory")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        requested,
        expected_hashes[..2],
        "the surviving peer must serve the bodies it demonstrated"
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
fn stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued()
-> Result<(), Box<dyn std::error::Error>> {
    // R8 core scenario and the terminator for the U6 wedge's bounded
    // cycle (and the first-audit ADV-2 shape: the staller is the
    // highest-advertising peer, holding the front on claimed height it
    // never serves). The 1-minute pending timeout can never fire inside
    // this test, so the staller disconnect is the ONLY recovery path.
    let budget = super::super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(super::super::PENDING_TIMEOUT)
    };
    let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
    let staller = test_addr(9320, 0)?;

    // Cold-start disarm: the wedge fixture never advances the window
    // front, so the cadence EWMA would stay unseeded and conviction
    // would defer to the 60s pending-timeout fallback (the cold-start
    // suppression, pinned at the window level). Seed it at 50ms — the
    // decay floor stays max(2x50ms, 100ms) = the injected initial
    // threshold — so this test keeps pinning the adaptive-timeout fire.
    sync.download_window
        .lock()
        .seed_front_cadence_for_test(50, Instant::now());

    // Tick 2: the wedge forms (staged 14 + pending 2 at the count
    // budget) and the stall episode starts on the front-stripe owner.
    sync.tick();
    {
        let window = sync.download_window.lock();
        assert_eq!(window.received_len(), 14);
        assert_eq!(window.pending_len(), 2);
        assert_eq!(
            window.stalling_peer().map(|(addr, _)| addr),
            Some(staller),
            "the front-stripe owner must be the observed staller"
        );
    }

    // Past the adaptive threshold: the staller is disconnected, its
    // front stripe re-queues, and a healthy peer is asked for it in the
    // same tick — with the staged set intact (no prune involvement).
    std::thread::sleep(Duration::from_millis(150));
    sync.tick();

    assert!(
        !peers.is_connected(staller),
        "staller's outbound lease must be revoked"
    );
    assert!(
        sync.download_window
            .lock()
            .peer_in_staller_cooldown(staller, Instant::now()),
        "disconnected staller must enter the cooldown"
    );
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
        "staged progress must survive the staller disconnect"
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
fn slow_trickle_front_peer_observable_but_never_disconnected()
-> Result<(), Box<dyn std::error::Error>> {
    // R10 slow-trickle: a peer delivering each front block just under
    // the adaptive threshold is never disconnected (Core has the same
    // exposure), but the stall state must be visible — via the window
    // accessor and the node.sync.stall_seconds gauge.
    let recorder = TestRecorder::default();
    metrics::with_local_recorder(&recorder, || {
        let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(6)?;
        install_budget(
            &sync,
            super::super::SyncBudget {
                max_pending_blocks: 3,
                max_received_blocks: 3,
                max_peer_inflight: 3,
                getdata_batch_limit: 3,
                // Default 2s initial threshold: the 100ms trickle below
                // stays far under it on any machine.
                ..super::super::default_sync_budget()
            },
        );
        let trickler = test_addr(9440, 0)?;
        let rx = connect_peer(&peers, synthetic_peer(trickler, 100));

        for round in 0..2_usize {
            let offset = round * 3;
            sync.tick();
            let inventory = next_getdata(&rx)?;
            assert_eq!(inventory.len(), 3);
            // Successors arrive, the front trickles: window-blocked.
            blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                blocks[offset + 1].clone(),
            ))?;
            blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                blocks[offset + 2].clone(),
            ))?;
            sync.tick();
            assert_eq!(
                sync.download_window
                    .lock()
                    .stalling_peer()
                    .map(|(addr, _)| addr),
                Some(trickler),
                "the stall episode must be observable while the front trickles"
            );
            std::thread::sleep(Duration::from_millis(100));
            sync.tick();
            // Still under the threshold: observed, not punished.
            assert!(peers.is_connected(trickler));
            match recorder.snapshot().get("node.sync.stall_seconds") {
                Some(TestMetric::Gauge(seconds)) => {
                    assert!(
                        *seconds > 0.0,
                        "stall age must be exported while an episode runs"
                    );
                }
                value => panic!("stall_seconds gauge missing or wrong type: {value:?}"),
            }
            // The front arrives just under the threshold: progress —
            // episode ends, adaptive threshold stays at its initial
            // value, and the next round starts clean.
            blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                blocks[offset].clone(),
            ))?;
            sync.tick();
            assert!(sync.download_window.lock().stalling_peer().is_none());
            assert_eq!(
                sync.download_window.lock().stall_timeout(),
                super::super::BLOCK_STALLING_TIMEOUT,
                "front progress must keep the adaptive threshold at its floor"
            );
        }

        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height;
        assert_eq!(applied_height, 6);
        assert!(
            peers.is_connected(trickler),
            "a trickler under the threshold must never be disconnected"
        );
        assert!(
            !recorder
                .snapshot()
                .contains_key("node.sync.staller_disconnects"),
            "no staller disconnect may fire for an under-threshold trickler"
        );
        Ok(())
    })
}

#[test]
fn uniform_slow_saturated_fanout_disconnects_no_peer_and_completes()
-> Result<(), Box<dyn std::error::Error>> {
    // Sync-level smoke for the self-eclipse blocker and the ADV-DRIP-1
    // drip: 8 eligible peers in saturated fan-out (window 24 = 8 peers x
    // cap 3 over a 32-block chain, so refills keep R+P pinned at the
    // count budget and "no request capacity" is the steady state) over a
    // fully applicable mined chain. Every peer keeps streaming — one
    // block per peer per round, lowest-block-first so the window front
    // advances at the round cadence — while every round lands 150ms
    // apart, past the injected 100ms threshold. Each tick drains the
    // round's deliveries before observing, so per-peer delivery progress
    // clears every delivery-time episode; the mid-gap ticks (the wake
    // path observes between the front owner's deliveries — where the
    // pre-fix drip fired) stay under the adaptive decay floor once the
    // interval EWMA has its first sample: zero staller disconnects and
    // the sync completes. (The timing-injected constructions live in the
    // window module: `uniform_slow_streaming_saturated_fanout_never_fires`
    // and `stall_decay_limit_cycle_stops_at_adaptive_floor`.)
    let recorder = TestRecorder::default();
    metrics::with_local_recorder(&recorder, || {
        let (sync, peers, applied_tip, blocks, blocks_tx) = sync_with_mined_chain(32)?;
        install_budget(
            &sync,
            super::super::SyncBudget {
                max_pending_blocks: 24,
                max_pending_bytes: usize::MAX,
                max_received_blocks: 24,
                max_received_bytes: usize::MAX,
                max_peer_inflight: 24,
                fanout_peer_inflight: 3,
                min_peers_for_fanout: 8,
                getdata_batch_limit: 24,
                stall_timeout_initial: Duration::from_millis(100),
                ..super::super::default_sync_budget()
            },
        );
        let mut rxs = Vec::new();
        for idx in 0..8_usize {
            let addr = test_addr(9470, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
        }

        // Tick 1: fan-out stripes the 24-block window, 3 blocks per peer.
        sync.tick();
        let mut stripes = Vec::new();
        for rx in &rxs {
            let stripe = witness_block_inventory(next_getdata(rx)?)?;
            assert_eq!(stripe.len(), 3, "each peer must own a 3-block stripe");
            stripes.push(stripe);
        }
        let by_hash: HashMap<BlockHash, Block> = blocks
            .iter()
            .map(|block| (block.block_hash(), block.clone()))
            .collect();

        // Three rounds, each past the stall threshold. The front
        // (heights 1, 2, 3 — peer 0's stripe) advances once per round,
        // so the interval EWMA takes its first sample at round 1 and the
        // adaptive floor (2x the ~150ms demonstrated cadence) covers the
        // mid-gap wakes from the round 1 -> 2 gap on. The round 0 -> 1
        // gap has no sample yet, but an unseeded window cannot fire at
        // all: cold-start conviction is suppressed and deferred to the
        // 60s pending-timeout fallback (`observe_stall` in the window
        // module), so even a wake landing there is safe.
        for round in 0..3_usize {
            if round == 2 {
                // The wake path observes at ~g/8 cadence, so episodes
                // form on the first wake after a round's deliveries
                // (the round tick itself observes before its refill
                // re-closes request capacity) and age across the
                // following wakes. Two mid-gap wakes reproduce that:
                // one just inside the gap to form the episode, one
                // ~120ms later — past the 100ms static threshold (the
                // pre-fix drip disconnected peer 0 exactly there) but
                // under the adaptive floor (2x the ~150ms demonstrated
                // front cadence).
                std::thread::sleep(Duration::from_millis(5));
                sync.tick();
                std::thread::sleep(Duration::from_millis(120));
                sync.tick();
                assert_eq!(
                    peers.len(),
                    8,
                    "a mid-gap wake must not disconnect a streaming peer"
                );
                std::thread::sleep(Duration::from_millis(25));
            } else {
                std::thread::sleep(Duration::from_millis(150));
            }
            for stripe in &stripes {
                let block = by_hash
                    .get(&stripe[round])
                    .ok_or_else(|| std::io::Error::other("unknown getdata hash"))?;
                blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
            }
            sync.tick();
            assert_eq!(
                peers.len(),
                8,
                "no streaming peer may be disconnected (round {round})"
            );
        }
        // Drain: feed the refill tail (heights 25..=32) one block per
        // tick — the staged set is still near the 24-block budget while
        // the expected-apply cache narrows, and a burst would push the
        // stager into evicting frontier blocks that are never
        // re-delivered here.
        let mut tail = blocks[24..].iter();
        for _ in 0..40_usize {
            let applied = applied_tip.load_full().map_or(0, |tip| tip.height);
            if applied == 32 {
                break;
            }
            if let Some(block) = tail.next() {
                blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))?;
            }
            sync.tick();
        }

        let applied_height = applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("apply did not publish tip"))?
            .height;
        assert_eq!(applied_height, 32, "uniform-slow sync must complete");
        assert_eq!(peers.len(), 8);
        assert!(
            !recorder
                .snapshot()
                .contains_key("node.sync.staller_disconnects"),
            "zero staller fires in the uniform-slow regime"
        );
        Ok(())
    })
}

#[test]
fn fatal_disconnect_readmits_nothing() -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Script;
    let (mut handles, main, mut bodies) = matured_chain(101)?;
    let tip = main
        .last()
        .ok_or_else(|| std::io::Error::other("empty chain"))?;
    let spend_txid = tip.txs[1].txid();
    // The in-flight marker can never be cleared, so the very first
    // disconnect dies fatal after rolling back cleanly. The wrapper keeps
    // the real records; only the disarm fails.
    let real_store = Arc::clone(&handles.undo_store);
    handles.undo_store = Arc::new(DisarmFailsUndoStore { inner: real_store });
    let fork_root_hash = main[49].block_hash();
    let mut tree = handles.block_tree.write();
    let mut fork_parent = tree
        .lookup(Hash256::from_le_bytes(fork_root_hash.as_bytes()))
        .ok_or_else(|| std::io::Error::other("missing fork root node"))?;
    let mut fork_prev = fork_root_hash;
    let mut fork_blocks = Vec::new();
    for height in 51..=52_u32 {
        let mut coinbase = coinbase_transaction(height);
        coinbase.outputs[0].script_pubkey = Script::from_bytes(push_int(2));
        let block = mined_block_with_prev_hash(fork_prev, height, vec![coinbase]);
        fork_parent = tree.insert_node(Some(fork_parent), block.header, NodeStatus::HeaderValid)?;
        fork_prev = block.block_hash();
        fork_blocks.push(block);
    }
    let fork_target = fork_parent;
    drop(tree);
    for block in &fork_blocks {
        bodies.insert(
            Hash256::from_le_bytes(block.block_hash().as_bytes()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
        );
    }

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |hash| bodies.get(&hash).cloned(),
        |_| {},
    );

    assert!(
        matches!(outcome, Err(crate::reorg::ReorgError::Fatal(_))),
        "a stuck disconnect marker is fatal, got {outcome:?}"
    );
    assert!(
        handles.mempool.read().is_empty(),
        "a fatal disconnect must never reconsider disconnected transactions"
    );
    assert_eq!(handles.mempool.read().sequence_number(), 0);
    // MPL-04: a stuck marker must keep all later chain changes fenced.
    assert!(handles.mempool_gateway.stable_generation().is_none());
    assert!(handles.begin_transition().is_err());
    let spend_in_pool = handles.mempool.read().contains_txid(&spend_txid);
    assert!(
        !spend_in_pool,
        "the off-chain matured spend must not be readmitted after a fatal disconnect"
    );
    Ok(())
}
