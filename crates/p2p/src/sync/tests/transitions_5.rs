use super::*;

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
                ..super::super::default_sync_budget(Network::Regtest)
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
            blocks_tx.send(crate::InboundBlock::from_decoded(
                blocks[offset + 1].clone(),
            ))?;
            blocks_tx.send(crate::InboundBlock::from_decoded(
                blocks[offset + 2].clone(),
            ))?;
            sync.tick();
            assert_eq!(
                sync.scheduler
                    .lock()
                    .window
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
            blocks_tx.send(crate::InboundBlock::from_decoded(blocks[offset].clone()))?;
            sync.tick();
            assert!(sync.scheduler.lock().window.stalling_peer().is_none());
            assert_eq!(
                sync.scheduler.lock().window.stall_timeout(),
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
                ..super::super::default_sync_budget(Network::Regtest)
            },
        );
        let mut rxs = Vec::new();
        let mut sources = Vec::new();
        for idx in 0..8_usize {
            let addr = test_addr(9470, idx)?;
            rxs.push(connect_peer(
                &peers,
                eligible_peer(addr, 200 - i32::try_from(idx)?),
            ));
            sources.push(current_source(&peers, addr));
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
        // gap has no sample yet and no wake lands there: the predicate
        // only arms at round 1's observe (the staged set crosses the
        // half-window term then), so the unseeded 100ms floor never
        // judges a front in that gap.
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
            for (idx, stripe) in stripes.iter().enumerate() {
                let block = by_hash
                    .get(&stripe[round])
                    .ok_or_else(|| std::io::Error::other("unknown getdata hash"))?;
                let mut inbound = crate::InboundBlock::from_decoded(block.clone());
                // Source-attributed, like the wire path: the front arrival
                // credits the cadence EWMA and clears the owner's episode.
                inbound.source = Some(sources[idx]);
                blocks_tx.send(inbound)?;
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
                blocks_tx.send(crate::InboundBlock::from_decoded(block.clone()))?;
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
            assert_applied_genesis(&applied_tip, &block_tree)?;
        }
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected getdata").into());
        };
        requested.extend(witness_block_inventory(inventory)?);
        let _headers = rx.try_recv()?;
    }

    assert_eq!(requested, expected);
    assert_eq!(
        sync.scheduler.lock().window.pending_len(),
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
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(first) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected first getdata").into());
    };
    assert_eq!(witness_block_inventory(first)?, expected[..4]);
    let _headers = rx.try_recv()?;
    apply_fixture_block(&sync, header_chain_block(&expected, 1)?)?;
    {
        let mut scheduler = sync.scheduler.lock();
        let window = &mut scheduler.window;
        window.requeue_for_retry(
            &Hash256::from_le_bytes(expected[1].as_bytes()),
            Some(2),
            Instant::now(),
        );
    }

    sync.tick();

    let Message::GetData(second) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected gap-filling getdata").into());
    };
    assert_eq!(
        witness_block_inventory(second)?,
        vec![expected[1], expected[4]]
    );
    assert_eq!(sync.scheduler.lock().window.pending_len(), 4);
    Ok(())
}
