use super::*;

#[test]
fn slow_trickle_front_peer_observable_but_never_disconnected() -> TestResult {
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
            blocks_tx.send(crate::InboundBlock::from_local(blocks[offset + 1].clone()))?;
            blocks_tx.send(crate::InboundBlock::from_local(blocks[offset + 2].clone()))?;
            sync.tick();
            assert_eq!(
                sync.scheduler
                    .lock()
                    .window
                    .stalling_peer()
                    .map(|(addr, _)| addr),
                Some(trickler.endpoint()),
                "the stall episode must be observable while the front trickles"
            );
            std::thread::sleep(Duration::from_millis(100));
            sync.tick();
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
            blocks_tx.send(crate::InboundBlock::from_local(blocks[offset].clone()))?;
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
fn uniform_slow_saturated_fanout_disconnects_no_peer_and_completes() -> TestResult {
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
                synthetic_peer(addr, 200 - i32::try_from(idx)?),
            ));
            sources.push(current_source(&peers, addr));
        }

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

        for round in 0..3_usize {
            if round == 2 {
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
                let mut inbound = crate::InboundBlock::from_local(block.clone());
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
        let mut tail = blocks[24..].iter();
        for _ in 0..40_usize {
            let applied = applied_tip.load_full().map_or(0, |tip| tip.height);
            if applied == 32 {
                break;
            }
            if let Some(block) = tail.next() {
                blocks_tx.send(crate::InboundBlock::from_local(block.clone()))?;
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
fn single_peer_can_fill_default_pending_window() -> TestResult {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    let addr = PeerRemote::Endpoint(crate::PeerEndpoint::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        8333,
    ));
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
fn tick_preserves_partial_window_order_across_pending_gap() -> TestResult {
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
    let addr = PeerRemote::Endpoint(crate::PeerEndpoint::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        8333,
    ));
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
