use super::*;

// Contract anchors: request eligibility and ordering are owned by
// docs/contracts/p2p-wire.md#P2P-03; batch sizing is the local sync budget
// invariant exercised by the fixtures below.

#[test]
fn tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch()
-> Result<(), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    let mut expected = Vec::new();
    let batch_size = 16_u32;

    for height in 1_u32..=batch_size + 4 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        if height <= batch_size {
            expected.push(BlockHash::from(tree.node(tip_id)?.hash));
        }
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::super::SyncBudget {
            getdata_batch_limit: usize::try_from(batch_size)?,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    let requested = inventory
        .into_iter()
        .map(|item| match item {
            // Wire seam: Inventory payloads stay bitcoin::; convert to native.
            Inventory::WitnessBlock(hash) => {
                Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
            }
            _ => Err(std::io::Error::other("expected witness block inventory")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(requested, expected);
    Ok(())
}

#[test]
fn second_tick_does_not_re_request_already_pending_blocks() -> Result<(), Box<dyn std::error::Error>>
{
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;

    for height in 1_u32..=3 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let first = rx.try_recv()?;
    if !matches!(first, Message::GetData(_)) {
        return Err(std::io::Error::other("expected first tick getdata").into());
    }
    let second = rx.try_recv()?;
    if !matches!(second, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected first tick getheaders").into());
    }

    sync.tick();

    // The in-flight getheaders gate suppresses a duplicate header request,
    // and already-pending blocks are not re-requested, so the second tick
    // emits no outbound messages.
    match rx.try_recv() {
        Ok(Message::GetData(_)) => {
            Err(std::io::Error::other("second tick re-requested pending blocks").into())
        }
        Ok(Message::GetHeaders(_)) => {
            Err(std::io::Error::other("second tick resent in-flight getheaders").into())
        }
        Ok(_) => Err(std::io::Error::other("unexpected extra message after second tick").into()),
        Err(crossbeam_channel::TryRecvError::Empty) => Ok(()),
        Err(crossbeam_channel::TryRecvError::Disconnected) => {
            Err(std::io::Error::other("outbound channel disconnected").into())
        }
    }
}

#[test]
fn successful_getdata_send_marks_requested_blocks_pending() -> Result<(), Box<dyn std::error::Error>>
{
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(3)?;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let first = rx.try_recv()?;
    let Message::GetData(inventory) = first else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected);

    let window = sync.download_window.lock();
    assert_eq!(window.pending_len(), expected.len());
    for hash in expected {
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(hash.as_bytes());
        assert!(window.contains_pending(&hash));
    }
    Ok(())
}

#[test]
fn drain_inbound_blocks_prunes_stale_received_blocks_without_new_arrivals()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, _peers, _block_tree, _applied_tip, _expected) = sync_with_header_chain(1)?;
    let block = Network::Regtest.genesis_block();
    let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_bytes());
    let received_at = Instant::now()
        .checked_sub(super::super::RECEIVED_BLOCK_TIMEOUT + Duration::from_secs(1))
        .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let staged = sync
        .block_stager
        .lock()
        .insert(hash, None, block, serialized, received_at);
    let StagedBlock::Memory { bytes, .. } = staged else {
        return Err(std::io::Error::other("test block should stage in memory").into());
    };
    sync.download_window
        .lock()
        .mark_received(hash, bytes, Instant::now());

    sync.drain_inbound_blocks();

    assert_eq!(sync.block_stager.lock().received_len(), 0);
    assert_eq!(sync.download_window.lock().received_len(), 0);
    Ok(())
}

#[test]
fn tick_respects_pending_byte_budget() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(3)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_bytes: 256 * 1024,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(inventory.len(), 1);
    assert_eq!(sync.download_window.lock().pending_len(), 1);
    Ok(())
}

#[test]
fn tick_limits_inflight_per_peer() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, _expected) = sync_with_header_chain(5)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_peer_inflight: 2,
            ..super::super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(inventory.len(), 2);
    let _headers = rx.try_recv()?;

    sync.tick();

    // Peer inflight budget is saturated and the in-flight getheaders gate
    // suppresses a duplicate header request, so the second tick is silent.
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_falls_back_to_single_deep_peer_below_fanout_threshold()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    let mut rxs = Vec::new();
    for idx in 0..super::super::MIN_PEERS_FOR_FANOUT - 1 {
        let addr = test_addr(9021, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rxs[0].try_recv()? else {
        return Err(std::io::Error::other("expected deep getdata for highest peer").into());
    };
    // The tracked window remains single-owner. Idle eligible alternates
    // receive only the same bounded frontier prefix for the one-shot race.
    assert_eq!(witness_block_inventory(inventory)?, expected);
    for rx in &rxs[1..] {
        assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
    }
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET
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
