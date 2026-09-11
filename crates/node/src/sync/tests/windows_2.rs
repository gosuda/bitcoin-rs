use super::*;

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
            ..super::super::default_sync_budget()
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
fn peer_disconnect_mid_window_requeues_blocks_to_remaining_peers()
-> Result<(), Box<dyn std::error::Error>> {
    const PEER_COUNT: usize = 9;
    const SELECTED_PEERS: usize = super::super::MIN_PEERS_FOR_FANOUT;
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::super::PENDING_BUDGET)?)?;
    install_budget(&sync, super::super::default_sync_budget());
    let mut receivers = Vec::new();
    let mut addrs = Vec::new();
    for idx in 0..PEER_COUNT {
        let addr = test_addr(9506, idx)?;
        addrs.push(addr);
        receivers.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    // Nine live peers at the first tick: the window divides nine ways
    // (mirrors `effective_peer_inflight`).
    let cap = super::super::PENDING_BUDGET.div_ceil(PEER_COUNT).clamp(
        super::super::MAX_BLOCKS_IN_TRANSIT_PER_PEER,
        super::super::PEER_INFLIGHT_BUDGET,
    );
    for (idx, receiver) in receivers[..SELECTED_PEERS].iter().enumerate() {
        let Message::GetData(inventory) = receiver.try_recv()? else {
            return Err(std::io::Error::other("expected initial stripe").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * cap..(idx + 1) * cap]
        );
    }
    let _ = receivers[0].try_recv()?;
    // The spare takes the window remainder past the eight full stripes;
    // drain it now so the next read sees only the requeued stripe.
    let Message::GetData(remainder) = receivers[SELECTED_PEERS].try_recv()? else {
        return Err(std::io::Error::other("expected remainder getdata for spare peer").into());
    };
    assert_eq!(
        witness_block_inventory(remainder)?,
        expected[SELECTED_PEERS * cap..]
    );
    let dropped = addrs[1];
    peers.disconnect(dropped);
    sync.tick();
    let Message::GetData(inventory) = receivers[SELECTED_PEERS].try_recv()? else {
        return Err(std::io::Error::other("expected requeued getdata").into());
    };
    // The freed stripe spreads across remaining capacity (the spare tops
    // up its remainder share while the other peers absorb the rest), so
    // prove the union over every remaining peer is exactly the freed
    // stripe: every freed block re-requested, nothing else.
    let mut requeued = witness_block_inventory(inventory)?;
    for (idx, rx) in receivers.iter().enumerate() {
        if idx == 1 || idx == SELECTED_PEERS {
            continue; // disconnected peer; spare drained above
        }
        requeued.extend(witness_block_inventory(next_getdata(rx)?)?);
    }
    requeued.sort();
    let mut freed = expected[cap..2 * cap].to_vec();
    freed.sort();
    assert_eq!(requeued, freed, "every freed block must be re-requested");
    assert_eq!(
        sync.download_window.lock().pending_len(),
        super::super::PENDING_BUDGET
    );
    Ok(())
}

#[test]
fn same_address_registration_after_window_eviction_keeps_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain(3)?;
    let addr = test_addr(9508, 0)?;
    let (old_tx, old_rx) = unbounded::<Message>();
    let old = PeerLease::new(old_tx);
    peers.register(addr, old.clone());
    peers.publish_info(addr, &old, synthetic_peer(addr, 100));
    sync.tick();
    let _ = old_rx.try_recv()?;
    let _ = old_rx.try_recv()?;
    let (new_tx, new_rx) = unbounded::<Message>();
    let new = PeerLease::new(new_tx);
    peers.register(addr, new.clone());
    peers.publish_info(addr, &new, synthetic_peer(addr, 100));
    sync.tick();
    assert!(peers.is_current(new.source(addr)));
    assert!(old.is_cancelled());
    assert!(peers.is_connected(addr));
    assert!(new_rx.try_recv().is_ok());
    Ok(())
}

#[test]
fn reconcile_forgets_window_state_only_when_connection_identity_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture { sync, peers, .. } = header_sync_with_genesis()?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 0,
            ..super::super::default_sync_budget()
        },
    );
    let addr = test_addr(9509, 0)?;
    let (tx, _rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peers.register(addr, lease.clone());
    peers.publish_info(addr, &lease, synthetic_peer(addr, 8));
    sync.tick();
    assert!(sync.pending_getheaders.lock().is_some());

    assert!(!peers.register(addr, lease));
    sync.reconcile_peer_sessions();
    assert!(sync.pending_getheaders.lock().is_some());

    let (new_tx, _new_rx) = unbounded::<Message>();
    let replacement = PeerLease::new(new_tx);
    peers.register(addr, replacement.clone());
    peers.publish_info(addr, &replacement, synthetic_peer(addr, 8));
    sync.reconcile_peer_sessions();
    assert!(sync.pending_getheaders.lock().is_none());
    Ok(())
}
