//! P2P-05: canonical progress, not a scheduler cursor, owns the next body.

use super::*;

/// Returns the next `getheaders` from `rx`, skipping other traffic; fails
/// when none is queued.
fn next_getheaders(
    rx: &crossbeam_channel::Receiver<Message>,
) -> Result<bitcoin::p2p::message_blockdata::GetHeadersMessage, Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if let Message::GetHeaders(request) = message {
            return Ok(request);
        }
    }
    Err(std::io::Error::other("expected getheaders").into())
}

#[test]
fn applied_rewind_with_unchanged_headers_refetches_the_missing_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, applied, blocks, incoming) = sync_with_mined_chain(3)?;
    let peer = test_addr(9760, 0)?;
    let outbound = connect_peer(&peers, eligible_peer(peer, 3));
    sync.tick();
    let genesis = applied.load_full().ok_or("missing genesis")?;
    let hashes: Vec<_> = blocks.iter().map(Block::block_hash).collect();
    assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
    for block in blocks {
        incoming.send(crate::InboundBlock::from_decoded(block))?;
    }
    sync.tick();
    assert_eq!(applied.load_full().ok_or("missing applied tip")?.height, 3);
    assert_no_getdata(&outbound)?;

    // The chain owner may disconnect independently of this executor. Headers
    // still select the same branch; the old forward cursor is not authority.
    applied.store(Some(genesis));
    sync.tick();
    assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
    sync.tick();
    assert_no_getdata(&outbound)?;
    Ok(())
}

#[test]
fn cancelled_ready_event_does_not_wait_for_an_unrelated_body_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let peer = test_addr(9760, 1)?;
    let _old = connect_peer(&peers, eligible_peer(peer, 1));
    let stale = current_source(&peers, peer);
    let _replacement = connect_peer(&peers, eligible_peer(peer, 1));
    let sync = Arc::new(sync);
    let body = sync.frontier_state.lock();
    let (finished, completed) = crossbeam_channel::bounded(1);
    let worker_sync = Arc::clone(&sync);
    let worker = std::thread::spawn(move || {
        worker_sync.on_peer_ready(stale);
        let _ = finished.send(());
    });
    let result = completed.recv_timeout(Duration::from_secs(1));
    drop(body);
    worker.join().map_err(|_| "ready handler panicked")?;
    result?;
    assert!(peers.is_current(current_source(&peers, peer)));
    Ok(())
}

#[test]
fn empty_header_probe_is_paced_then_rotates_to_another_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let first = test_addr(9760, 2)?;
    let second = test_addr(9760, 3)?;
    let first_rx = connect_peer(&peers, eligible_peer(first, 0));
    let second_rx = connect_peer(&peers, eligible_peer(second, 0));
    let (headers, receiver) = unbounded();
    *sync.inbound_headers_rx.lock() = receiver;
    sync.tick();
    assert!(matches!(first_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(second_rx.try_recv().is_err());
    headers.send(InboundHeaders {
        headers: vec![],
        source: Some(current_source(&peers, first)),
    })?;
    sync.tick();
    assert!(first_rx.try_recv().is_err());
    assert!(second_rx.try_recv().is_err());
    sync.frontier_state
        .lock()
        .header_request
        .as_mut()
        .ok_or("probe lost its deadline")?
        .requested_at -= super::super::HEADER_REQUEST_TIMEOUT;
    sync.tick();
    assert!(matches!(second_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(first_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn staged_successors_behind_a_rejected_frontier_still_probe()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Amount;
    let (sync, peers, _, blocks, incoming) = sync_with_mined_chain(3)?;
    let peer = test_addr(9761, 0)?;
    // start_height 0: not getdata-eligible (height must exceed the floor of
    // 0) but probe-eligible (services carry NETWORK|WITNESS), so any
    // GetHeaders this peer observes can only come from the idle probe.
    let outbound = connect_peer(&peers, eligible_peer(peer, 0));

    // Malformed frontier body: the header still hashes to block 1's hash, but
    // the txid Merkle root no longer binds to the header, so the body fails
    // the binding gate and is rejected instead of staged.
    let mut malformed_frontier = blocks[0].clone();
    malformed_frontier.txs[0].outputs[0].value = Amount::from_sat(2);
    assert_eq!(
        malformed_frontier.block_hash(),
        blocks[0].block_hash(),
        "altering body transaction bytes must retain the header-derived hash"
    );
    incoming.send(crate::InboundBlock::from_decoded(malformed_frontier))?;
    incoming.send(crate::InboundBlock::from_decoded(blocks[1].clone()))?;
    incoming.send(crate::InboundBlock::from_decoded(blocks[2].clone()))?;

    // One tick: bootstraps genesis, drains and stages, and probes. No earlier
    // tick ran, so the probe decision is the one under test.
    sync.tick();

    // The rejected frontier leaves the apply-frontier block unowned, so the
    // idle probe must fire despite the two staged successors.
    let probe = next_getheaders(&outbound)?;
    assert_eq!(
        probe
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*Network::Regtest.genesis_block().block_hash().as_bytes()),
        "the probe must start from the applied chain"
    );

    // The successors staged; the malformed frontier body did not.
    let body = sync.frontier_state.lock();
    assert_eq!(body.stager.received_len(), 2);
    assert!(!body.stager.contains(&Hash256::from(blocks[0].block_hash())));
    drop(body);

    Ok(())
}

#[test]
fn superseded_session_gets_no_probe_and_cannot_send_getheaders()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let peer = test_addr(9762, 0)?;
    let old_rx = connect_peer(&peers, eligible_peer(peer, 1));
    let old_source = current_source(&peers, peer);

    // A handshaking replacement takes the address; it never publishes
    // handshake metadata, so it cannot be selected by either header path.
    let (replacement_tx, replacement_rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(replacement_tx));

    sync.tick();

    let mut saw_getheaders = false;
    while let Ok(message) = replacement_rx.try_recv() {
        if matches!(message, Message::GetHeaders(_)) {
            saw_getheaders = true;
        }
    }
    assert!(
        !saw_getheaders,
        "handshaking replacement must receive no probe"
    );
    let mut stale_getheaders = false;
    while let Ok(message) = old_rx.try_recv() {
        if matches!(message, Message::GetHeaders(_)) {
            stale_getheaders = true;
        }
    }
    assert!(
        !stale_getheaders,
        "superseded session must receive no probe"
    );

    // The superseded identity must be rejected by the source-validated lease
    // even when addressed directly, and it must leave no pending request.
    let genesis = Network::Regtest.genesis_block().block_hash();
    let locator = vec![Hash256::from_le_bytes(genesis.as_bytes())];
    assert!(
        !sync.send_getheaders(old_source, 0, 10, locator),
        "lease_source must reject a superseded session identity"
    );
    assert!(
        sync.frontier_state.lock().header_request.is_none(),
        "a rejected send must not leave scheduler state behind"
    );
    Ok(())
}

#[test]
fn failed_probe_send_falls_back_to_best_peer_in_the_same_tick()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
    // Inert getdata: an exhausted staging byte budget closes the request gate
    // before any scan, so no pending body work can suppress the probe.
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_bytes: 0,
            max_received_bytes: 0,
            ..super::super::default_sync_budget()
        },
    );
    let low = test_addr(9763, 0)?;
    let high = test_addr(9763, 1)?;
    // Lowest address wins the probe's min_by_key(addr) rotation, but its
    // channel is dead: dropping the receiver disconnects the crossbeam
    // sender, so the lease's try_send fails and the lease cancels itself.
    let dead_rx = connect_peer(&peers, eligible_peer(low, 1));
    drop(dead_rx);
    let high_rx = connect_peer(&peers, eligible_peer(high, 5));

    sync.tick();
    assert!(
        !peers.sessions().iter().any(|session| session.addr == low),
        "the failed probe source must be evicted instead of lingering table-resident",
    );

    // The failed probe must hand off to request_headers_from_best_peer in the
    // same tick, which sends to the live higher peer.
    let request = next_getheaders(&high_rx)?;
    assert_eq!(
        request
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*expected[0].as_bytes()),
        "the fallback request must start at the header tip"
    );

    // The dead peer must not have inherited the pending request, and no
    // further getheaders lands anywhere in this tick.
    assert_eq!(
        sync.frontier_state
            .lock()
            .header_request
            .as_ref()
            .map(|request| request.source.addr),
        Some(high),
        "the fallback owner must hold the pending request"
    );
    assert!(high_rx.try_recv().is_err());

    Ok(())
}

#[test]
fn failed_probe_send_excludes_dead_highest_peer_from_header_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_bytes: 0,
            max_received_bytes: 0,
            ..super::super::default_sync_budget()
        },
    );
    let dead = test_addr(9764, 0)?;
    let live = test_addr(9764, 1)?;
    // The lowest address is selected for the probe and has the highest
    // advertised height, but its disconnected queue makes the send fail.
    let dead_rx = connect_peer(&peers, eligible_peer(dead, 5));
    drop(dead_rx);
    let live_rx = connect_peer(&peers, eligible_peer(live, 3));

    sync.tick();

    // Without the failed-source exclusion, normal selection retries the dead
    // highest peer and masks the lower live peer in this same tick.
    let request = next_getheaders(&live_rx)?;
    assert_eq!(
        request
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*expected[0].as_bytes()),
        "the fallback request must start at the header tip"
    );
    assert_eq!(
        sync.frontier_state
            .lock()
            .header_request
            .as_ref()
            .map(|request| request.source.addr),
        Some(live),
        "the lower live peer must own the fallback request"
    );
    assert!(live_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn dead_probe_peer_is_evicted_and_not_repicked_on_the_next_tick()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_bytes: 0,
            max_received_bytes: 0,
            ..super::super::default_sync_budget()
        },
    );
    let dead = test_addr(9766, 0)?;
    let live = test_addr(9766, 1)?;
    // Lowest address wins the probe's min_by_key(addr) rotation, but its
    // channel is dead: dropping the receiver disconnects the crossbeam
    // sender, so the lease's try_send fails and the lease cancels itself.
    let dead_rx = connect_peer(&peers, eligible_peer(dead, 5));
    drop(dead_rx);
    let live_rx = connect_peer(&peers, eligible_peer(live, 3));

    // Tick 1: the dead peer's probe send fails and the same-tick fallback
    // hands the request to the live peer.
    sync.tick();
    let request = next_getheaders(&live_rx)?;
    assert_eq!(
        request
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*expected[0].as_bytes()),
        "the fallback request must start at the header tip"
    );

    // Expire the live peer's pending request so the next tick must choose a
    // probe target again.
    sync.frontier_state
        .lock()
        .header_request
        .as_mut()
        .ok_or("fallback lost its deadline")?
        .requested_at -= super::super::HEADER_REQUEST_TIMEOUT;

    // Tick 2: the dead session must be gone (evicted on the failed send,
    // swept by the reconciler as backstop) instead of being re-picked once
    // per tick forever.
    sync.tick();
    assert!(
        !peers.sessions().iter().any(|session| session.addr == dead),
        "the dead peer session must not survive into the next tick",
    );
    assert_ne!(
        sync.frontier_state
            .lock()
            .header_request
            .as_ref()
            .map(|request| request.source.addr),
        Some(dead),
        "the pending request must not be keyed to the dead addr",
    );
    let request = next_getheaders(&live_rx)?;
    // The follow-up request is the idle frontier probe, anchored on the
    // active chain at the applied height (genesis here) — not the fallback's
    // chain-tip locator.
    assert_eq!(
        request
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*Network::Regtest.genesis_block().block_hash().as_bytes()),
        "the live peer must own the follow-up header request",
    );
    assert!(live_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn reconciler_sweeps_cancelled_lease_sessions_within_one_tick()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let addr = test_addr(9767, 0)?;
    // A lease cancelled by any path (here: direct teardown request) while its
    // session stays table-resident must leave the table within one tick.
    let _rx = connect_peer(&peers, eligible_peer(addr, 5));
    peers.lease(addr).ok_or("peer missing from table")?.cancel();
    assert!(peers.sessions().iter().any(|session| session.addr == addr));
    sync.tick();
    assert!(
        !peers.sessions().iter().any(|session| session.addr == addr),
        "the reconciler must sweep cancelled-lease sessions",
    );
    Ok(())
}

#[test]
fn reorg_probe_anchors_locator_before_first_required_body() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;

    let common = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let common_id = tree.insert_node(Some(genesis_id), common.header, NodeStatus::HeaderValid)?;

    let losing_2 =
        mined_block_with_prev_hash(common.block_hash(), 2, vec![coinbase_transaction(2_002)]);
    let losing_2_id =
        tree.insert_node(Some(common_id), losing_2.header, NodeStatus::HeaderValid)?;
    let losing_3 =
        mined_block_with_prev_hash(losing_2.block_hash(), 3, vec![coinbase_transaction(2_003)]);
    let losing_3_id =
        tree.insert_node(Some(losing_2_id), losing_3.header, NodeStatus::HeaderValid)?;

    let winning_2 =
        mined_block_with_prev_hash(common.block_hash(), 2, vec![coinbase_transaction(1_002)]);
    let winning_2_id =
        tree.insert_node(Some(common_id), winning_2.header, NodeStatus::HeaderValid)?;
    let winning_3 =
        mined_block_with_prev_hash(winning_2.block_hash(), 3, vec![coinbase_transaction(1_003)]);
    let winning_3_id = tree.insert_node(
        Some(winning_2_id),
        winning_3.header,
        NodeStatus::HeaderValid,
    )?;
    let winning_4 =
        mined_block_with_prev_hash(winning_3.block_hash(), 4, vec![coinbase_transaction(1_004)]);
    let winning_4_id = tree.insert_node(
        Some(winning_3_id),
        winning_4.header,
        NodeStatus::HeaderValid,
    )?;

    let active_tip = tree.tip().ok_or("missing active tip")?;
    assert_eq!(active_tip.tip_id, winning_4_id);
    let active_anchor = tree
        .node_at_height_from(winning_4_id, 1)
        .ok_or("missing active parent of first required body")?;
    assert_eq!(active_anchor, common_id);
    let active_anchor_hash = tree.node(active_anchor)?.hash;
    let losing_tip = tree.node(losing_3_id)?;
    let losing_snapshot = TipSnapshot {
        tip_id: losing_3_id,
        height: losing_tip.height,
        chainwork: losing_tip.chainwork,
        hash: losing_tip.hash,
    };

    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx: _headers_tx,
        inbound_blocks_tx: _blocks_tx,
        ..
    } = SyncHarness::new(tree);
    applied_tip.store(Some(Arc::new(losing_snapshot)));

    let peer = test_addr(9765, 0)?;
    let outbound = connect_peer(&peers, eligible_peer(peer, 0));
    sync.tick();

    let probe = next_getheaders(&outbound)?;
    let locator_tip = probe
        .locator_hashes
        .first()
        .ok_or("probe locator is empty")?;
    assert_eq!(
        *locator_tip.as_byte_array(),
        active_anchor_hash.to_le_bytes(),
        "idle recovery must anchor immediately before the first required body",
    );
    assert_ne!(
        *locator_tip.as_byte_array(),
        *losing_3.block_hash().as_bytes(),
        "the losing applied tip must never anchor a deep-reorg recovery probe",
    );
    Ok(())
}

#[test]
fn same_address_replacement_is_not_convicted_for_predecessor_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    // Identity reconciliation runs before conviction: a pending-timeout
    // suspicion recorded against one connection must not convict the
    // replacement that now owns its address.
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            ..super::super::default_sync_budget()
        },
    );
    let addr = test_addr(9768, 0)?;
    let rx = connect_peer(&peers, eligible_peer(addr, 100));

    // Tick 1: the first connection takes the front stripe.
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
    // Header traffic is a plan detail; drain it without asserting shape.
    while rx.try_recv().is_ok() {}

    // Tick 2: the zero timeout records the suspicion; conviction waits for
    // a second observation tick (suspicion -> conviction cadence).
    sync.tick();
    assert!(
        peers.is_connected(addr),
        "the suspicion tick must not convict yet"
    );

    // The predecessor is replaced at the same address before the
    // conviction tick can run.
    let _replacement_rx = connect_peer(&peers, eligible_peer(addr, 100));
    let replacement = current_source(&peers, addr);

    // Tick 3: the recorded timeout belonged to the predecessor's session
    // and must die with it.
    sync.tick();
    assert!(
        peers.is_current(replacement),
        "the replacement must not be disconnected for its predecessor's timeout"
    );
    assert!(
        peers.is_connected(addr),
        "the table must still hold the address under the replacement"
    );
    assert!(
        !sync
            .frontier_state
            .lock()
            .window
            .peer_in_staller_cooldown(addr, Instant::now()),
        "the replacement must not inherit the predecessor's staller mark"
    );
    Ok(())
}
