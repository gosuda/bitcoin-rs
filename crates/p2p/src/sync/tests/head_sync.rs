use super::*;

use bitcoin_rs_primitives::BlockPayload;

fn next_getheaders(
    rx: &crate::test_support::MessageReceiver,
) -> Result<bitcoin::p2p::message_blockdata::GetHeadersMessage, Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if let Message::GetHeaders(request) = message {
            return Ok(request);
        }
    }
    Err(std::io::Error::other("expected getheaders").into())
}

#[test]
fn body_delivered_without_headers_announcement_admits_and_applies() -> TestResult {
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        applied_tip,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let unannounced = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    let expected = unannounced.block_hash();
    inbound_blocks_tx.send(crate::InboundBlock::from_local(unannounced))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(expected),
        "the body-carried header must admit and the body must apply"
    );
    Ok(())
}

#[test]
fn body_arriving_ahead_of_its_header_chain_requests_the_gap() -> TestResult {
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let peer = test_addr(9700, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(peer, 3));

    let block2 = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    let block3 = regtest_fixture::mined_block_with_prev_hash(
        block2.block_hash(),
        3,
        vec![regtest_fixture::coinbase(3)],
    )
    .or_fail("regtest fixture block");
    inbound_blocks_tx.send(crate::InboundBlock::from_local(block3.clone()))?;
    sync.drain_inbound_blocks();
    sync.drain_inbound_blocks();
    next_getheaders(&rx)?;

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block2.header, block3.header],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_local(block2))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(block3.block_hash()),
        "the staged tip body must apply once its parent headers land"
    );
    Ok(())
}

#[test]
fn queued_body_from_replaced_source_cannot_enter_staging() -> TestResult {
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    let original_tip = applied_tip.load_full().ok_or("missing applied tip")?.hash;

    let peer = test_addr(9781, 0)?;
    let _old_rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let old_source = current_source(&peers, peer);
    let block = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    let hash = Hash256::from(block.block_hash());
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block.header],
        source: Some(old_source),
        wire_response: false,
    })?;
    let mut inbound = crate::InboundBlock::from_local(block.clone());
    inbound.source = Some(old_source);
    inbound_blocks_tx.send(inbound)?;

    assert!(peers.disconnect_source(old_source));
    let _replacement_rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let replacement = current_source(&peers, peer);
    assert_ne!(replacement, old_source);
    sync.drain_inbound_headers();
    sync.drain_inbound_blocks();

    assert!(sync.chain.block_tree().lookup(hash).is_none());
    assert!(!sync.scheduler.lock().stager.contains(&hash));
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        original_tip,
        "a retired delivery must not enter through its body-carried header",
    );

    let mut current_inbound = crate::InboundBlock::from_local(block);
    current_inbound.source = Some(replacement);
    inbound_blocks_tx.send(current_inbound)?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        hash,
        "the same body from a current connection remains admissible",
    );
    Ok(())
}

#[test]
fn staged_body_retries_after_source_replacement_without_replacement_credit() -> TestResult {
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let peer = test_addr(9780, 0)?;
    let old_rx = connect_peer(&peers, synthetic_peer(peer, 3));
    let old_source = current_source(&peers, peer);
    let block2 = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    let block3 = regtest_fixture::mined_block_with_prev_hash(
        block2.block_hash(),
        3,
        vec![regtest_fixture::coinbase(3)],
    )
    .or_fail("regtest fixture block");
    let block3_hash = Hash256::from(block3.block_hash());

    let mut orphan_body = crate::InboundBlock::from_local(block3);
    orphan_body.source = Some(old_source);
    inbound_blocks_tx.send(orphan_body)?;
    sync.drain_inbound_blocks();
    sync.drain_inbound_blocks();
    next_getheaders(&old_rx)?;
    {
        let scheduler = sync.scheduler.lock();
        assert!(scheduler.stager.contains(&block3_hash));
        assert_eq!(
            scheduler.stager.staged_source(&block3_hash),
            Some(old_source),
            "the staged body must retain its delivering connection",
        );
    }

    assert!(peers.disconnect_source(old_source));
    let _replacement_rx = connect_peer(&peers, synthetic_peer(peer, 3));
    let replacement_source = current_source(&peers, peer);
    assert_ne!(replacement_source, old_source);

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block2.header],
        source: Some(replacement_source),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();
    let mut parent_body = crate::InboundBlock::from_local(block2);
    parent_body.source = Some(replacement_source);
    inbound_blocks_tx.send(parent_body)?;
    sync.tick();
    sync.tick();

    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        block3_hash,
        "the retained body must apply after its parent header arrives",
    );
    assert!(!sync.scheduler.lock().stager.contains(&block3_hash));
    let replacement_session = peers
        .sessions()
        .into_iter()
        .find(|session| session.endpoint == peer.endpoint())
        .ok_or("replacement peer session missing")?;
    assert!(
        !replacement_session.demonstrated_tips.contains(&block3_hash),
        "a predecessor's staged body must not credit its replacement",
    );
    Ok(())
}

#[test]
fn headers_batch_missing_parent_requests_ancestry() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9701, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(peer, 10));

    let gap_parent = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
        .or_fail("regtest fixture header");
    let orphan_tip = regtest_fixture::mined_regtest_header(gap_parent.compute_hash(), 2)
        .or_fail("regtest fixture header");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_tip],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;

    sync.drain_inbound_headers();

    next_getheaders(&rx)?;
    Ok(())
}

#[test]
fn body_carried_rejection_keeps_the_live_pending_gate() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9768, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(peer, 10));

    let gap_parent = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)?;
    let orphan_tip = regtest_fixture::mined_regtest_header(gap_parent.compute_hash(), 2)?;
    let batch = || InboundHeaders {
        headers: vec![orphan_tip],
        source: Some(current_source(&peers, peer)),
        wire_response: false,
    };

    inbound_headers_tx.send(batch())?;
    sync.drain_inbound_headers();
    next_getheaders(&rx)?;
    let first_requested_at = sync
        .scheduler
        .lock()
        .header_request()
        .map(|request| request.requested_at)
        .ok_or("the first rejection must install the pending gate")?;

    std::thread::sleep(Duration::from_millis(20));
    while rx.try_recv().is_ok() {}
    inbound_headers_tx.send(batch())?;
    sync.drain_inbound_headers();
    assert!(
        rx.try_recv().is_err(),
        "a live pending gate must suppress the identical re-request"
    );
    let second_requested_at = sync
        .scheduler
        .lock()
        .header_request()
        .map(|request| request.requested_at)
        .ok_or("the suppressed re-request must leave the gate installed")?;
    assert_eq!(
        first_requested_at, second_requested_at,
        "the pending deadline must survive an identical body-carried rejection"
    );
    Ok(())
}

#[test]
fn known_header_batch_still_credits_the_announcer() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let tip1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
        .or_fail("regtest fixture header");
    tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9702, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip1],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.endpoint == peer.endpoint())
            .ok_or("peer info missing")?
            .best_known_height,
        1,
        "a known tip still credits the announcer"
    );
    Ok(())
}

#[test]
fn headers_batch_too_far_ahead_does_not_replay_a_request() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9704, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(peer, 0));

    let future_tip = far_future_header(genesis.compute_hash(), 1)?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![future_tip],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;
    sync.drain_inbound_headers();

    assert!(
        next_getheaders(&rx).is_err(),
        "a future-dated rejection must not re-request the same batch"
    );
    Ok(())
}

#[test]
fn staged_body_with_permanently_inadmissible_header_is_discarded() -> TestResult {
    use bitcoin_rs_primitives::CompactTarget;
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        applied_tip,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let mut bad = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    bad.header.bits = CompactTarget::from_consensus(0x1e0f_ff00);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(bad))?;
    sync.tick();
    sync.tick();

    assert_eq!(
        sync.scheduler.lock().stager.received_len(),
        0,
        "the inadmissible body must be discarded, not retried"
    );
    Ok(())
}

#[test]
fn staged_body_whose_resolved_header_is_inadmissible_is_evicted() -> TestResult {
    let (tree, blocks) = mined_chain(2, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9709, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let source = current_source(&peers, peer);
    assert!(
        sync.send_getdata_for_pending_blocks(source, false, 100, &test_frontier(&sync))
            .sent,
        "the fixture must put requested bodies in flight"
    );
    assert_eq!(sync.scheduler.lock().window.pending_len(), 2);

    let fork = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(60)],
    )
    .or_fail("regtest fixture");
    let fork_hash = Hash256::from(fork.block_hash());
    inbound_blocks_tx.send(crate::InboundBlock::from_local(fork))?;
    sync.tick();
    sync.tick();

    let scheduler = sync.scheduler.lock();
    assert!(
        !scheduler.stager.contains(&fork_hash),
        "a body that resolves inadmissible must not survive header resolution"
    );
    assert_eq!(
        scheduler.window.pending_len(),
        2,
        "evicting the inadmissible body must not touch the pending requested bodies"
    );
    Ok(())
}

#[test]
fn staged_body_gated_when_the_headers_drain_resolves_its_header() -> TestResult {
    let (tree, _blocks) = mined_chain(2, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9711, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 2));

    let fork_root = regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
        .or_fail("regtest fixture");
    let orphan_body = regtest_fixture::mined_block_with_prev_hash(
        fork_root.compute_hash(),
        2,
        vec![regtest_fixture::coinbase(70)],
    )
    .or_fail("regtest fixture");
    let orphan_hash = Hash256::from(orphan_body.block_hash());
    inbound_blocks_tx.send(crate::InboundBlock::from_local(orphan_body.clone()))?;
    sync.tick();
    assert!(
        sync.scheduler.lock().stager.contains(&orphan_hash),
        "the body must stage while its header is unknown"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_root, orphan_body.header],
        source: None,
        wire_response: true,
    })?;
    sync.tick();

    assert!(
        !sync.scheduler.lock().stager.contains(&orphan_hash),
        "a body whose header resolves off-branch must not survive the drain"
    );
    Ok(())
}

#[test]
fn deferred_owned_body_fetch_settles_the_staged_gate() -> TestResult {
    let (tree, _blocks) = mined_chain(2, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9712, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let source = current_source(&peers, peer);

    let fork_root = regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
        .or_fail("regtest fixture");
    let orphan_body = regtest_fixture::mined_block_with_prev_hash(
        fork_root.compute_hash(),
        2,
        vec![regtest_fixture::coinbase(71)],
    )
    .or_fail("regtest fixture");
    let orphan_hash = Hash256::from(orphan_body.block_hash());

    assert!(sync.enqueue_owned_body_fetch(source, orphan_hash, || true));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_body.header],
        source: Some(source),
        wire_response: true,
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_local(orphan_body.clone()))?;
    sync.tick();

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_root, orphan_body.header],
        source: None,
        wire_response: true,
    })?;
    sync.tick();

    assert!(
        sync.scheduler.lock().stager.contains(&orphan_hash),
        "a body the peer already fetches must be exempt from the recheck"
    );
    Ok(())
}

#[test]
fn failed_enqueue_publishes_no_owned_body_fetch() -> TestResult {
    let (tree, _blocks) = mined_chain(2, 0)?;
    let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9713, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let source = current_source(&peers, peer);
    let hash = Hash256::from_le_bytes(&[7_u8; 32]);

    assert!(!sync.enqueue_owned_body_fetch(source, hash, || false));
    assert!(
        sync.scheduler.lock().owned_body_fetches.is_empty(),
        "a failed enqueue must publish no ownership mark"
    );
    assert!(!sync.owns_body_fetch(source, hash));
    Ok(())
}

#[test]
fn stale_source_never_reaches_the_enqueue_closure() -> TestResult {
    let (tree, _blocks) = mined_chain(2, 0)?;
    let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9714, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let stale = current_source(&peers, peer);
    let _rx2 = connect_peer(&peers, synthetic_peer(peer, 2));
    let hash = Hash256::from_le_bytes(&[9_u8; 32]);

    let called = std::cell::Cell::new(false);
    assert!(!sync.enqueue_owned_body_fetch(stale, hash, || {
        called.set(true);
        true
    }));
    assert!(!called.get(), "stale source must not reach the send");
    assert!(
        sync.scheduler.lock().owned_body_fetches.is_empty(),
        "stale source must publish no ownership mark"
    );
    Ok(())
}

#[test]
fn unrequested_body_at_the_count_budget_is_refused() -> TestResult {
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_blocks: 2,
            ..super::super::default_sync_budget(bitcoin_rs_primitives::Network::Regtest)
        },
    );
    {
        let mut scheduler = sync.scheduler.lock();
        let now = Instant::now();
        for (idx, block) in blocks[..2].iter().enumerate() {
            let mut key = [0_u8; 32];
            key[0] = 0x71_u8.saturating_add(idx.try_into()?);
            scheduler.stager.insert(
                Hash256::from_le_bytes(&key),
                None,
                BlockPayload::from_local(block.clone()),
                None,
                now,
            );
        }
    }

    let refused_hash = Hash256::from(blocks[2].block_hash());
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[2].clone()))?;
    sync.drain_inbound_blocks();

    let scheduler = sync.scheduler.lock();
    assert_eq!(
        scheduler.stager.received_len(),
        2,
        "a refused body must not evict staged entries to make room"
    );
    assert!(
        !scheduler.stager.contains(&refused_hash),
        "the unrequested body is refused, not staged"
    );
    Ok(())
}

#[test]
fn stale_owned_fetch_source_does_not_settle_the_gate() -> TestResult {
    let (tree, _blocks) = mined_chain(2, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let peer = test_addr(9713, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let source = current_source(&peers, peer);

    let fork_root = regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
        .or_fail("regtest fixture");
    let orphan_body = regtest_fixture::mined_block_with_prev_hash(
        fork_root.compute_hash(),
        2,
        vec![regtest_fixture::coinbase(72)],
    )
    .or_fail("regtest fixture");
    let orphan_hash = Hash256::from(orphan_body.block_hash());

    assert!(sync.enqueue_owned_body_fetch(source, orphan_hash, || true));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_body.header],
        source: Some(source),
        wire_response: true,
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_local(orphan_body.clone()))?;
    sync.tick();
    peers.disconnect_source(source);

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_root, orphan_body.header],
        source: None,
        wire_response: true,
    })?;
    sync.tick();

    assert!(
        !sync.scheduler.lock().stager.contains(&orphan_hash),
        "a stale owner's mark must not exempt the staged body from the gate"
    );
    Ok(())
}

#[test]
fn binding_failure_does_not_burn_the_last_staging_slot() -> TestResult {
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_blocks: 1,
            ..super::super::default_sync_budget(bitcoin_rs_primitives::Network::Regtest)
        },
    );

    let mut bad = blocks[2].clone();
    bad.txs.push(regtest_fixture::coinbase(90));
    let bad_hash = Hash256::from(bad.block_hash());
    let good_hash = Hash256::from(blocks[1].block_hash());
    inbound_blocks_tx.send(crate::InboundBlock::from_local(bad))?;
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[1].clone()))?;
    sync.drain_inbound_blocks();

    let scheduler = sync.scheduler.lock();
    assert_eq!(
        scheduler.stager.received_len(),
        1,
        "the binding-failed body must not consume the single staging slot"
    );
    assert!(!scheduler.stager.contains(&bad_hash));
    assert!(
        scheduler.stager.contains(&good_hash),
        "the admissible unrequested body stages into the freed slot"
    );
    Ok(())
}

#[test]
fn gate_pending_body_survives_a_pending_branch_switch() -> TestResult {
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        inbound_blocks_tx,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    for block in &blocks {
        inbound_blocks_tx.send(crate::InboundBlock::from_local(block.clone()))?;
    }
    sync.tick();
    assert_eq!(
        sync.chain.applied_tip().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[2].block_hash()),
        "the losing branch must be applied to height 3"
    );

    let fork_root = regtest_fixture::mined_regtest_header(genesis_header().compute_hash(), 1)
        .or_fail("regtest fixture");
    let winner_body = regtest_fixture::mined_block_with_prev_hash(
        fork_root.compute_hash(),
        2,
        vec![regtest_fixture::coinbase(73)],
    )
    .or_fail("regtest fixture");
    let winner_hash = Hash256::from(winner_body.block_hash());
    let fork_h3 = regtest_fixture::mined_regtest_header(winner_body.header.compute_hash(), 3)
        .or_fail("regtest fixture");
    let fork_h4 =
        regtest_fixture::mined_regtest_header(fork_h3.compute_hash(), 4).or_fail("regtest fixture");
    inbound_blocks_tx.send(crate::InboundBlock::from_local(winner_body.clone()))?;
    sync.tick();
    assert!(
        sync.scheduler.lock().stager.contains(&winner_hash),
        "the body must stage while its header is unknown"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_root, winner_body.header, fork_h3, fork_h4],
        source: None,
        wire_response: true,
    })?;
    sync.tick();

    let applied = sync.chain.applied_tip().ok_or("missing applied tip")?;
    assert_eq!(
        applied.hash,
        Hash256::from(blocks[2].block_hash()),
        "the switch must still be pending on the missing fork bodies"
    );
    assert!(
        sync.scheduler.lock().stager.contains(&winner_hash),
        "a winning-branch body must survive a pending branch switch"
    );
    Ok(())
}

#[test]
fn body_carried_header_does_not_consume_a_pending_getheaders() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9705, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
    let source = current_source(&peers, peer);
    {
        let mut scheduler = sync.scheduler.lock();
        scheduler.headers_sync.entry(source).or_default().request =
            Some(super::super::HeaderRequest {
                source,
                kind: super::super::HeaderRequestKind::Frontier,
                locator_tip_hash: Hash256::default(),
                target_height: 1,
                requested_at: Instant::now(),
                state: super::super::HeaderRequestState::AwaitingResponse,
            });
        scheduler.header_request_owner = Some(source);
    }

    let body_tip = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
        .or_fail("regtest fixture header");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![body_tip],
        source: Some(source),
        wire_response: false,
    })?;
    sync.drain_inbound_headers();
    assert!(
        sync.scheduler.lock().header_request().is_some(),
        "a body-carried header must not consume the pending request"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![body_tip],
        source: Some(source),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();
    assert!(
        sync.scheduler.lock().header_request().is_none(),
        "a wire `headers` response consumes the pending request"
    );
    Ok(())
}

#[test]
fn staged_retry_acceptance_credits_the_delivering_peer() -> TestResult {
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();

    let peer = test_addr(9706, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

    let unannounced = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    let expected = unannounced.block_hash();
    let mut inbound = crate::InboundBlock::from_local(unannounced);
    inbound.source = Some(current_source(&peers, peer));
    inbound_blocks_tx.send(inbound)?;
    sync.tick();
    sync.tick();

    let session = peers
        .sessions()
        .into_iter()
        .find(|session| session.endpoint == peer.endpoint())
        .ok_or("peer session missing")?;
    assert_eq!(
        session.demonstrated_tips,
        vec![Hash256::from(expected)],
        "the delivering peer's demonstrated tip must record the admitted header"
    );
    Ok(())
}

#[test]
fn fork_tip_attests_its_shared_active_ancestor() -> TestResult {
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9707, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

    let fork1 = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)
        .or_fail("regtest fixture header");
    let fork2 = regtest_fixture::mined_regtest_header(fork1.compute_hash(), 3)
        .or_fail("regtest fixture header");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork1, fork2],
        source: Some(current_source(&peers, peer)),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.endpoint == peer.endpoint())
            .ok_or("peer info missing")?
            .best_known_height,
        1,
        "an off-active tip attests the shared prefix it proves"
    );
    Ok(())
}

#[test]
fn fork_evidence_cannot_credit_a_tainted_ancestor_height() -> TestResult {
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        peers,
        block_tree,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9707, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
    let fork = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)
        .or_fail("regtest fixture header");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork],
        source: Some(current_source(&peers, peer)),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();
    let peer_height = || {
        peers
            .infos()
            .into_iter()
            .find(|info| info.endpoint == peer.endpoint())
            .map(|info| info.best_known_height)
    };
    assert_eq!(peer_height(), Some(1));
    {
        let mut tree = block_tree.write();
        let ancestor = tree
            .lookup(Hash256::from(blocks[0].block_hash()))
            .ok_or("ancestor")?;
        tree.node_mut(ancestor)?.height = 100;
    }
    sync.refresh_active_peer_credit();
    assert_eq!(peer_height(), Some(1));
    Ok(())
}

#[test]
fn retained_unresolved_tips_are_deduplicated_and_capped() -> TestResult {
    let (tree, blocks) = mined_chain(10, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9708, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
    let source = current_source(&peers, peer);

    let fork_base = regtest_fixture::mined_regtest_header(blocks[0].block_hash(), 2)
        .or_fail("regtest fixture header");
    let fork_tip = regtest_fixture::mined_regtest_header(fork_base.compute_hash(), 3)
        .or_fail("regtest fixture header");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_base],
        source: Some(source),
        wire_response: true,
    })?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_tip],
        source: Some(source),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();
    assert_eq!(
        peers
            .sessions()
            .into_iter()
            .find(|session| session.endpoint == peer.endpoint())
            .ok_or("peer session missing")?
            .demonstrated_tips,
        vec![Hash256::from(fork_tip.compute_hash())],
        "an ancestor tip subsumed by a kept descendant is dropped"
    );

    let mut branch_tips = Vec::new();
    for (index, parent) in blocks.iter().enumerate().skip(1).take(8) {
        let height = u32::try_from(index + 2)?;
        let tip = regtest_fixture::mined_regtest_header(parent.block_hash(), height)
            .or_fail("regtest fixture header");
        branch_tips.push(tip);
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![tip],
            source: Some(source),
            wire_response: true,
        })?;
    }
    sync.drain_inbound_headers();

    let retained = peers
        .sessions()
        .into_iter()
        .find(|session| session.endpoint == peer.endpoint())
        .ok_or("peer session missing")?
        .demonstrated_tips;
    assert_eq!(
        retained.len(),
        8,
        "unresolved tips are bounded by the per-session cap"
    );
    assert_eq!(
        retained[0],
        Hash256::from(branch_tips[7].compute_hash()),
        "the deepest unresolved tip is retained first"
    );
    Ok(())
}

#[test]
fn delivered_tip_evidence_is_compacted_to_the_max_resolving_tip() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let tip1 = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
        .or_fail("regtest fixture header");
    let tip1_id = tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
    let tip2 = regtest_fixture::mined_regtest_header(tip1.compute_hash(), 2)
        .or_fail("regtest fixture header");
    tree.insert_node(Some(tip1_id), tip2, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9703, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip1],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip2],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .sessions()
            .into_iter()
            .find(|session| session.endpoint == peer.endpoint())
            .ok_or("peer session missing")?
            .demonstrated_tips,
        vec![Hash256::from(tip2.compute_hash())],
        "retained evidence compacts to the max-resolving tip"
    );
    Ok(())
}

#[test]
fn compact_owned_body_fetch_marks_the_tip_pending() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9706, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
    let tip = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
        .or_fail("regtest fixture header");
    let tip_hash = Hash256::from(tip.compute_hash());

    assert!(sync.enqueue_owned_body_fetch(current_source(&peers, peer), tip_hash, || true,));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip],
        source: Some(current_source(&peers, peer)),
        wire_response: false,
    })?;
    sync.drain_inbound_headers();

    assert!(
        sync.scheduler.lock().window.contains_pending(&tip_hash),
        "a compact-owned tip body must be recorded pending, not re-requested"
    );
    Ok(())
}

type CompactGateFixture = (
    SyncHarness,
    Vec<Block>,
    crate::PeerSource,
    crate::test_support::MessageReceiver,
);

fn compact_gate_fixture(port: usize) -> Result<CompactGateFixture, Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(2, 0)?;
    let harness = SyncHarness::new(tree);
    let peer = test_addr(port, 0)?;
    let rx = connect_peer(&harness.peers, synthetic_peer(peer, 0));
    let source = current_source(&harness.peers, peer);
    Ok((harness, blocks, source, rx))
}

fn tip_child(
    tip: &Block,
    coinbase_height: u32,
) -> Result<bitcoin_rs_primitives::Header, Box<dyn std::error::Error>> {
    Ok(regtest_fixture::mined_block_with_prev_hash(
        tip.block_hash(),
        3,
        vec![regtest_fixture::coinbase(coinbase_height)],
    )?
    .header)
}

#[test]
fn compact_reconstruction_admission_follows_cores_header_gate() -> TestResult {
    let (harness, blocks, source, _rx) = compact_gate_fixture(9707)?;
    let other = test_addr(9708, 0)?;
    let _other_rx = connect_peer(&harness.peers, synthetic_peer(other, 0));
    let sync = &harness.sync;
    let tip = blocks.last().ok_or("chain has a tip")?;

    let extending = tip_child(tip, 3)?;
    let replayed = blocks.first().ok_or("chain has block 1")?.header;
    assert!(
        sync.compact_reconstruction_admissible(source, &replayed),
        "with nothing applied yet, any valid connected header carries more work"
    );
    harness.applied_tip.store(harness.block_tree.read().tip());
    assert!(
        sync.compact_reconstruction_admissible(source, &extending),
        "a mined child of the applied tip"
    );
    let mut wrong_target = extending;
    wrong_target.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x2000_ffff);
    regtest_fixture::mine_header_to_declared_target(&mut wrong_target)?;
    assert!(
        !sync.compact_reconstruction_admissible(source, &wrong_target),
        "a target other than the required one"
    );
    let mut no_work = extending;
    no_work.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x1d00_ffff);
    assert!(
        !sync.compact_reconstruction_admissible(source, &no_work),
        "no proof of work"
    );
    let orphan = regtest_fixture::mined_regtest_header(no_work.compute_hash(), 4)?;
    assert!(
        !sync.compact_reconstruction_admissible(source, &orphan),
        "unknown parent"
    );

    let replayed_hash = Hash256::from(replayed.compute_hash());
    assert!(
        !sync.compact_reconstruction_admissible(source, &replayed),
        "no more work than the applied tip"
    );
    assert!(sync.enqueue_owned_body_fetch(
        current_source(&harness.peers, other),
        replayed_hash,
        || true,
    ));
    assert!(
        !sync.compact_reconstruction_admissible(source, &replayed),
        "another connection's fetch"
    );
    assert!(sync.enqueue_owned_body_fetch(source, replayed_hash, || true,));
    assert!(
        sync.compact_reconstruction_admissible(source, &replayed),
        "this connection's fetch"
    );
    Ok(())
}

#[test]
fn compact_reconstruction_admission_reads_admitted_tree_state() -> TestResult {
    let (harness, blocks, source, _rx) = compact_gate_fixture(9709)?;
    let sync = &harness.sync;
    let tip = blocks.last().ok_or("chain has a tip")?;
    harness.applied_tip.store(harness.block_tree.read().tip());
    let admit = |header, status| -> TestResult {
        let mut tree = harness.block_tree.write();
        let parent = tree
            .lookup(Hash256::from(tip.block_hash()))
            .ok_or("tip is in the tree")?;
        tree.insert_node(Some(parent), header, status)?;
        Ok(())
    };

    let mut ahead = tip_child(tip, 43)?;
    ahead.time = bitcoin_rs_chain::current_unix_seconds().saturating_add(3 * 60 * 60);
    regtest_fixture::mine_header_to_declared_target(&mut ahead)?;
    assert!(
        !sync.compact_reconstruction_admissible(source, &ahead),
        "unknown and too far ahead"
    );
    admit(ahead, NodeStatus::HeaderValid)?;
    assert!(
        sync.compact_reconstruction_admissible(source, &ahead),
        "admitted, not rechecked"
    );

    let invalid = tip_child(tip, 33)?;
    admit(invalid, NodeStatus::Invalid)?;
    assert!(
        !sync.compact_reconstruction_admissible(source, &invalid),
        "a block marked invalid"
    );
    let invalid_child = regtest_fixture::mined_regtest_header(invalid.compute_hash(), 4)?;
    assert!(
        !sync.compact_reconstruction_admissible(source, &invalid_child),
        "a child of an invalid block"
    );
    Ok(())
}

#[test]
fn compact_reconstruction_admission_stays_near_the_applied_tip() -> TestResult {
    let (tree, blocks) = mined_chain(6, 0)?;
    let applied = {
        let id = tree
            .lookup(Hash256::from(blocks[0].block_hash()))
            .ok_or("block 1 is in the tree")?;
        let node = tree.node(id)?;
        TipSnapshot {
            tip_id: id,
            chain_tx_count: node.chain_tx_count,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    };
    let harness = SyncHarness::new(tree);
    harness.applied_tip.store(Some(Arc::new(applied)));
    let peer = test_addr(9790, 0)?;
    let _rx = connect_peer(&harness.peers, synthetic_peer(peer, 0));
    let source = current_source(&harness.peers, peer);
    let sync = &harness.sync;

    assert!(
        sync.compact_reconstruction_admissible(source, &blocks[1].header),
        "one block above the applied tip"
    );
    assert!(
        sync.compact_reconstruction_admissible(source, &blocks[2].header),
        "two blocks above the applied tip"
    );
    assert!(
        !sync.compact_reconstruction_admissible(source, &blocks[3].header),
        "three blocks above the applied tip"
    );
    assert!(
        !sync.compact_reconstruction_admissible(source, &blocks[5].header),
        "five blocks above the applied tip"
    );
    assert!(sync.enqueue_owned_body_fetch(source, Hash256::from(blocks[3].block_hash()), || true));
    assert!(
        sync.compact_reconstruction_admissible(source, &blocks[3].header),
        "a fetch this connection owns"
    );
    Ok(())
}

#[test]
fn owned_fetch_mark_survives_until_its_tip_header_attaches() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9707, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));
    let mid = regtest_fixture::mined_regtest_header(genesis.compute_hash(), 1)
        .or_fail("regtest fixture header");
    let tip = regtest_fixture::mined_regtest_header(mid.compute_hash(), 2)
        .or_fail("regtest fixture header");
    let tip_hash = Hash256::from(tip.compute_hash());

    assert!(sync.enqueue_owned_body_fetch(current_source(&peers, peer), tip_hash, || true,));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip],
        source: Some(current_source(&peers, peer)),
        wire_response: false,
    })?;
    sync.drain_inbound_headers();
    assert!(
        !sync.scheduler.lock().window.contains_pending(&tip_hash),
        "an unattached tip cannot be window-pending yet"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![mid, tip],
        source: Some(current_source(&peers, peer)),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();
    assert!(
        sync.scheduler.lock().window.contains_pending(&tip_hash),
        "the retained owned fetch must mark once its tip attaches"
    );
    Ok(())
}

#[test]
fn announced_near_tip_is_direct_fetched_before_tick() -> TestResult {
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let peer = test_addr(9740, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(peer, 3));
    let source = current_source(&peers, peer);
    let block2 = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .or_fail("regtest fixture block");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block2.header],
        source: Some(source),
        wire_response: true,
    })?;

    sync.drain_inbound_headers();
    assert_eq!(
        witness_block_inventory(next_getdata(&rx)?)?,
        vec![block2.block_hash()],
        "the announcing connection is asked for the body without another tick"
    );
    assert!(
        sync.scheduler
            .lock()
            .window
            .contains_pending(&Hash256::from(block2.block_hash())),
        "the window owns the body the direct fetch requested"
    );

    peers.note_compact_relay(source);
    let block3 = regtest_fixture::mined_block_with_prev_hash(
        block2.block_hash(),
        3,
        vec![regtest_fixture::coinbase(3)],
    )
    .or_fail("regtest fixture block");
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block3.header],
        source: Some(source),
        wire_response: true,
    })?;
    sync.drain_inbound_headers();
    assert!(
        matches!(
            next_getdata(&rx)?.first(),
            Some(Inventory::CompactBlock(hash))
                if Hash256::from_le_bytes(hash.as_byte_array())
                    == Hash256::from(block3.block_hash())
        ),
        "a compact-relay peer's single near-tip fetch rides the compact flavor for the announced block"
    );
    Ok(())
}
