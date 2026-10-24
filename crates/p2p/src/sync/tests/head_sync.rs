//! Live head-sync: announcements learned inside bodies, and gaps between
//! delivered headers and the tree, must still reach admission and become
//! fetchable — a staged body can never apply while the tree does not know
//! its hash, and a batch that cannot attach must not end the conversation.

use super::*;

/// Returns the next `getheaders` from `rx`, skipping other traffic; fails
/// when none is queued.
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
    // A block body carries its own header. Bodies arriving via `inv`
    // getdata, compact-block reconstruction, or an unsolicited push
    // otherwise stage a body whose hash the tree does not know — it can
    // never become the expected block, so it times out and is dropped
    // while nothing re-requests it. The staged-header retry must admit
    // the embedded header and let the apply drain catch up.
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        applied_tip,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(unannounced))?;
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
    // A body two blocks past the applied tip has an unannounced parent.
    // Header admission fails MissingParent — sync must ask an eligible
    // peer for the missing ancestry instead of retaining the body until
    // its staged timeout drops it.
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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
    // Only the tip-of-gap body arrives — its parent's header is unknown.
    // Draining twice isolates the ancestry request: the first buffers the
    // body, the second's staged-header retry must emit the only possible
    // `getheaders` on this connection (a `tick` tail could also queue one
    // via `request_headers_from_best_peer` and mask a regression).
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block3.clone()))?;
    sync.drain_inbound_blocks();
    sync.drain_inbound_blocks();
    next_getheaders(&rx)?;

    // The ancestry fill lands: the gap headers admit, both bodies stage,
    // and the chain applies through the delivered tip.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block2.header, block3.header],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block2))?;
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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
    let mut inbound = crate::InboundBlock::from_decoded(block.clone());
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

    let mut current_inbound = crate::InboundBlock::from_decoded(block);
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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

    let mut orphan_body = crate::InboundBlock::from_decoded(block3);
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
    let mut parent_body = crate::InboundBlock::from_decoded(block2);
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
        .find(|session| session.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
        .ok_or("replacement peer session missing")?;
    assert!(
        !replacement_session.demonstrated_tips.contains(&block3_hash),
        "a predecessor's staged body must not credit its replacement",
    );
    Ok(())
}

#[test]
fn headers_batch_missing_parent_requests_ancestry() -> TestResult {
    // An announce of a tip whose parent is unknown cannot attach. The
    // announcer demonstrably has the gap, so sync asks it for the ancestry
    // rather than dropping the batch and wedging the live tip.
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
    // A body-carried header that rejects `MissingParent` asks the
    // delivering peer for the missing ancestry, but the ask must respect
    // the pending gate: an unexpired `getheaders` to the same connection
    // suppresses the identical re-request and keeps its original deadline,
    // so a peer that never answers the wire request still rotates once the
    // timeout elapses. Retiring a live gate on each body delivery let every
    // rejection install a fresh `requested_at` and pin the slot forever.
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

    // The first rejection installs the pending gate on this connection.
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
    // The all-known fast path must keep the announced-tip credit the
    // admission path produced — the delivering peer's demonstrated height
    // raises its best-known watermark.
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
            .find(|info| info.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
            .ok_or("peer info missing")?
            .best_known_height,
        1,
        "a known tip still credits the announcer"
    );
    Ok(())
}

#[test]
fn headers_batch_too_far_ahead_does_not_replay_a_request() -> TestResult {
    // A valid-PoW header beyond our two-hour clock window is a non-fault
    // rejection: the announcer can only replay the same batch into the same
    // rejection, so the drain must not re-request — the tip is relearned
    // once the local clock catches up or the next announcement arrives.
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(bad))?;
    // The body stages in the first drain; the staged-header retry runs
    // before staging on the next and discards it.
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
    // A body may stage while its header is still unknown — a body slightly
    // ahead of its in-flight header is legitimate. Once the header
    // resolves, the body must face the same unrequested-admission clauses
    // a resolved arrival faced: an off-branch body is dead inventory and
    // is evicted at once, without releasing a concurrently pending
    // requested body.
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
    // Put requested bodies in flight next to the unsolicited one: the
    // getdata marks heights 1..=2 pending in the window.
    assert!(
        sync.send_getdata_for_pending_blocks(source, false, 100, &test_frontier(&sync))
            .sent,
        "the fixture must put requested bodies in flight"
    );
    assert_eq!(sync.scheduler.lock().window.pending_len(), 2);

    // An unsolicited body whose header is not in the tree: it stages at
    // arrival (the missing-header path), and its header extends the losing
    // height-2 branch — once the header resolves it is off the active
    // branch and inadmissible.
    let fork = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(60)],
    )
    .or_fail("regtest fixture");
    let fork_hash = Hash256::from(fork.block_hash());
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(fork))?;
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
    // A staged body gated on an unknown header must face the
    // unrequested-admission clauses wherever the header lands — including
    // the ordinary headers drain, which resolves most headers long before
    // the staged-header retry reaches them. An off-branch body is dead
    // inventory and is evicted the same drain its header attaches.
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(orphan_body.clone()))?;
    sync.tick();
    assert!(
        sync.scheduler.lock().stager.contains(&orphan_hash),
        "the body must stage while its header is unknown"
    );

    // The headers drain resolves the body's header directly: the fork
    // tops out at the incumbent tip's height and loses, so the body
    // resolves inadmissible and the same drain evicts it.
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
    // A compact-relayed body may stage while its header is still unknown;
    // the peer already owns the fetch, so the mark is deferred without a
    // tree height. When the header later admits, resolving the mark must
    // lift the gate on the staged body — otherwise the recheck evicts a
    // body the peer already fetches for us and the window would schedule
    // a duplicate request.
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

    // The owned-fetch announcement arrives before the batch can attach:
    // the tip is retained as a deferred mark, and the body stages
    // gate-pending in the same tick.
    assert!(sync.enqueue_owned_body_fetch(source, orphan_hash, || true));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_body.header],
        source: Some(source),
        wire_response: true,
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(orphan_body.clone()))?;
    sync.tick();

    // The fork admits through the ordinary drain; resolving the deferred
    // mark settles the staged body's flag, so the recheck leaves it
    // alone even though the fork is off the active branch.
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
    // The send and the ownership publication are one transition: when the
    // outbound enqueue fails, nothing may be marked, or the window would
    // wait on a request that never left this node.
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
    // A same-address replacement invalidates the old connection identity.
    // The exact-source guard is held across the send, so the stale
    // source's closure must not even run: no frame leaves on the new
    // connection and no mark is published under the old identity.
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
    // `max_received_blocks` is a window budget: at the cap an unrequested
    // body is refused outright instead of evicting a staged entry to make
    // room — the stager never holds more than the budget, and already
    // staged bodies are never displaced.
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
                block.clone(),
                bytes::Bytes::from(consensus_bytes(block)),
                None,
                now,
            );
        }
    }

    let refused_hash = Hash256::from(blocks[2].block_hash());
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[2].clone()))?;
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
    // A deferred owned-fetch mark belongs to a connection. If that
    // connection dies before the header resolves, the dead fetch is no
    // request evidence: resolving the mark must not settle the staged
    // body's gate, and the ordinary recheck evicts the inadmissible body.
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

    // Defer the mark, stage the body, then drop the owning connection.
    assert!(sync.enqueue_owned_body_fetch(source, orphan_hash, || true));
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_body.header],
        source: Some(source),
        wire_response: true,
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(orphan_body.clone()))?;
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
    // The staging-slot charge lands at insert time, not at the admission
    // precheck: a body that fails body/header binding never occupies the
    // slot it tentatively counted, so a later admissible unrequested body
    // in the same chunk still stages.
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(bad))?;
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[1].clone()))?;
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
    // During a header-first reorg the applied tip still sits on the losing
    // branch until the switch completes — and the switch cannot complete
    // while branch bodies are still missing. A gated body on the winning
    // branch must keep its flag through that window: evicting it would
    // force a re-download of ancestry the pending apply needs.
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        inbound_blocks_tx,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    for block in &blocks {
        inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block.clone()))?;
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(winner_body.clone()))?;
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
    // The listener forwards each delivered body's embedded header through
    // the headers sink so its tip reaches admission — but that forward is
    // not a response to `getheaders`. Letting it consume the pending slot
    // would let every delivered block reset request pacing and emit
    // duplicate requests; only a wire `headers` message may clear it.
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
    // A body that arrives without a prior `headers` announcement admits
    // its embedded header through the staged retry. The delivering peer
    // still demonstrated that tip: the credit the headers drain would have
    // paid must land here, or a body-only announcer never earns body
    // capability (C22).
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
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
    let mut inbound = crate::InboundBlock::from_decoded(unannounced);
    inbound.source = Some(current_source(&peers, peer));
    inbound_blocks_tx.send(inbound)?;
    sync.tick();
    sync.tick();

    let session = peers
        .sessions()
        .into_iter()
        .find(|session| session.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
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
    // A demonstrated tip that stays off the active chain still proves the
    // deepest prefix it shares with it — the peer demonstrably holds that
    // ancestry and can serve its bodies. Resolving fork evidence only
    // against the active tip would read a losing branch as no capability
    // at all and skip a perfectly usable body source (C27).
    let (tree, blocks) = mined_chain(3, 0)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9707, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(peer, 0));

    // An equal-work fork rooted at height 1 stays off the active chain
    // (first-seen wins a tie), so the batch's tip is retained as fork
    // evidence while its shared ancestor — height 1 — still credits.
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
            .find(|info| info.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
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
            .find(|info| info.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
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
    // Unbounded fork evidence is a memory problem: a peer could announce
    // an arbitrary number of distinct side chains and grow the retained
    // tip vector without bound. The credit refresh keeps the maximal tip
    // per branch — a kept descendant subsumes its ancestors — and caps the
    // unresolved set outright (CR-2).
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

    // An ancestor and its descendant on the same fork branch: the retained
    // set keeps only the descendant.
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
            .find(|session| session.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
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
        .find(|session| session.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
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
    // Every delivered body's embedded header forwards through the headers
    // sink (P2P-06) and pushes a demonstrated tip per block. The credit
    // refresh compacts retained evidence to the max-resolving tip —
    // resolved tips below it can never raise the watermark again — or the
    // record would grow with every download.
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
            .find(|session| session.endpoint == Some(crate::PeerEndpoint::Ip(peer)))
            .ok_or("peer session missing")?
            .demonstrated_tips,
        vec![Hash256::from(tip2.compute_hash())],
        "retained evidence compacts to the max-resolving tip"
    );
    Ok(())
}

#[test]
fn compact_owned_body_fetch_marks_the_tip_pending() -> TestResult {
    // A `cmpctblock` whose reconstruction pends has its body fetch in
    // flight off-window (`getblocktxn`, or the fallback `getdata`). The
    // forwarded header still admits, and the window records the tip hash
    // pending under the announcing peer so normal scheduling does not
    // issue a duplicate `getdata` for it.
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

/// The harness, its mined blocks, the connected peer's source, and that
/// peer's outbound receiver, which keeps it connected.
type CompactGateFixture = (
    SyncHarness,
    Vec<Block>,
    crate::PeerSource,
    crate::test_support::MessageReceiver,
);

/// Genesis plus two mined blocks under one connected peer, with nothing
/// applied yet; callers store the applied tip when a case needs it.
fn compact_gate_fixture(port: usize) -> Result<CompactGateFixture, Box<dyn std::error::Error>> {
    let (tree, blocks) = mined_chain(2, 0)?;
    let harness = SyncHarness::new(tree);
    let peer = test_addr(port, 0)?;
    let rx = connect_peer(&harness.peers, synthetic_peer(peer, 0));
    let source = current_source(&harness.peers, peer);
    Ok((harness, blocks, source, rx))
}

/// A block-3 header on top of `tip`, distinct per `coinbase_height`.
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
    // Valid proof of work for its own declared target, but not the target
    // the chain requires after this parent.
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

    // Beyond the live future-drift ceiling, as an admitted header can be once
    // the clock moves backwards: refused while unknown, not rechecked once
    // admitted, as header admission treats it.
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
fn owned_fetch_mark_survives_until_its_tip_header_attaches() -> TestResult {
    // A compact-owned tip announced ahead of its ancestry cannot be marked
    // at delivery: the tree has no height for it yet. Dropping the mark
    // would let normal scheduling issue a second fetch while the compact
    // `getblocktxn` is still in flight, so the scheduler retains it and
    // resolves it once the missing parent chain admits.
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

    // The tip arrives ahead of `mid`: admission reports MissingParent and
    // the owned-fetch mark is retained rather than dropped.
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

    // The ancestry batch admits; the retained mark resolves to a pending.
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
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let peer = test_addr(9740, 0)?;
    // The outbound receiver stays alive: dropping it would cancel the lease.
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

    // The same path rides the compact flavor for a peer that announced BIP152
    // relay, because the fetch is the single near-tip request.
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
