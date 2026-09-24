//! Live head-sync: announcements learned inside bodies, and gaps between
//! delivered headers and the tree, must still reach admission and become
//! fetchable — a staged body can never apply while the tree does not know
//! its hash, and a batch that cannot attach must not end the conversation.

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
fn body_delivered_without_headers_announcement_admits_and_applies()
-> Result<(), Box<dyn std::error::Error>> {
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

    let unannounced =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
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
fn body_arriving_ahead_of_its_header_chain_requests_the_gap()
-> Result<(), Box<dyn std::error::Error>> {
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

    let block2 =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
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
        body_fetch_owned: false,
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
fn headers_batch_missing_parent_requests_ancestry() -> Result<(), Box<dyn std::error::Error>> {
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

    let gap_parent = test_header(genesis.compute_hash(), 1);
    let orphan_tip = test_header(gap_parent.compute_hash(), 2);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_tip],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
        body_fetch_owned: false,
    })?;

    sync.drain_inbound_headers();

    next_getheaders(&rx)?;
    Ok(())
}

#[test]
fn known_header_batch_still_credits_the_announcer() -> Result<(), Box<dyn std::error::Error>> {
    // The all-known fast path must keep the announced-tip credit the
    // admission path produced — the delivering peer's demonstrated height
    // raises its best-known watermark.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let tip1 = test_header(genesis.compute_hash(), 1);
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
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer)
            .ok_or("peer info missing")?
            .best_known_height,
        1,
        "a known tip still credits the announcer"
    );
    Ok(())
}

#[test]
fn headers_batch_too_far_ahead_does_not_replay_a_request() -> Result<(), Box<dyn std::error::Error>>
{
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

    // The header must keep valid PoW while carrying a far-future timestamp:
    // `test_header`'s mined nonce no longer validates once `time` is
    // overwritten, so a manual `u32::MAX` overwrite would trip InvalidPow (a
    // peer-fault) instead of TimestampTooFarAhead.
    let future_tip = far_future_header(genesis.compute_hash(), 1)?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![future_tip],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();

    assert!(
        next_getheaders(&rx).is_err(),
        "a future-dated rejection must not re-request the same batch"
    );
    Ok(())
}

#[test]
fn staged_body_with_permanently_inadmissible_header_is_discarded()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::CompactTarget;
    // A staged body whose embedded header fails a permanent check (wrong
    // bits) can never become expected. The staged-header retry must drop it
    // instead of paying the transition lock for the same rejection every
    // drain until the staged timeout.
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

    let mut bad =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    bad.header.bits = CompactTarget::from_consensus(0x1e0f_ff00);
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(bad))?;
    // The body stages in the first drain; the staged-header retry runs
    // before staging on the next and discards it — the window's delivery
    // record must be dropped outright too: keeping it would re-queue a
    // body whose header can never admit (C19).
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
fn body_carried_header_does_not_consume_a_pending_getheaders()
-> Result<(), Box<dyn std::error::Error>> {
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
    sync.scheduler.lock().header_request = Some(super::super::PendingHeaderRequest {
        source,
        locator_tip_hash: Hash256::default(),
        target_height: 1,
        requested_at: Instant::now(),
    });

    let body_tip = test_header(genesis.compute_hash(), 1);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![body_tip],
        source: Some(source),
        wire_response: false,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    assert!(
        sync.scheduler.lock().header_request.is_some(),
        "a body-carried header must not consume the pending request"
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![body_tip],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    assert!(
        sync.scheduler.lock().header_request.is_none(),
        "a wire `headers` response consumes the pending request"
    );
    Ok(())
}

#[test]
fn staged_retry_acceptance_credits_the_delivering_peer() -> Result<(), Box<dyn std::error::Error>> {
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

    let unannounced =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    let expected = unannounced.block_hash();
    let mut inbound = crate::InboundBlock::from_decoded(unannounced);
    inbound.source = Some(current_source(&peers, peer));
    inbound_blocks_tx.send(inbound)?;
    sync.tick();
    sync.tick();

    let session = peers
        .sessions()
        .into_iter()
        .find(|session| session.addr == peer)
        .ok_or("peer session missing")?;
    assert_eq!(
        session.demonstrated_tips,
        vec![Hash256::from(expected)],
        "the delivering peer's demonstrated tip must record the admitted header"
    );
    Ok(())
}

#[test]
fn fork_tip_attests_its_shared_active_ancestor() -> Result<(), Box<dyn std::error::Error>> {
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
    let fork1 = test_header(blocks[0].block_hash(), 2);
    let fork2 = test_header(fork1.compute_hash(), 3);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork1, fork2],
        source: Some(current_source(&peers, peer)),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer)
            .ok_or("peer info missing")?
            .best_known_height,
        1,
        "an off-active tip attests the shared prefix it proves"
    );
    Ok(())
}

#[test]
fn retained_unresolved_tips_are_deduplicated_and_capped() -> Result<(), Box<dyn std::error::Error>>
{
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
    let fork_base = test_header(blocks[0].block_hash(), 2);
    let fork_tip = test_header(fork_base.compute_hash(), 3);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_base],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![fork_tip],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    assert_eq!(
        peers
            .sessions()
            .into_iter()
            .find(|session| session.addr == peer)
            .ok_or("peer session missing")?
            .demonstrated_tips,
        vec![Hash256::from(fork_tip.compute_hash())],
        "an ancestor tip subsumed by a kept descendant is dropped"
    );

    // Distinct side branches beyond the cap: the retained set keeps the
    // deepest eight and stays bounded. Each branch is a single header
    // rooted at a lower active block — none outworks the height-10 tip.
    let mut branch_tips = Vec::new();
    for (index, parent) in blocks.iter().enumerate().skip(1).take(8) {
        let height = u32::try_from(index + 2)?;
        let tip = test_header(parent.block_hash(), height);
        branch_tips.push(tip);
        inbound_headers_tx.send(InboundHeaders {
            headers: vec![tip],
            source: Some(source),
            wire_response: true,
            body_fetch_owned: false,
        })?;
    }
    sync.drain_inbound_headers();

    let retained = peers
        .sessions()
        .into_iter()
        .find(|session| session.addr == peer)
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
fn delivered_tip_evidence_is_compacted_to_the_max_resolving_tip()
-> Result<(), Box<dyn std::error::Error>> {
    // Every delivered body's embedded header forwards through the headers
    // sink (P2P-06) and pushes a demonstrated tip per block. The credit
    // refresh compacts retained evidence to the max-resolving tip —
    // resolved tips below it can never raise the watermark again — or the
    // record would grow with every download.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let tip1 = test_header(genesis.compute_hash(), 1);
    let tip1_id = tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
    let tip2 = test_header(tip1.compute_hash(), 2);
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
        body_fetch_owned: false,
    })?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip2],
        source: Some(current_source(&peers, peer)),

        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .sessions()
            .into_iter()
            .find(|session| session.addr == peer)
            .ok_or("peer session missing")?
            .demonstrated_tips,
        vec![Hash256::from(tip2.compute_hash())],
        "retained evidence compacts to the max-resolving tip"
    );
    Ok(())
}

#[test]
fn compact_owned_body_fetch_marks_the_tip_pending() -> Result<(), Box<dyn std::error::Error>> {
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
    let tip = test_header(genesis.compute_hash(), 1);
    let tip_hash = Hash256::from(tip.compute_hash());

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip],
        source: Some(current_source(&peers, peer)),
        wire_response: false,
        body_fetch_owned: true,
    })?;
    sync.drain_inbound_headers();

    assert!(
        sync.scheduler.lock().window.contains_pending(&tip_hash),
        "a compact-owned tip body must be recorded pending, not re-requested"
    );
    Ok(())
}

#[test]
fn owned_fetch_mark_survives_until_its_tip_header_attaches()
-> Result<(), Box<dyn std::error::Error>> {
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
    let mid = test_header(genesis.compute_hash(), 1);
    let tip = test_header(mid.compute_hash(), 2);
    let tip_hash = Hash256::from(tip.compute_hash());

    // The tip arrives ahead of `mid`: admission reports MissingParent and
    // the owned-fetch mark is retained rather than dropped.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip],
        source: Some(current_source(&peers, peer)),
        wire_response: false,
        body_fetch_owned: true,
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
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    assert!(
        sync.scheduler.lock().window.contains_pending(&tip_hash),
        "the retained owned fetch must mark once its tip attaches"
    );
    Ok(())
}

/// A header batch that admits a near-tip block must fetch that block's body
/// from the announcing connection in the same drain: leaving it to the next
/// scheduler tick costs a poll interval per block at the tip (Core
/// `HeadersDirectFetchBlocks`, `net_processing.cpp:3098-3158`).
#[test]
fn announced_near_tip_is_direct_fetched_before_tick() -> Result<(), Box<dyn std::error::Error>> {
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
    let block2 =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block2.header],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
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
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block3.header],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    assert!(
        matches!(next_getdata(&rx)?.first(), Some(Inventory::CompactBlock(_))),
        "a compact-relay peer's single near-tip fetch rides the compact flavor"
    );
    Ok(())
}
