//! Frontier liveness after serving peers miss the block-request timeout
//! (issue #1153): the peers this node holds must carry the frontier.

use super::*;

/// Answers every request `rx` carried, as an honest peer does: its own
/// headers for a `getheaders`, and the bodies it holds for a `getdata`.
///
/// `wire_response` marks whether the headers reply is the answer to the
/// node's request (`true`) or a batch forwarded out of a delivery
/// (`false`), which is what the header gate distinguishes.
fn answer_requests(
    rx: &crossbeam_channel::Receiver<Message>,
    source: PeerSource,
    headers: &[Header],
    bodies: &HashMap<Hash256, Block>,
    inbound_headers_tx: &crossbeam_channel::Sender<InboundHeaders>,
    inbound_blocks_tx: &crossbeam_channel::Sender<crate::InboundBlock>,
    wire_response: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        match message {
            Message::GetHeaders(_) => {
                inbound_headers_tx.send(InboundHeaders {
                    headers: headers.to_vec(),
                    source: Some(source),
                    wire_response,
                    body_fetch_owned: false,
                })?;
            }
            Message::GetData(inventory) => {
                for hash in witness_block_inventory(inventory)? {
                    if let Some(block) = bodies.get(&hash.0) {
                        let mut inbound = crate::InboundBlock::from_decoded(block.clone());
                        inbound.source = Some(source);
                        inbound_blocks_tx.send(inbound)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The incident shape: both serving peers demonstrate the active tip and
/// own frontier work, then miss the block-request timeout and are
/// convicted one after the other; freshly handshaked replacements arrive
/// afterwards. The replacements must be driven into header sync past the
/// stuck tip and serve the requeued bodies, so the apply frontier advances.
#[test]
fn replacements_carry_frontier_after_serving_peer_timeouts()
-> Result<(), Box<dyn std::error::Error>> {
    // Header tip at 6, bodies for 1..=6; the public tip sits at 8, two
    // blocks past the header tip, so the replacements have headers to bring
    // as well as bodies.
    let (tree, mut blocks) = mined_chain(6, 0)?;
    let mut prev = blocks[5].block_hash();
    for height in 7..=8_u32 {
        let block = mined_block_with_prev_hash(prev, height, vec![coinbase_transaction(height)]);
        prev = block.block_hash();
        blocks.push(block);
    }
    let bodies: HashMap<Hash256, Block> = blocks
        .iter()
        .map(|block| (Hash256::from(block.block_hash()), block.clone()))
        .collect();
    let active: Vec<Header> = blocks[1..6].iter().map(|block| block.header).collect();
    let beyond: Vec<Header> = blocks[6..8].iter().map(|block| block.header).collect();

    let SyncHarness {
        sync,
        peers,
        block_tree: _,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
    } = SyncHarness::new(tree);
    install_budget(
        &sync,
        super::super::SyncBudget {
            pending_timeout_override: Some(Duration::from_millis(200)),
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );

    // Apply block 1 so the apply frontier needs block 2's body.
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;

    // Two serving peers at the header tip. Each demonstrates the active tip
    // through headers carried by its earlier deliveries, then answers
    // nothing else — the request that times out is its own fault.
    let s1 = test_addr(9821, 0)?;
    let s2 = test_addr(9821, 1)?;
    let _s1_rx = connect_peer(&peers, synthetic_peer(s1, 6));
    let _s2_rx = connect_peer(&peers, synthetic_peer(s2, 6));
    for addr in [s1, s2] {
        let source = current_source(&peers, addr);
        inbound_headers_tx.send(InboundHeaders {
            headers: active.clone(),
            source: Some(source),
            wire_response: false,
            body_fetch_owned: false,
        })?;
    }

    sync.tick();
    // Neither server answers, so each owns a request that ages past the
    // block-request timeout and is convicted — the incident's staggered
    // double loss.
    for _ in 0..24 {
        std::thread::sleep(Duration::from_millis(250));
        sync.tick();
        if !peers.is_connected(s1) && !peers.is_connected(s2) {
            break;
        }
    }
    assert!(
        !peers.is_connected(s1) && !peers.is_connected(s2),
        "both serving peers must be convicted of the block-request timeout"
    );
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "the fixture must reach the stall state: applied frozen behind the header tip",
    );

    // The replacements: freshly handshaked, no demonstrated tips, claiming
    // the public height 8, and answering every request they receive.
    let r1 = test_addr(9821, 2)?;
    let r2 = test_addr(9821, 3)?;
    let r1_rx = connect_peer(&peers, synthetic_peer(r1, 8));
    let r2_rx = connect_peer(&peers, synthetic_peer(r2, 8));
    let r1_source = current_source(&peers, r1);
    let r2_source = current_source(&peers, r2);

    // The frontier must advance: the replacements carry both the requeued
    // bodies and the headers past the stuck tip.
    let mut advanced = false;
    for _ in 0..120 {
        std::thread::sleep(Duration::from_millis(50));
        sync.tick();
        answer_requests(
            &r1_rx,
            r1_source,
            &beyond,
            &bodies,
            &inbound_headers_tx,
            &inbound_blocks_tx,
            true,
        )?;
        answer_requests(
            &r2_rx,
            r2_source,
            &beyond,
            &bodies,
            &inbound_headers_tx,
            &inbound_blocks_tx,
            true,
        )?;
        if applied_tip.load_full().is_some_and(|tip| tip.height >= 6) {
            advanced = true;
            break;
        }
    }
    assert!(
        advanced,
        "the apply frontier must advance through the replacements; applied tip: {:?}",
        applied_tip.load_full().map(|tip| tip.height)
    );
    Ok(())
}

/// One connection, never asked, holding the frontier block: the report's
/// `no_capable_peer` loop with a healthy peer set.
///
/// The peer proved a tip on a branch this node no longer follows, so its
/// demonstrated evidence resolves at the fork point — below the frontier —
/// while its handshake claim covers the frontier and its store holds the
/// frontier block. Its `getheaders` answer follows that losing branch, so
/// the probe meant to restore capability only replays headers this node
/// already holds: the evidence never refreshes, and the body path that
/// reads it never asks. The frontier then reports no capable peer for the
/// life of the connection, which is what a restart "cures" by dropping the
/// per-connection evidence.
#[test]
fn losing_fork_evidence_never_revokes_the_height_a_peer_was_asked_at()
-> Result<(), Box<dyn std::error::Error>> {
    // Active branch X: genesis plus six mined blocks, block 1 applied, so
    // the frontier needs block 2's body.
    let (tree, blocks) = mined_chain(6, 0)?;
    let bodies: HashMap<Hash256, Block> = blocks
        .iter()
        .map(|block| (Hash256::from(block.block_hash()), block.clone()))
        .collect();
    let SyncHarness {
        sync,
        peers,
        block_tree: _,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
    } = SyncHarness::new(tree);
    install_budget(&sync, super::super::default_sync_budget(Network::Regtest));
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "the fixture applies block 1, so the frontier needs block 2's body",
    );

    // The peer claims this node's own header height, so no header ask can
    // reach it either: the body path is its only route to the frontier. Its
    // best chain is a losing fork off block 1, which it proved to us.
    let p = test_addr(9823, 0)?;
    let p_rx = connect_peer(&peers, synthetic_peer(p, 6));
    let p_source = current_source(&peers, p);
    let fork2 = test_header(blocks[0].block_hash(), 2);
    let fork: Vec<Header> = vec![fork2, test_header(fork2.compute_hash(), 3)];
    inbound_headers_tx.send(InboundHeaders {
        headers: fork.clone(),
        source: Some(p_source),
        wire_response: false,
        body_fetch_owned: false,
    })?;
    sync.tick();

    // The defect, named: proving a tip on a branch this node no longer
    // follows used to revoke the height the connection was asked at,
    // pinning its capability at the fork point. Branch evidence may raise
    // what a peer may serve, never lower it below the credit it carries.
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    let capability = frontier
        .usable_peers
        .iter()
        .find(|peer| peer.source == p_source)
        .and_then(super::super::frontier::UsablePeer::capability);
    assert_eq!(
        capability,
        Some(6),
        "a fork-only answer must not revoke the height the peer was asked at",
    );
    assert_eq!(
        frontier.plan().no_progress,
        None,
        "a peer that claimed the frontier must not leave the frontier reporting no_capable_peer",
    );

    // The peer answers every request it receives and is at fault for none:
    // its `getheaders` reply is its own losing branch, its `getdata` reply
    // is the frontier block it holds.
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(20));
        sync.tick();
        answer_requests(
            &p_rx,
            p_source,
            &fork,
            &bodies,
            &inbound_headers_tx,
            &inbound_blocks_tx,
            true,
        )?;
        if applied_tip.load_full().is_some_and(|tip| tip.height >= 2) {
            return Ok(());
        }
    }
    Err(format!(
        "a peer that holds the frontier block and answers every request must be asked for it; \
         applied tip stayed at {:?}",
        applied_tip.load_full().map(|tip| tip.height)
    )
    .into())
}
