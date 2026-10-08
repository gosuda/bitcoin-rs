//! E2E: live head-sync over the real P2P wire against a spawned bitcoin-rs
//! daemon (regtest, fjall). A minimal loopback wire peer feeds `headers` /
//! `inv` announcements and serves `getdata` bodies, exercising the live
//! tip-following fixes in cba8166 (PR #1137):
//!
//!  * inv-echo getdata must upgrade announced `MSG_BLOCK` to
//!    `MSG_WITNESS_BLOCK` for WITNESS peers;
//!  * while a heavier branch is pending, the apply path must not drain the
//!    winner-branch body staged at `applied_height + 1` (drain/fail/
//!    re-request churn), and the reorg switch must complete;
//!  * untracked deliveries (hedge/inv-race bodies with no pending request)
//!    must not corrupt the request cursor.

#![expect(clippy::expect_used, reason = "process test assertions")]

use std::time::{Duration, Instant};

use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_e2e::helpers::{
    assert_clean_stderr, best_hash, block_count, build_chain, connection_count, genesis_block,
    wait_for,
};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::live_peer::pump_until_tip;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode};

/// T1+T2: a block announced by `inv` is availability, not a body order: the
/// node fetches headers first, and the admitted tip's body rides a window
/// request as `MSG_WITNESS_BLOCK`. The
/// headers->getdata->bodies->apply pipeline must still apply segwit bodies
/// served with witnesses, and an `inv` for the already-known tip must never
/// produce a plain `MSG_BLOCK` request.
#[test]
fn announced_tip_fetches_witness_block_and_applies_segwit_chain() -> Result<(), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let mut peer = LivePeer::connect(&node, "t1")?;

    assert!(
        wait_for(Duration::from_secs(10), &mut || {
            connection_count(&mut node).is_ok_and(|c| c == 1)
        }),
        "node did not report the inbound peer connection"
    );
    eprintln!("[E2E] peer connected (getconnectioncount == 1)");

    let genesis = genesis_block();
    let chain = build_chain(&genesis, 3, 0xA1, 1);
    peer.offer_chain(&chain);
    let tip = chain.last().expect("chain tip");
    let tip_hash = tip.block_hash();

    // Send the chain's headers, then announce the tip by `inv` as well: the
    // announcement route must keep the header-led fetch intact.
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.announce_headers(&chain, deadline)?;
    peer.send(
        NetworkMessage::Inv(vec![Inventory::Block(tip_hash)]),
        deadline,
    )?;

    // Observe while serving every getdata type-faithfully, until the window
    // asks for the announced tip (bounded so a stalled plan still fails).
    let tip_hex = tip_hash.to_string();
    let tip_requested_witness = |peer: &LivePeer| {
        peer.getdata_seen.iter().any(|frame| {
            frame
                .items
                .iter()
                .any(|(inv_type, hex)| *inv_type == 0x4000_0002 && *hex == tip_hex)
        })
    };
    let collect_end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < collect_end && !peer.dropped && !tip_requested_witness(&peer) {
        peer.pump(Duration::from_millis(300), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let _ = peer.serve_item(item, deadline);
            }
        });
    }
    // The announced tip's body must be requested as MSG_WITNESS_BLOCK —
    // possibly batched by the window with its other near-tip requests.
    assert!(
        tip_requested_witness(&peer),
        "no MSG_WITNESS_BLOCK getdata for the announced tip was observed; \
         getdata frames: {:?}",
        peer.getdata_seen
            .iter()
            .map(|f| (f.at_ms, f.items.clone()))
            .collect::<Vec<_>>()
    );

    // A plain MSG_BLOCK request for ANY announced block is the bug signature.
    for block in &chain {
        assert_eq!(
            peer.plain_block_requests(&block.block_hash()),
            0,
            "plain MSG_BLOCK getdata seen for {}",
            block.block_hash()
        );
    }
    eprintln!("[E2E] no MSG_BLOCK-typed getdata for announced blocks");

    // Bodies served in response to witness requests must apply end to end.
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            0,
            3,
            &tip_hash.to_string(),
            Duration::from_secs(40)
        )?,
        "applied tip never reached h3={tip_hash} (count={:?}, hash={:?}); \
         stripped bodies served: {}",
        block_count(&mut node),
        best_hash(&mut node),
        peer.stripped_served
    );
    assert_eq!(
        peer.stripped_served, 0,
        "node requested MSG_BLOCK at least once and got a stripped body"
    );
    eprintln!("[E2E] applied tip reached h3 ({tip_hash}) — segwit bodies bound and applied");

    assert_clean_stderr(&node, "extension commit churn");
    eprintln!("[E2E] T1/T2 PASSED");
    Ok(())
}

/// T3: while a heavier branch B is pending (applied tip sits on losing
/// branch A), the staged winner body at `applied_height+1` (B3) must stay
/// staged for the branch switch — not drain/fail/re-request every tick.
/// After B1,B2 arrive the switch must complete and the tip move to B3.
#[test]
fn pending_reorg_keeps_staged_winner_then_switches() -> Result<(), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let mut peer = LivePeer::connect(&node, "t3")?;

    assert!(
        wait_for(Duration::from_secs(10), &mut || {
            connection_count(&mut node).is_ok_and(|c| c == 1)
        }),
        "node did not report the inbound peer connection"
    );

    let genesis = genesis_block();
    // Branch A: two blocks, applied first.
    let branch_a = build_chain(&genesis, 2, 0x0A, 1);
    peer.offer_chain(&branch_a);
    let a2_hash = branch_a[1].block_hash();

    let deadline = Instant::now() + Duration::from_secs(10);
    peer.announce_headers(&branch_a, deadline)?;
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            0,
            2,
            &a2_hash.to_string(),
            Duration::from_secs(40)
        )?,
        "branch A never applied to tip A2"
    );
    eprintln!("[E2E] applied tip at A2 ({a2_hash}), count=2");

    // Heavier branch B: three blocks forked at genesis.
    let branch_b = build_chain(&genesis, 3, 0x0B, 1);
    peer.offer_chain(&branch_b);
    let b_hashes: Vec<bitcoin::BlockHash> =
        branch_b.iter().map(bitcoin::Block::block_hash).collect();

    peer.announce_headers(&branch_b, deadline)?;

    // Collect the window getdata for the branch-B bodies, then serve ONLY
    // B3 (the winner-branch block at applied_height+1 = 3). Under the buggy
    // code it drains into the extension commit each tick and gets
    // dropped/re-requested (PrevHashMismatch); under the fix it stays staged
    // for the branch switch.
    let served = b_hashes[2];
    collect_window_requests_serving_only(&mut peer, served, Duration::from_secs(3));
    assert!(
        peer.requests_for(&served) > 0,
        "window never requested the B3 body"
    );
    eprintln!(
        "[E2E] window requested B bodies; served ONLY B3 ({served}); holding to observe churn"
    );

    // Hold ~2.4s (2-3 sync ticks at 1s cadence; below the ~2-3s stall-fire
    // edge since frontier B1 is pending on this peer — abort early if the
    // node convicts us and drops the connection).
    let hold_start = Instant::now();
    peer.pump(Duration::from_millis(2400), &mut |_, _| {});
    let held_ms = hold_start.elapsed().as_millis();

    let b3_requests = peer.requests_for(&served);
    eprintln!(
        "[E2E] getdata requests for staged B3 after {held_ms} ms hold: {b3_requests} \
         (fix expects exactly 1; bug churns once per tick)"
    );
    assert_eq!(
        b3_requests, 1,
        "staged winner-branch body B3 was re-requested {b3_requests} times — \
         drain/fail/re-request churn"
    );
    // The request cursor must never rewind to already-applied blocks:
    // each branch-A body may appear in at most one getdata ever (its
    // original fetch). A re-request is the rewind signature.
    for applied in &branch_a {
        let hash = applied.block_hash();
        let requests = peer.requests_for(&hash);
        assert!(
            requests <= 1,
            "already-applied block {hash} requested {requests} times (cursor rewind?)"
        );
    }

    // Now deliver B1 and B2 — the connect path — and let the switch run.
    if peer.dropped {
        // The fixed stall machinery may legitimately convict the withheld
        // frontier owner; reconnect, re-announce all headers so the fresh
        // lease demonstrates height, and keep serving.
        eprintln!("[E2E] peer was disconnected during the hold (stall conviction); reconnecting");
        let mut fresh = LivePeer::connect(&node, "t3b")?;
        fresh.offer_chain(&branch_a);
        fresh.offer_chain(&branch_b);
        let headers = fresh.headers.clone();
        fresh.send(
            NetworkMessage::Headers(headers),
            Instant::now() + Duration::from_secs(10),
        )?;
        // Carry the getdata observations forward so the B3 count still
        // includes the pre-disconnect frames.
        fresh.getdata_seen = peer.getdata_seen.clone();
        peer = fresh;
    }
    // B1 and B2 are still pending on the node — deliver them explicitly.
    let serve_deadline = Instant::now() + Duration::from_secs(10);
    for hash in [b_hashes[0], b_hashes[1]] {
        let body = peer.blocks.get(&hash).cloned().expect("offered block body");
        peer.send(NetworkMessage::Block(body), serve_deadline)?;
    }
    eprintln!("[E2E] delivered withheld B1,B2; waiting for the branch switch to B3");
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            0,
            3,
            &b_hashes[2].to_string(),
            Duration::from_secs(30)
        )?,
        "reorg to branch B never completed (tip should be B3={})",
        b_hashes[2]
    );

    assert_clean_stderr(&node, "churn while branch B was pending");
    eprintln!("[E2E] T3 PASSED: pending reorg held B3 staged, then switched tip to B3");
    Ok(())
}

/// T4: an unsolicited block body for a tree-known hash whose pending request
/// was already released (peer disconnect) takes the untracked-delivery path:
/// the stager holds the body and the block tree supplies its height. The
/// chain must still converge and the request cursor must never rewind to
/// applied heights.
#[test]
fn untracked_delivery_of_tree_known_block_converges() -> Result<(), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let mut peer = LivePeer::connect(&node, "t4")?;

    assert!(
        wait_for(Duration::from_secs(10), &mut || {
            connection_count(&mut node).is_ok_and(|c| c == 1)
        }),
        "node did not report the inbound peer connection"
    );

    let genesis = genesis_block();
    let chain = build_chain(&genesis, 5, 0xC4, 1);
    peer.offer_chain(&chain);
    let tip_hash = chain[4].block_hash();

    let deadline = Instant::now() + Duration::from_secs(10);
    peer.announce_headers(&chain, deadline)?;

    // Serve every window request EXCEPT the tip: h1..h4 arrive as tracked
    // deliveries while h5 stays pending on this peer.
    let mut served_all_but_tip = false;
    let collect_end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < collect_end && !peer.dropped && !served_all_but_tip {
        peer.pump(Duration::from_millis(300), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let hash = match item {
                    Inventory::WitnessBlock(h)
                    | Inventory::CompactBlock(h)
                    | Inventory::Block(h) => Some(*h),
                    _ => None,
                };
                if hash.is_some_and(|h| h != tip_hash) {
                    let _ = peer.serve_item(item, deadline);
                }
            }
        });
        served_all_but_tip = chain[..4]
            .iter()
            .all(|b| peer.requests_for(&b.block_hash()) > 0);
    }
    assert!(
        served_all_but_tip,
        "window never requested the h1..h4 bodies"
    );
    assert!(
        wait_for(Duration::from_secs(30), &mut || {
            block_count(&mut node).is_ok_and(|c| c == 4)
        }),
        "applied tip never reached h4 (count={:?})",
        block_count(&mut node)
    );
    eprintln!("[E2E] applied tip at h4; h5 still pending on peer 1");

    // Second peer connects; peer 1 disconnects — h5's pending request is
    // released. A block body arriving now for h5 has NO pending entry:
    // the untracked-delivery path.
    let mut hedge = LivePeer::connect(&node, "t4-hedge")?;
    drop(peer);
    std::thread::sleep(Duration::from_millis(300));
    hedge.send(NetworkMessage::Block(chain[4].clone()), deadline)?;
    eprintln!(
        "[E2E] peer 1 dropped; pushed tree-known block {tip_hash} from second peer (untracked)"
    );

    // The staged h5 body must apply; the chain converges to h5.
    hedge.pump(Duration::from_millis(100), &mut |_, _| {});
    assert!(
        wait_for(Duration::from_secs(30), &mut || {
            block_count(&mut node).is_ok_and(|c| c == 5)
                && best_hash(&mut node).is_ok_and(|h| h == tip_hash.to_string())
        }),
        "tip never reached h5={tip_hash} (count={:?}, hash={:?})",
        block_count(&mut node),
        best_hash(&mut node)
    );
    eprintln!("[E2E] untracked h5 body applied; tip={tip_hash}, count=5");

    // Watch a few more ticks on the hedge connection: a retry of that entry
    // must never rewind the request cursor toward genesis, so the node never
    // re-requests already-applied heights.
    hedge.pump(Duration::from_secs(4), &mut |peer, items| {
        let deadline = Instant::now() + Duration::from_secs(5);
        for item in items {
            let _ = peer.serve_item(item, deadline);
        }
    });
    for block in &chain[..4] {
        let reasks = hedge.requests_for(&block.block_hash());
        assert!(
            reasks == 0,
            "applied block {} re-requested {reasks} times on the hedge peer (cursor rewind?)",
            block.block_hash()
        );
    }
    // h5 may be re-requested at most once: if the disconnect requeue beat
    // the hedge delivery, one legitimate re-request is expected behavior.
    assert!(
        hedge.requests_for(&tip_hash) <= 1,
        "h5 re-requested {} times on the hedge peer",
        hedge.requests_for(&tip_hash)
    );

    assert_clean_stderr(&node, "after untracked delivery");
    eprintln!("[E2E] T4 PASSED: untracked delivery pinned and chain converged to h5");
    Ok(())
}

/// Pumps the wire until `dur` elapses, serving only the getdata item naming
/// `served` — every other requested body is withheld.
fn collect_window_requests_serving_only(
    peer: &mut LivePeer,
    served: bitcoin::BlockHash,
    dur: Duration,
) {
    let end = Instant::now() + dur;
    while Instant::now() < end && !peer.dropped {
        peer.pump(Duration::from_millis(300), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let wants = match item {
                    Inventory::WitnessBlock(h)
                    | Inventory::CompactBlock(h)
                    | Inventory::Block(h) => *h == served,
                    _ => false,
                };
                if wants {
                    let _ = peer.serve_item(item, deadline);
                }
            }
        });
    }
}
