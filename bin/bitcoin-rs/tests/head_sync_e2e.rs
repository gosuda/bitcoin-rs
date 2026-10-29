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

    let deadline = Instant::now() + Duration::from_secs(10);
    peer.announce_headers(&chain, deadline)?;
    peer.send(
        NetworkMessage::Inv(vec![Inventory::Block(tip_hash)]),
        deadline,
    )?;

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
    assert!(
        tip_requested_witness(&peer),
        "no MSG_WITNESS_BLOCK getdata for the announced tip was observed; \
         getdata frames: {:?}",
        peer.getdata_seen
            .iter()
            .map(|f| (f.at_ms, f.items.clone()))
            .collect::<Vec<_>>()
    );

    for block in &chain {
        assert_eq!(
            peer.plain_block_requests(&block.block_hash()),
            0,
            "plain MSG_BLOCK getdata seen for {}",
            block.block_hash()
        );
    }
    eprintln!("[E2E] no MSG_BLOCK-typed getdata for announced blocks");

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

    let branch_b = build_chain(&genesis, 3, 0x0B, 1);
    peer.offer_chain(&branch_b);
    let b_hashes: Vec<bitcoin::BlockHash> =
        branch_b.iter().map(bitcoin::Block::block_hash).collect();

    peer.announce_headers(&branch_b, deadline)?;

    let served = b_hashes[2];
    collect_window_requests_serving_only(&mut peer, served, Duration::from_secs(3));
    assert!(
        peer.requests_for(&served) > 0,
        "window never requested the B3 body"
    );
    eprintln!(
        "[E2E] window requested B bodies; served ONLY B3 ({served}); holding to observe churn"
    );

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
    for applied in &branch_a {
        let hash = applied.block_hash();
        let requests = peer.requests_for(&hash);
        assert!(
            requests <= 1,
            "already-applied block {hash} requested {requests} times (cursor rewind?)"
        );
    }

    if peer.dropped {
        eprintln!("[E2E] peer was disconnected during the hold (stall conviction); reconnecting");
        let mut fresh = LivePeer::connect(&node, "t3b")?;
        fresh.offer_chain(&branch_a);
        fresh.offer_chain(&branch_b);
        let headers = fresh.headers.clone();
        fresh.send(
            NetworkMessage::Headers(headers),
            Instant::now() + Duration::from_secs(10),
        )?;
        fresh.getdata_seen = peer.getdata_seen.clone();
        peer = fresh;
    }
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

    let mut hedge = LivePeer::connect(&node, "t4-hedge")?;
    drop(peer);
    std::thread::sleep(Duration::from_millis(300));
    hedge.send(NetworkMessage::Block(chain[4].clone()), deadline)?;
    eprintln!(
        "[E2E] peer 1 dropped; pushed tree-known block {tip_hash} from second peer (untracked)"
    );

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
    assert!(
        hedge.requests_for(&tip_hash) <= 1,
        "h5 re-requested {} times on the hedge peer",
        hedge.requests_for(&tip_hash)
    );

    assert_clean_stderr(&node, "after untracked delivery");
    eprintln!("[E2E] T4 PASSED: untracked delivery pinned and chain converged to h5");
    Ok(())
}

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
