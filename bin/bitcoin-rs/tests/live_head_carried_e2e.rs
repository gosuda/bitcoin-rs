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

/// Pumps until a `getdata` requests `hash` (serving every request
/// type-faithfully), up to `dur`. Returns true when the request was seen.
fn pump_until_request(peer: &mut LivePeer, want: bitcoin::BlockHash, dur: Duration) -> bool {
    let end = Instant::now() + dur;
    while Instant::now() < end && !peer.dropped {
        if peer.requests_for(&want) > 0 {
            return true;
        }
        peer.pump(Duration::from_millis(300), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let _ = peer.serve_item(item, deadline);
            }
        });
    }
    peer.requests_for(&want) > 0
}

#[test]
fn announced_live_head_applies_and_continues() -> Result<(), Error> {
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
    let chain = build_chain(&genesis, 6, 0xD1, 1);
    peer.offer_bodies(&chain);
    peer.headers = chain[..3].iter().map(|b| b.header).collect();
    let h3 = chain[2].block_hash();
    let h6 = chain[5].block_hash();

    let deadline = Instant::now() + Duration::from_secs(10);

    peer.announce_headers(&chain[..3], deadline)?;
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            0,
            3,
            &h3.to_string(),
            Duration::from_secs(40)
        )?,
        "headers bootstrap never applied to h3 (count={:?}, hash={:?})",
        block_count(&mut node),
        best_hash(&mut node)
    );
    eprintln!("[E2E] bootstrap applied: tip=h3 ({h3}), count=3");

    for (height, block) in chain.iter().enumerate().skip(3) {
        let hash = block.block_hash();
        peer.headers = chain[..=height].iter().map(|b| b.header).collect();
        peer.send(NetworkMessage::Inv(vec![Inventory::Block(hash)]), deadline)?;
        eprintln!("[E2E] announced h{} via inv ({hash})", height + 1);
        assert!(
            pump_until_request(&mut peer, hash, Duration::from_secs(15)),
            "node never requested announced body {hash}"
        );
        assert_eq!(
            peer.plain_block_requests(&hash),
            0,
            "h{} requested as plain MSG_BLOCK",
            height + 1
        );
        assert!(
            pump_until_tip(
                &mut peer,
                &mut node,
                u64::try_from(height).unwrap_or(u64::MAX),
                u64::try_from(height + 1).unwrap_or(u64::MAX),
                &hash.to_string(),
                Duration::from_secs(20)
            )?,
            "announced block h{}={} never applied (count={:?}, best={:?})",
            height + 1,
            hash,
            block_count(&mut node),
            best_hash(&mut node)
        );
        eprintln!(
            "[E2E] h{} applied via the announcement route ({hash})",
            height + 1
        );
    }

    for block in &chain {
        let hash = block.block_hash();
        assert_eq!(
            peer.plain_block_requests(&hash),
            0,
            "plain MSG_BLOCK getdata seen for {hash}"
        );
        assert!(
            peer.requests_for(&hash) >= 1,
            "block {hash} never requested"
        );
    }
    assert_eq!(
        peer.stripped_served, 0,
        "node requested MSG_BLOCK and got a stripped body"
    );
    assert_eq!(block_count(&mut node)?, 6, "tip must be h6");
    assert_eq!(best_hash(&mut node)?, h6.to_string());

    assert_clean_stderr(&node, "live-head announcement chain");
    eprintln!("[E2E] T1 PASSED: announced headers admitted, tip advanced h3→h6 without stall");
    Ok(())
}

#[expect(clippy::too_many_lines)]
#[test]
fn missing_parent_delivery_recovers_via_getheaders() -> Result<(), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let mut peer = LivePeer::connect_with_height(&node, "t2", 0)?;

    assert!(
        wait_for(Duration::from_secs(10), &mut || {
            connection_count(&mut node).is_ok_and(|c| c == 1)
        }),
        "node did not report the inbound peer connection"
    );

    let genesis = genesis_block();
    let chain = build_chain(&genesis, 5, 0xE2, 1);
    peer.offer_bodies(&chain);
    peer.headers = Vec::new();

    peer.pump(Duration::from_millis(1500), &mut |_, _| {});
    assert!(
        peer.getheaders_at.is_empty(),
        "spontaneous getheaders probes fired with start_height=0: {:?}",
        peer.getheaders_at
    );
    eprintln!("[E2E] wire quiet for 1.5s (no discovery probes with start_height=0)");

    let h4 = chain[3].block_hash();
    let h5 = chain[4].block_hash();
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(NetworkMessage::Inv(vec![Inventory::Block(h4)]), deadline)?;
    eprintln!("[E2E] announced h4 alone ({h4}); h1..h3 unknown to node");

    peer.pump(Duration::from_secs(2), &mut |_, _| {});
    assert!(
        !peer.getheaders_at.is_empty(),
        "the inv announcement never led to a getheaders probe (announcement route broken)"
    );
    assert_eq!(
        peer.requests_for(&h4),
        0,
        "inv alone requested the announced h4 body"
    );
    assert_eq!(
        peer.plain_block_requests(&h4),
        0,
        "h4 requested as plain MSG_BLOCK"
    );
    eprintln!("[E2E] announcement probed for headers; h4 body not requested");

    peer.pump(Duration::from_millis(1200), &mut |_, _| {});
    let announcement_probes = peer.getheaders_at.len();

    let body = peer.blocks.get(&h4).cloned().expect("offered block");
    peer.send(NetworkMessage::Block(body), deadline)?;
    let served_ms = peer.at_ms();
    eprintln!("[E2E] delivered h4 body at {served_ms}ms; waiting for recovery getheaders");

    let recovery_ok = wait_for(Duration::from_secs(6), &mut || {
        peer.pump(Duration::from_millis(100), &mut |_, _| {});
        peer.getheaders_at.len() > announcement_probes
    });
    assert!(
        recovery_ok,
        "no getheaders arrived after h4 body delivery (recovery path never fired); \
         body sent at {served_ms}ms",
    );
    let recovery_at = peer.getheaders_at[announcement_probes];
    eprintln!(
        "[E2E] recovery getheaders observed at {recovery_at}ms ({}ms after body)",
        recovery_at.saturating_sub(served_ms)
    );

    let pre_headers_requests = peer.requests_for(&h4);
    peer.headers = chain[..4].iter().map(|b| b.header).collect();
    peer.announce_headers(&chain[..4], deadline)?;
    eprintln!("[E2E] sent headers h1..h4; expecting window getdata for h1..h3 only");

    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            0,
            4,
            &h4.to_string(),
            Duration::from_secs(30)
        )?,
        "staged h4 body never applied after ancestors landed (count={:?}, best={:?}); \
         requests seen: {:?}",
        block_count(&mut node),
        best_hash(&mut node),
        peer.requested_hashes()
    );
    assert_eq!(
        peer.requests_for(&h4),
        pre_headers_requests,
        "h4 body re-requested after headers landed ({} -> {}) — staged body lost",
        pre_headers_requests,
        peer.requests_for(&h4)
    );
    eprintln!(
        "[E2E] staged h4 applied in place; tip=h4, h4 requested {pre_headers_requests} time(s)"
    );

    for block in &chain[..3] {
        let hash = block.block_hash();
        assert_eq!(
            peer.requests_for(&hash),
            1,
            "ancestor {} requested {} times (expected exactly 1)",
            hash,
            peer.requests_for(&hash)
        );
    }

    peer.headers = chain[..5].iter().map(|b| b.header).collect();
    peer.send(NetworkMessage::Inv(vec![Inventory::Block(h5)]), deadline)?;
    assert!(
        pump_until_request(&mut peer, h5, Duration::from_secs(15)),
        "node never requested h5 after recovery"
    );
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            4,
            5,
            &h5.to_string(),
            Duration::from_secs(20)
        )?,
        "tip never advanced to h5 after recovery (count={:?}, best={:?})",
        block_count(&mut node),
        best_hash(&mut node)
    );
    assert_eq!(
        peer.stripped_served, 0,
        "node requested MSG_BLOCK and got a stripped body"
    );
    assert_clean_stderr(&node, "missing-parent recovery + staged apply");
    eprintln!("[E2E] T2 PASSED: recovery getheaders, staged body applied in place, tip continued");
    Ok(())
}
