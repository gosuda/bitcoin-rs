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

use bitcoin::absolute::LockTime;
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode};
use serde_json::{Value, json};

/// Builds a BIP141 segwit coinbase-only block on `parent`: the coinbase
/// carries the 32-byte reserved nonce in its input witness and an `OP_RETURN`
/// commitment output (`aa21a9ed`), so the body binds to the header only when
/// witness data is intact. `tag` separates competing branches so coinbases
/// (and therefore txids/headers) differ across forks at equal heights.
fn segwit_coinbase_block(parent: &Block, height: u32, tag: u8) -> Block {
    let reserved = [tag; 32];
    // Coinbase-only tree: witness leaf 0 is zeroed out, so the wtxid merkle
    // root is exactly [0;32]; commitment = sha256d(root || reserved).
    let mut buffer = [0_u8; 64];
    buffer[32..].copy_from_slice(&reserved);
    let commitment = sha256d::Hash::hash(&buffer).to_byte_array();
    let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commit_script.extend_from_slice(&commitment);
    let coinbase = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![
                0x01,
                u8::try_from(height).unwrap_or(0xff),
                0x01,
                tag,
            ]),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&reserved[..]]),
        }],
        output: vec![
            TxOut {
                // 50 BTC regtest subsidy; spend path never exercised.
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commit_script),
            },
        ],
    };
    let mut block = Block {
        header: BlockHeader {
            version: parent.header.version,
            prev_blockhash: parent.block_hash(),
            merkle_root: parent.header.merkle_root, // placeholder, replaced below
            time: parent.header.time.saturating_add(1),
            bits: parent.header.bits,
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("coinbase merkle root");
    while !pow_met(block.header.bits, block.header.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .expect("nonce space exhausted");
    }
    block
}

fn pow_met(bits: CompactTarget, hash: bitcoin::BlockHash) -> bool {
    bitcoin::Target::from_compact(bits).is_met_by(hash)
}

/// RPC helpers.
fn rpc(node: &mut ProcessNode, method: &str) -> Result<Value, Error> {
    node.rpc(method, &json!([]))
}

fn block_count(node: &mut ProcessNode) -> Result<u64, Error> {
    Ok(rpc(node, "getblockcount")?.as_u64().unwrap_or(u64::MAX))
}

fn best_hash(node: &mut ProcessNode) -> Result<String, Error> {
    Ok(rpc(node, "getbestblockhash")?
        .as_str()
        .unwrap_or("")
        .to_owned())
}

fn connection_count(node: &mut ProcessNode) -> Result<u64, Error> {
    Ok(rpc(node, "getconnectioncount")?
        .as_u64()
        .unwrap_or(u64::MAX))
}

/// Polls an RPC predicate until it holds or `dur` elapses.
fn wait_for(dur: Duration, check: &mut dyn FnMut() -> bool) -> bool {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Keeps serving bodies (type-faithfully) while waiting for the applied tip
/// to reach `height`/`hash`.
fn pump_until_tip(
    peer: &mut LivePeer,
    node: &mut ProcessNode,
    height: u64,
    hash: &str,
    dur: Duration,
) -> Result<bool, Error> {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline && !peer.dropped {
        if block_count(node)? == height && best_hash(node)? == hash {
            return Ok(true);
        }
        peer.pump(Duration::from_millis(400), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let _ = peer.serve_item(item, deadline);
            }
        });
    }
    Ok(block_count(node)? == height && best_hash(node)? == hash)
}

/// Reads the node's stderr evidence so far.
fn node_stderr(node: &ProcessNode) -> String {
    std::fs::read_to_string(node.evidence.join("stderr.log")).unwrap_or_default()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn regtest_genesis() -> Block {
    bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
}

/// Builds a chain of `count` segwit coinbase blocks extending `parent`.
fn build_chain(parent: &Block, count: u32, tag: u8, start_height: u32) -> Vec<Block> {
    let mut chain = Vec::with_capacity(usize::try_from(count).unwrap_or(64));
    let mut prev = parent.clone();
    for i in 0..count {
        let tag = tag.wrapping_add(u8::try_from(i).unwrap_or(0));
        let block = segwit_coinbase_block(&prev, start_height + i, tag);
        prev = block.clone();
        chain.push(block);
    }
    chain
}

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

    let genesis = regtest_genesis();
    let chain = build_chain(&genesis, 3, 0xA1, 1);
    peer.offer_chain(&chain);
    let tip = chain.last().expect("chain tip");
    let tip_hash = tip.block_hash();

    // Send the chain's headers, then announce the tip by `inv` as well: the
    // announcement route must keep the header-led fetch intact.
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(
        NetworkMessage::Headers(chain.iter().map(|b| b.header).collect()),
        deadline,
    )?;
    peer.send(
        NetworkMessage::Inv(vec![Inventory::Block(tip_hash)]),
        deadline,
    )?;

    // Observe for ~4s while serving every getdata type-faithfully.
    peer.pump(Duration::from_secs(4), &mut |peer, items| {
        let deadline = Instant::now() + Duration::from_secs(5);
        for item in items {
            let _ = peer.serve_item(item, deadline);
        }
    });

    // The announced tip's body must be requested as MSG_WITNESS_BLOCK —
    // possibly batched by the window with its other near-tip requests.
    let tip_hex = tip_hash.to_string();
    let tip_requested_witness = peer.getdata_seen.iter().any(|frame| {
        frame
            .items
            .iter()
            .any(|(inv_type, hex)| *inv_type == 0x4000_0002 && *hex == tip_hex)
    });
    assert!(
        tip_requested_witness,
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

    let genesis = regtest_genesis();
    // Branch A: two blocks, applied first.
    let branch_a = build_chain(&genesis, 2, 0x0A, 1);
    peer.offer_chain(&branch_a);
    let a2_hash = branch_a[1].block_hash();

    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(
        NetworkMessage::Headers(branch_a.iter().map(|b| b.header).collect()),
        deadline,
    )?;
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
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

    peer.send(
        NetworkMessage::Headers(branch_b.iter().map(|b| b.header).collect()),
        deadline,
    )?;

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
        assert!(
            peer.requests_for(&applied.block_hash()) <= 1,
            "already-applied block {} requested {} times (cursor rewind?)",
            applied.block_hash(),
            peer.requests_for(&applied.block_hash())
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
/// `mark_received_from` reports `needs_height_lookup` and the fix pins the
/// tree height instead of recording 0 forever. The chain must still converge
/// and the request cursor must never rewind to applied heights.
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

    let genesis = regtest_genesis();
    let chain = build_chain(&genesis, 5, 0xC4, 1);
    peer.offer_chain(&chain);
    let tip_hash = chain[4].block_hash();

    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(
        NetworkMessage::Headers(chain.iter().map(|b| b.header).collect()),
        deadline,
    )?;

    // Serve every window request EXCEPT the tip: h1..h4 arrive as tracked
    // deliveries while h5 stays pending on this peer.
    let mut served_all_but_tip = false;
    let collect_end = Instant::now() + Duration::from_secs(4);
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
    // the untracked-delivery (needs_height_lookup) path.
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

    // Watch a few more ticks on the hedge connection: under the height-0
    // bug, a later drop-for-retry of that entry rewinds the request cursor
    // toward genesis and the node re-requests already-applied heights.
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

/// Asserts the node's stderr shows no panic and no `PrevHashMismatch` —
/// `context` names where a mismatch would indicate commit churn.
fn assert_clean_stderr(node: &ProcessNode, context: &str) {
    let stderr = node_stderr(node);
    assert_eq!(
        count_occurrences(&stderr, "panic"),
        0,
        "node stderr contains a panic"
    );
    assert_eq!(
        count_occurrences(&stderr, "PrevHashMismatch"),
        0,
        "node stderr shows PrevHashMismatch: {context}"
    );
}
