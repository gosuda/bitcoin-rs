//! E2E: live-head body-carried header admission over the real P2P wire
//! against a spawned bitcoin-rs daemon (regtest, fjall). A loopback wire peer
//! announces blocks by `inv` only — never sending a `headers` batch for them —
//! so the delivered body is the node's only copy of the header and must admit
//! through the staged-body path (P2P-06). Heights come from the block tree.
//!
//!  * T1: headers bootstrap, then inv-only live-head blocks apply one after
//!    another via their carried headers — no stall across the chain.
//!  * T2: a delivered body whose carried header's parent is unknown triggers a
//!    recovery `getheaders`; once the ancestors land the staged body applies in
//!    place and is never re-requested.

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
/// commitment output (`aa21a9ed`), so a stripped body fails the
/// body/header binding check.
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

/// Asserts the node's stderr shows no panic and no `PrevHashMismatch`.
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

/// T1: headers bootstrap proves the baseline pipeline, then blocks announced
/// ONLY by `inv` (no `headers` batch ever carries them) must still apply —
/// each delivered body is the node's only copy of its header and admits
/// through the staged path. Several in a row must keep advancing: no stall.
#[test]
fn carried_header_live_head_applies_and_continues() -> Result<(), Error> {
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
    let chain = build_chain(&genesis, 6, 0xD1, 1);
    peer.offer_bodies(&chain);
    // `getheaders` answers may only ever reveal h1..h3: h4..h6 must reach the
    // node exclusively inside delivered bodies (carried headers).
    peer.headers = chain[..3].iter().map(|b| b.header).collect();
    let h3 = chain[2].block_hash();
    let h6 = chain[5].block_hash();

    let deadline = Instant::now() + Duration::from_secs(10);

    // Baseline: headers for h1..h3, serve bodies, tip must reach h3. The
    // first batch can land before the node bootstraps genesis into its
    // header tree (rejected "missing parent"); the ~5s discovery probes are
    // auto-answered with the same batch and recover it.
    peer.send(
        NetworkMessage::Headers(chain[..3].iter().map(|b| b.header).collect()),
        deadline,
    )?;
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
            3,
            &h3.to_string(),
            Duration::from_secs(40)
        )?,
        "headers bootstrap never applied to h3 (count={:?}, hash={:?})",
        block_count(&mut node),
        best_hash(&mut node)
    );
    eprintln!("[E2E] bootstrap applied: tip=h3 ({h3}), count=3");

    // Live-head blocks h4,h5,h6 arrive ONLY via inv announcements — the
    // delivered body is the node's only copy of each header.
    for (height, block) in chain.iter().enumerate().skip(3) {
        let hash = block.block_hash();
        peer.send(NetworkMessage::Inv(vec![Inventory::Block(hash)]), deadline)?;
        eprintln!("[E2E] announced h{} via inv only ({hash})", height + 1);
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
                u64::try_from(height + 1).unwrap_or(u64::MAX),
                &hash.to_string(),
                Duration::from_secs(20)
            )?,
            "carried-header block h{}={} never applied (count={:?}, best={:?})",
            height + 1,
            hash,
            block_count(&mut node),
            best_hash(&mut node)
        );
        eprintln!("[E2E] h{} applied via carried header ({hash})", height + 1);
    }

    // Every block requested at least once; none re-requested after its
    // body was delivered (the rewind signature); and never a plain
    // MSG_BLOCK request (witness-stripped bodies would fail binding).
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
    assert!(
        peer.post_serve_requests.is_empty(),
        "blocks re-requested after delivery (churn/rewind?): {:?}",
        peer.post_serve_requests
    );
    assert_eq!(
        peer.stripped_served, 0,
        "node requested MSG_BLOCK and got a stripped body"
    );
    assert_eq!(block_count(&mut node)?, 6, "tip must be h6");
    assert_eq!(best_hash(&mut node)?, h6.to_string());

    assert_clean_stderr(&node, "live-head carried-header chain");
    eprintln!("[E2E] T1 PASSED: carried headers admitted, tip advanced h3→h6 without stall");
    Ok(())
}

/// T2: a delivered body whose carried header's parent is unknown is not a
/// peer fault — the node must issue a recovery `getheaders`, then apply the
/// staged body in place once the ancestors land. The staged h4 body keeps
/// no height of its own; the tree places it once its header lands, so the
/// node must never re-request h4 and must apply it.
#[allow(clippy::too_many_lines)]
#[test]
fn missing_parent_delivery_recovers_via_getheaders() -> Result<(), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    // start_height=0: the peer advertises no better tip, so the node has no
    // reason to send discovery getheaders — any getheaders that arrives can
    // only be the staged-header recovery send.
    let mut peer = LivePeer::connect_with_height(&node, "t2", 0)?;

    assert!(
        wait_for(Duration::from_secs(10), &mut || {
            connection_count(&mut node).is_ok_and(|c| c == 1)
        }),
        "node did not report the inbound peer connection"
    );

    let genesis = regtest_genesis();
    let chain = build_chain(&genesis, 5, 0xE2, 1);
    peer.offer_bodies(&chain);
    // Nothing is revealed until the ancestry step: any probe that does show
    // up gets an empty reply and the wire stays clean.
    peer.headers = Vec::new();

    // Quiet-wire precondition: with start_height=0 the peer demonstrates no
    // better tip, so no discovery getheaders should ever fire — making any
    // later getheaders attributable to the staged-body recovery path alone.
    peer.pump(Duration::from_millis(1500), &mut |_, _| {});
    assert!(
        peer.getheaders_at.is_empty(),
        "spontaneous getheaders probes fired with start_height=0: {:?}",
        peer.getheaders_at
    );
    eprintln!("[E2E] wire quiet for 1.5s (no discovery probes with start_height=0)");

    // Announce ONLY h4 — h1..h3 stay entirely unknown to the node.
    let h4 = chain[3].block_hash();
    let h5 = chain[4].block_hash();
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(NetworkMessage::Inv(vec![Inventory::Block(h4)]), deadline)?;
    eprintln!("[E2E] announced h4 alone ({h4}); h1..h3 unknown to node");

    // Wait for the inv-echo getdata WITHOUT serving the body yet.
    let requested = wait_for(Duration::from_secs(15), &mut || {
        peer.pump(Duration::from_millis(150), &mut |_, _| {});
        peer.requests_for(&h4) > 0
    });
    assert!(requested, "node never requested announced h4 body");
    assert_eq!(
        peer.plain_block_requests(&h4),
        0,
        "h4 requested as plain MSG_BLOCK"
    );
    eprintln!("[E2E] node requested h4 as WitnessBlock; withholding body");

    // Hold ~1.2s with the body withheld: an inv announcement alone must not
    // produce a getheaders. Anything that fires after the BODY lands is then
    // unambiguously the staged-header recovery send.
    peer.pump(Duration::from_millis(1200), &mut |_, _| {});
    assert!(
        peer.getheaders_at.is_empty(),
        "getheaders fired with the body still withheld: {:?} — inv alone probed?",
        peer.getheaders_at
    );

    // Deliver the requested h4 body; its carried header fails admission
    // (parent h3 unknown) and the staged retry must ask us for the gap.
    let body = peer.blocks.get(&h4).cloned().expect("offered block");
    peer.send(NetworkMessage::Block(body), deadline)?;
    let served_ms = peer.at_ms();
    eprintln!("[E2E] delivered h4 body at {served_ms}ms; waiting for recovery getheaders");

    let recovery_ok = wait_for(Duration::from_secs(6), &mut || {
        peer.pump(Duration::from_millis(100), &mut |_, _| {});
        !peer.getheaders_at.is_empty()
    });
    assert!(
        recovery_ok,
        "no getheaders arrived after h4 body delivery (recovery path never fired); \
         body sent at {served_ms}ms",
    );
    let recovery_at = peer.getheaders_at[0];
    eprintln!(
        "[E2E] recovery getheaders observed at {recovery_at}ms ({}ms after body)",
        recovery_at.saturating_sub(served_ms)
    );

    // Reveal the ancestry: admit h1..h4 headers (the staged retry + this
    // reply converge). Also switch future getheaders replies to the real
    // ancestry minus h5 — h5 must stay body-carried only.
    let pre_headers_requests = peer.requests_for(&h4);
    peer.headers = chain[..4].iter().map(|b| b.header).collect();
    peer.send(
        NetworkMessage::Headers(chain[..4].iter().map(|b| b.header).collect()),
        deadline,
    )?;
    eprintln!("[E2E] sent headers h1..h4; expecting window getdata for h1..h3 only");

    // Serve whatever gets requested while the tip walks to h4.
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
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

    // The gap-fill getdata must cover each of h1..h3 exactly once (h4's body
    // was already delivered — a second request would mean the staged body
    // was lost).
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

    // Post-recovery liveness: announce h5 by inv only — its carried header
    // admits (h4 now in tree) and the tip keeps advancing.
    peer.send(NetworkMessage::Inv(vec![Inventory::Block(h5)]), deadline)?;
    assert!(
        pump_until_request(&mut peer, h5, Duration::from_secs(15)),
        "node never requested h5 after recovery"
    );
    assert!(
        pump_until_tip(
            &mut peer,
            &mut node,
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
