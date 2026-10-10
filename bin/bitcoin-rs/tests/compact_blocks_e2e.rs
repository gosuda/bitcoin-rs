//! BIP152 compact-block conformance over the real P2P wire.
//!
//! One bitcoin-rs process, one raw loopback peer speaking the production
//! codec and the production inbound dispatch path — no mock dispatcher, so
//! what these tests observe is what a real peer sees: which message answers
//! a `getdata`, which request follows a failed reconstruction, and whether a
//! malformed request ends the connection.
//!
//! Three behaviours are pinned here and cannot be pinned in the crate unit
//! tests, which stop at the protocol object boundary:
//!
//! * serving depth — a compact `getdata` and a `getblocktxn` are answered
//!   with a `cmpctblock`/`blocktxn` only near the active tip, and with the
//!   whole witness-bearing `block` beyond the bound;
//! * the coinbase prefill a served compact block carries;
//! * the receive side — a `cmpctblock` whose body does not hash to its own
//!   header is never applied, and recovery is one full-block `getdata` on
//!   the same connection.
//!
//! The pinned Core 31.1 authority for each is cited at the test.

#![expect(clippy::expect_used, reason = "process test assertions")]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::{Amount, Block, BlockHash};
use bitcoin_rs_e2e::helpers::{
    best_hash, block_count, build_chain, genesis_block, segwit_coinbase_block, wait_for,
};
use bitcoin_rs_e2e::process_peer::is_soft_recv_error;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode};
#[path = "support/wire_peer.rs"]
mod wire_peer;
use wire_peer::Peer;

use serde_json::json;

/// Blocks applied before the serving probes: deep enough that a request 11
/// below the tip exists on the active chain.
const CHAIN_LEN: u32 = 13;

/// One raw BIP152 peer: negotiates compact blocks, serves bodies it knows,
/// and records what the node asks for and answers with.
struct CompactPeer {
    wire: Peer,
    /// Servable bodies by hash.
    blocks: BTreeMap<BlockHash, Block>,
    /// The header chain, so a `getheaders` probe is answered.
    headers: Vec<bitcoin::block::Header>,
}

impl CompactPeer {
    /// Handshakes at v70016 and negotiates BIP152 at `cmpct_version` so the
    /// node will serve compact requests at it.
    fn connect(node: &ProcessNode, name: &str, cmpct_version: u64) -> Result<Self, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut wire = Peer::connect(
            node.p2p_addr,
            "compact-blocks-e2e",
            name,
            i32::try_from(CHAIN_LEN).expect("chain height fits i32"),
            deadline,
        )?;
        wire.send(
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: false,
                version: cmpct_version,
            }),
            deadline,
        )?;
        Ok(Self {
            wire,
            blocks: BTreeMap::new(),
            headers: Vec::new(),
        })
    }

    fn offer_chain(&mut self, chain: &[Block]) {
        for block in chain {
            self.blocks.insert(block.block_hash(), block.clone());
            self.headers.push(block.header);
        }
    }

    /// Serves one block-typed inventory item from the offered chain.
    fn serve_item(&mut self, item: &Inventory, deadline: Instant) -> Result<(), Error> {
        let hash = match item {
            Inventory::WitnessBlock(hash)
            | Inventory::CompactBlock(hash)
            | Inventory::Block(hash) => *hash,
            _ => return Ok(()),
        };
        // The wire takes an owned body; the map keeps serving further requests.
        let Some(body) = self.blocks.get(&hash).cloned() else {
            return self
                .wire
                .send(NetworkMessage::NotFound(vec![*item]), deadline);
        };
        self.wire.log("serve", &format!("block {hash}"));
        self.wire.send(NetworkMessage::Block(body), deadline)
    }

    /// Drains the socket until a reply satisfies `wanted`, serving every
    /// `getdata` the node issues on the way. Returns `None` at the deadline
    /// or once the connection is gone.
    fn await_reply(
        &mut self,
        timeout: Duration,
        wanted: &dyn Fn(&NetworkMessage) -> bool,
    ) -> Option<NetworkMessage> {
        let end = Instant::now() + timeout;
        while Instant::now() < end && !self.wire.dropped {
            match self.wire.recv(end) {
                Ok(message) => {
                    if wanted(&message) {
                        return Some(message);
                    }
                    if let NetworkMessage::GetData(items) = &message {
                        let items = items.clone();
                        for item in &items {
                            let _ = self.serve_item(item, end);
                        }
                    }
                    if let NetworkMessage::GetHeaders(_) = &message {
                        let headers = self.headers.clone();
                        let _ = self.wire.send(NetworkMessage::Headers(headers), end);
                    }
                    if let NetworkMessage::Ping(nonce) = &message {
                        let _ = self.wire.send(NetworkMessage::Pong(*nonce), end);
                    }
                }
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => return None,
            }
        }
        None
    }

    /// Reads until the connection dies or `timeout` elapses. `true` means the
    /// peer was dropped; a soft timeout means it is still alive.
    fn observe_disconnect(&mut self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        while Instant::now() < end {
            match self.wire.recv(end) {
                Ok(NetworkMessage::Ping(nonce)) => {
                    let _ = self.wire.send(NetworkMessage::Pong(nonce), end);
                }
                Ok(_) => {}
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => return true,
            }
        }
        false
    }
}

/// The offered block `depth` below the applied tip. `chain[0]` is height 1, so
/// a tip at `tip_height` puts depth `d` at index `tip_height - 1 - d`.
fn block_at_depth(chain: &[Block], tip_height: u32, depth: u32) -> &Block {
    let index = usize::try_from(tip_height - 1 - depth).expect("depth inside the chain");
    &chain[index]
}

fn synced_peer(name: &str) -> Result<(ProcessNode, CompactPeer, Vec<Block>), Error> {
    synced_peer_with_len(name, CHAIN_LEN)
}

fn synced_peer_with_len(
    name: &str,
    chain_len: u32,
) -> Result<(ProcessNode, CompactPeer, Vec<Block>), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let mut peer = CompactPeer::connect(&node, name, 2)?;
    if !wait_for(Duration::from_secs(10), &mut || {
        node.rpc("getconnectioncount", &json!([]))
            .ok()
            .as_ref()
            .and_then(ok_count)
            .is_some_and(|count| count == 1)
    }) {
        return Err(Error::Protocol(
            "node never reported the inbound peer".to_owned(),
        ));
    }
    let chain = build_chain(&genesis_block(), chain_len, 0xB1, 1);
    peer.offer_chain(&chain);
    let tip = chain.last().expect("chain has blocks");
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.wire.send(
        NetworkMessage::Headers(chain.iter().map(|block| block.header).collect()),
        deadline,
    )?;
    peer.wire.send(
        NetworkMessage::Inv(vec![Inventory::WitnessBlock(tip.block_hash())]),
        deadline,
    )?;
    let end = Instant::now() + Duration::from_mins(1);
    while Instant::now() < end {
        if block_count(&mut node)? == u64::from(chain_len)
            && best_hash(&mut node)? == tip.block_hash().to_string()
        {
            return Ok((node, peer, chain));
        }
        peer.pump_serving(Duration::from_millis(400));
    }
    Err(Error::Protocol(format!(
        "applied tip never reached h{chain_len}; count={}",
        block_count(&mut node)?
    )))
}

/// Serves every request for `dur` without waiting for a particular reply.
impl CompactPeer {
    fn pump_serving(&mut self, dur: Duration) {
        self.await_reply(dur, &|_| false);
    }
}

fn ok_count(value: &serde_json::Value) -> Option<u64> {
    value.as_u64()
}

/// A compact `getdata` within 5 blocks of the active tip is answered with a
/// `cmpctblock` that prefills the coinbase at index zero; one block deeper is
/// answered with the whole witness-bearing `block`, not `notfound` and not a
/// compact reply a peer cannot fill from its own mempool.
/// Core 31.1 `net_processing.cpp:2705-2721`.
#[test]
fn serves_compact_by_depth_on_the_wire() -> Result<(), Error> {
    let (mut node, mut peer, chain) = synced_peer("depth")?;
    let tip_height = u32::try_from(block_count(&mut node)?).expect("tip height");
    let at_bound = block_at_depth(&chain, tip_height, 5);
    let one_deeper = block_at_depth(&chain, tip_height, 6);
    let deadline = Instant::now() + Duration::from_secs(10);

    peer.wire.send(
        NetworkMessage::GetData(vec![Inventory::CompactBlock(at_bound.block_hash())]),
        deadline,
    )?;
    let reply = peer
        .await_reply(Duration::from_secs(10), &|message| {
            matches!(
                message,
                NetworkMessage::CmpctBlock(_) | NetworkMessage::Block(_)
            )
        })
        .ok_or_else(|| Error::Protocol("no compact-bound reply".to_owned()))?;
    let NetworkMessage::CmpctBlock(cmpct) = reply else {
        return Err(Error::Protocol(format!(
            "a block at the compact bound must be served as cmpctblock, got {}",
            reply.cmd()
        )));
    };
    let compact = &cmpct.compact_block;
    if compact.header.block_hash() != at_bound.block_hash() {
        return Err(Error::Protocol("cmpctblock header mismatch".to_owned()));
    }
    if compact.prefilled_txs.len() != 1 || u64::from(compact.prefilled_txs[0].idx) != 0 {
        return Err(Error::Protocol(
            "the coinbase must be prefilled at index zero".to_owned(),
        ));
    }
    if serialize(&compact.prefilled_txs[0].tx) != serialize(&at_bound.txdata[0]) {
        return Err(Error::Protocol(
            "the prefilled body must be the block's coinbase".to_owned(),
        ));
    }
    eprintln!("[E2E] depth 5 served as cmpctblock with the coinbase prefilled");

    peer.wire.send(
        NetworkMessage::GetData(vec![Inventory::CompactBlock(one_deeper.block_hash())]),
        deadline,
    )?;
    let reply = peer
        .await_reply(Duration::from_secs(10), &|message| {
            matches!(
                message,
                NetworkMessage::CmpctBlock(_)
                    | NetworkMessage::Block(_)
                    | NetworkMessage::NotFound(_)
            )
        })
        .ok_or_else(|| Error::Protocol("no deep-compact reply".to_owned()))?;
    match reply {
        NetworkMessage::Block(block) if block.block_hash() == one_deeper.block_hash() => {}
        other => {
            return Err(Error::Protocol(format!(
                "a block deeper than the compact bound must be served whole, got {}",
                other.cmd()
            )));
        }
    }
    eprintln!("[E2E] depth 6 served as the whole block");
    node.stop()
}

/// A `getblocktxn` within 10 blocks of the tip is answered with a `blocktxn`;
/// one block deeper is answered with the whole witness-bearing `block`
/// (Core 31.1 `net_processing.cpp:4590-4624`).
#[test]
fn serves_blocktxn_by_depth_on_the_wire() -> Result<(), Error> {
    let (mut node, mut peer, chain) = synced_peer("blocktxn")?;
    let tip_height = u32::try_from(block_count(&mut node)?).expect("tip height");
    let deadline = Instant::now() + Duration::from_secs(10);

    for (offset, want_blocktxn) in [(10_u32, true), (11, false)] {
        let block = block_at_depth(&chain, tip_height, offset);
        let request = GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: block.block_hash(),
                indexes: vec![0],
            },
        };
        peer.wire
            .send(NetworkMessage::GetBlockTxn(request), deadline)?;
        let reply = peer
            .await_reply(Duration::from_secs(10), &|message| {
                matches!(
                    message,
                    NetworkMessage::BlockTxn(_)
                        | NetworkMessage::Block(_)
                        | NetworkMessage::NotFound(_)
                )
            })
            .ok_or_else(|| Error::Protocol(format!("no reply at depth {offset}")))?;
        let served_whole = matches!(
            &reply,
            NetworkMessage::Block(served) if served.block_hash() == block.block_hash()
        );
        if want_blocktxn {
            if !matches!(reply, NetworkMessage::BlockTxn(_)) {
                return Err(Error::Protocol(format!(
                    "depth {offset} must be answered with blocktxn, got {}",
                    reply.cmd()
                )));
            }
            let NetworkMessage::BlockTxn(BlockTxn { transactions }) = reply else {
                unreachable!("checked above");
            };
            if transactions.transactions != block.txdata {
                return Err(Error::Protocol(
                    "blocktxn must carry the requested body".to_owned(),
                ));
            }
        } else if !served_whole {
            return Err(Error::Protocol(format!(
                "depth {offset} must be answered with the whole block, got {}",
                reply.cmd()
            )));
        }
        eprintln!("[E2E] depth {offset} answered as required");
    }
    node.stop()
}

/// An empty `getblocktxn` index list ends the connection at the inbound
/// boundary (Core 31.1 `net_processing.cpp:4560-4574`). A ping/pong proves
/// the socket was alive immediately before the request, so the drop is
/// attributed to the malformed message and not to an idle timeout.
#[test]
fn empty_getblocktxn_disconnects_on_the_wire() -> Result<(), Error> {
    let (mut node, mut peer, _chain) = synced_peer("empty-txn")?;
    let deadline = Instant::now() + Duration::from_secs(10);

    peer.wire.send(NetworkMessage::Ping(4_321), deadline)?;
    let pong = peer.await_reply(Duration::from_secs(10), &|message| {
        matches!(message, NetworkMessage::Pong(_))
    });
    if pong.is_none() {
        return Err(Error::Protocol(
            "the connection was already dead before the probe".to_owned(),
        ));
    }

    peer.wire.send(
        NetworkMessage::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: bitcoin::BlockHash::from_byte_array([7; 32]),
                indexes: Vec::new(),
            },
        }),
        deadline,
    )?;
    if !peer.observe_disconnect(Duration::from_secs(10)) {
        return Err(Error::Protocol(
            "an empty getblocktxn must drop the peer".to_owned(),
        ));
    }
    if !wait_for(Duration::from_secs(10), &mut || {
        node.rpc("getconnectioncount", &json!([]))
            .ok()
            .as_ref()
            .and_then(ok_count)
            .is_some_and(|count| count == 0)
    }) {
        return Err(Error::Protocol(
            "the node kept the connection after the malformed request".to_owned(),
        ));
    }
    eprintln!("[E2E] empty getblocktxn dropped the connection");
    node.stop()
}

/// A `cmpctblock` whose prefilled body does not hash to its own header is
/// never delivered as a block: the node asks this same peer for the full
/// witness body and applies the block only once the real body arrives
/// (Core 31.1 `blockencodings.cpp:207-219`, `net_processing.cpp:3734-3754`).
#[test]
fn wrong_root_compact_block_falls_back_to_same_peer() -> Result<(), Error> {
    let (mut node, mut peer, chain) = synced_peer("wrong-root")?;
    let tip_height = u32::try_from(block_count(&mut node)?).expect("tip height");
    let parent = chain.last().expect("chain has a tip");
    let real = segwit_coinbase_block(parent, tip_height + 1, 0xC3);
    let hash = real.block_hash();
    peer.offer_chain(std::slice::from_ref(&real));

    // The same header, announced with a coinbase body that is not the one the
    // header commits to.
    let mut wrong = real.txdata[0].clone();
    wrong.output[0].value = Amount::from_sat(1);
    let announced = CmpctBlock {
        compact_block: HeaderAndShortIds {
            header: real.header,
            nonce: 0x515,
            short_ids: Vec::new(),
            prefilled_txs: vec![PrefilledTransaction { idx: 0, tx: wrong }],
        },
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.wire
        .send(NetworkMessage::CmpctBlock(announced), deadline)?;

    let asked = peer
        .await_reply(Duration::from_secs(10), &|message| {
            matches!(message, NetworkMessage::GetData(_))
        })
        .ok_or_else(|| Error::Protocol("no fallback request seen".to_owned()))?;
    let NetworkMessage::GetData(items) = asked else {
        unreachable!("checked above");
    };
    if items.as_slice() != [Inventory::WitnessBlock(hash)] {
        return Err(Error::Protocol(format!(
            "a failed reconstruction must fetch the full witness body from this peer, got {items:?}"
        )));
    }
    if block_count(&mut node)? != u64::from(tip_height)
        || best_hash(&mut node)? != parent.block_hash().to_string()
    {
        return Err(Error::Protocol(
            "the node applied a block it could not verify".to_owned(),
        ));
    }
    eprintln!("[E2E] unverifiable compact block fell back to a same-peer getdata");

    let answer_by = Instant::now() + Duration::from_secs(10);
    for item in &items {
        peer.serve_item(item, answer_by)?;
    }

    let served = Instant::now() + Duration::from_mins(1);
    while Instant::now() < served {
        if block_count(&mut node)? == u64::from(tip_height + 1) {
            node.stop()?;
            return Ok(());
        }
        peer.pump_serving(Duration::from_millis(400));
    }
    Err(Error::Protocol(format!(
        "the real body never applied: tip is {}",
        block_count(&mut node)?
    )))
}

/// Hold a compact-block reconstruction across a real chain switch. Core v31.1
/// GETBLOCKTXN resolves stored bodies by hash even after they leave the chain
/// (9be056a8a72b624dae9623b2f7bded92c2a21c91, net_processing.cpp:4333-4391).
#[test]
fn stale_compact_block_finishes_reconstruction_after_reorg() -> Result<(), Error> {
    let (mut node, mut peer, common) = synced_peer_with_len("stale-race", 100)?;
    let parent = common.last().expect("common tip");
    let mut stale = segwit_coinbase_block(parent, 101, 0xD1);
    // Include a non-coinbase transaction, forcing an actual missing short-ID
    // slot after the compact response's sole coinbase prefill.
    stale.txdata[0].input[0].witness.clear();
    stale.txdata[0].output.truncate(1);
    let funding = &common[0].txdata[0];
    stale.txdata.push(bitcoin_rs_e2e::helpers::spend_anyone(
        bitcoin::OutPoint::new(funding.compute_txid(), 0),
        &funding.output[0],
        1_000,
    ));
    stale.header.merkle_root = stale.compute_merkle_root().expect("nonempty block");
    bitcoin_rs_e2e::helpers::grind_pow(&mut stale.header)?;
    peer.offer_chain(std::slice::from_ref(&stale));
    peer.wire.send(
        NetworkMessage::Headers(vec![stale.header]),
        Instant::now() + Duration::from_secs(10),
    )?;
    wait_for_peer_tip(&mut node, &mut peer, &stale)?;

    peer.wire.send(
        NetworkMessage::GetData(vec![Inventory::CompactBlock(stale.block_hash())]),
        Instant::now() + Duration::from_secs(10),
    )?;
    let Some(NetworkMessage::CmpctBlock(compact)) =
        peer.await_reply(Duration::from_secs(10), &|m| {
            matches!(
                m,
                NetworkMessage::CmpctBlock(_) | NetworkMessage::NotFound(_)
            )
        })
    else {
        return Err(Error::Assertion(
            "expected compact stale candidate before reorg".into(),
        ));
    };
    assert_eq!(compact.compact_block.header, stale.header);
    assert_eq!(compact.compact_block.short_ids.len(), 1);
    assert_eq!(compact.compact_block.prefilled_txs.len(), 1);
    assert_eq!(compact.compact_block.prefilled_txs[0].idx, 0);

    // The peer holds the prefill while a different, longer branch wins.
    let branch = build_chain(parent, 2, 0xE1, 101);
    peer.headers = common.iter().map(|b| b.header).collect();
    peer.offer_chain(&branch);
    peer.wire.send(
        NetworkMessage::Headers(branch.iter().map(|b| b.header).collect()),
        Instant::now() + Duration::from_secs(10),
    )?;
    wait_for_peer_tip(&mut node, &mut peer, branch.last().expect("winner"))?;
    peer.wire
        .log("assert", "reorg committed before stale getblocktxn");

    peer.wire.send(
        NetworkMessage::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: stale.block_hash(),
                indexes: vec![1],
            },
        }),
        Instant::now() + Duration::from_secs(10),
    )?;
    let Some(NetworkMessage::BlockTxn(reply)) = peer.await_reply(Duration::from_secs(10), &|m| {
        matches!(
            m,
            NetworkMessage::BlockTxn(_) | NetworkMessage::Block(_) | NetworkMessage::NotFound(_)
        )
    }) else {
        return Err(Error::Assertion(
            "stored stale block must answer getblocktxn after reorg".into(),
        ));
    };
    assert_eq!(reply.transactions.block_hash, stale.block_hash());
    let mut reconstructed = Block {
        header: compact.compact_block.header,
        txdata: vec![compact.compact_block.prefilled_txs[0].tx.clone()],
    };
    reconstructed.txdata.extend(reply.transactions.transactions);
    assert_eq!(reconstructed, stale);
    assert!(reconstructed.check_merkle_root());

    peer.wire.send(
        NetworkMessage::GetData(vec![
            Inventory::WitnessBlock(stale.block_hash()),
            Inventory::WitnessBlock(branch[0].block_hash()),
        ]),
        Instant::now() + Duration::from_secs(10),
    )?;
    for expected in [&stale, &branch[0]] {
        let Some(NetworkMessage::Block(body)) = peer.await_reply(Duration::from_secs(10), &|m| {
            matches!(m, NetworkMessage::Block(_) | NetworkMessage::NotFound(_))
        }) else {
            return Err(Error::Assertion(
                "both stored bodies at height 101 must be served".into(),
            ));
        };
        assert_eq!(&body, expected);
    }
    eprintln!("[E2E] stale compact reconstruction and both height-101 bodies verified after reorg");
    node.stop()
}

fn wait_for_peer_tip(
    node: &mut ProcessNode,
    peer: &mut CompactPeer,
    expected: &Block,
) -> Result<(), Error> {
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        if best_hash(node)? == expected.block_hash().to_string() {
            return Ok(());
        }
        peer.pump_serving(Duration::from_millis(100));
    }
    Err(Error::Assertion(format!(
        "expected tip {}, got {}",
        expected.block_hash(),
        best_hash(node)?
    )))
}
