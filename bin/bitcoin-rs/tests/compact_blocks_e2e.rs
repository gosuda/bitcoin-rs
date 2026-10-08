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
use std::fs::File;
use std::io::Write as _;
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{Amount, Block, BlockHash};
use bitcoin_rs_e2e::helpers::{
    best_hash, block_count, build_chain, genesis_block, segwit_coinbase_block, wait_for,
};
use bitcoin_rs_e2e::node::workspace;
use bitcoin_rs_e2e::process_peer::{
    FrameBuffer, connect_loopback, decode_frame, is_soft_recv_error, read_frame,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode};
use serde_json::json;

/// The remaining slice of `deadline` as a socket timeout, or an error
/// naming `message` once the deadline has already passed.
fn remaining(deadline: Instant, message: &str) -> Result<Option<Duration>, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| *d >= Duration::from_micros(1))
        .map(Some)
        .ok_or_else(|| Error::Protocol(format!("{message} ran past the deadline")))
}

/// Blocks applied before the serving probes: deep enough that a request 11
/// below the tip exists on the active chain.
const CHAIN_LEN: u32 = 13;

/// One raw BIP152 peer: negotiates compact blocks, serves bodies it knows,
/// and records what the node asks for and answers with.
struct CompactPeer {
    stream: TcpStream,
    journal: File,
    t0: Instant,
    /// Servable bodies by hash.
    blocks: BTreeMap<BlockHash, Block>,
    /// The header chain, so a `getheaders` probe is answered.
    headers: Vec<bitcoin::block::Header>,
    /// The peer socket died (node disconnected or transport error).
    dropped: bool,
    /// Partial bytes of an in-flight frame carried between reads.
    pending: FrameBuffer,
}

impl CompactPeer {
    /// Handshakes at v70016 and negotiates BIP152 at `cmpct_version` so the
    /// node will serve compact requests at it.
    fn connect(node: &ProcessNode, name: &str, cmpct_version: u64) -> Result<Self, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = connect_loopback(node.p2p_addr, deadline)?;
        stream.set_nodelay(true)?;
        let journal = File::create(evidence_dir().join(format!("{name}-peer.jsonl")))?;
        let mut peer = Self {
            stream,
            journal,
            t0: Instant::now(),
            blocks: BTreeMap::new(),
            headers: Vec::new(),
            dropped: false,
            pending: FrameBuffer::default(),
        };
        let services = ServiceFlags::WITNESS | ServiceFlags::NETWORK;
        let mut version = VersionMessage::new(
            services,
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| Error::Protocol(error.to_string()))?
                    .as_secs(),
            )
            .map_err(|error| Error::Protocol(error.to_string()))?,
            Address::new(&node.p2p_addr, ServiceFlags::NONE),
            Address::new(
                &peer
                    .stream
                    .local_addr()
                    .map_err(|error| Error::Protocol(error.to_string()))?,
                services,
            ),
            0,
            "/compact-blocks-e2e:0.1/".to_owned(),
            i32::try_from(CHAIN_LEN).expect("chain height fits i32"),
        );
        version.version = 70016;
        peer.send(NetworkMessage::Version(version), deadline)?;
        let mut saw_version = false;
        for _ in 0..64 {
            match peer.recv(deadline)? {
                NetworkMessage::Version(_) if !saw_version => {
                    saw_version = true;
                    peer.send(NetworkMessage::WtxidRelay, deadline)?;
                    peer.send(NetworkMessage::Verack, deadline)?;
                }
                NetworkMessage::Verack if saw_version => {
                    peer.send(
                        NetworkMessage::SendCmpct(SendCmpct {
                            send_compact: false,
                            version: cmpct_version,
                        }),
                        deadline,
                    )?;
                    return Ok(peer);
                }
                NetworkMessage::Ping(nonce) => peer.send(NetworkMessage::Pong(nonce), deadline)?,
                // The node sends its own `wtxidrelay` and feature messages
                // before `verack`; only the version/verack pair matters here.
                _ => {}
            }
        }
        Err(Error::Protocol("P2P handshake message limit".to_owned()))
    }

    fn log(&mut self, direction: &str, detail: &str) {
        let at_ms = u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let _ = writeln!(
            self.journal,
            r#"{{"at_ms":{at_ms},"dir":"{direction}","detail":"{detail}"}}"#
        );
        let _ = self.journal.flush();
        eprintln!("[E2E {at_ms:>6}ms {direction}] {detail}");
    }

    fn send(&mut self, message: NetworkMessage, deadline: Instant) -> Result<(), Error> {
        let cmd = message.cmd().to_owned();
        let frame = serialize(&RawNetworkMessage::new(Magic::REGTEST, message));
        self.stream
            .set_write_timeout(remaining(deadline, "write deadline reached")?)
            .map_err(Error::Io)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.log("send", &cmd);
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> Result<NetworkMessage, Error> {
        match read_frame(&mut self.stream, deadline, &mut self.pending) {
            Ok(frame) => {
                let message = decode_frame(&frame)?;
                self.log("recv", message.cmd());
                Ok(message)
            }
            Err(error) => {
                if !is_soft_recv_error(&error) {
                    self.dropped = true;
                    self.log("dropped", &error.to_string());
                }
                Err(error)
            }
        }
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
            return self.send(NetworkMessage::NotFound(vec![*item]), deadline);
        };
        self.log("serve", &format!("block {hash}"));
        self.send(NetworkMessage::Block(body), deadline)
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
        while Instant::now() < end && !self.dropped {
            match self.recv(end) {
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
                        let _ = self.send(NetworkMessage::Headers(headers), end);
                    }
                    if let NetworkMessage::Ping(nonce) = &message {
                        let _ = self.send(NetworkMessage::Pong(*nonce), end);
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
            match self.recv(end) {
                Ok(NetworkMessage::Ping(nonce)) => {
                    let _ = self.send(NetworkMessage::Pong(nonce), end);
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
    let chain = build_chain(&genesis_block(), CHAIN_LEN, 0xB1, 1);
    peer.offer_chain(&chain);
    let tip = chain.last().expect("chain has blocks");
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(
        NetworkMessage::Headers(chain.iter().map(|block| block.header).collect()),
        deadline,
    )?;
    peer.send(
        NetworkMessage::Inv(vec![Inventory::WitnessBlock(tip.block_hash())]),
        deadline,
    )?;
    let end = Instant::now() + Duration::from_mins(1);
    while Instant::now() < end {
        if block_count(&mut node)? == u64::from(CHAIN_LEN)
            && best_hash(&mut node)? == tip.block_hash().to_string()
        {
            return Ok((node, peer, chain));
        }
        peer.pump_serving(Duration::from_millis(400));
    }
    Err(Error::Protocol(format!(
        "applied tip never reached h{CHAIN_LEN}; count={}",
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

fn evidence_dir() -> std::path::PathBuf {
    let dir = workspace().join("target/compact-blocks-e2e");
    std::fs::create_dir_all(&dir).expect("evidence dir");
    dir
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

    peer.send(
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

    peer.send(
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
        peer.send(NetworkMessage::GetBlockTxn(request), deadline)?;
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

    peer.send(NetworkMessage::Ping(4_321), deadline)?;
    let pong = peer.await_reply(Duration::from_secs(10), &|message| {
        matches!(message, NetworkMessage::Pong(_))
    });
    if pong.is_none() {
        return Err(Error::Protocol(
            "the connection was already dead before the probe".to_owned(),
        ));
    }

    peer.send(
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
    peer.send(NetworkMessage::CmpctBlock(announced), deadline)?;

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
