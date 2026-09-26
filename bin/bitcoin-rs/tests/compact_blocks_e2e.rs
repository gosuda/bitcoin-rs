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

mod support;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::absolute::LockTime;
use bitcoin::bip152::{BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction};
use bitcoin::consensus::serialize;
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{
    Amount, Block, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde_json::json;
use support::process_node::{HarnessError, NodeBinary, ProcessNode, workspace};
use support::process_peer::connect_loopback;

/// Frames are read with the protocol payload bound, not the harness's 4 MiB
/// cap: a full `block` reply for a heavier block is legal and must not be
/// mistaken for a transport failure.
const HEADER_BYTES: usize = 24;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
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
    /// Every block-typed `getdata` item the node sent, in arrival order.
    requested: Vec<(u32, BlockHash)>,
    /// The peer socket died (node disconnected or transport error).
    dropped: bool,
}

impl CompactPeer {
    /// Handshakes at v70016 and, when `cmpct_version` is given, negotiates
    /// BIP152 with that recorded version so the node will serve compact
    /// requests at it.
    fn connect(
        node: &ProcessNode,
        name: &str,
        cmpct_version: Option<u64>,
    ) -> Result<Self, HarnessError> {
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
            requested: Vec::new(),
            dropped: false,
        };
        let services = ServiceFlags::WITNESS | ServiceFlags::NETWORK;
        let mut version = VersionMessage::new(
            services,
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|error| HarnessError::Protocol(error.to_string()))?
                    .as_secs(),
            )
            .map_err(|error| HarnessError::Protocol(error.to_string()))?,
            Address::new(&node.p2p_addr, ServiceFlags::NONE),
            Address::new(
                &peer
                    .stream
                    .local_addr()
                    .map_err(|error| HarnessError::Protocol(error.to_string()))?,
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
                    if let Some(v) = cmpct_version {
                        peer.send(
                            NetworkMessage::SendCmpct(SendCmpct {
                                send_compact: false,
                                version: v,
                            }),
                            deadline,
                        )?;
                    }
                    return Ok(peer);
                }
                NetworkMessage::Ping(nonce) => peer.send(NetworkMessage::Pong(nonce), deadline)?,
                // The node sends its own `wtxidrelay` and feature messages
                // before `verack`; only the version/verack pair matters here.
                _ => {}
            }
        }
        Err(HarnessError::Protocol(
            "P2P handshake message limit".to_owned(),
        ))
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

    fn send(&mut self, message: NetworkMessage, deadline: Instant) -> Result<(), HarnessError> {
        let cmd = message.cmd().to_owned();
        let frame = serialize(&RawNetworkMessage::new(Magic::REGTEST, message));
        self.stream
            .set_write_timeout(remaining(deadline, "write deadline reached")?)
            .map_err(HarnessError::Io)?;
        self.stream.write_all(&frame).map_err(HarnessError::Io)?;
        self.log("send", &cmd);
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> Result<NetworkMessage, HarnessError> {
        match read_frame(&mut self.stream, deadline) {
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
    fn serve_item(&mut self, item: &Inventory, deadline: Instant) -> Result<(), HarnessError> {
        let hash = match item {
            Inventory::WitnessBlock(hash)
            | Inventory::CompactBlock(hash)
            | Inventory::Block(hash) => *hash,
            _ => return Ok(()),
        };
        self.requested.push((inv_type(item), hash));
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

fn inv_type(item: &Inventory) -> u32 {
    match item {
        Inventory::Block(_) => 0x0000_0002,
        Inventory::CompactBlock(_) => 0x0000_0004,
        Inventory::WitnessBlock(_) => 0x4000_0002,
        _ => 0,
    }
}

/// The offered block `depth` below the applied tip. `chain[0]` is height 1, so
/// a tip at `tip_height` puts depth `d` at index `tip_height - 1 - d`.
fn block_at_depth(chain: &[Block], tip_height: u32, depth: u32) -> &Block {
    let index = usize::try_from(tip_height - 1 - depth).expect("depth inside the chain");
    &chain[index]
}

fn remaining(deadline: Instant, message: &'static str) -> Result<Option<Duration>, HarnessError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| *time >= Duration::from_micros(1))
        .map(Some)
        .ok_or_else(|| HarnessError::Protocol(message.to_owned()))
}

fn read_frame(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, HarnessError> {
    fn read_exact(
        stream: &mut TcpStream,
        mut bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), HarnessError> {
        while !bytes.is_empty() {
            stream.set_read_timeout(remaining(deadline, "read deadline reached")?)?;
            let count = stream.read(bytes)?;
            if count == 0 {
                return Err(HarnessError::Protocol("truncated P2P frame".to_owned()));
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
    let mut header = [0; HEADER_BYTES];
    read_exact(stream, &mut header, deadline)?;
    let raw = u32::from_le_bytes(
        header[16..20]
            .try_into()
            .map_err(|_| HarnessError::Protocol("truncated P2P header".to_owned()))?,
    );
    let length = usize::try_from(raw).map_err(|error| HarnessError::Protocol(error.to_string()))?;
    if length > MAX_PAYLOAD_BYTES {
        return Err(HarnessError::Protocol("P2P payload byte limit".to_owned()));
    }
    let mut frame = header.to_vec();
    frame.resize(HEADER_BYTES + length, 0);
    read_exact(stream, &mut frame[HEADER_BYTES..], deadline)?;
    Ok(frame)
}

fn decode_frame(frame: &[u8]) -> Result<NetworkMessage, HarnessError> {
    let envelope: RawNetworkMessage = bitcoin::consensus::deserialize(frame)
        .map_err(|error| HarnessError::Protocol(format!("invalid P2P envelope: {error}")))?;
    if *envelope.magic() != Magic::REGTEST {
        return Err(HarnessError::Protocol("P2P network mismatch".to_owned()));
    }
    Ok(envelope.into_payload())
}

fn is_soft_recv_error(error: &HarnessError) -> bool {
    match error {
        HarnessError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        HarnessError::Protocol(detail) => detail.contains("deadline"),
        _ => false,
    }
}

/// Applies a fresh regtest chain and connects one compact-aware peer.
fn synced_peer(name: &str) -> Result<(ProcessNode, CompactPeer, Vec<Block>), HarnessError> {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;
    let mut peer = CompactPeer::connect(&node, name, Some(2))?;
    if !wait_for(Duration::from_secs(10), &mut || {
        node.rpc("getconnectioncount", &json!([]))
            .ok()
            .as_ref()
            .and_then(ok_count)
            .is_some_and(|count| count == 1)
    }) {
        return Err(HarnessError::Protocol(
            "node never reported the inbound peer".to_owned(),
        ));
    }
    let chain = build_chain(&regtest_genesis(), CHAIN_LEN, 0xB1, 1);
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
    Err(HarnessError::Protocol(format!(
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

fn block_count(node: &mut ProcessNode) -> Result<u64, HarnessError> {
    Ok(node
        .rpc("getblockcount", &json!([]))?
        .as_u64()
        .unwrap_or(u64::MAX))
}

fn best_hash(node: &mut ProcessNode) -> Result<String, HarnessError> {
    Ok(node
        .rpc("getbestblockhash", &json!([]))?
        .as_str()
        .unwrap_or("")
        .to_owned())
}

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

fn evidence_dir() -> std::path::PathBuf {
    let dir = workspace().join("target/compact-blocks-e2e");
    std::fs::create_dir_all(&dir).expect("evidence dir");
    dir
}

fn regtest_genesis() -> Block {
    bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
}

/// Builds a BIP141 segwit coinbase-only block on `parent`, with the witness
/// commitment and merkle root the node's own body check requires. `tag`
/// separates branches so equal-height coinbases differ.
fn segwit_coinbase_block(parent: &Block, height: u32, tag: u8) -> Block {
    let reserved = [tag; 32];
    // A coinbase-only tree zeroes witness leaf 0, so the witness merkle root
    // is [0; 32] and the commitment is sha256d(root || reserved).
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
            script_sig: ScriptBuf::from_bytes(vec![0x01, u8::try_from(height).unwrap_or(0xff)]),
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
        header: bitcoin::block::Header {
            version: parent.header.version,
            prev_blockhash: parent.block_hash(),
            merkle_root: parent.header.merkle_root,
            time: parent.header.time.saturating_add(1),
            bits: parent.header.bits,
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("coinbase merkle root");
    while !bitcoin::Target::from_compact(block.header.bits).is_met_by(block.header.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .expect("nonce space exhausted");
    }
    block
}

fn build_chain(parent: &Block, count: u32, tag: u8, start_height: u32) -> Vec<Block> {
    let mut chain = Vec::with_capacity(usize::try_from(count).unwrap_or(64));
    let mut prev = parent.clone();
    for index in 0..count {
        let tag = tag.wrapping_add(u8::try_from(index).unwrap_or(0));
        let block = segwit_coinbase_block(&prev, start_height + index, tag);
        prev = block.clone();
        chain.push(block);
    }
    chain
}

/// A compact `getdata` within 5 blocks of the active tip is answered with a
/// `cmpctblock` that prefills the coinbase at index zero; one block deeper is
/// answered with the whole witness-bearing `block`, not `notfound` and not a
/// compact reply a peer cannot fill from its own mempool.
/// Core 31.1 `net_processing.cpp:2705-2721`.
#[test]
fn serves_compact_by_depth_on_the_wire() -> Result<(), HarnessError> {
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
        .ok_or_else(|| HarnessError::Protocol("no compact-bound reply".to_owned()))?;
    let NetworkMessage::CmpctBlock(cmpct) = reply else {
        return Err(HarnessError::Protocol(format!(
            "a block at the compact bound must be served as cmpctblock, got {}",
            reply.cmd()
        )));
    };
    let compact = &cmpct.compact_block;
    if compact.header.block_hash() != at_bound.block_hash() {
        return Err(HarnessError::Protocol(
            "cmpctblock header mismatch".to_owned(),
        ));
    }
    if compact.prefilled_txs.len() != 1 || u64::from(compact.prefilled_txs[0].idx) != 0 {
        return Err(HarnessError::Protocol(
            "the coinbase must be prefilled at index zero".to_owned(),
        ));
    }
    if serialize(&compact.prefilled_txs[0].tx) != serialize(&at_bound.txdata[0]) {
        return Err(HarnessError::Protocol(
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
        .ok_or_else(|| HarnessError::Protocol("no deep-compact reply".to_owned()))?;
    match reply {
        NetworkMessage::Block(block) if block.block_hash() == one_deeper.block_hash() => {}
        other => {
            return Err(HarnessError::Protocol(format!(
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
fn serves_blocktxn_by_depth_on_the_wire() -> Result<(), HarnessError> {
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
            .ok_or_else(|| HarnessError::Protocol(format!("no reply at depth {offset}")))?;
        let served_whole = matches!(
            &reply,
            NetworkMessage::Block(served) if served.block_hash() == block.block_hash()
        );
        if want_blocktxn {
            if !matches!(reply, NetworkMessage::BlockTxn(_)) {
                return Err(HarnessError::Protocol(format!(
                    "depth {offset} must be answered with blocktxn, got {}",
                    reply.cmd()
                )));
            }
            let NetworkMessage::BlockTxn(BlockTxn { transactions }) = reply else {
                unreachable!("checked above");
            };
            if transactions.transactions != block.txdata {
                return Err(HarnessError::Protocol(
                    "blocktxn must carry the requested body".to_owned(),
                ));
            }
        } else if !served_whole {
            return Err(HarnessError::Protocol(format!(
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
fn empty_getblocktxn_disconnects_on_the_wire() -> Result<(), HarnessError> {
    let (mut node, mut peer, _chain) = synced_peer("empty-txn")?;
    let deadline = Instant::now() + Duration::from_secs(10);

    peer.send(NetworkMessage::Ping(4_321), deadline)?;
    let pong = peer.await_reply(Duration::from_secs(10), &|message| {
        matches!(message, NetworkMessage::Pong(_))
    });
    if pong.is_none() {
        return Err(HarnessError::Protocol(
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
        return Err(HarnessError::Protocol(
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
        return Err(HarnessError::Protocol(
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
fn wrong_root_compact_block_falls_back_to_same_peer() -> Result<(), HarnessError> {
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
        .ok_or_else(|| HarnessError::Protocol("no fallback request seen".to_owned()))?;
    let NetworkMessage::GetData(items) = asked else {
        unreachable!("checked above");
    };
    if items.as_slice() != [Inventory::WitnessBlock(hash)] {
        return Err(HarnessError::Protocol(format!(
            "a failed reconstruction must fetch the full witness body from this peer, got {items:?}"
        )));
    }
    if block_count(&mut node)? != u64::from(tip_height)
        || best_hash(&mut node)? != parent.block_hash().to_string()
    {
        return Err(HarnessError::Protocol(
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
    Err(HarnessError::Protocol(format!(
        "the real body never applied: tip is {}",
        block_count(&mut node)?
    )))
}
