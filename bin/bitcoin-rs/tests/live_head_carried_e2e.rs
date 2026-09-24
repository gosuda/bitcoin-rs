//! E2E: live-head announcement and body-carried header admission over the
//! real P2P wire against a spawned bitcoin-rs daemon (regtest, fjall). A
//! loopback wire peer announces blocks by `inv`; the node probes headers
//! first (the announcement route), and where the peer withholds the ancestry
//! a delivered body's carried header must still admit through the staged-body
//! path (P2P-06). Heights come from the block tree.
//!
//!  * T1: headers bootstrap, then inv-announced live-head blocks apply one
//!    after another through the announcement route — no stall across the chain.
//!  * T2: a delivered body whose carried header's parent is unknown triggers a
//!    recovery `getheaders`; once the ancestors land the staged body applies in
//!    place and is never re-requested.

#![expect(clippy::expect_used, reason = "process test assertions")]

mod support;

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::absolute::LockTime;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::serialize;
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde_json::{Value, json};
use support::process_node::{HarnessError, NodeBinary, ProcessNode, workspace};
use support::process_peer::connect_loopback;

/// One decoded getdata frame: every item flattened to `(inv_type, hash)`.
#[derive(Clone, Debug)]
struct GetdataSeen {
    items: Vec<(u32, String)>,
}

/// Minimal Bitcoin wire peer: `NODE_NETWORK|WITNESS` service (both required for
/// `request_headers_from_eligible`), no compact relay, speaks regtest v70016.
/// Serves full bodies for `MSG_WITNESS_BLOCK` and witness-stripped bodies for
/// plain `MSG_BLOCK`. `getheaders` is answered from `headers_reply` — the test
/// controls exactly which header ancestry is revealed and when.
struct LivePeer {
    stream: TcpStream,
    journal: File,
    t0: Instant,
    /// Full blocks servable by hash.
    blocks: BTreeMap<bitcoin::BlockHash, Block>,
    /// The exact reply to every inbound `getheaders` — set per test phase so
    /// early discovery probes cannot leak headers the test wants withheld.
    headers_reply: Vec<BlockHeader>,
    /// Every decoded getdata frame in arrival order.
    getdata_seen: Vec<GetdataSeen>,
    /// Block hashes whose body has been served at least once.
    served: HashSet<bitcoin::BlockHash>,
    /// Hashes named by a getdata arriving after their body was served — the
    /// re-request signature of a lost staged body or a retry rewind. A duplicate getdata emitted before delivery is tolerated
    /// (a preexisting burst quirk, not this path's invariant).
    post_serve_requests: Vec<bitcoin::BlockHash>,
    /// `at_ms` of every getheaders frame, in arrival order.
    getheaders_at: Vec<u64>,
    /// Bodies served stripped because the node asked `MSG_BLOCK`.
    stripped_served: usize,
    /// Peer socket died (node disconnected or transport error).
    dropped: bool,
}

impl LivePeer {
    fn connect(node: &ProcessNode, name: &str) -> Result<Self, HarnessError> {
        Self::connect_with_height(node, name, 10_000)
    }

    /// `start_height` sets the peer's advertised best-known height: `10_000`
    /// claims a deep chain (discovery probes fire and self-recover a
    /// pre-bootstrap-rejected batch); 0 keeps the wire quiet so a lone
    /// `getheaders` can only be the staged-header recovery send.
    fn connect_with_height(
        node: &ProcessNode,
        name: &str,
        start_height: i32,
    ) -> Result<Self, HarnessError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = connect_loopback(node.p2p_addr, deadline)?;
        stream.set_nodelay(true)?;
        let dir = evidence_dir();
        let journal = File::create(dir.join(format!("{name}-peer.jsonl")))?;
        let mut peer = Self {
            stream,
            journal,
            t0: Instant::now(),
            blocks: BTreeMap::new(),
            headers_reply: Vec::new(),
            getdata_seen: Vec::new(),
            served: HashSet::new(),
            post_serve_requests: Vec::new(),
            getheaders_at: Vec::new(),
            stripped_served: 0,
            dropped: false,
        };
        // NODE_NETWORK|WITNESS: the recovery getheaders path only considers
        // fully-serving peers eligible.
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
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
            "/live-head-e2e:0.1/".to_owned(),
            start_height,
        );
        version.version = 70016;
        peer.send(NetworkMessage::Version(version), deadline)?;
        let mut received_version = false;
        for _ in 0..64 {
            match peer.recv(deadline)? {
                NetworkMessage::Version(_) if !received_version => {
                    received_version = true;
                    peer.send(NetworkMessage::WtxidRelay, deadline)?;
                    peer.send(NetworkMessage::Verack, deadline)?;
                }
                NetworkMessage::Verack if received_version => return Ok(peer),
                NetworkMessage::Verack | NetworkMessage::Version(_) => {
                    return Err(HarnessError::Protocol(
                        "out-of-order P2P handshake".to_owned(),
                    ));
                }
                NetworkMessage::Ping(nonce) => {
                    peer.send(NetworkMessage::Pong(nonce), deadline)?;
                }
                _ => {}
            }
        }
        Err(HarnessError::Protocol(
            "P2P handshake message limit".to_owned(),
        ))
    }

    fn at_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn log(&mut self, direction: &str, detail: &str) {
        let line = json!({"at_ms": self.at_ms(), "dir": direction, "detail": detail});
        let _ = writeln!(self.journal, "{line}");
        let _ = self.journal.flush();
        eprintln!("[E2E {:>5}ms {direction}] {detail}", self.at_ms());
    }

    fn send(&mut self, message: NetworkMessage, deadline: Instant) -> Result<(), HarnessError> {
        let cmd = message.cmd().to_owned();
        let frame = serialize(&RawNetworkMessage::new(Magic::REGTEST, message));
        self.stream
            .set_write_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::from_secs(1)),
            ))
            .map_err(HarnessError::Io)?;
        self.stream.write_all(&frame).map_err(HarnessError::Io)?;
        self.log("send", &cmd);
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> Result<NetworkMessage, HarnessError> {
        match read_frame_local(&mut self.stream, deadline) {
            Ok(frame) => {
                let message = decode_frame_local(&frame)?;
                self.log("recv", message.cmd());
                Ok(message)
            }
            Err(error) => {
                if !is_soft_recv_error(&error) {
                    self.log("recv_error", &error.to_string());
                    self.dropped = true;
                }
                Err(error)
            }
        }
    }

    /// Registers servable bodies only — headers are revealed solely through
    /// `headers_reply` / explicit `headers` sends.
    fn offer_bodies(&mut self, chain: &[Block]) {
        for block in chain {
            self.blocks.insert(block.block_hash(), block.clone());
        }
    }

    /// Serves one getdata item type-faithfully: witness inventory gets the
    /// full body; a plain `MSG_BLOCK` gets a witness-stripped body.
    fn serve_item(&mut self, item: &Inventory, deadline: Instant) -> Result<(), HarnessError> {
        let (hash, stripped) = match item {
            Inventory::WitnessBlock(hash) | Inventory::CompactBlock(hash) => (*hash, false),
            Inventory::Block(hash) => (*hash, true),
            _ => return Ok(()),
        };
        let Some(block) = self.blocks.get(&hash) else {
            return Ok(());
        };
        self.served.insert(hash);
        let body = if stripped {
            self.stripped_served += 1;
            strip_witnesses(block)
        } else {
            block.clone()
        };
        self.log(
            "serve",
            &format!(
                "block {} ({})",
                hash,
                if stripped { "STRIPPED" } else { "full" }
            ),
        );
        self.send(NetworkMessage::Block(body), deadline)
    }

    /// Pump the connection for `dur`: decode inbound frames, answer Ping and
    /// record getdata; answer every `getheaders` with `headers_reply` exactly
    /// (a real peer behavior — repeated probes repeat the reply).
    fn pump(&mut self, dur: Duration, serve: &mut dyn FnMut(&mut Self, &[Inventory])) {
        let end = Instant::now() + dur;
        while Instant::now() < end && !self.dropped {
            match self.recv(end) {
                Ok(NetworkMessage::GetData(items)) => {
                    let seen = GetdataSeen {
                        items: items.iter().map(inv_item_desc).collect(),
                    };
                    self.log("getdata", &format!("{:?}", seen.items));
                    self.getdata_seen.push(seen);
                    for item in &items {
                        if let Inventory::WitnessBlock(hash)
                        | Inventory::CompactBlock(hash)
                        | Inventory::Block(hash) = item
                        {
                            if self.served.contains(hash) {
                                self.post_serve_requests.push(*hash);
                            }
                        }
                    }
                    let items = items.clone();
                    serve(self, &items);
                }
                Ok(NetworkMessage::GetHeaders(_)) => {
                    let at = self.at_ms();
                    self.getheaders_at.push(at);
                    let reply = self.headers_reply.clone();
                    self.log(
                        "getheaders",
                        &format!("replying with {} header(s)", reply.len()),
                    );
                    let _ = self.send(NetworkMessage::Headers(reply), end);
                }
                Ok(NetworkMessage::Ping(nonce)) => {
                    let _ = self.send(NetworkMessage::Pong(nonce), end);
                }
                Ok(_) => {}
                // Soft read timeouts inside a pump slice are not a
                // disconnect — keep observing; hard failures end the pump.
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => break,
            }
        }
    }

    /// Count of getdata items naming `hash` with plain `MSG_BLOCK` type.
    fn plain_block_requests(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(inv_type, hex)| *inv_type == 0x0000_0002 && hex == &hash.to_string())
            .count()
    }

    /// Count of getdata items naming `hash` regardless of request type.
    fn requests_for(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(_, hex)| hex == &hash.to_string())
            .count()
    }

    /// Every hash requested at least once, deduplicated, in first-seen order.
    fn requested_hashes(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for frame in &self.getdata_seen {
            for (_, hex) in &frame.items {
                if !seen.contains(hex) {
                    seen.push(hex.clone());
                }
            }
        }
        seen
    }
}

/// Local frame reader with a 32 MiB payload cap (wire `MAX_MESSAGE_PAYLOAD` —
/// the harness's 4 MiB cap is below what a `block` frame legitimately holds).
const HEADER_BYTES: usize = 24;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

fn read_frame_local(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, HarnessError> {
    fn read_exact(
        stream: &mut TcpStream,
        mut bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), HarnessError> {
        while !bytes.is_empty() {
            stream.set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::from_millis(1)),
            ))?;
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
    let length =
        usize::try_from(u32::from_le_bytes(header[16..20].try_into().map_err(
            |_| HarnessError::Protocol("truncated P2P header".to_owned()),
        )?))
        .map_err(|error| HarnessError::Protocol(error.to_string()))?;
    if length > MAX_PAYLOAD_BYTES {
        return Err(HarnessError::Protocol("P2P payload byte limit".to_owned()));
    }
    let mut frame = header.to_vec();
    frame.resize(HEADER_BYTES + length, 0);
    read_exact(stream, &mut frame[HEADER_BYTES..], deadline)?;
    Ok(frame)
}

/// Decode without the harness's 4 MiB payload cap.
fn decode_frame_local(frame: &[u8]) -> Result<NetworkMessage, HarnessError> {
    let envelope: RawNetworkMessage = bitcoin::consensus::deserialize(frame)
        .map_err(|error| HarnessError::Protocol(format!("invalid P2P envelope: {error}")))?;
    if *envelope.magic() != Magic::REGTEST {
        return Err(HarnessError::Protocol("P2P network mismatch".to_owned()));
    }
    Ok(envelope.into_payload())
}

/// True when a frame-read failure is just "no data yet" (read timeout or
/// deadline bookkeeping) rather than a dropped connection.
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

/// `(inv_type, hash-display)` for an inventory item. Type codes follow the
/// wire encoding: `MSG_BLOCK`=2, `MSG_WITNESS_BLOCK`=0x40000002.
fn inv_item_desc(item: &Inventory) -> (u32, String) {
    match item {
        Inventory::Transaction(txid) => (0x0000_0001, txid.to_string()),
        Inventory::Block(hash) => (0x0000_0002, hash.to_string()),
        Inventory::CompactBlock(hash) => (0x0000_0004, hash.to_string()),
        Inventory::WTx(wtxid) => (0x4000_0005, wtxid.to_string()),
        Inventory::WitnessTransaction(txid) => (0x4000_0001, txid.to_string()),
        Inventory::WitnessBlock(hash) => (0x4000_0002, hash.to_string()),
        Inventory::Unknown { inv_type, hash } => (
            *inv_type,
            bitcoin::hashes::sha256d::Hash::from_byte_array(*hash).to_string(),
        ),
        Inventory::Error => (0, "error".to_owned()),
    }
}

/// Returns a copy of `block` with every input witness removed.
fn strip_witnesses(block: &Block) -> Block {
    let mut stripped = block.clone();
    for tx in &mut stripped.txdata {
        for input in &mut tx.input {
            input.witness = Witness::new();
        }
    }
    stripped
}

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
fn rpc(node: &mut ProcessNode, method: &str) -> Result<Value, HarnessError> {
    node.rpc(method, &json!([]))
}

fn block_count(node: &mut ProcessNode) -> Result<u64, HarnessError> {
    Ok(rpc(node, "getblockcount")?.as_u64().unwrap_or(u64::MAX))
}

fn best_hash(node: &mut ProcessNode) -> Result<String, HarnessError> {
    Ok(rpc(node, "getbestblockhash")?
        .as_str()
        .unwrap_or("")
        .to_owned())
}

fn connection_count(node: &mut ProcessNode) -> Result<u64, HarnessError> {
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
) -> Result<bool, HarnessError> {
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

fn evidence_dir() -> std::path::PathBuf {
    let dir = workspace().join("target/live-head-e2e");
    std::fs::create_dir_all(&dir).expect("evidence dir");
    dir
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

/// T1: headers bootstrap proves the baseline pipeline, then each block
/// announced by `inv` reaches the node through the announcement route: the
/// node probes `getheaders`, the revealed header admits near the tip, and
/// the fetched body applies. Several in a row must keep advancing: no stall.
#[test]
fn announced_live_head_applies_and_continues() -> Result<(), HarnessError> {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;
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
    // `getheaders` answers start at h1..h3: h4..h6 are revealed one at a
    // time, each only when its block is announced.
    peer.headers_reply = chain[..3].iter().map(|b| b.header).collect();
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

    // Live-head blocks h4,h5,h6 arrive via inv announcements: the
    // announcement route probes for headers, the revealed header admits near
    // the tip, and the window asks this peer for the body.
    for (height, block) in chain.iter().enumerate().skip(3) {
        let hash = block.block_hash();
        peer.headers_reply = chain[..=height].iter().map(|b| b.header).collect();
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

    assert_clean_stderr(&node, "live-head announcement chain");
    eprintln!("[E2E] T1 PASSED: announced headers admitted, tip advanced h3→h6 without stall");
    Ok(())
}

/// T2: an announced block is probed with `getheaders` first; when the body
/// then arrives with its carried header's parent still unknown that is not a
/// peer fault — the node must issue a recovery `getheaders`, then apply the
/// staged body in place once the ancestors land. The staged h4 body keeps no
/// height of its own; the tree places it once its header lands, so the node
/// must never re-request h4 and must apply it.
#[allow(clippy::too_many_lines)]
#[test]
fn missing_parent_delivery_recovers_via_getheaders() -> Result<(), HarnessError> {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;
    // start_height=0: the peer advertises no better tip, so no discovery
    // getheaders fires before the announcement; later probes are
    // attributable by their position in `getheaders_at`.
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
    peer.headers_reply = Vec::new();

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

    // New semantics: the announcement route probes for headers at once, and
    // no body request may be emitted for a hash the tree has never admitted.
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

    // Settle ~1.2s with the body withheld; the probe count after that is the
    // announcement baseline, so anything new once the body lands is the
    // staged-header recovery send.
    peer.pump(Duration::from_millis(1200), &mut |_, _| {});
    let announcement_probes = peer.getheaders_at.len();

    // Deliver the body unsolicited; its carried header fails admission
    // (parent h3 unknown) and the staged retry must ask us for the gap.
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

    // Reveal the ancestry: admit h1..h4 headers (the staged retry + this
    // reply converge). Also switch future getheaders replies to the real
    // ancestry minus h5 — h5 must stay body-carried only.
    let pre_headers_requests = peer.requests_for(&h4);
    peer.headers_reply = chain[..4].iter().map(|b| b.header).collect();
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

    // Post-recovery liveness: announce h5 by inv — the announcement route
    // probes, the reply reveals h5's header, and the tip keeps advancing.
    peer.headers_reply = chain[..5].iter().map(|b| b.header).collect();
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
