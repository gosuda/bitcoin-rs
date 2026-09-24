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

mod support;

use std::collections::BTreeMap;
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
    at_ms: u64,
    items: Vec<(u32, String)>,
}

/// Minimal Bitcoin wire peer: WITNESS service, no compact relay, speaks
/// regtest v70016. Serves full bodies for `MSG_WITNESS_BLOCK` and
/// witness-stripped bodies for plain `MSG_BLOCK` — the same type-faithful
/// behavior a real peer (e.g. Bitcoin Core) exhibits, which is what makes a
/// plain `MSG_BLOCK` request fatal for segwit bodies.
struct LivePeer {
    stream: TcpStream,
    journal: File,
    t0: Instant,
    /// Full blocks servable by hash.
    blocks: BTreeMap<bitcoin::BlockHash, Block>,
    /// Header chain to answer `getheaders` probes with.
    headers: Vec<BlockHeader>,
    /// Every decoded getdata frame in arrival order.
    getdata_seen: Vec<GetdataSeen>,
    /// Bodies we had to serve stripped because the node asked `MSG_BLOCK`.
    stripped_served: usize,
    /// Peer socket died (node disconnected or transport error).
    dropped: bool,
}

impl LivePeer {
    fn connect(node: &ProcessNode, name: &str) -> Result<Self, HarnessError> {
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
            headers: Vec::new(),
            getdata_seen: Vec::new(),
            stripped_served: 0,
            dropped: false,
        };
        let services = ServiceFlags::WITNESS;
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
            "/head-sync-e2e:0.1/".to_owned(),
            // Advertise a deep chain so the peer is immediately attractive for
            // body requests once it demonstrates the tip with headers.
            10_000,
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
                self.log("recv_error", &error.to_string());
                if !is_soft_recv_error(&error) {
                    self.dropped = true;
                }
                Err(error)
            }
        }
    }

    /// Registers servable blocks and remember their headers for `getheaders`.
    fn offer_chain(&mut self, chain: &[Block]) {
        for block in chain {
            self.blocks.insert(block.block_hash(), block.clone());
            self.headers.push(block.header);
        }
    }

    /// Serves one getdata item type-faithfully: witness inventory gets the
    /// full body; a plain `MSG_BLOCK` gets a witness-stripped body (what a
    /// real peer would send for that request type).
    fn serve_item(&mut self, item: &Inventory, deadline: Instant) -> Result<(), HarnessError> {
        let (hash, stripped) = match item {
            Inventory::WitnessBlock(hash) | Inventory::CompactBlock(hash) => (*hash, false),
            Inventory::Block(hash) => (*hash, true),
            _ => return Ok(()),
        };
        let Some(block) = self.blocks.get(&hash) else {
            return Ok(());
        };
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

    /// Pump the connection for `dur`: decode every inbound frame, answer
    /// Ping/GetHeaders, record every getdata, and hand each getdata to
    /// `serve` (a no-op closure turns this into pure observation).
    fn pump(&mut self, dur: Duration, serve: &mut dyn FnMut(&mut Self, &[Inventory])) {
        let end = Instant::now() + dur;
        while Instant::now() < end && !self.dropped {
            match self.recv(end) {
                Ok(NetworkMessage::GetData(items)) => {
                    let seen = GetdataSeen {
                        at_ms: self.at_ms(),
                        items: items.iter().map(inv_item_desc).collect(),
                    };
                    self.log("getdata", &format!("{:?}", seen.items));
                    self.getdata_seen.push(seen);
                    let items = items.clone();
                    serve(self, &items);
                }
                Ok(NetworkMessage::Ping(nonce)) => {
                    let _ = self.send(NetworkMessage::Pong(nonce), end);
                }
                Ok(NetworkMessage::GetHeaders(_)) => {
                    let headers = self.headers.clone();
                    let _ = self.send(NetworkMessage::Headers(headers), end);
                }
                Ok(_) => {}
                // Soft read timeouts inside a pump slice are not a
                // disconnect — keep observing; hard failures mark the peer
                // dropped and end the pump.
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => break,
            }
        }
    }

    /// Count of getdata items (across all frames) naming `hash` with the
    /// `MSG_BLOCK` (non-witness) type.
    fn plain_block_requests(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(inv_type, hex)| *inv_type == 0x0000_0002 && hex == &hash.to_string())
            .count()
    }

    /// Count of getdata items (across all frames) naming `hash` regardless of
    /// request type.
    fn requests_for(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(_, hex)| hex == &hash.to_string())
            .count()
    }
}

/// Local frame reader identical to `process_peer::read_frame` but with a
/// 32 MiB payload cap: the harness 4 MiB cap is below the protocol limit
/// and the node legitimately emits larger frames.
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
        Inventory::WTx(wtxid) => (0x0000_0005, wtxid.to_string()),
        Inventory::WitnessTransaction(txid) => (0x4000_0001, txid.to_string()),
        Inventory::WitnessBlock(hash) => (0x4000_0002, hash.to_string()),
        Inventory::Unknown { inv_type, hash } => (
            *inv_type,
            bitcoin::hashes::sha256d::Hash::from_byte_array(*hash).to_string(),
        ),
        Inventory::Error => (0, "error".to_owned()),
    }
}

/// Returns a copy of `block` with every input witness removed: the body a
/// peer serves for a plain `MSG_BLOCK` getdata.
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

fn evidence_dir() -> std::path::PathBuf {
    let dir = workspace().join("target/head-sync-e2e");
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

/// T1+T2: a block announced by `inv` is availability, not a body order: the
/// node fetches headers first, and the admitted tip's body rides a window
/// request as `MSG_WITNESS_BLOCK`. The
/// headers->getdata->bodies->apply pipeline must still apply segwit bodies
/// served with witnesses, and an `inv` for the already-known tip must never
/// produce a plain `MSG_BLOCK` request.
#[test]
fn announced_tip_fetches_witness_block_and_applies_segwit_chain() -> Result<(), HarnessError> {
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
fn pending_reorg_keeps_staged_winner_then_switches() -> Result<(), HarnessError> {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;
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
/// the stager holds the body and the block tree supplies its height. The
/// chain must still converge and the request cursor must never rewind to
/// applied heights.
#[test]
fn untracked_delivery_of_tree_known_block_converges() -> Result<(), HarnessError> {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;
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
