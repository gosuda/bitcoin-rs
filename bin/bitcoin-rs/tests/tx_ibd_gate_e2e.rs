//! L1: transaction ingress is gated on initial block download, over the real
//! P2P wire against a spawned bitcoin-rs daemon (regtest, fjall).
//!
//! Bitcoin Core requests no announced transaction and drops unsolicited `tx`
//! bodies while in initial block download (net_processing.cpp:4401-4404,
//! :4713-4716). This test pins the same behavior on the wire:
//!
//!  * phase 1: a fresh node reports `initialblockdownload == true`; an
//!    announced transaction draws no `getdata`, and its body is neither
//!    admitted nor relayed to a bystander peer.
//!  * phase 2: a locally built, mature regtest chain is applied, the applied
//!    tip becomes recent, and the node leaves initial block download.
//!  * phase 3: the same announcement is now requested, the delivered body is
//!    admitted, and the mempool grows to exactly one entry.

#![expect(clippy::expect_used, reason = "process test assertions")]

mod support;

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::absolute::LockTime;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
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

const REGTEST_BITS: u32 = 0x207f_ffff;
const HEADER_BYTES: usize = 24;
const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded window during which an absence must persist: admission and relay
/// run asynchronously behind the bounded ingress channel.
const ABSENCE_WINDOW: Duration = Duration::from_millis(1_500);

// ---------------------------------------------------------------------------
// Minimal wire peer
// ---------------------------------------------------------------------------

struct GatePeer {
    stream: TcpStream,
    journal: File,
    t0: Instant,
    /// Every decoded getdata frame, flattened to `(inv_type, hash)` pairs.
    getdata_seen: Vec<Vec<(u32, String)>>,
    /// Transaction ids announced to us by the node (relay reachability).
    relayed_seen: Vec<String>,
    dropped: bool,
}

impl GatePeer {
    fn connect(node: &ProcessNode, name: &str) -> Result<Self, HarnessError> {
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let stream = connect_loopback(node.p2p_addr, deadline)?;
        stream.set_nodelay(true)?;
        let journal = File::create(evidence_dir().join(format!("{name}-peer.jsonl")))?;
        let mut peer = Self {
            stream,
            journal,
            t0: Instant::now(),
            getdata_seen: Vec::new(),
            relayed_seen: Vec::new(),
            dropped: false,
        };
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| HarnessError::Protocol(error.to_string()))?
                .as_secs(),
        )
        .map_err(|error| HarnessError::Protocol(error.to_string()))?;
        let local = peer.stream.local_addr().map_err(HarnessError::Io)?;
        let mut version = VersionMessage::new(
            services,
            now,
            Address::new(&node.p2p_addr, ServiceFlags::NONE),
            Address::new(&local, services),
            0,
            "/tx-ibd-gate-e2e:0.1/".to_owned(),
            0,
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
        match read_frame(&mut self.stream, deadline) {
            Ok(frame) => {
                let message = decode_frame(&frame)?;
                self.log("recv", message.cmd());
                Ok(message)
            }
            Err(error) => {
                if !is_soft_recv_error(&error) {
                    self.dropped = true;
                }
                Err(error)
            }
        }
    }

    fn log(&mut self, direction: &str, detail: &str) {
        let at_ms = u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let line = json!({"at_ms": at_ms, "dir": direction, "detail": detail});
        let _ = writeln!(self.journal, "{line}");
        let _ = self.journal.flush();
    }

    /// Sends `inv` followed by a ping barrier and pumps until the pong
    /// returns, recording every getdata frame seen on the way. The node
    /// processes wire messages in order, so the pong proves the `inv` was
    /// fully handled.
    fn announce_with_barrier(
        &mut self,
        items: Vec<Inventory>,
        nonce: u64,
    ) -> Result<(), HarnessError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        self.send(NetworkMessage::Inv(items), deadline)?;
        self.send(NetworkMessage::Ping(nonce), deadline)?;
        self.pump_until_pong(nonce, deadline)
    }

    /// Ping barrier without an announcement.
    fn bar(&mut self, nonce: u64) -> Result<(), HarnessError> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        self.send(NetworkMessage::Ping(nonce), deadline)?;
        self.pump_until_pong(nonce, deadline)
    }

    fn pump_until_pong(&mut self, nonce: u64, deadline: Instant) -> Result<(), HarnessError> {
        while !self.dropped {
            if Instant::now() >= deadline {
                return Err(HarnessError::Protocol("pong barrier deadline".to_owned()));
            }
            match self.recv(deadline) {
                Ok(NetworkMessage::Pong(reply)) if reply == nonce => return Ok(()),
                Ok(NetworkMessage::GetData(items)) => self.record_getdata(&items),
                Ok(NetworkMessage::GetHeaders(_)) => {
                    // Keep the wire quiet: an empty headers reply is always a
                    // valid answer and never advances header sync.
                    let _ = self.send(NetworkMessage::Headers(Vec::new()), deadline);
                }
                Ok(NetworkMessage::Ping(reply)) => {
                    let _ = self.send(NetworkMessage::Pong(reply), deadline);
                }
                Ok(_) => {}
                Err(error) if is_soft_recv_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(HarnessError::Protocol(
            "peer dropped during barrier".to_owned(),
        ))
    }

    /// Pumps for `dur`: answers pings and getheaders, records getdata and
    /// relayed inv announcements.
    fn pump(&mut self, dur: Duration) {
        let end = Instant::now() + dur;
        while Instant::now() < end && !self.dropped {
            match self.recv(end) {
                Ok(NetworkMessage::GetData(items)) => {
                    self.record_getdata(&items);
                }
                Ok(NetworkMessage::Inv(items)) => {
                    for item in items {
                        if let Inventory::Transaction(txid) = item {
                            self.relayed_seen.push(txid.to_string());
                            self.log("relayed_inv", &txid.to_string());
                        }
                    }
                }
                Ok(NetworkMessage::GetHeaders(_)) => {
                    let _ = self.send(NetworkMessage::Headers(Vec::new()), end);
                }
                Ok(NetworkMessage::Ping(nonce)) => {
                    let _ = self.send(NetworkMessage::Pong(nonce), end);
                }
                Ok(_) => {}
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => break,
            }
        }
    }

    fn record_getdata(&mut self, items: &[Inventory]) {
        let flat: Vec<(u32, String)> = items
            .iter()
            .map(|item| match item {
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
            })
            .collect();
        self.log("getdata", &format!("{flat:?}"));
        self.getdata_seen.push(flat);
    }

    fn txid_requested(&self, txid: &str) -> bool {
        self.getdata_seen
            .iter()
            .flatten()
            .any(|(_, hash)| hash == txid)
    }

    fn relayed(&self, txid: &str) -> bool {
        self.relayed_seen.iter().any(|announced| announced == txid)
    }
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

fn read_frame(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, HarnessError> {
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

fn decode_frame(frame: &[u8]) -> Result<NetworkMessage, HarnessError> {
    let envelope: RawNetworkMessage = bitcoin::consensus::deserialize(frame)
        .map_err(|error| HarnessError::Protocol(format!("invalid P2P envelope: {error}")))?;
    if *envelope.magic() != Magic::REGTEST {
        return Err(HarnessError::Protocol("P2P network mismatch".to_owned()));
    }
    Ok(envelope.into_payload())
}

fn evidence_dir() -> std::path::PathBuf {
    let dir = workspace().join("target/tx-ibd-gate-e2e");
    std::fs::create_dir_all(&dir).expect("evidence dir");
    dir
}

// ---------------------------------------------------------------------------
// Fixtures: the relayed transaction and the mature funding chain
// ---------------------------------------------------------------------------

/// UNIX seconds now, clamped into u32.
fn now_unix() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

/// Minimal `CScriptNum` push, the BIP34 height encoding.
fn script_num_push(value: u32) -> Vec<u8> {
    let low = u8::try_from(value & 0xff).unwrap_or(0xff);
    if value < 0x80 {
        vec![0x01, low]
    } else if value < 0x80_00 {
        vec![0x02, low, u8::try_from(value >> 8).unwrap_or(0)]
    } else {
        vec![
            0x03,
            low,
            u8::try_from((value >> 8) & 0xff).unwrap_or(0),
            u8::try_from(value >> 16).unwrap_or(0),
        ]
    }
}

/// Coinbase paying `value` sats to `OP_TRUE`, with the BIP34 height push.
fn op_true_coinbase(height: u32, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_num_push(height)),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// Anyone-can-spend funding transaction paying `value` sats to `OP_TRUE`.
fn funding_tx(previous_output: OutPoint, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// The relayed transaction: spends the funding output into one `OP_RETURN`.
fn relayed_tx(funding: &Transaction, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]),
        }],
    }
}

/// Builds one block on `parent` at `time` carrying `txs`, ground to the
/// declared regtest target.
fn build_block(parent: &Block, time: u32, txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: parent.block_hash(),
            merkle_root: parent.header.merkle_root,
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txdata: txs,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .expect("non-empty block merkle root");
    while !bitcoin::Target::from_compact(block.header.bits).is_met_by(block.header.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .expect("regtest nonce space exhausted");
    }
    block
}

/// Builds the mature chain the relayed transaction spends from: coinbase-only
/// blocks at heights 1..=100, then block 101 carrying the funding transaction
/// that spends the height-1 coinbase (mature exactly at depth 100).
fn build_funding_chain(base_time: u32) -> (Vec<Block>, Transaction) {
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    let mut blocks: Vec<Block> = Vec::new();
    let mut parent = genesis;
    for height in 1_u32..=101 {
        let time = base_time.saturating_add(height);
        let txs = if height == 101 {
            let height_one_coinbase = blocks
                .first()
                .expect("height-1 block exists")
                .txdata
                .first()
                .expect("coinbase exists")
                .compute_txid();
            let funding = funding_tx(OutPoint::new(height_one_coinbase, 0), 40_000);
            vec![op_true_coinbase(height, 5_000), funding]
        } else {
            vec![op_true_coinbase(height, 50_000)]
        };
        let block = build_block(&parent, time, txs);
        parent = block.clone();
        blocks.push(block);
    }
    let funding = blocks
        .last()
        .expect("funding block exists")
        .txdata
        .last()
        .expect("funding tx exists")
        .clone();
    (blocks, funding)
}

fn hex_body(block: &Block) -> String {
    bitcoin::consensus::encode::serialize_hex(block)
}

// ---------------------------------------------------------------------------
// RPC helpers
// ---------------------------------------------------------------------------

fn rpc(node: &mut ProcessNode, method: &str) -> Result<Value, HarnessError> {
    node.rpc(method, &json!([]))
}

fn initial_block_download(node: &mut ProcessNode) -> bool {
    rpc(node, "getblockchaininfo")
        .ok()
        .and_then(|info| info.get("initialblockdownload").and_then(Value::as_bool))
        .unwrap_or(true)
}

/// `None` on a transient RPC failure: callers decide whether absence of an
/// answer proves anything.
fn mempool_size(node: &mut ProcessNode) -> Option<u64> {
    rpc(node, "getmempoolinfo")
        .ok()
        .and_then(|info| info.get("size").and_then(Value::as_u64))
}

/// Polls `check` until it holds or `dur` elapses, pumping `peer` between
/// polls so the node keeps making progress.
fn wait_with_pump(
    node: &mut ProcessNode,
    peer: &mut GatePeer,
    dur: Duration,
    check: &mut dyn FnMut(&mut ProcessNode) -> bool,
) -> bool {
    let deadline = Instant::now() + dur;
    loop {
        peer.pump(Duration::from_millis(300));
        if check(node) {
            return true;
        }
        if Instant::now() >= deadline || peer.dropped {
            return false;
        }
    }
}

// ---------------------------------------------------------------------------
// The L1 test
// ---------------------------------------------------------------------------

#[test]
fn ibd_node_ignores_then_requests_relay_transactions() -> Result<(), HarnessError> {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;
    let mut peer = GatePeer::connect(&node, "gate")?;
    let mut bystander = GatePeer::connect(&node, "bystander")?;

    // Phase 1a: a fresh node is in initial block download.
    assert!(
        initial_block_download(&mut node),
        "a node with no applied tip must report initial block download"
    );

    let (blocks, funding) = build_funding_chain(now_unix().saturating_sub(3_600));
    let relayed = relayed_tx(&funding, 30_000);
    let txid = relayed.compute_txid();

    // Phase 1b: an announced transaction draws no getdata while in IBD.
    peer.announce_with_barrier(vec![Inventory::Transaction(txid)], 7_001)?;
    assert!(
        !peer.txid_requested(&txid.to_string()),
        "the node requested a transaction while in initial block download"
    );

    // Phase 1c: the delivered body is not admitted and not relayed.
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    peer.send(NetworkMessage::Tx(relayed.clone()), deadline)?;
    peer.bar(7_002)?;
    let end = Instant::now() + ABSENCE_WINDOW;
    while Instant::now() < end {
        if let Some(size) = mempool_size(&mut node) {
            assert_eq!(
                size, 0,
                "a relayed transaction entered the mempool during initial block download"
            );
        }
        bystander.pump(Duration::from_millis(200));
        assert!(
            !bystander.relayed(&txid.to_string()),
            "the transaction was relayed to a bystander peer during initial block download"
        );
    }

    // Phase 2: apply the mature funding chain; the recent applied tip ends
    // initial block download.
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
    node.rpc("submitblock", &json!([hex_body(&genesis)]))?;
    for block in &blocks {
        let accepted = node.rpc("submitblock", &json!([hex_body(block)]))?;
        assert!(
            accepted.is_null(),
            "submitblock rejected a block: {accepted}"
        );
    }
    assert!(
        wait_with_pump(&mut node, &mut peer, Duration::from_secs(20), &mut |node| {
            !initial_block_download(node)
        },),
        "the node never left initial block download after applying a recent tip"
    );

    // Phase 3: the same announcement is now requested and admitted.
    peer.announce_with_barrier(vec![Inventory::Transaction(txid)], 7_003)?;
    assert!(
        peer.txid_requested(&txid.to_string()),
        "after initial block download the announced transaction must be requested"
    );
    let body_deadline = Instant::now() + REQUEST_TIMEOUT;
    peer.log("serve", "relayed tx body");
    peer.send(NetworkMessage::Tx(relayed), body_deadline)?;
    let admitted = wait_with_pump(&mut node, &mut peer, Duration::from_secs(15), &mut |node| {
        mempool_size(node) == Some(1)
    });
    assert!(
        admitted,
        "the relayed transaction never entered the mempool after initial block download"
    );
    assert_eq!(mempool_size(&mut node), Some(1));

    let stderr = std::fs::read_to_string(node.evidence.join("stderr.log")).unwrap_or_default();
    assert_eq!(stderr.matches("panic").count(), 0, "node panicked");
    Ok(())
}
