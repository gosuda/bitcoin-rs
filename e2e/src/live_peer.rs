//! One scripted loopback wire peer for the live-sync scenarios.
//!
//! PRE: the node's P2P listener is bound; the caller supplies the blocks
//! the peer may serve.
//! POST: every frame in either direction is journaled next to the node's
//! evidence, and every getdata the node sent is recorded for inspection.
//! INVARIANT: `NODE_NETWORK|WITNESS` service, no compact relay, regtest
//! v70016. Bodies are served type-faithfully: witness inventory gets the
//! full body, a plain `MSG_BLOCK` gets a witness-stripped body — the same
//! behavior a real peer exhibits, which is what makes a plain `MSG_BLOCK`
//! request fatal for segwit bodies.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::Write as _;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{Block, Witness};
use serde_json::json;

use crate::error::{Error, Result};
use crate::node::{ProcessNode, workspace};
use crate::process_peer::{decode_frame, read_frame};

/// One decoded getdata frame: every item flattened to `(inv_type, hash)`.
#[derive(Clone, Debug)]
pub struct GetdataSeen {
    /// Milliseconds since the peer connected when the frame arrived.
    pub at_ms: u64,
    /// Flattened inventory items in wire order.
    pub items: Vec<(u32, String)>,
}

/// A scripted wire peer: it announces, serves, and records exactly what the
/// node asked for.
#[derive(Debug)]
pub struct LivePeer {
    stream: TcpStream,
    journal: File,
    t0: Instant,
    /// Full blocks servable by hash.
    pub blocks: BTreeMap<bitcoin::BlockHash, Block>,
    /// The exact reply to every inbound `getheaders`. `offer` with
    /// `reveal_headers` appends to it; a script assigns it wholesale so
    /// early discovery probes cannot leak headers the test withholds.
    pub headers: Vec<BlockHeader>,
    /// Every decoded getdata frame in arrival order.
    pub getdata_seen: Vec<GetdataSeen>,
    /// Block hashes whose body has been served at least once.
    pub served: HashSet<bitcoin::BlockHash>,
    /// Hashes named by a getdata arriving after their body was served — the
    /// re-request signature of a broken staged-entry sentinel or a retry
    /// rewind. A duplicate getdata emitted before delivery is tolerated
    /// (a preexisting burst quirk, not this path's invariant).
    pub post_serve_requests: Vec<bitcoin::BlockHash>,
    /// `at_ms` of every getheaders frame, in arrival order.
    pub getheaders_at: Vec<u64>,
    /// Bodies served stripped because the node asked `MSG_BLOCK`.
    pub stripped_served: usize,
    /// Peer socket died (node disconnected or transport error).
    pub dropped: bool,
}

impl LivePeer {
    /// Handshake a deep-chain peer: discovery probes fire and self-recover.
    pub fn connect(node: &ProcessNode, name: &str) -> Result<Self> {
        Self::connect_with_height(node, name, 10_000)
    }

    /// Handshake with an advertised best-known height. `10_000` claims a
    /// deep chain (discovery probes fire and self-recover a
    /// pre-bootstrap-rejected batch); `0` keeps the wire quiet so a lone
    /// `getheaders` can only be the staged-header recovery send.
    ///
    /// `NODE_NETWORK|WITNESS`: the recovery getheaders path only considers
    /// fully-serving peers eligible.
    pub fn connect_with_height(
        node: &ProcessNode,
        name: &str,
        start_height: i32,
    ) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = crate::process_peer::connect_loopback(node.p2p_addr, deadline)?;
        stream.set_nodelay(true)?;
        let dir = evidence_dir()?;
        let journal = File::create(dir.join(format!("{name}-peer.jsonl")))?;
        let mut peer = Self {
            stream,
            journal,
            t0: Instant::now(),
            blocks: BTreeMap::new(),
            headers: Vec::new(),
            getdata_seen: Vec::new(),
            served: HashSet::new(),
            post_serve_requests: Vec::new(),
            getheaders_at: Vec::new(),
            stripped_served: 0,
            dropped: false,
        };
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
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
            format!("/{name}:0.1/"),
            // Advertise the chain depth so the peer is immediately
            // attractive for body requests once it demonstrates the tip
            // with headers.
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
                    return Err(Error::Protocol("out-of-order P2P handshake".to_owned()));
                }
                NetworkMessage::Ping(nonce) => {
                    peer.send(NetworkMessage::Pong(nonce), deadline)?;
                }
                _ => {}
            }
        }
        Err(Error::Protocol(
            "P2P handshake message limit".to_owned(),
        ))
    }

    /// Register servable blocks and reveal their headers: the peer answers
    /// every `getheaders` with the offered chain.
    pub fn offer_chain(&mut self, chain: &[Block]) {
        self.offer(chain, true);
    }

    /// Register servable bodies only: headers are revealed solely through
    /// the script-controlled [`Self::headers`] field or explicit `headers`
    /// sends.
    pub fn offer_bodies(&mut self, chain: &[Block]) {
        self.offer(chain, false);
    }

    fn offer(&mut self, chain: &[Block], reveal_headers: bool) {
        for block in chain {
            self.blocks.insert(block.block_hash(), block.clone());
            if reveal_headers {
                self.headers.push(block.header);
            }
        }
    }

    /// Milliseconds since the peer connected.
    #[must_use]
    pub fn at_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Send one wire frame.
    pub fn send(&mut self, message: NetworkMessage, deadline: Instant) -> Result<()> {
        let cmd = message.cmd().to_owned();
        let frame = serialize(&RawNetworkMessage::new(Magic::REGTEST, message));
        self.stream
            .set_write_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::from_secs(1)),
            ))
            .map_err(Error::Io)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.log("send", &cmd);
        Ok(())
    }

    /// Read one wire frame, marking the peer dropped on hard failures.
    pub fn recv(&mut self, deadline: Instant) -> Result<NetworkMessage> {
        match read_frame(&mut self.stream, deadline) {
            Ok(frame) => {
                let message = decode_frame(&frame)?;
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

    /// Serves one getdata item type-faithfully: witness inventory gets the
    /// full body; a plain `MSG_BLOCK` gets a witness-stripped body.
    pub fn serve_item(&mut self, item: &Inventory, deadline: Instant) -> Result<()> {
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

    /// Pump the connection for `dur`: decode every inbound frame, answer
    /// Ping and every `getheaders` with the current `headers` (a real peer
    /// behavior — repeated probes repeat the reply), record every getdata,
    /// and hand each getdata to `serve` (a no-op closure turns this into
    /// pure observation).
    pub fn pump(&mut self, dur: Duration, serve: &mut dyn FnMut(&mut Self, &[Inventory])) {
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
                    let reply = self.headers.clone();
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
                // disconnect — keep observing; hard failures mark the peer
                // dropped and end the pump.
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => break,
            }
        }
    }

    /// Count of getdata items (across all frames) naming `hash` with the
    /// `MSG_BLOCK` (non-witness) type.
    #[must_use]
    pub fn plain_block_requests(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(inv_type, hex)| *inv_type == 0x0000_0002 && hex == &hash.to_string())
            .count()
    }

    /// Count of getdata items (across all frames) naming `hash` regardless
    /// of request type.
    #[must_use]
    pub fn requests_for(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(_, hex)| hex == &hash.to_string())
            .count()
    }

    /// The first getdata frame whose item set equals `expected` (order-free).
    #[must_use]
    pub fn find_getdata(&self, expected: &[Inventory]) -> Option<&GetdataSeen> {
        self.getdata_seen.iter().find(|frame| {
            let mut want: Vec<(u32, String)> = expected.iter().map(inv_item_desc).collect();
            let mut got = frame.items.clone();
            want.sort();
            got.sort();
            want == got
        })
    }

    /// Every hash requested at least once, deduplicated, in first-seen order.
    #[must_use]
    pub fn requested_hashes(&self) -> Vec<String> {
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

    fn log(&mut self, direction: &str, detail: &str) {
        let line = json!({"at_ms": self.at_ms(), "dir": direction, "detail": detail});
        let _ = writeln!(self.journal, "{line}");
        let _ = self.journal.flush();
        eprintln!("[E2E {:>5}ms {direction}] {detail}", self.at_ms());
    }
}

/// True when a frame-read failure is just "no data yet" (read timeout or
/// deadline bookkeeping) rather than a dropped connection.
fn is_soft_recv_error(error: &Error) -> bool {
    match error {
        Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        Error::Protocol(detail) => detail.contains("deadline"),
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

fn evidence_dir() -> Result<PathBuf> {
    let dir = workspace().join("target/live-peer-e2e");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}
