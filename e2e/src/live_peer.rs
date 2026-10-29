//! One scripted loopback wire peer for the live-sync scenarios.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::net::TcpStream;
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
use sonic_rs::json;

use crate::error::{Error, Result};
use crate::node::ProcessNode;
use crate::process_peer::{FrameBuffer, decode_frame, is_soft_recv_error, read_frame};

#[derive(Clone, Debug)]
pub struct GetdataSeen {
    pub at_ms: u64,
    pub items: Vec<(u32, String)>,
}

#[derive(Debug)]
pub struct LivePeer {
    stream: TcpStream,
    journal: File,
    journal_broken: bool,
    t0: Instant,
    pub blocks: BTreeMap<bitcoin::BlockHash, Block>,
    pub headers: Vec<BlockHeader>,
    pub getdata_seen: Vec<GetdataSeen>,
    pub inventory_seen: Vec<Inventory>,
    /// Proactive BIP133 thresholds observed from the node (sat/kvB).
    pub fee_filters_seen: Vec<i64>,
    pub getheaders_at: Vec<u64>,
    pub stripped_served: usize,
    pub dropped: bool,
    pending: FrameBuffer,
}

impl LivePeer {
    pub fn connect(node: &ProcessNode, name: &str) -> Result<Self> {
        Self::connect_with_height(node, name, 10_000)
    }

    pub fn connect_with_height(node: &ProcessNode, name: &str, start_height: i32) -> Result<Self> {
        Self::connect_with_wtxid_relay(node, name, start_height, true)
    }

    /// Handshake with an explicit BIP339 profile for mixed txid/wtxid peers.
    pub fn connect_with_wtxid_relay(
        node: &ProcessNode,
        name: &str,
        start_height: i32,
        wtxid_relay: bool,
    ) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = crate::process_peer::connect_loopback(node.p2p_addr, deadline)?;
        stream.set_nodelay(true)?;
        let journal = File::create(node.evidence.join(format!("{name}-peer.jsonl")))?;
        let mut peer = Self {
            stream,
            journal,
            journal_broken: false,
            t0: Instant::now(),
            blocks: BTreeMap::new(),
            headers: Vec::new(),
            getdata_seen: Vec::new(),
            inventory_seen: Vec::new(),
            fee_filters_seen: Vec::new(),
            getheaders_at: Vec::new(),
            stripped_served: 0,
            dropped: false,
            pending: FrameBuffer::default(),
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
            start_height,
        );
        version.version = 70016;
        version.relay = true;
        peer.send(NetworkMessage::Version(version), deadline)?;
        let mut received_version = false;
        for _ in 0..64 {
            match peer.recv(deadline)? {
                NetworkMessage::Version(_) if !received_version => {
                    received_version = true;
                    if wtxid_relay {
                        peer.send(NetworkMessage::WtxidRelay, deadline)?;
                    }
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
        Err(Error::Protocol("P2P handshake message limit".to_owned()))
    }

    pub fn offer_chain(&mut self, chain: &[Block]) {
        self.offer(chain, true);
    }

    pub fn offer_bodies(&mut self, chain: &[Block]) {
        self.offer(chain, false);
    }

    pub fn announce_headers(&mut self, blocks: &[Block], deadline: Instant) -> Result<()> {
        let headers = blocks.iter().map(|block| block.header).collect();
        self.send(NetworkMessage::Headers(headers), deadline)
    }

    fn offer(&mut self, chain: &[Block], reveal_headers: bool) {
        for block in chain {
            self.blocks.insert(block.block_hash(), block.clone());
            if reveal_headers {
                self.headers.push(block.header);
            }
        }
    }

    #[must_use]
    pub fn at_ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

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

    pub fn ping_barrier(&mut self, nonce: u64, deadline: Instant) -> Result<()> {
        self.send(NetworkMessage::Ping(nonce), deadline)?;
        for _ in 0..128 {
            match self.recv(deadline)? {
                NetworkMessage::Pong(reply) if reply == nonce => return Ok(()),
                NetworkMessage::Ping(reply) => self.send(NetworkMessage::Pong(reply), deadline)?,
                _ => {}
            }
        }
        Err(Error::Protocol(
            "ping barrier message budget exhausted".to_owned(),
        ))
    }

    fn recv(&mut self, deadline: Instant) -> Result<NetworkMessage> {
        match read_frame(&mut self.stream, deadline, &mut self.pending) {
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

    pub fn serve_item(&mut self, item: &Inventory, deadline: Instant) -> Result<()> {
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
                    let items = items.clone();
                    serve(self, &items);
                }
                Ok(NetworkMessage::Inv(items)) => self.inventory_seen.extend(items),
                Ok(NetworkMessage::FeeFilter(rate)) => self.fee_filters_seen.push(rate),
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
                Err(error) if is_soft_recv_error(&error) => {}
                Err(_) => break,
            }
        }
    }

    #[must_use]
    pub fn plain_block_requests(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(inv_type, hex)| *inv_type == 0x0000_0002 && hex == &hash.to_string())
            .count()
    }

    #[must_use]
    pub fn requests_for(&self, hash: &bitcoin::BlockHash) -> usize {
        self.getdata_seen
            .iter()
            .flat_map(|frame| frame.items.iter())
            .filter(|(_, hex)| hex == &hash.to_string())
            .count()
    }

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
        let result = writeln!(self.journal, "{line}").and_then(|()| self.journal.flush());
        if result.is_err() && !self.journal_broken {
            self.journal_broken = true;
            eprintln!(
                "[E2E {:>5}ms {direction}] JOURNAL WRITE FAILED: {result:?}",
                self.at_ms()
            );
        }
        eprintln!("[E2E {:>5}ms {direction}] {detail}", self.at_ms());
    }
}

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

fn strip_witnesses(block: &Block) -> Block {
    let mut stripped = block.clone();
    for tx in &mut stripped.txdata {
        for input in &mut tx.input {
            input.witness = Witness::new();
        }
    }
    stripped
}

pub fn pump_until_tip(
    peer: &mut LivePeer,
    node: &mut ProcessNode,
    min_height: u64,
    height: u64,
    hash: &str,
    dur: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + dur;
    loop {
        let count = crate::helpers::block_count(node)?;
        if count < min_height {
            return Err(Error::Assertion(format!(
                "applied tip rewound below h{min_height} while waiting for h{height}: h{count}"
            )));
        }
        if count == height && crate::helpers::best_hash(node)? == hash {
            return Ok(true);
        }
        if Instant::now() >= deadline || peer.dropped {
            return Ok(false);
        }
        peer.pump(Duration::from_millis(400), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let _ = peer.serve_item(item, deadline);
            }
        });
    }
}
