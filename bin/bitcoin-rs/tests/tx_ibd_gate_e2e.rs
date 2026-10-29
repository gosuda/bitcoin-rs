#![expect(clippy::expect_used, reason = "process test assertions")]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::support::wire_peer;
use bitcoin::absolute::LockTime;
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_rs_e2e::helpers::coinbase_script_sig;
use bitcoin_rs_e2e::process_peer::is_soft_recv_error;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode};
use wire_peer::Peer;

use sonic_rs::{JsonValueTrait as _, Value, json};

const REGTEST_BITS: u32 = 0x207f_ffff;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const ABSENCE_WINDOW: Duration = Duration::from_millis(1_500);

struct GatePeer {
    wire: Peer,
    getdata_seen: Vec<Vec<(u32, String)>>,
    relayed_seen: Vec<String>,
}

impl GatePeer {
    fn connect(node: &ProcessNode, name: &str) -> Result<Self, Error> {
        Ok(Self {
            wire: Peer::connect(
                node.p2p_addr,
                "tx-ibd-gate-e2e",
                name,
                0,
                Instant::now() + HANDSHAKE_TIMEOUT,
            )?,
            getdata_seen: Vec::new(),
            relayed_seen: Vec::new(),
        })
    }

    fn announce_with_barrier(&mut self, items: Vec<Inventory>, nonce: u64) -> Result<(), Error> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        self.wire.send(NetworkMessage::Inv(items), deadline)?;
        self.wire.send(NetworkMessage::Ping(nonce), deadline)?;
        self.pump_until_pong(nonce, deadline)
    }

    fn bar(&mut self, nonce: u64) -> Result<(), Error> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        self.wire.send(NetworkMessage::Ping(nonce), deadline)?;
        self.pump_until_pong(nonce, deadline)
    }

    fn pump_until_pong(&mut self, nonce: u64, deadline: Instant) -> Result<(), Error> {
        while !self.wire.dropped {
            if Instant::now() >= deadline {
                return Err(Error::Protocol("pong barrier deadline".to_owned()));
            }
            match self.wire.recv(deadline) {
                Ok(NetworkMessage::Pong(reply)) if reply == nonce => return Ok(()),
                Ok(NetworkMessage::GetData(items)) => self.record_getdata(&items),
                Ok(NetworkMessage::GetHeaders(_)) => {
                    let _ = self
                        .wire
                        .send(NetworkMessage::Headers(Vec::new()), deadline);
                }
                Ok(NetworkMessage::Ping(reply)) => {
                    let _ = self.wire.send(NetworkMessage::Pong(reply), deadline);
                }
                Ok(_) => {}
                Err(error) if is_soft_recv_error(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::Protocol("peer dropped during barrier".to_owned()))
    }

    fn pump(&mut self, dur: Duration) {
        let end = Instant::now() + dur;
        while Instant::now() < end && !self.wire.dropped {
            match self.wire.recv(end) {
                Ok(NetworkMessage::GetData(items)) => {
                    self.record_getdata(&items);
                }
                Ok(NetworkMessage::Inv(items)) => {
                    for item in items {
                        let announced = match item {
                            Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                                Some(txid.to_string())
                            }
                            Inventory::WTx(wtxid) => Some(wtxid.to_string()),
                            _ => None,
                        };
                        if let Some(hash) = announced {
                            self.relayed_seen.push(hash.clone());
                            self.wire.log("relayed_inv", &hash);
                        }
                    }
                }
                Ok(NetworkMessage::GetHeaders(_)) => {
                    let _ = self.wire.send(NetworkMessage::Headers(Vec::new()), end);
                }
                Ok(NetworkMessage::Ping(nonce)) => {
                    let _ = self.wire.send(NetworkMessage::Pong(nonce), end);
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
        self.wire.log("getdata", &format!("{flat:?}"));
        self.getdata_seen.push(flat);
    }

    fn txid_requested(&self, txid: &str) -> bool {
        self.getdata_seen
            .iter()
            .flatten()
            .any(|(_, hash)| hash == txid)
    }

    fn relayed(&self, tx: &Transaction) -> bool {
        let txid = tx.compute_txid().to_string();
        let wtxid = tx.compute_wtxid().to_string();
        self.relayed_seen
            .iter()
            .any(|announced| announced == &txid || announced == &wtxid)
    }
}

fn now_unix() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

fn op_true_coinbase(height: u32, value: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

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

fn rpc(node: &mut ProcessNode, method: &str) -> Result<Value, Error> {
    node.rpc(method, &json!([]))
}

fn initial_block_download(node: &mut ProcessNode) -> bool {
    rpc(node, "getblockchaininfo")
        .ok()
        .and_then(|info| {
            info.get("initialblockdownload")
                .and_then(sonic_rs::JsonValueTrait::as_bool)
        })
        .unwrap_or(true)
}

fn mempool_size(node: &mut ProcessNode) -> Option<u64> {
    rpc(node, "getmempoolinfo")
        .ok()
        .and_then(|info| info.get("size").and_then(sonic_rs::JsonValueTrait::as_u64))
}

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
        if Instant::now() >= deadline || peer.wire.dropped {
            return false;
        }
    }
}

#[test]
fn ibd_node_ignores_then_requests_relay_transactions() -> Result<(), Error> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let mut peer = GatePeer::connect(&node, "gate")?;
    let mut bystander = GatePeer::connect(&node, "bystander")?;

    assert!(
        initial_block_download(&mut node),
        "a node with no applied tip must report initial block download"
    );

    let (blocks, funding) = build_funding_chain(now_unix().saturating_sub(3_600));
    let relayed = relayed_tx(&funding, 30_000);
    let txid = relayed.compute_txid();

    peer.announce_with_barrier(vec![Inventory::Transaction(txid)], 7_001)?;
    assert!(
        !peer.txid_requested(&txid.to_string()),
        "the node requested a transaction while in initial block download"
    );

    let deadline = Instant::now() + REQUEST_TIMEOUT;
    peer.wire
        .send(NetworkMessage::Tx(relayed.clone()), deadline)?;
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
            !bystander.relayed(&relayed),
            "the transaction was relayed to a bystander peer during initial block download"
        );
    }

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

    peer.announce_with_barrier(vec![Inventory::Transaction(txid)], 7_003)?;
    let request_deadline = Instant::now() + REQUEST_TIMEOUT;
    while !peer.txid_requested(&txid.to_string()) && Instant::now() < request_deadline {
        peer.pump(Duration::from_millis(100));
    }
    assert!(
        peer.txid_requested(&txid.to_string()),
        "after initial block download the announced transaction must be requested"
    );
    let body_deadline = Instant::now() + REQUEST_TIMEOUT;
    peer.wire.log("serve", "relayed tx body");
    peer.wire.send(NetworkMessage::Tx(relayed), body_deadline)?;
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
