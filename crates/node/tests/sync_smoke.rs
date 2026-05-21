//! Block sync smoke tests.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{BlockHash, Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_node::{BlockSync, Network, apply::ApplyHandles};
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

#[test]
fn tick_sends_getheaders_to_best_peer_above_our_height() -> Result<(), Box<dyn std::error::Error>> {
    let chain_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<bitcoin::block::Header>>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    sync.tick();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    peers.write().push(synthetic_peer(addr, 100));
    let (tx, rx) = unbounded::<Message>();
    peer_outbound.write().insert(addr, tx);

    sync.tick();

    let received = rx.try_recv()?;
    let NetworkMessage::GetHeaders(getheaders) = received else {
        panic!("expected getheaders");
    };
    let genesis_hash =
        BlockHash::from_byte_array(Network::Regtest.genesis_block_hash().to_le_bytes());
    assert_eq!(getheaders.locator_hashes.len(), 1);
    assert_eq!(getheaders.locator_hashes.first(), Some(&genesis_hash));
    assert_eq!(getheaders.stop_hash, BlockHash::all_zeros());
    Ok(())
}

#[test]
fn tick_uses_applied_tip_height_when_selecting_sync_peer() {
    let chain_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> =
        Arc::new(ArcSwapOption::from_pointee(TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(0),
            height: 100,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash: Network::Regtest.genesis_block_hash(),
        }));
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<bitcoin::block::Header>>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    peers.write().push(synthetic_peer(addr, 50));
    let (tx, rx) = unbounded::<Message>();
    peer_outbound.write().insert(addr, tx);

    sync.tick();

    assert!(
        rx.try_recv().is_err(),
        "peer below applied tip height must not be selected"
    );
}

#[test]
fn tick_applies_inbound_blocks_before_sync_selection() -> Result<(), Box<dyn std::error::Error>> {
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<bitcoin::block::Header>>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_blocks_tx.send(regtest_genesis_block()?)?;
    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.height, 0);
    assert_eq!(applied.hash, Network::Regtest.genesis_block_hash());
    assert_eq!(block_tree.read().len(), 1);
    Ok(())
}

#[test]
fn tick_buffers_out_of_order_blocks_until_parent_arrives() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = regtest_genesis_block()?;
    let block_one = child_coinbase_block(&genesis, 1)?;
    let block_two = child_coinbase_block(&block_one, 2)?;

    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<bitcoin::block::Header>>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_headers_tx.send(vec![genesis.header, block_one.header, block_two.header])?;
    inbound_blocks_tx.send(block_two.clone())?;
    inbound_blocks_tx.send(block_one)?;

    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.height, 2);
    assert_eq!(
        applied.hash,
        bitcoin_rs_primitives::Hash256::from_le_bytes(block_two.block_hash().as_byte_array())
    );
    assert_eq!(block_tree.read().len(), 3);
    Ok(())
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    network: Network,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> ApplyHandles {
    ApplyHandles::new(
        network,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::new(UtxoSet::new()),
        Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
            bitcoin_rs_coinstats::CoinStats::default(),
        )),
        noop_tx_index(),
        noop_filter_index(),
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(RwLock::new(HashMap::<Txid, Transaction>::new())),
        Arc::new(bitcoin_rs_node::NoOpZmqPublisher),
    )
}

struct NoopIndexer;

impl IndexerLike for NoopIndexer {
    fn ingest_block(&mut self, _block: &[u8], _height: u32) -> Result<IndexRowCounts, IndexError> {
        Ok(IndexRowCounts::default())
    }

    fn resolve_outpoint_value(
        &self,
        _outpoint: bitcoin::OutPoint,
        _source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError> {
        Ok(None)
    }
}

fn noop_tx_index() -> Arc<Mutex<Box<dyn IndexerLike>>> {
    let indexer: Box<dyn IndexerLike> = Box::new(NoopIndexer);
    Arc::new(Mutex::new(indexer))
}

struct NoopFilterIndex;

impl FilterIndexLike for NoopFilterIndex {
    fn put_filter(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
        _prev_header: bitcoin_rs_primitives::Hash256,
        _filter_bytes: &[u8],
    ) -> Result<bitcoin_rs_primitives::Hash256, FilterIndexError> {
        Ok(bitcoin_rs_primitives::Hash256::default())
    }

    fn filter_header(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<bitcoin_rs_primitives::Hash256>, FilterIndexError> {
        Ok(None)
    }
}

fn noop_filter_index() -> Arc<Box<dyn FilterIndexLike>> {
    let filter_index: Box<dyn FilterIndexLike> = Box::new(NoopFilterIndex);
    Arc::new(filter_index)
}

fn regtest_genesis_block() -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
    use bitcoin::consensus::Decodable as _;

    let bytes = hex_decode(REGTEST_GENESIS_HEX)?;
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    Ok(bitcoin::Block::consensus_decode(&mut cursor)?)
}

fn child_coinbase_block(
    parent: &bitcoin::Block,
    height: u8,
) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
    let mut block = parent.clone();
    block.header.prev_blockhash = parent.block_hash();
    block.header.time = parent.header.time.saturating_add(1);
    block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, height]);
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

fn mine_block_to_declared_target(
    block: &mut bitcoin::Block,
) -> Result<(), Box<dyn std::error::Error>> {
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("exhausted nonce while mining test block"))?;
    }
    Ok(())
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut chunks = hex.as_bytes().chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "odd hex length").into());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in &mut chunks {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, Box<dyn std::error::Error>> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex digit").into()),
    }
}

fn synthetic_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        services: 0,
        user_agent: String::from("/test/"),
        start_height,
        conn_time: 0,
        inbound: true,
    }
}
