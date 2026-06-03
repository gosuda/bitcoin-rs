//! Deterministic initial-sync proxy benchmark.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwapOption;
use bitcoin::absolute;
use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, transaction,
};
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_node::{
    BlockSync, Config, Network, NoOpZmqPublisher, apply::ApplyHandles, state::NodeState,
};
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::UtxoSet;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};
use tempfile::TempDir;

type TxIndexHandle = Arc<Mutex<Box<dyn IndexerLike>>>;
type TxIndexFixture = (Option<TxIndexHandle>, Option<TempDir>);

const PROXY_BLOCKS: u32 = 32;
const SYNC_PROXY_BLOCKS: u32 = 128;
const SYNC_PROXY_HEADER_HEIGHT: u32 = 4_096;
const SYNC_PROXY_BLOCKS_USIZE: usize = 128;
const SYNC_PROXY_START_HEIGHT: i32 = 4_096;

fn sync_pipeline_apply_proxy(c: &mut Criterion) {
    let blocks = proxy_blocks(PROXY_BLOCKS);
    print_proxy_summary(&blocks);

    c.bench_function("sync_pipeline_apply_proxy", |b| {
        b.iter_batched(
            open_regtest_state,
            |(_dir, state)| {
                for block in &blocks {
                    state
                        .apply_block(black_box(block))
                        .unwrap_or_else(|error| panic!("proxy apply failed: {error}"));
                }
                black_box(
                    state
                        .applied_tip()
                        .load_full()
                        .unwrap_or_else(|| panic!("proxy apply did not publish a tip"))
                        .height,
                );
            },
            BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "rocksdb")]
    c.bench_function("sync_pipeline_apply_proxy_pruned_rocksdb", |b| {
        b.iter_batched(
            open_pruned_regtest_state,
            |(_dir, state)| {
                for block in &blocks {
                    state
                        .apply_block(black_box(block))
                        .unwrap_or_else(|error| panic!("pruned proxy apply failed: {error}"));
                }
                let tip = state
                    .applied_tip()
                    .load_full()
                    .unwrap_or_else(|| panic!("pruned proxy apply did not publish a tip"));
                let record = state
                    .blocks()
                    .read()
                    .last()
                    .cloned()
                    .unwrap_or_else(|| panic!("pruned proxy apply did not publish a record"));
                assert!(
                    record.block_hex.is_empty(),
                    "pruned proxy should publish metadata-only block records"
                );
                black_box((tip.height, record.body_size));
            },
            BatchSize::SmallInput,
        );
    });
}

fn deterministic_initial_sync_proxy(c: &mut Criterion) {
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_pure_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::Disabled),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_indexed_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::Noop),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    #[cfg(feature = "rocksdb")]
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_txindex_rocksdb_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::RocksDb),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
}

fn print_proxy_summary(blocks: &[Block]) {
    let (_dir, state) = open_regtest_state();
    let started = Instant::now();
    for block in blocks {
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("proxy summary apply failed: {error}"));
    }
    let elapsed = started.elapsed();
    let applied_height = state
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("proxy summary did not publish a tip"))
        .height;
    let blocks_per_second = f64::from(applied_height.saturating_add(1)) / elapsed.as_secs_f64();
    let recorded_body_bytes: usize = state
        .blocks()
        .read()
        .iter()
        .map(|record| record.body_size)
        .sum();
    println!(
        "sync_pipeline_apply_proxy blocks={} elapsed={elapsed:?} blocks_per_second={blocks_per_second:.2} recorded_body_bytes={recorded_body_bytes}",
        applied_height.saturating_add(1),
    );
}

fn open_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    config.txindex = false;
    let state =
        NodeState::open(config).unwrap_or_else(|error| panic!("open node state failed: {error}"));
    (dir, state)
}

#[cfg(feature = "rocksdb")]
fn open_pruned_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    "rocksdb".clone_into(&mut config.storage_backend);
    config.txindex = false;
    config.prune_target_mb = 1;
    let state = NodeState::open(config)
        .unwrap_or_else(|error| panic!("open pruned node state failed: {error}"));
    (dir, state)
}

struct SyncFixture {
    sync: BlockSync,
    inbound_blocks_tx: crossbeam_channel::Sender<Block>,
    outbound_rx: crossbeam_channel::Receiver<Message>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    blocks: Vec<Block>,
    _tx_index_dir: Option<TempDir>,
}

#[derive(Clone, Copy)]
enum TxIndexMode {
    Disabled,
    Noop,
    #[cfg(feature = "rocksdb")]
    RocksDb,
}

impl SyncFixture {
    fn new(tx_index_mode: TxIndexMode) -> Self {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut tree = BlockTree::new();
        let genesis_id = tree
            .insert_node(None, genesis.header, NodeStatus::HeaderValid)
            .unwrap_or_else(|error| panic!("regtest genesis header insert failed: {error}"));
        let mut tip_id = genesis_id;
        let mut parent = genesis;
        let mut prev_hash = parent.block_hash();
        let mut header_time = parent.header.time;
        let mut blocks = Vec::with_capacity(SYNC_PROXY_BLOCKS_USIZE);

        for height in 1_u32..=SYNC_PROXY_HEADER_HEIGHT {
            let header = if height <= SYNC_PROXY_BLOCKS {
                let block = child_coinbase_block(&parent, height);
                parent = block.clone();
                prev_hash = block.block_hash();
                header_time = block.header.time;
                blocks.push(block.clone());
                block.header
            } else {
                header_time = header_time.saturating_add(1);
                let header = child_header(prev_hash, header_time);
                prev_hash = header.block_hash();
                header
            };
            tip_id = tree
                .insert_node(Some(tip_id), header, NodeStatus::HeaderValid)
                .unwrap_or_else(|error| panic!("synthetic header insert failed: {error}"));
        }

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<Header>>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<Block>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let (tx_index, tx_index_dir) = tx_index_for_mode(tx_index_mode);
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
            tx_index,
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peers),
            Arc::clone(&peer_outbound),
            inbound_headers_rx,
            inbound_blocks_rx,
        );

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
        peers.write().push(synthetic_peer(addr));
        let (outbound_tx, outbound_rx) = unbounded::<Message>();
        peer_outbound.write().insert(addr, outbound_tx);

        Self {
            sync,
            inbound_blocks_tx,
            outbound_rx,
            applied_tip,
            blocks,
            _tx_index_dir: tx_index_dir,
        }
    }

    fn run(self) -> u32 {
        self.sync.tick();
        let getdata_count = match self
            .outbound_rx
            .try_recv()
            .unwrap_or_else(|error| panic!("expected getdata: {error}"))
        {
            NetworkMessage::GetData(inventory) => inventory.len(),
            other => panic!("expected getdata, got {other:?}"),
        };
        assert_eq!(getdata_count, SYNC_PROXY_BLOCKS_USIZE);
        match self.outbound_rx.try_recv() {
            Ok(other) => panic!("expected no getheaders, got {other:?}"),
            Err(crossbeam_channel::TryRecvError::Empty) => {}
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                panic!("outbound channel disconnected")
            }
        }

        for block in self.blocks[1..].iter().rev() {
            self.inbound_blocks_tx
                .send(block.clone())
                .unwrap_or_else(|error| panic!("send staged block failed: {error}"));
        }
        self.sync.tick();
        self.inbound_blocks_tx
            .send(self.blocks[0].clone())
            .unwrap_or_else(|error| panic!("send contiguous block failed: {error}"));
        self.sync.tick();

        self.applied_tip
            .load_full()
            .unwrap_or_else(|| panic!("sync proxy did not publish applied tip"))
            .height
    }
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    tx_index: Option<Arc<Mutex<Box<dyn IndexerLike>>>>,
) -> ApplyHandles {
    ApplyHandles::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::new(UtxoSet::new()),
        Arc::new(CoinStatsListener::new(CoinStats::default())),
        tx_index,
        noop_filter_index(),
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(RwLock::new(HashMap::<Txid, Transaction>::new())),
        Arc::new(NoOpZmqPublisher),
    )
}

fn tx_index_for_mode(mode: TxIndexMode) -> TxIndexFixture {
    match mode {
        TxIndexMode::Disabled => (None, None),
        TxIndexMode::Noop => (Some(noop_tx_index()), None),
        #[cfg(feature = "rocksdb")]
        TxIndexMode::RocksDb => {
            let dir = tempfile::tempdir()
                .unwrap_or_else(|error| panic!("txindex tempdir failed: {error}"));
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open(dir.path())
                    .unwrap_or_else(|error| panic!("txindex rocksdb open failed: {error}")),
            );
            let indexer: Box<dyn IndexerLike> =
                Box::new(bitcoin_rs_index::Indexer::new(Arc::clone(&store)));
            (Some(Arc::new(Mutex::new(indexer))), Some(dir))
        }
    }
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
    fn wants_filters(&self) -> bool {
        false
    }

    fn put_filter(
        &self,
        _block_hash: Hash256,
        _prev_header: Hash256,
        _filter_bytes: &[u8],
    ) -> Result<Hash256, FilterIndexError> {
        Ok(Hash256::default())
    }

    fn filter_header(&self, _block_hash: Hash256) -> Result<Option<Hash256>, FilterIndexError> {
        Ok(None)
    }
}

fn noop_filter_index() -> Arc<Box<dyn FilterIndexLike>> {
    let filter_index: Box<dyn FilterIndexLike> = Box::new(NoopFilterIndex);
    Arc::new(filter_index)
}

fn synthetic_peer(addr: SocketAddr) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        services: 0,
        user_agent: "/bitcoin-rs-sync-bench:0.0.0/".to_owned(),
        start_height: SYNC_PROXY_START_HEIGHT,
        conn_time: 0,
        inbound: false,
    }
}

fn proxy_blocks(count: u32) -> Vec<Block> {
    let mut blocks = Vec::with_capacity(
        usize::try_from(count).unwrap_or_else(|error| panic!("invalid proxy count: {error}")),
    );
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..count {
        let block = child_coinbase_block(&parent, height);
        parent = block.clone();
        blocks.push(block);
    }
    blocks
}

fn child_coinbase_block(parent: &Block, height: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase_transaction(height)],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("proxy block should have merkle root"));
    mine_block_to_declared_target(&mut block);
    block
}

fn child_header(prev_blockhash: BlockHash, time: u32) -> Header {
    Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash,
        merkle_root: TxMerkleNode::all_zeros(),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    }
}

fn coinbase_transaction(height: u32) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn coinbase_script_sig(height: u32) -> ScriptBuf {
    let mut script = Vec::with_capacity(5);
    script.push(4);
    script.extend_from_slice(&height.to_le_bytes());
    ScriptBuf::from_bytes(script)
}

fn mine_block_to_declared_target(block: &mut Block) {
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .unwrap_or_else(|| panic!("exhausted nonce while mining proxy block"));
    }
}

criterion_group!(
    benches,
    sync_pipeline_apply_proxy,
    deterministic_initial_sync_proxy
);
criterion_main!(benches);
