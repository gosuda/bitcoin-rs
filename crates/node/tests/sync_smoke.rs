//! Block sync smoke tests.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{
    Amount, BlockHash, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute, transaction,
};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_node::{BlockSync, Config, Network, apply::ApplyHandles, state::NodeState};
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use bitcoin_rs_utxo::{UtxoChangeListener, UtxoSet};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
const CORE_EMPTY_MUHASH: &str = "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8";

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
fn tick_writes_g2_muhash_sample_for_applied_genesis() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let samples_path = temp.path().join("g2.samples");
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.storage_backend = "redb".to_owned();
    config.p2p_listen.clear();
    config.g2_muhash_samples = Some(samples_path.clone());
    config.g2_muhash_tip_height = Some(1);
    let state = NodeState::open(config)?;

    state.sync().tick();

    assert_eq!(
        std::fs::read_to_string(&samples_path)?,
        format!("0:{CORE_EMPTY_MUHASH}")
    );
    assert!(state.utxo().is_empty());
    assert_eq!(
        state
            .coin_stats()
            .snapshot()
            .muhash
            .finalize_hash()
            .to_string_be(),
        CORE_EMPTY_MUHASH
    );
    Ok(())
}

#[test]
fn node_state_open_rejects_g2_tip_height_without_sample_path()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("node");
    config.storage_backend = "redb".to_owned();
    config.p2p_listen.clear();
    config.g2_muhash_tip_height = Some(10_000);

    let Err(error) = NodeState::open(config) else {
        panic!("G2 tip height without sample path must fail");
    };

    assert!(
        error
            .to_string()
            .contains("g2_muhash_tip_height requires g2_muhash_samples")
    );
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
    let (handles, coin_stats) = apply_handles_with_coin_stats(
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
    inbound_blocks_tx.send(block_one.clone())?;

    sync.tick();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    assert_eq!(applied.height, 2);
    assert_eq!(
        applied.hash,
        bitcoin_rs_primitives::Hash256::from_le_bytes(block_two.block_hash().as_byte_array())
    );
    assert_eq!(
        coin_stats.snapshot(),
        expected_coin_stats(&[&genesis, &block_one, &block_two])?
    );
    assert_eq!(block_tree.read().len(), 3);
    Ok(())
}

#[test]
fn tick_applies_non_coinbase_spend_and_updates_utxo_and_coinstats()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = non_coinbase_spend_chain()?;
    let outcome = replay_non_coinbase_spend_chain(&fixture, true)?;

    assert_eq!(outcome.applied_height, 102);
    assert_eq!(
        outcome.applied_hash,
        bitcoin_rs_primitives::Hash256::from_le_bytes(
            fixture
                .blocks
                .last()
                .ok_or_else(|| std::io::Error::other("missing final block"))?
                .block_hash()
                .as_byte_array(),
        )
    );
    assert!(
        outcome
            .utxo
            .get(&primitive_outpoint(fixture.mature_coinbase_outpoint))
            .is_none(),
        "mature coinbase prevout must be removed by the height-101 spend",
    );
    assert!(
        outcome
            .utxo
            .get(&primitive_outpoint(fixture.funding_outpoint))
            .is_none(),
        "funding prevout must be removed by the height-102 spend",
    );
    assert!(
        outcome
            .utxo
            .get(&primitive_outpoint(fixture.spend_outpoint))
            .is_some(),
        "height-102 spend output must remain live",
    );

    let block_refs: Vec<&bitcoin::Block> = fixture.blocks.iter().collect();
    assert_eq!(
        outcome.coin_stats.snapshot(),
        expected_coin_stats(&block_refs)?
    );
    Ok(())
}

#[test]
#[ignore = "bounded local profiling harness; run explicitly with RUST_LOG=bitcoin_rs_node::apply=info"]
fn bounded_apply_profile_replay() -> Result<(), Box<dyn std::error::Error>> {
    let _subscriber_already_set = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .is_err();
    let fixture = non_coinbase_spend_chain()?;

    // This profiles apply path branch overhead, not storage-backed index cost.
    for use_noop_index_hooks in [false, true] {
        let label = if use_noop_index_hooks {
            "index_hooks=noop"
        } else {
            "index_hooks=disabled"
        };
        let outcome = replay_non_coinbase_spend_chain(&fixture, use_noop_index_hooks)?;
        println!(
            "bounded_apply_profile_replay {label} elapsed_ms={} applied_height={} blocks={}",
            elapsed_ms(outcome.elapsed),
            outcome.applied_height,
            fixture.blocks.len(),
        );
    }

    Ok(())
}

#[test]
#[ignore = "bounded local coinstats listener cost harness; run explicitly with RUST_LOG=bitcoin_rs_node::apply=info"]
fn bounded_apply_profile_replay_coinstats_listener_cost() -> Result<(), Box<dyn std::error::Error>>
{
    let _subscriber_already_set = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .is_err();
    let fixture = non_coinbase_spend_chain()?;

    for coin_stats_listener in [
        CoinStatsListenerMode::Attached,
        CoinStatsListenerMode::Detached,
    ] {
        let outcome = replay_non_coinbase_spend_chain_with_coin_stats_listener(
            &fixture,
            false,
            coin_stats_listener,
        )?;
        let listener_calls = outcome.listener_calls;
        println!(
            "bounded_apply_profile_replay_coinstats_listener_cost coin_stats_listener={} elapsed_ms={} applied_height={} blocks={} listener_insert_calls={} listener_remove_calls={} listener_remove_coin_calls={} listener_total_calls={}",
            coin_stats_listener.label(),
            elapsed_ms(outcome.elapsed),
            outcome.applied_height,
            fixture.blocks.len(),
            listener_calls.insert_calls,
            listener_calls.remove_calls,
            listener_calls.remove_coin_calls,
            listener_calls.total_calls(),
        );
    }

    Ok(())
}

#[cfg(feature = "redb")]
#[test]
#[ignore = "bounded local storage-backed optional-index cost harness; run explicitly"]
fn optional_index_redb_direct_cost() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let tx_store = bitcoin_rs_storage::RedbStore::open(temp.path().join("txindex"))?;
    let filter_store = bitcoin_rs_storage::RedbStore::open(temp.path().join("filters"))?;
    let mut tx_index = bitcoin_rs_index::Indexer::new(Arc::new(tx_store));
    let filter_index = bitcoin_rs_filters::FilterIndex::new(filter_store);
    let fixture = non_coinbase_spend_chain()?;

    let mut txids = 0_usize;
    let mut funding = 0_usize;
    let mut spending = 0_usize;
    let mut filter_bytes_len = 0_usize;
    let mut txindex_us = 0_u128;
    let mut filterindex_us = 0_u128;
    let mut prev_header = Hash256::default();
    let mut final_block_hash = None;

    for (height, block) in fixture.blocks.iter().enumerate() {
        let height = u32::try_from(height)?;
        let block_bytes = bitcoin::consensus::serialize(block);

        let started = Instant::now();
        let counts = tx_index.ingest_block(&block_bytes, height)?;
        txindex_us = txindex_us.saturating_add(started.elapsed().as_micros());
        txids = txids.saturating_add(counts.txids);
        funding = funding.saturating_add(counts.funding);
        spending = spending.saturating_add(counts.spending);

        let filter_bytes = deterministic_filter_bytes(block);
        filter_bytes_len = filter_bytes_len.saturating_add(filter_bytes.len());
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let started = Instant::now();
        prev_header = filter_index.put_filter(block_hash, prev_header, &filter_bytes)?;
        filterindex_us = filterindex_us.saturating_add(started.elapsed().as_micros());
        final_block_hash = Some(block_hash);
    }

    if txids == 0 || funding == 0 || spending == 0 || filter_bytes_len == 0 {
        return Err(std::io::Error::other(format!(
            "optional index direct cost no-op: txids={txids} funding={funding} spending={spending} filter_bytes={filter_bytes_len}",
        ))
        .into());
    }
    let final_block_hash = final_block_hash
        .ok_or_else(|| std::io::Error::other("missing final block hash after direct indexing"))?;
    let final_header = filter_index
        .filter_header(final_block_hash)?
        .ok_or_else(|| {
            std::io::Error::other("missing final filter header after direct indexing")
        })?;
    assert_eq!(final_header, prev_header);

    let total_us = txindex_us.saturating_add(filterindex_us);
    println!(
        "optional_index_redb_direct_cost blocks={} txids={} funding={} spending={} filter_bytes={} txindex_us={} filterindex_us={} total_us={}",
        fixture.blocks.len(),
        txids,
        funding,
        spending,
        filter_bytes_len,
        txindex_us,
        filterindex_us,
        total_us,
    );

    Ok(())
}

struct ReplayOutcome {
    elapsed: Duration,
    applied_height: u32,
    applied_hash: Hash256,
    coin_stats: Arc<CoinStatsListener>,
    listener_calls: ListenerCallCountSnapshot,
    utxo: Arc<UtxoSet>,
}

#[derive(Default)]
struct ListenerCallCounters {
    insert_calls: AtomicU64,
    remove_calls: AtomicU64,
    remove_coin_calls: AtomicU64,
}

impl ListenerCallCounters {
    fn snapshot(&self) -> ListenerCallCountSnapshot {
        ListenerCallCountSnapshot {
            insert_calls: self.insert_calls.load(Ordering::Relaxed),
            remove_calls: self.remove_calls.load(Ordering::Relaxed),
            remove_coin_calls: self.remove_coin_calls.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ListenerCallCountSnapshot {
    insert_calls: u64,
    remove_calls: u64,
    remove_coin_calls: u64,
}

impl ListenerCallCountSnapshot {
    const fn total_calls(self) -> u64 {
        self.insert_calls
            .saturating_add(self.remove_calls)
            .saturating_add(self.remove_coin_calls)
    }
}

struct CountingCoinStatsListener {
    inner: CoinStatsListener,
    counters: Arc<ListenerCallCounters>,
}

impl UtxoChangeListener for CountingCoinStatsListener {
    fn on_insert(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.counters.insert_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.on_insert(op, txout, height, coinbase);
    }

    fn on_remove(&self, op: &OutPoint, txout: &TxOut, height: u32) {
        self.counters.remove_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.on_remove(op, txout, height);
    }

    fn on_remove_coin(&self, op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) {
        self.counters
            .remove_coin_calls
            .fetch_add(1, Ordering::Relaxed);
        self.inner.on_remove_coin(op, txout, height, coinbase);
    }

    fn muhash3072(&self) -> Option<[u8; 384]> {
        self.inner.muhash3072()
    }
}

#[derive(Clone, Copy)]
enum CoinStatsListenerMode {
    Attached,
    Detached,
}

impl CoinStatsListenerMode {
    const fn label(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Detached => "detached",
        }
    }
}

fn replay_non_coinbase_spend_chain(
    fixture: &SpendChainFixture,
    use_noop_index_hooks: bool,
) -> Result<ReplayOutcome, Box<dyn std::error::Error>> {
    replay_non_coinbase_spend_chain_with_coin_stats_listener(
        fixture,
        use_noop_index_hooks,
        CoinStatsListenerMode::Attached,
    )
}

fn replay_non_coinbase_spend_chain_with_coin_stats_listener(
    fixture: &SpendChainFixture,
    use_noop_index_hooks: bool,
    coin_stats_listener: CoinStatsListenerMode,
) -> Result<ReplayOutcome, Box<dyn std::error::Error>> {
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<Vec<bitcoin::block::Header>>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin::Block>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let (mut handles, coin_stats, listener_calls, utxo) = apply_handles_with_coin_stats_and_utxo(
        Network::Regtest,
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
        coin_stats_listener,
    );
    if !use_noop_index_hooks {
        handles.tx_index = None;
        handles.filter_index = None;
    }
    let sync = BlockSync::new(
        handles,
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    inbound_headers_tx.send(fixture.blocks.iter().map(|block| block.header).collect())?;
    for block in fixture.blocks.iter().skip(1) {
        inbound_blocks_tx.send(block.clone())?;
    }

    let started = Instant::now();
    sync.tick();
    let elapsed = started.elapsed();

    let applied = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let expected_height = u32::try_from(
        fixture
            .blocks
            .len()
            .checked_sub(1)
            .ok_or_else(|| std::io::Error::other("empty replay fixture"))?,
    )?;
    let expected_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(
        fixture
            .blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing final block"))?
            .block_hash()
            .as_byte_array(),
    );
    if applied.height != expected_height || applied.hash != expected_hash {
        return Err(std::io::Error::other(format!(
            "replay stopped before final block: applied height/hash {}/{:?}, expected {}/{:?}",
            applied.height, applied.hash, expected_height, expected_hash,
        ))
        .into());
    }
    Ok(ReplayOutcome {
        elapsed,
        applied_height: applied.height,
        applied_hash: applied.hash,
        coin_stats,
        listener_calls: listener_calls.snapshot(),
        utxo,
    })
}

fn elapsed_ms(duration: Duration) -> u128 {
    duration.as_millis()
}

#[cfg(feature = "redb")]
fn deterministic_filter_bytes(block: &bitcoin::Block) -> Vec<u8> {
    let mut filter_bytes = Vec::with_capacity(block.txdata.len().saturating_mul(32));
    for tx in &block.txdata {
        filter_bytes.extend_from_slice(tx.compute_txid().as_byte_array());
    }
    filter_bytes
}

struct SpendChainFixture {
    blocks: Vec<bitcoin::Block>,
    mature_coinbase_outpoint: BitcoinOutPoint,
    funding_outpoint: BitcoinOutPoint,
    spend_outpoint: BitcoinOutPoint,
}

fn non_coinbase_spend_chain() -> Result<SpendChainFixture, Box<dyn std::error::Error>> {
    let mut blocks = vec![regtest_genesis_block()?];
    let spendable_script = op_true_script();
    for height in 1_u8..=100 {
        let parent = blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing chain parent"))?;
        blocks.push(child_coinbase_block_with_script(
            parent,
            height,
            spendable_script.clone(),
        )?);
    }

    let mature_coinbase_outpoint = BitcoinOutPoint {
        txid: blocks[1].txdata[0].compute_txid(),
        vout: 0,
    };
    let mature_coinbase_txout = blocks[1].txdata[0].output[0].clone();
    let funding_tx =
        spend_to_op_true(mature_coinbase_outpoint, mature_coinbase_txout.value, 1_000)?;
    let funding_outpoint = BitcoinOutPoint {
        txid: funding_tx.compute_txid(),
        vout: 0,
    };
    let funding_txout = funding_tx.output[0].clone();
    let funding_block = child_block_with_transactions(
        blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing funding parent"))?,
        101,
        vec![funding_tx],
    )?;
    blocks.push(funding_block);

    let spend_tx = spend_to_op_true(funding_outpoint, funding_txout.value, 1_000)?;
    let spend_outpoint = BitcoinOutPoint {
        txid: spend_tx.compute_txid(),
        vout: 0,
    };
    let spend_block = child_block_with_transactions(
        blocks
            .last()
            .ok_or_else(|| std::io::Error::other("missing spend parent"))?,
        102,
        vec![spend_tx],
    )?;
    blocks.push(spend_block);

    Ok(SpendChainFixture {
        blocks,
        mature_coinbase_outpoint,
        funding_outpoint,
        spend_outpoint,
    })
}

fn expected_coin_stats(
    blocks: &[&bitcoin::Block],
) -> Result<CoinStats, Box<dyn std::error::Error>> {
    let mut stats = CoinStats::default();
    let mut live_outputs = HashMap::<OutPoint, (TxOut, u32, bool)>::new();
    for (height, block) in blocks.iter().enumerate() {
        let height = u32::try_from(height)?;
        if height == 0 {
            stats.finish_block(height, u64::try_from(block.txdata.len())?);
            continue;
        }
        for tx in &block.txdata {
            let txid = Hash256::from_le_bytes(tx.compute_txid().as_byte_array());
            for (vout, txout) in tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(txid, u32::try_from(vout)?);
                stats.insert_utxo(&outpoint, txout, height, tx.is_coinbase());
                live_outputs.insert(outpoint, (txout.clone(), height, tx.is_coinbase()));
            }
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.input {
                let outpoint = primitive_outpoint(input.previous_output);
                let Some((txout, output_height, coinbase)) = live_outputs.remove(&outpoint) else {
                    return Err(std::io::Error::other(format!(
                        "missing expected prevout {outpoint:?}"
                    ))
                    .into());
                };
                stats.remove_utxo(&outpoint, &txout, output_height, coinbase);
            }
        }
        stats.finish_block(height, u64::try_from(block.txdata.len())?);
    }
    Ok(stats)
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    network: Network,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> ApplyHandles {
    apply_handles_with_coin_stats(network, chain_tip, applied_tip, block_tree).0
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles_with_coin_stats(
    network: Network,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> (ApplyHandles, Arc<CoinStatsListener>) {
    let (handles, coin_stats, _listener_calls, _utxo) = apply_handles_with_coin_stats_and_utxo(
        network,
        chain_tip,
        applied_tip,
        block_tree,
        CoinStatsListenerMode::Attached,
    );
    (handles, coin_stats)
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles_with_coin_stats_and_utxo(
    network: Network,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    coin_stats_listener: CoinStatsListenerMode,
) -> (
    ApplyHandles,
    Arc<CoinStatsListener>,
    Arc<ListenerCallCounters>,
    Arc<UtxoSet>,
) {
    let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let listener_calls = Arc::new(ListenerCallCounters::default());
    let mut utxo = UtxoSet::new();
    if matches!(coin_stats_listener, CoinStatsListenerMode::Attached) {
        utxo.set_listener(Box::new(CountingCoinStatsListener {
            inner: (*coin_stats).clone(),
            counters: Arc::clone(&listener_calls),
        }));
    }
    let utxo = Arc::new(utxo);
    let handles = ApplyHandles::new(
        network,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::clone(&utxo),
        Arc::clone(&coin_stats),
        Some(noop_tx_index()),
        Some(noop_filter_index()),
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(RwLock::new(HashMap::<Txid, Transaction>::new())),
        Arc::new(bitcoin_rs_node::NoOpZmqPublisher),
    );
    (handles, coin_stats, listener_calls, utxo)
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
    child_coinbase_block_with_script(
        parent,
        height,
        parent.txdata[0].output[0].script_pubkey.clone(),
    )
}

fn child_coinbase_block_with_script(
    parent: &bitcoin::Block,
    height: u8,
    script_pubkey: ScriptBuf,
) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
    let mut block = parent.clone();
    block.header.prev_blockhash = parent.block_hash();
    block.header.time = parent.header.time.saturating_add(1);
    block.txdata.truncate(1);
    block.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![1, height]);
    block.txdata[0].output[0].script_pubkey = script_pubkey;
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

fn child_block_with_transactions(
    parent: &bitcoin::Block,
    height: u8,
    transactions: Vec<Transaction>,
) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
    let mut block = child_coinbase_block(parent, height)?;
    block.txdata.extend(transactions);
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

fn spend_to_op_true(
    previous_output: BitcoinOutPoint,
    previous_value: Amount,
    fee: u64,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let value = previous_value
        .to_sat()
        .checked_sub(fee)
        .ok_or_else(|| std::io::Error::other("spend fee exceeds previous output value"))?;
    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: op_true_script(),
        }],
    })
}

fn op_true_script() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn primitive_outpoint(outpoint: BitcoinOutPoint) -> OutPoint {
    OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
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
