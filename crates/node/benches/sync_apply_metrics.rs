//! Metrics-enabled apply-path diagnostic for deterministic sync proxy blocks.
//!
//! This target intentionally runs outside `sync_pipeline` so installing the
//! in-memory metrics recorder cannot contaminate Criterion timing baselines.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bitcoin::absolute;
use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, transaction,
};
use bitcoin_rs_chain::{BlockTree, NodeStatus};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_node::{
    Config, Network,
    metrics::{MetricValue, MetricsHandle, install_metrics},
    state::NodeState,
};
use bitcoin_rs_p2p::{Message, PeerInfo};
use bitcoin_rs_primitives::{Hash256, OutPoint as PrimitiveOutPoint};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::RwLock;
use tempfile::TempDir;

const COINBASE_PROXY_BLOCKS: u32 = 32;
const PRODUCTION_PROXY_BLOCKS: u32 = 128;
const SYNC_PROXY_HEADER_HEIGHT: u32 = 4_096;
const SYNC_PROXY_START_HEIGHT: i32 = 4_096;
const SPEND_PROXY_COINBASE_MATURITY: u32 = 100;
const SPEND_PROXY_SPEND_BLOCKS: u32 = 16;
const SPEND_PROXY_FANOUT: u32 = 64;
const SPEND_PROXY_COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_PROXY_SPEND_OUTPUT_VALUE: u64 = 78_124_999;
const SYNC_APPLY_BUFFERED_METRIC: &str = "node.sync.apply_buffered_blocks_seconds";
const APPLY_TOTAL_METRIC: &str = "node.apply_block.total_seconds";
const APPLY_STAGE_METRICS: &[(&str, &str)] = &[
    (
        "pow_self_consistency",
        "node.apply_block.pow_self_consistency_seconds",
    ),
    ("block_rules", "node.apply_block.block_rules_seconds"),
    ("bip30_bip34", "node.apply_block.bip30_bip34_seconds"),
    (
        "pow_limit_continuity",
        "node.apply_block.pow_limit_continuity_seconds",
    ),
    ("bip113", "node.apply_block.bip113_seconds"),
    ("script_verify", "node.apply_block.script_verify_seconds"),
    (
        "coinbase_maturity",
        "node.apply_block.coinbase_maturity_seconds",
    ),
    ("bip68", "node.apply_block.bip68_seconds"),
    ("utxo_changes", "node.apply_block.utxo_changes_seconds"),
    (
        "block_body_persist",
        "node.apply_block.block_body_persist_seconds",
    ),
    (
        "tx_index_ingest",
        "node.apply_block.tx_index_ingest_seconds",
    ),
    ("utxo_commit", "node.apply_block.utxo_commit_seconds"),
    (
        "utxo_listener_event_batches",
        "node.utxo.listener.event_batches_seconds",
    ),
    ("utxo_listener_replay", "node.utxo.listener.replay_seconds"),
    (
        "block_tree_insert",
        "node.apply_block.block_tree_insert_seconds",
    ),
    ("block_record", "node.apply_block.block_record_seconds"),
    ("mempool_evict", "node.apply_block.mempool_evict_seconds"),
    (
        "coin_stats_finish",
        "node.apply_block.coin_stats_finish_seconds",
    ),
    ("filter_build", "node.apply_block.filter_build_seconds"),
    ("filter_index", "node.apply_block.filter_index_seconds"),
    ("total", "node.apply_block.total_seconds"),
];

fn main() {
    let metrics = install_diagnostic_metrics();
    print_utxo_fanout_commit_metrics("utxo_fanout_128_no_listener", false);
    print_utxo_fanout_commit_metrics("utxo_fanout_128_listener", true);
    print_utxo_block_commit_metrics(
        "utxo_spend_heavy_117_no_listener",
        &spend_heavy_proxy_blocks(),
        false,
    );
    print_utxo_block_commit_metrics(
        "utxo_spend_heavy_117_listener",
        &spend_heavy_proxy_blocks(),
        true,
    );
    print_apply_metrics(
        "coinbase_32",
        &proxy_blocks(COINBASE_PROXY_BLOCKS),
        false,
        false,
        &metrics,
    );
    print_apply_metrics(
        "coinbase_128",
        &proxy_blocks(PRODUCTION_PROXY_BLOCKS),
        false,
        false,
        &metrics,
    );
    print_apply_metrics(
        "fanout_128",
        &fanout_proxy_blocks(PRODUCTION_PROXY_BLOCKS),
        false,
        false,
        &metrics,
    );
    print_apply_metrics(
        "fanout_128_txindex",
        &fanout_proxy_blocks(PRODUCTION_PROXY_BLOCKS),
        true,
        false,
        &metrics,
    );
    print_apply_metrics(
        "fanout_128_filter",
        &fanout_proxy_blocks(PRODUCTION_PROXY_BLOCKS),
        false,
        true,
        &metrics,
    );
    print_apply_metrics(
        "fanout_128_all_indexes",
        &fanout_proxy_blocks(PRODUCTION_PROXY_BLOCKS),
        true,
        true,
        &metrics,
    );
    print_apply_metrics(
        "spend_heavy_117",
        &spend_heavy_proxy_blocks(),
        false,
        false,
        &metrics,
    );
    print_apply_metrics(
        "spend_heavy_117_filter",
        &spend_heavy_proxy_blocks(),
        false,
        true,
        &metrics,
    );
    print_apply_metrics(
        "spend_heavy_117_txindex",
        &spend_heavy_proxy_blocks(),
        true,
        false,
        &metrics,
    );
    print_apply_metrics(
        "spend_heavy_117_all_indexes",
        &spend_heavy_proxy_blocks(),
        true,
        true,
        &metrics,
    );
    print_staged_sync_apply_metrics(
        "staged_fjall_all_indexes_apply_tick_128_blocks",
        StagedSyncApplyKind::Contiguous,
        &metrics,
    );
    print_staged_sync_apply_metrics(
        "staged_fjall_all_indexes_partial_apply_tick_128_blocks",
        StagedSyncApplyKind::PartialCached,
        &metrics,
    );
}

fn print_utxo_block_commit_metrics(name: &str, blocks: &[Block], with_listener: bool) {
    let commit_inputs: Vec<_> = blocks
        .iter()
        .enumerate()
        .map(|(height, block)| {
            let height =
                u32::try_from(height).unwrap_or_else(|error| panic!("invalid height: {error}"));
            (height_hash(height), block_utxo_changes(block, height))
        })
        .collect();
    let mut set = UtxoSet::new();
    if with_listener {
        set.set_listener(Box::new(CoinStatsListener::new(CoinStats::new())));
    }
    let started = Instant::now();
    for (block_hash, changes) in &commit_inputs {
        set.commit_block(changes, block_hash)
            .unwrap_or_else(|error| panic!("{name} commit failed: {error}"));
    }
    let elapsed = started.elapsed();
    let commit_count = f64::from(
        u32::try_from(commit_inputs.len())
            .unwrap_or_else(|error| panic!("invalid commit count: {error}")),
    );
    let commits_per_second = commit_count / elapsed.as_secs_f64();
    let avg_commit_ms = (elapsed.as_secs_f64() / commit_count) * 1_000.0;
    println!(
        "utxo_commit_metrics workload={name} listener={with_listener} commits={} elapsed={elapsed:?} commits_per_second={commits_per_second:.2} avg_commit_ms={avg_commit_ms:.4}",
        commit_inputs.len(),
    );
}

fn print_utxo_fanout_commit_metrics(name: &str, with_listener: bool) {
    let mut set = UtxoSet::new();
    if with_listener {
        set.set_listener(Box::new(CoinStatsListener::new(CoinStats::new())));
    }
    let started = Instant::now();
    for height in 1..=PRODUCTION_PROXY_BLOCKS {
        let changes = fanout_utxo_changes(height);
        set.commit_block(&changes, &height_hash(height))
            .unwrap_or_else(|error| panic!("{name} commit failed at height {height}: {error}"));
    }
    let elapsed = started.elapsed();
    let commit_count = f64::from(PRODUCTION_PROXY_BLOCKS);
    let commits_per_second = commit_count / elapsed.as_secs_f64();
    let avg_commit_ms = (elapsed.as_secs_f64() / commit_count) * 1_000.0;
    println!(
        "utxo_commit_metrics workload={name} listener={with_listener} commits={PRODUCTION_PROXY_BLOCKS} elapsed={elapsed:?} commits_per_second={commits_per_second:.2} avg_commit_ms={avg_commit_ms:.4}",
    );
}

fn install_diagnostic_metrics() -> MetricsHandle {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    install_metrics(Some(bind))
        .unwrap_or_else(|error| panic!("install metrics recorder failed: {error}"))
        .unwrap_or_else(|| panic!("metrics recorder was not installed"))
}

fn print_apply_metrics(
    name: &str,
    blocks: &[Block],
    txindex: bool,
    blockfilterindex: bool,
    metrics: &MetricsHandle,
) {
    let before = metrics.snapshot();
    let backend = storage_backend();
    let (_dir, state) = open_regtest_state(backend, txindex, blockfilterindex);
    let started = Instant::now();
    for block in blocks {
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("{name} apply failed: {error}"));
    }
    let elapsed = started.elapsed();
    let after = metrics.snapshot();
    let height = state
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("{name} did not publish applied tip"))
        .height;
    let block_count = height.saturating_add(1);
    let blocks_per_second = f64::from(block_count) / elapsed.as_secs_f64();
    let recorded_body_bytes: usize = state
        .blocks()
        .read()
        .iter()
        .map(|record| record.body_size)
        .sum();
    println!(
        "sync_apply_metrics backend={backend} workload={name} txindex={txindex} blockfilterindex={blockfilterindex} blocks={block_count} elapsed={elapsed:?} blocks_per_second={blocks_per_second:.2} recorded_body_bytes={recorded_body_bytes} selected_apply_stage_metrics={} {}",
        APPLY_STAGE_METRICS.len(),
        apply_stage_sum_summary(&before, &after),
    );
}

#[derive(Clone, Copy)]
enum StagedSyncApplyKind {
    Contiguous,
    PartialCached,
}

fn print_staged_sync_apply_metrics(name: &str, kind: StagedSyncApplyKind, metrics: &MetricsHandle) {
    let fixture = match kind {
        StagedSyncApplyKind::Contiguous => {
            StagedSyncApplyFixture::new_fjall_all_indexes().stage_for_contiguous_apply()
        }
        StagedSyncApplyKind::PartialCached => {
            StagedSyncApplyFixture::new_fjall_all_indexes().stage_for_partial_cached_apply()
        }
    };
    let before = metrics.snapshot();
    let started = Instant::now();
    let height = fixture.apply_staged();
    let elapsed = started.elapsed();
    let after = metrics.snapshot();
    let block_count = height.saturating_add(1);
    let blocks_per_second = f64::from(block_count) / elapsed.as_secs_f64();
    let sync_apply = required_histogram_delta_ms(
        &before,
        &after,
        SYNC_APPLY_BUFFERED_METRIC,
        "sync apply buffered",
    );
    let apply_total =
        required_histogram_delta_ms(&before, &after, APPLY_TOTAL_METRIC, "apply total");
    let sync_wrapper_gap_ms = sync_apply.sum_ms - apply_total.sum_ms;
    println!(
        "staged_sync_apply_metrics backend=fjall workload={name} txindex=true blockfilterindex=true blocks={block_count} elapsed={elapsed:?} blocks_per_second={blocks_per_second:.2} sync_apply_buffered_samples={} sync_apply_buffered_sum_ms={:.4} sync_apply_buffered_avg_ms={:.4} apply_total_samples={} apply_total_sum_ms={:.4} apply_total_avg_ms={:.4} sync_wrapper_gap_ms={sync_wrapper_gap_ms:.4} selected_apply_stage_metrics={} {}",
        sync_apply.count,
        sync_apply.sum_ms,
        sync_apply.avg_ms,
        apply_total.count,
        apply_total.sum_ms,
        apply_total.avg_ms,
        APPLY_STAGE_METRICS.len(),
        apply_stage_sum_summary(&before, &after),
    );
}

struct StagedSyncApplyFixture {
    _dir: TempDir,
    state: NodeState,
    outbound_rxs: Vec<crossbeam_channel::Receiver<Message>>,
    blocks: Vec<Block>,
}

impl StagedSyncApplyFixture {
    fn new_fjall_all_indexes() -> Self {
        let mut config = production_state_config();
        "fjall".clone_into(&mut config.storage_backend);
        config.txindex = true;
        config.blockfilterindex = true;
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        config.data_dir = dir.path().join("node");
        let state = NodeState::open(config)
            .unwrap_or_else(|error| panic!("open staged sync state failed: {error}"));
        let blocks = {
            let block_tree = state.block_tree();
            let mut tree = block_tree.write();
            populate_sync_header_chain(&mut tree, PRODUCTION_PROXY_BLOCKS)
        };
        let outbound_rxs = install_synthetic_peers(&state.peers(), &state.peer_outbound());
        Self {
            _dir: dir,
            state,
            outbound_rxs,
            blocks,
        }
    }

    fn stage_for_contiguous_apply(self) -> Self {
        let sync = self.state.sync();
        sync.tick();
        self.assert_getdata_batch();
        let inbound_blocks_tx = self.state.inbound_blocks_sender();
        for block in self.blocks[1..].iter().rev() {
            inbound_blocks_tx
                .send(block.clone())
                .unwrap_or_else(|error| panic!("send production staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(self.blocks[0].clone())
            .unwrap_or_else(|error| panic!("send production contiguous block failed: {error}"));
        self
    }

    fn stage_for_partial_cached_apply(self) -> Self {
        let split = self.blocks.len() / 2;
        let sync = self.state.sync();
        sync.tick();
        self.assert_getdata_batch();
        let inbound_blocks_tx = self.state.inbound_blocks_sender();

        for block in self.blocks[1..split].iter().rev() {
            inbound_blocks_tx
                .send(block.clone())
                .unwrap_or_else(|error| panic!("send first partial staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(self.blocks[0].clone())
            .unwrap_or_else(|error| panic!("send first partial contiguous block failed: {error}"));
        sync.tick();

        for block in self.blocks[split + 1..].iter().rev() {
            inbound_blocks_tx
                .send(block.clone())
                .unwrap_or_else(|error| panic!("send second partial staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(self.blocks[split].clone())
            .unwrap_or_else(|error| panic!("send second partial contiguous block failed: {error}"));
        self
    }

    fn apply_staged(self) -> u32 {
        self.state.sync().tick();
        self.state
            .applied_tip()
            .load_full()
            .unwrap_or_else(|| panic!("staged sync proxy did not publish applied tip"))
            .height
    }

    fn assert_getdata_batch(&self) {
        let getdata_count = match self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"))
            .try_recv()
            .unwrap_or_else(|error| panic!("expected production getdata: {error}"))
        {
            NetworkMessage::GetData(inventory) => inventory.len(),
            other => panic!("expected production getdata, got {other:?}"),
        };
        assert_eq!(getdata_count, self.blocks.len());
    }
}

fn storage_backend() -> &'static str {
    match std::env::var("BITCOIN_RS_SYNC_APPLY_BACKEND") {
        Ok(backend) if backend == "fjall" => "fjall",
        Ok(backend) if backend == "redb" => "redb",
        Ok(backend) if backend == "mdbx" => "mdbx",
        Ok(backend) if backend == "rocksdb" => "rocksdb",
        Ok(backend) => panic!("unsupported BITCOIN_RS_SYNC_APPLY_BACKEND={backend}"),
        Err(_) => "fjall",
    }
}

fn production_state_config() -> Config {
    let mut config = Config::default_for_network(Network::Regtest);
    config.p2p_listen.clear();
    config.txindex = false;
    config.blockfilterindex = false;
    config
}

fn open_regtest_state(
    backend: &str,
    txindex: bool,
    blockfilterindex: bool,
) -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    backend.clone_into(&mut config.storage_backend);
    config.p2p_listen.clear();
    config.txindex = txindex;
    config.blockfilterindex = blockfilterindex;
    let state =
        NodeState::open(config).unwrap_or_else(|error| panic!("open node state failed: {error}"));
    (dir, state)
}

fn apply_stage_sum_summary(
    before: &HashMap<String, MetricValue>,
    after: &HashMap<String, MetricValue>,
) -> String {
    let mut summary = String::new();
    for (label, metric) in APPLY_STAGE_METRICS {
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(label);
        if let Some(delta) = histogram_delta_stats_ms(before, after, metric) {
            write!(
                &mut summary,
                "_samples={} {label}_sum_ms={:.4} {label}_avg_ms={:.4}",
                delta.count, delta.sum_ms, delta.avg_ms,
            )
            .unwrap_or_else(|error| panic!("format apply stage summary failed: {error}"));
        } else {
            summary.push_str("_samples=0 ");
            summary.push_str(label);
            summary.push_str("_sum_ms=missing ");
            summary.push_str(label);
            summary.push_str("_avg_ms=missing");
        }
    }
    summary
}

#[derive(Clone, Copy)]
struct HistogramDelta {
    count: u64,
    sum_ms: f64,
    avg_ms: f64,
}

fn required_histogram_delta_ms(
    before: &HashMap<String, MetricValue>,
    after: &HashMap<String, MetricValue>,
    metric: &str,
    label: &str,
) -> HistogramDelta {
    histogram_delta_stats_ms(before, after, metric)
        .unwrap_or_else(|| panic!("missing {label} histogram delta for {metric}"))
}

fn histogram_delta_stats_ms(
    before: &HashMap<String, MetricValue>,
    after: &HashMap<String, MetricValue>,
    metric: &str,
) -> Option<HistogramDelta> {
    let (after_count, after_sum) = histogram_parts(after.get(metric)?)?;
    let (before_count, before_sum) = before
        .get(metric)
        .and_then(histogram_parts)
        .unwrap_or((0, 0.0));
    let count = after_count.saturating_sub(before_count);
    (count > 0).then(|| {
        let sum_ms = (after_sum - before_sum) * 1_000.0;
        HistogramDelta {
            count,
            sum_ms,
            avg_ms: sum_ms / metric_sample_count(count),
        }
    })
}

fn histogram_parts(value: &MetricValue) -> Option<(u64, f64)> {
    match value {
        MetricValue::Histogram { count, sum } => Some((*count, *sum)),
        MetricValue::Counter(_) | MetricValue::Gauge(_) => None,
    }
}

fn metric_sample_count(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
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

fn populate_sync_header_chain(tree: &mut BlockTree, body_blocks: u32) -> Vec<Block> {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let genesis_id = tree
        .insert_node(None, genesis.header, NodeStatus::HeaderValid)
        .unwrap_or_else(|error| panic!("regtest genesis header insert failed: {error}"));
    let mut tip_id = genesis_id;
    let mut parent = genesis;
    let mut prev_hash = parent.block_hash();
    let mut header_time = parent.header.time;
    let block_capacity =
        usize::try_from(body_blocks).unwrap_or_else(|error| panic!("invalid body count: {error}"));
    let mut blocks = Vec::with_capacity(block_capacity);

    for height in 1_u32..=SYNC_PROXY_HEADER_HEIGHT {
        let header = if height <= body_blocks {
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
    blocks
}

fn fanout_proxy_blocks(count: u32) -> Vec<Block> {
    let mut blocks = Vec::with_capacity(
        usize::try_from(count).unwrap_or_else(|error| panic!("invalid fanout count: {error}")),
    );
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..count {
        let block = child_fanout_coinbase_block(&parent, height);
        parent = block.clone();
        blocks.push(block);
    }
    blocks
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

fn install_synthetic_peers(
    peers: &Arc<RwLock<Vec<PeerInfo>>>,
    peer_outbound: &Arc<RwLock<HashMap<SocketAddr, crossbeam_channel::Sender<Message>>>>,
) -> Vec<crossbeam_channel::Receiver<Message>> {
    let mut peers = peers.write();
    let mut peer_outbound = peer_outbound.write();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8_333);
    let (outbound_tx, outbound_rx) = unbounded::<Message>();
    peers.push(synthetic_peer(addr));
    peer_outbound.insert(addr, outbound_tx);
    vec![outbound_rx]
}

fn synthetic_peer(addr: SocketAddr) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        services: 0,
        user_agent: "/bitcoin-rs-sync-apply-metrics:0.0.0/".to_owned(),
        start_height: SYNC_PROXY_START_HEIGHT,
        conn_time: 0,
        inbound: false,
    }
}

fn fanout_utxo_changes(height: u32) -> BlockChanges {
    let transaction = fanout_coinbase_transaction(height);
    let txid = transaction.compute_txid();
    let mut changes = BlockChanges::default();
    for (vout, txout) in transaction.output.iter().enumerate() {
        let vout = u32::try_from(vout).unwrap_or_else(|error| panic!("invalid vout: {error}"));
        changes.add(UtxoAdd::new(
            PrimitiveOutPoint::new(Hash256::from_le_bytes(&txid.to_byte_array()), vout),
            txout.clone(),
            true,
            height,
        ));
    }
    changes
}

fn block_utxo_changes(block: &Block, height: u32) -> BlockChanges {
    let mut changes = BlockChanges::default();
    for transaction in &block.txdata {
        let coinbase = transaction.is_coinbase();
        if !coinbase {
            for input in &transaction.input {
                changes.remove(primitive_outpoint(input.previous_output));
            }
        }
        let txid = transaction.compute_txid();
        let txid = Hash256::from_le_bytes(&txid.to_byte_array());
        for (vout, txout) in transaction.output.iter().enumerate() {
            let vout = u32::try_from(vout).unwrap_or_else(|error| panic!("invalid vout: {error}"));
            changes.add(UtxoAdd::new(
                PrimitiveOutPoint::new(txid, vout),
                txout.clone(),
                coinbase,
                height,
            ));
        }
    }
    changes
}

fn primitive_outpoint(outpoint: OutPoint) -> PrimitiveOutPoint {
    PrimitiveOutPoint::new(
        Hash256::from_le_bytes(&outpoint.txid.to_byte_array()),
        outpoint.vout,
    )
}

fn height_hash(height: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&height.to_le_bytes());
    bytes[4..8].copy_from_slice(&height.rotate_left(13).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn spend_heavy_proxy_blocks() -> Vec<Block> {
    let spend_start_height = SPEND_PROXY_COINBASE_MATURITY.saturating_add(1);
    let spend_end_height = spend_start_height
        .saturating_add(SPEND_PROXY_SPEND_BLOCKS)
        .saturating_sub(1);
    let capacity = usize::try_from(spend_end_height.saturating_add(1))
        .unwrap_or_else(|error| panic!("invalid spend proxy capacity: {error}"));
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut blocks = Vec::with_capacity(capacity);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..=spend_end_height {
        let block = if height < spend_start_height {
            child_fanout_coinbase_block(&parent, height)
        } else {
            let source_height = height.saturating_sub(SPEND_PROXY_COINBASE_MATURITY);
            let source_index = usize::try_from(source_height)
                .unwrap_or_else(|error| panic!("invalid source height: {error}"));
            child_spend_fanout_block(&parent, height, &blocks[source_index])
        };
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

fn child_fanout_coinbase_block(parent: &Block, height: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![fanout_coinbase_transaction(height)],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("fanout proxy block should have merkle root"));
    mine_block_to_declared_target(&mut block);
    block
}

fn child_spend_fanout_block(parent: &Block, height: u32, source_block: &Block) -> Block {
    let source_coinbase = source_block
        .txdata
        .first()
        .unwrap_or_else(|| panic!("spend-heavy source block missing coinbase"));
    let source_txid = source_coinbase.compute_txid();
    let mut txdata = Vec::with_capacity(
        usize::try_from(SPEND_PROXY_FANOUT.saturating_add(1))
            .unwrap_or_else(|error| panic!("invalid spend proxy fanout: {error}")),
    );
    txdata.push(fanout_coinbase_transaction(height));
    for vout in 0..SPEND_PROXY_FANOUT {
        txdata.push(spend_proxy_transaction(source_txid, vout));
    }
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("spend-heavy proxy block should have merkle root"));
    mine_block_to_declared_target(&mut block);
    block
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

fn fanout_coinbase_transaction(height: u32) -> Transaction {
    let outputs = (0..SPEND_PROXY_FANOUT)
        .map(|_| TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: Builder::new().push_int(1).into_script(),
        })
        .collect();
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn spend_proxy_transaction(prev_txid: Txid, vout: u32) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: Builder::new().push_int(1).into_script(),
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
