//! Metrics-enabled apply-path diagnostic for deterministic sync proxy blocks.
//!
//! This target intentionally runs outside `sync_pipeline` so installing the
//! in-memory metrics recorder cannot contaminate Criterion timing baselines.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use bitcoin::absolute;
use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, Witness, transaction,
};
use bitcoin_rs_node::{
    Config, Network,
    metrics::{MetricValue, MetricsHandle, install_metrics},
    state::NodeState,
};
use hashbrown::HashMap;
use tempfile::TempDir;

const COINBASE_PROXY_BLOCKS: u32 = 32;
const PRODUCTION_PROXY_BLOCKS: u32 = 128;
const SPEND_PROXY_COINBASE_MATURITY: u32 = 100;
const SPEND_PROXY_SPEND_BLOCKS: u32 = 16;
const SPEND_PROXY_FANOUT: u32 = 64;
const SPEND_PROXY_COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_PROXY_SPEND_OUTPUT_VALUE: u64 = 78_124_999;
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
        "block_tree_insert",
        "node.apply_block.block_tree_insert_seconds",
    ),
    ("block_record", "node.apply_block.block_record_seconds"),
    ("mempool_evict", "node.apply_block.mempool_evict_seconds"),
    (
        "coin_stats_finish",
        "node.apply_block.coin_stats_finish_seconds",
    ),
    ("filter_index", "node.apply_block.filter_index_seconds"),
    ("total", "node.apply_block.total_seconds"),
];

fn main() {
    let metrics = install_diagnostic_metrics();
    print_apply_metrics(
        "coinbase_32",
        &proxy_blocks(COINBASE_PROXY_BLOCKS),
        &metrics,
    );
    print_apply_metrics(
        "coinbase_128",
        &proxy_blocks(PRODUCTION_PROXY_BLOCKS),
        &metrics,
    );
    print_apply_metrics("spend_heavy_117", &spend_heavy_proxy_blocks(), &metrics);
}

fn install_diagnostic_metrics() -> MetricsHandle {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    install_metrics(Some(bind))
        .unwrap_or_else(|error| panic!("install metrics recorder failed: {error}"))
        .unwrap_or_else(|| panic!("metrics recorder was not installed"))
}

fn print_apply_metrics(name: &str, blocks: &[Block], metrics: &MetricsHandle) {
    let before = metrics.snapshot();
    let backend = storage_backend();
    let (_dir, state) = open_regtest_state(backend);
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
        "sync_apply_metrics backend={backend} workload={name} blocks={block_count} elapsed={elapsed:?} blocks_per_second={blocks_per_second:.2} recorded_body_bytes={recorded_body_bytes} selected_apply_stage_metrics={} {}",
        APPLY_STAGE_METRICS.len(),
        apply_stage_summary(&before, &after),
    );
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

fn open_regtest_state(backend: &str) -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    backend.clone_into(&mut config.storage_backend);
    config.p2p_listen.clear();
    config.txindex = false;
    let state =
        NodeState::open(config).unwrap_or_else(|error| panic!("open node state failed: {error}"));
    (dir, state)
}

fn apply_stage_summary(
    before: &HashMap<String, MetricValue>,
    after: &HashMap<String, MetricValue>,
) -> String {
    let mut summary = String::new();
    for (label, metric) in APPLY_STAGE_METRICS {
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(label);
        if let Some((count, avg_ms)) = histogram_delta_average_ms(before, after, metric) {
            write!(&mut summary, "_samples={count} {label}_avg_ms={avg_ms:.4}")
                .unwrap_or_else(|error| panic!("format apply stage summary failed: {error}"));
        } else {
            summary.push_str("_samples=0 ");
            summary.push_str(label);
            summary.push_str("_avg_ms=missing");
        }
    }
    summary
}

fn histogram_delta_average_ms(
    before: &HashMap<String, MetricValue>,
    after: &HashMap<String, MetricValue>,
    metric: &str,
) -> Option<(u64, f64)> {
    let (after_count, after_sum) = histogram_parts(after.get(metric)?)?;
    let (before_count, before_sum) = before
        .get(metric)
        .and_then(histogram_parts)
        .unwrap_or((0, 0.0));
    let count = after_count.saturating_sub(before_count);
    (count > 0).then(|| {
        let sum = after_sum - before_sum;
        (count, (sum / metric_sample_count(count)) * 1_000.0)
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
