//! Deterministic initial-sync proxy benchmark.
#![expect(
    clippy::as_conversions,
    reason = "benchmark casts are intentionally lossy for perf measurement"
)]
#![expect(
    clippy::unwrap_used,
    reason = "benchmark: panicking on setup failure is correct behavior"
)]
#![expect(
    clippy::cast_possible_truncation,
    reason = "benchmark: truncation is intentional for perf measurement"
)]
#![expect(
    clippy::cast_sign_loss,
    reason = "benchmark: sign loss is intentional for perf measurement"
)]
#![expect(
    clippy::cast_precision_loss,
    reason = "benchmark: precision loss is intentional for perf measurement"
)]
#![expect(
    clippy::items_after_statements,
    reason = "benchmark: helper structs defined near use site for readability"
)]
#![expect(
    clippy::suboptimal_flops,
    reason = "benchmark: explicit mul-add is clearer than fma here"
)]
#![expect(
    clippy::semicolon_if_nothing_returned,
    reason = "benchmark: closure returns elapsed time, semicolon would break it"
)]

use std::hint::black_box;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::path::Path;

use arc_swap::ArcSwapOption;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::secp256k1::{All, Message as SecpMessage, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Amount as OracleAmount, OutPoint as OracleOutPoint, ScriptBuf as OracleScriptBuf,
    Sequence as OracleSequence, Transaction as OracleTx, TxIn as OracleTxIn, TxOut as OracleTxOut,
    Txid as OracleTxid, Witness as OracleWitness, absolute, opcodes,
    script::Builder as OracleBuilder, transaction,
};
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
use bitcoin_rs_consensus::compute_merkle_root;
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::push_int;
pub mod evidence;

#[path = "../../../tools/benchmark-support/measured_samples.rs"]
mod measured_samples;

use bitcoin_rs_mempool::{LocalOrigin, MutationResult};
use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, Candidate,
    GenerateRequest, GeneratedBlock, MiningControl, MiningControlError, MiningInfo,
};
use bitcoin_rs_primitives::unix_time_secs;
use bitcoin_rs_rpc::Handler;
use bitcoin_rs_rpc::context::{
    ChainAdmissionView, Context, DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB,
};

use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_node::metrics::{CorpusIdentity, EvidenceIdentity, Sha256Hex};
use bitcoin_rs_node::{
    BlockSync, DerivedIndexRuntime, MiningCoordinator, Network, NodeConfig, state::NodeState,
    sync::default_sync_budget,
};
use bitcoin_rs_p2p::Message;
use bitcoin_rs_primitives::{BlockPayload, consensus_bytes, deserialize};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use criterion::{BatchSize, Criterion, criterion_group};
use crossbeam_channel::unbounded;
use evidence::{Cell, Interval, IntervalKind, LEDGER_SCHEMA, Ledger, Sample};
use parking_lot::Mutex as ParkingMutex;
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};
use tempfile::TempDir;

const PROXY_BLOCKS: u32 = 32;

const SYNC_PROXY_BLOCKS: u32 = 128;

const SYNC_PROXY_HEADER_HEIGHT: u32 = 4_096;

const SYNC_PROXY_BLOCKS_USIZE: usize = 128;

const SYNC_PROXY_PEERS: usize = 512;

const SYNC_OVERSIZED_BURST_BLOCKS: u32 = 1_024;

const SYNC_OVERSIZED_BURST_BLOCKS_USIZE: usize = 1_024;

const SYNC_REVERSE_SCAN_OVERFLOW_BODY_BLOCKS: u32 = 384;

const SYNC_REVERSE_SCAN_OVERFLOW_RECEIVED_START_HEIGHT: usize = 257;

const SYNC_REVERSE_SCAN_OVERFLOW_RECEIVED_BLOCKS: usize = 128;

const SPEND_PROXY_COINBASE_MATURITY: u32 = 100;

const SPEND_PROXY_SPEND_BLOCKS: u32 = 16;

const SPEND_PROXY_FANOUT: u32 = 64;

const SPEND_PROXY_COINBASE_OUTPUT_VALUE: u64 = 78_125_000;

const SPEND_PROXY_SPEND_OUTPUT_VALUE: u64 = 78_124_999;

const SIGNED_SPEND_OUTPUT_VALUE: u64 = 78_124_499;

fn sync_pipeline_apply_proxy(c: &mut Criterion) {
    let blocks = proxy_blocks(PROXY_BLOCKS);
    print_proxy_summary(&blocks);
    let payloads: Vec<BlockPayload> = blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();

    c.bench_function("sync_pipeline_apply_proxy", |b| {
        b.iter_batched(
            open_regtest_state,
            |(_dir, state)| {
                for payload in &payloads {
                    state
                        .apply_block(black_box(payload))
                        .unwrap_or_else(|error| panic!("proxy apply failed: {error}"));
                }
                black_box(
                    state
                        .chainstate()
                        .applied_tip_snapshot()
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
                for payload in &payloads {
                    state
                        .apply_block(black_box(payload))
                        .unwrap_or_else(|error| panic!("pruned proxy apply failed: {error}"));
                }
                let tip = state
                    .chainstate()
                    .applied_tip_snapshot()
                    .unwrap_or_else(|| panic!("pruned proxy apply did not publish a tip"));
                let record = state
                    .block_log_reader()
                    .read()
                    .last()
                    .cloned()
                    .unwrap_or_else(|| panic!("pruned proxy apply did not publish a record"));
                black_box((tip.height, record.body_size));
            },
            BatchSize::SmallInput,
        );
    });

    let spend_blocks = spend_heavy_proxy_blocks();
    print_spend_proxy_summary(&spend_blocks);
    let spend_payloads: Vec<BlockPayload> = spend_blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();
    c.bench_function("sync_pipeline_apply_spend_heavy_proxy", |b| {
        b.iter_batched(
            open_regtest_state,
            |(_dir, state)| {
                for payload in &spend_payloads {
                    state
                        .apply_block(black_box(payload))
                        .unwrap_or_else(|error| panic!("spend-heavy proxy apply failed: {error}"));
                }
                black_box(
                    state
                        .chainstate()
                        .applied_tip_snapshot()
                        .unwrap_or_else(|| panic!("spend-heavy proxy did not publish a tip"))
                        .height,
                );
            },
            BatchSize::SmallInput,
        );
    });
}

fn sync_pipeline_apply_signed_spend_proxy(c: &mut Criterion) {
    let blocks = legacy_signed_spend_proxy_blocks();
    print_signed_spend_proxy_summary(&blocks);
    let payloads: Vec<BlockPayload> = blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();

    const SIGNED_SPEND_SAMPLES: usize = 30;
    let origin = Instant::now();
    let samples: ParkingMutex<Vec<(Duration, Duration)>> =
        ParkingMutex::new(Vec::with_capacity(SIGNED_SPEND_SAMPLES.saturating_mul(4)));

    c.bench_function("sync_pipeline_apply_signed_spend_proxy", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let (_dir, state) = open_regtest_state();
                let sweep_start = Instant::now();
                for payload in &payloads {
                    state
                        .apply_block(black_box(payload))
                        .unwrap_or_else(|error| panic!("signed-spend apply failed: {error}"));
                }
                samples
                    .lock()
                    .push((sweep_start.duration_since(origin), sweep_start.elapsed()));
                black_box(
                    state
                        .chainstate()
                        .applied_tip_snapshot()
                        .unwrap_or_else(|| panic!("signed-spend proxy did not publish a tip"))
                        .height,
                );
            }
            start.elapsed()
        })
    });

    let sweeps = samples.lock();
    print_percentiles(
        "signed_spend_proxy",
        &sweeps
            .iter()
            .map(|(_, elapsed)| *elapsed)
            .collect::<Vec<_>>(),
    );
    record_evidence("sync_pipeline.signed_spend_proxy", &blocks, &sweeps);
}

fn record_evidence(cell: &str, blocks: &[Block], sweeps: &[(Duration, Duration)]) {
    if sweeps.is_empty() {
        return;
    }
    let config = production_state_config();
    let mut identity = EvidenceIdentity::of_process(&config)
        .unwrap_or_else(|error| panic!("evidence identity: {error}"));
    let corpus_bytes: Vec<u8> = blocks.iter().flat_map(consensus_bytes).collect();
    identity.corpus = Some(CorpusIdentity {
        id: cell.to_owned(),
        manifest_sha256: Sha256Hex::digest(&corpus_bytes),
    });
    let path = bench_ledger_path("sync_pipeline.toml");
    let mut ledger = load_bench_ledger(&path);
    if !ledger.cells.iter().any(|candidate| candidate.id == cell) {
        ledger.cells.push(Cell {
            id: cell.to_owned(),
            samples: Vec::new(),
        });
    }
    let nanos = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
    for (start, elapsed) in sweeps {
        let sample = Sample {
            path: "apply.prove_window".into(),
            owner: "node".into(),
            identity: identity.clone(),
            interval: Interval {
                kind: IntervalKind::Inside,
                start_ns: nanos(*start),
                end_ns: nanos(start.saturating_add(*elapsed)),
            },
            cpu_ns: None,
            elapsed_ns: nanos(*elapsed),
            rss_peak_bytes: None,
            io_bytes: None,
            storage_bytes: None,
        };
        ledger
            .record(cell, sample)
            .unwrap_or_else(|error| panic!("record bench sample: {error}"));
    }
    store_bench_ledger(&path, &ledger);
}

fn bench_ledger_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/benchmarks")
        .join(name)
}

fn load_bench_ledger(path: &Path) -> Ledger {
    match std::fs::read_to_string(path) {
        Ok(text) => Ledger::parse(&text).unwrap_or_else(|error| panic!("bench ledger: {error}")),
        Err(_) => Ledger {
            schema: LEDGER_SCHEMA.into(),
            cells: Vec::new(),
            contract: std::collections::BTreeMap::new(),
        },
    }
}

fn store_bench_ledger(path: &Path, ledger: &Ledger) {
    std::fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))
        .unwrap_or_else(|error| panic!("bench evidence dir: {error}"));
    let rendered = ledger
        .render()
        .unwrap_or_else(|error| panic!("render bench ledger: {error}"));
    std::fs::write(path, rendered).unwrap_or_else(|error| panic!("write bench ledger: {error}"));
}

fn deterministic_initial_sync_proxy(c: &mut Criterion) {
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_pure_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(DerivedIndexMode::Disabled).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_indexed_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(DerivedIndexMode::Noop).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_received_scan_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(DerivedIndexMode::Disabled).prebuild_unsolicited(),
                |fixture| black_box(fixture.request_after_unsolicited_received()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_reverse_scan_overflow_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new_reverse_scan_overflow(DerivedIndexMode::Disabled),
                |fixture| black_box(fixture.run_reverse_scan_overflow()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_in_order_inbound_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(DerivedIndexMode::Disabled).prebuild_in_order(),
                |fixture| black_box(fixture.run_in_order_inbound()),
                BatchSize::SmallInput,
            );
        },
    );
    bench_production_state_sync(c);
    c.bench_function("deterministic_initial_sync_proxy_many_peers_512", |b| {
        b.iter_batched(
            || SyncFixture::new_with_peers(DerivedIndexMode::Disabled, SYNC_PROXY_PEERS),
            |fixture| black_box(fixture.run_many_peer_tick()),
            BatchSize::SmallInput,
        );
    });
    c.bench_function(
        "deterministic_initial_sync_proxy_oversized_inbound_burst_1024_blocks",
        |b| {
            b.iter_batched(
                || {
                    SyncFixture::new_with_block_count(
                        DerivedIndexMode::Disabled,
                        1,
                        SYNC_OVERSIZED_BURST_BLOCKS,
                    )
                    .prebuild_oversized_burst()
                },
                |fixture| black_box(fixture.run_oversized_inbound_burst()),
                BatchSize::SmallInput,
            );
        },
    );
    #[cfg(feature = "rocksdb")]
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_txindex_rocksdb_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(DerivedIndexMode::RocksDb).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
}

fn bench_production_state_sync(c: &mut Criterion) {
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_128_blocks",
        |b| {
            b.iter_batched(
                || ProductionStateSyncFixture::new(1).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    #[cfg(feature = "fjall")]
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_fjall_all_indexes_128_blocks",
        |b| {
            b.iter_batched(
                || ProductionStateSyncFixture::new_fjall_all_indexes(1).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    #[cfg(feature = "fjall")]
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_fjall_all_indexes_spend_heavy",
        |b| {
            b.iter_batched(
                || ProductionStateSyncFixture::new_fjall_all_indexes_spend_heavy().prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_apply_tick_128_blocks",
        |b| {
            b.iter_batched(
                || ProductionStateSyncFixture::new(1).stage_for_contiguous_apply(),
                |fixture| black_box(fixture.apply_staged()),
                BatchSize::SmallInput,
            );
        },
    );
    #[cfg(feature = "fjall")]
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_fjall_all_indexes_apply_tick_128_blocks",
        |b| {
            b.iter_batched(
                || {
                    ProductionStateSyncFixture::new_fjall_all_indexes(1)
                        .stage_for_contiguous_apply()
                },
                |fixture| black_box(fixture.apply_staged()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_partial_apply_tick_128_blocks",
        |b| {
            b.iter_batched(
                || ProductionStateSyncFixture::new(1).stage_for_partial_cached_apply(),
                |fixture| black_box(fixture.apply_staged()),
                BatchSize::SmallInput,
            );
        },
    );
    #[cfg(feature = "fjall")]
    c.bench_function(
        "deterministic_initial_sync_proxy_production_state_fjall_all_indexes_partial_apply_tick_128_blocks",
        |b| {
            b.iter_batched(
                || {
                    ProductionStateSyncFixture::new_fjall_all_indexes(1)
                        .stage_for_partial_cached_apply()
                },
                |fixture| black_box(fixture.apply_staged()),
                BatchSize::SmallInput,
            );
        },
    );
}

fn print_proxy_summary(blocks: &[Block]) {
    let (_dir, state) = open_regtest_state();
    let payloads: Vec<BlockPayload> = blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();
    let started = Instant::now();
    for payload in &payloads {
        state
            .apply_block(payload)
            .unwrap_or_else(|error| panic!("proxy summary apply failed: {error}"));
    }
    let elapsed = started.elapsed();
    let applied_height = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("proxy summary did not publish a tip"))
        .height;
    let blocks_per_second = f64::from(applied_height.saturating_add(1)) / elapsed.as_secs_f64();
    let recorded_body_bytes: usize = state
        .block_log_reader()
        .read()
        .iter()
        .map(|record| record.body_size)
        .sum();
    println!(
        "sync_pipeline_apply_proxy engine={} blocks={} elapsed={elapsed:?} blocks_per_second={blocks_per_second:.2} recorded_body_bytes={recorded_body_bytes}",
        bench_engine(),
        applied_height.saturating_add(1),
    );
}

fn print_spend_proxy_summary(blocks: &[Block]) {
    let (_dir, state) = open_regtest_state();
    let payloads: Vec<BlockPayload> = blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();
    let started = Instant::now();
    for payload in &payloads {
        state
            .apply_block(payload)
            .unwrap_or_else(|error| panic!("spend-heavy proxy summary apply failed: {error}"));
    }
    let elapsed = started.elapsed();
    let applied_height = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("spend-heavy proxy summary did not publish a tip"))
        .height;
    let transaction_count: usize = blocks.iter().map(|block| block.txs.len()).sum();
    let recorded_body_bytes: usize = state
        .block_log_reader()
        .read()
        .iter()
        .map(|record| record.body_size)
        .sum();
    println!(
        "sync_pipeline_apply_spend_heavy_proxy engine={} blocks={} txs={transaction_count} elapsed={elapsed:?} recorded_body_bytes={recorded_body_bytes}",
        bench_engine(),
        applied_height.saturating_add(1),
    );
}

fn open_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.validation.engine = bench_engine();
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    let state = NodeState::open(config, None)
        .unwrap_or_else(|error| panic!("open node state failed: {error}"));
    (dir, state)
}

#[cfg(feature = "rocksdb")]
fn open_pruned_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.validation.engine = bench_engine();
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.backend = bitcoin_rs_storage::StorageBackend::RocksDb;
    config.indexes.txindex = false;
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config, None)
        .unwrap_or_else(|error| panic!("open pruned node state failed: {error}"));
    (dir, state)
}

struct SyncFixture {
    sync: BlockSync,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    outbound_rxs: Vec<crossbeam_channel::Receiver<bitcoin_rs_p2p::QueuedFrame>>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    blocks: Vec<Block>,
    prebuilt_inbound: Vec<bitcoin_rs_p2p::InboundBlock>,
    received_scan_expected: Vec<BlockHash>,
}

#[derive(Clone, Copy)]
enum DerivedIndexMode {
    Disabled,
    Noop,
    #[cfg(feature = "rocksdb")]
    RocksDb,
}

impl SyncFixture {
    fn new(tx_index_mode: DerivedIndexMode) -> Self {
        Self::new_with_peers(tx_index_mode, 1)
    }

    fn new_with_peers(tx_index_mode: DerivedIndexMode, peer_count: usize) -> Self {
        Self::new_with_block_count(tx_index_mode, peer_count, SYNC_PROXY_BLOCKS)
    }

    fn new_with_block_count(
        tx_index_mode: DerivedIndexMode,
        peer_count: usize,
        block_count: u32,
    ) -> Self {
        let mut tree = BlockTree::new();
        let (blocks, received_scan_expected) = populate_sync_header_chain(&mut tree, block_count);

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx) =
            unbounded::<bitcoin_rs_p2p::InboundHeaders>();
        let (inbound_blocks_tx, inbound_blocks_rx) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let derived_index_runtime = tx_index_for_mode(tx_index_mode);
        let followers =
            bitcoin_rs_node::ChainFollowers::noop().with_tx_index(derived_index_runtime);
        let mut handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
        );
        handles.set_capture_flags(followers.needs_rawtx(), followers.needs_block_bytes());
        let ibd = handles.ibd_latch();
        let sync = bitcoin_rs_node::sync::block_sync(
            Arc::new(handles),
            followers,
            Arc::clone(&peer_table),
            inbound_headers_rx,
            inbound_blocks_rx,
            Arc::clone(&ibd),
            None,
        );

        let outbound_rxs = install_synthetic_peers(&peer_table, peer_count);

        Self {
            sync,
            inbound_blocks_tx,
            outbound_rxs,
            peer_table,
            applied_tip,
            blocks,
            prebuilt_inbound: Vec::new(),
            received_scan_expected,
        }
    }

    fn prebuild_run(mut self) -> Self {
        self.prebuilt_inbound = self.blocks[1..]
            .iter()
            .rev()
            .chain(std::iter::once(&self.blocks[0]))
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
            .collect();
        self
    }

    fn prebuild_unsolicited(mut self) -> Self {
        self.prebuilt_inbound = vec![bitcoin_rs_p2p::InboundBlock::from_local(
            self.blocks[1].clone(),
        )];
        self
    }

    fn prebuild_in_order(mut self) -> Self {
        self.prebuilt_inbound = self
            .blocks
            .iter()
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
            .collect();
        self
    }

    fn prebuild_oversized_burst(mut self) -> Self {
        self.prebuilt_inbound = self.blocks[1..]
            .iter()
            .rev()
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
            .collect();
        self
    }

    fn new_reverse_scan_overflow(tx_index_mode: DerivedIndexMode) -> Self {
        let mut fixture =
            Self::new_with_block_count(tx_index_mode, 0, SYNC_REVERSE_SCAN_OVERFLOW_BODY_BLOCKS);
        let mut budget = default_sync_budget(bitcoin_rs_primitives::Network::Regtest);
        budget.max_received_blocks = budget
            .max_pending_blocks
            .saturating_add(SYNC_REVERSE_SCAN_OVERFLOW_RECEIVED_BLOCKS);
        fixture.sync.install_budget(budget);
        let first_index = SYNC_REVERSE_SCAN_OVERFLOW_RECEIVED_START_HEIGHT.saturating_sub(1);
        let last_index = first_index.saturating_add(SYNC_REVERSE_SCAN_OVERFLOW_RECEIVED_BLOCKS);
        for block in fixture
            .blocks
            .get(first_index..last_index)
            .unwrap_or_else(|| panic!("reverse-scan overflow block range missing"))
            .iter()
            .rev()
        {
            fixture
                .inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
                .unwrap_or_else(|error| panic!("send staged overflow block failed: {error}"));
        }
        fixture.sync.tick();
        fixture.outbound_rxs = install_synthetic_peers(&fixture.peer_table, 1);
        fixture
    }

    fn run(mut self) -> u32 {
        self.sync.tick();
        let getdata_count = match self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"))
            .try_recv()
            .unwrap_or_else(|error| panic!("expected getdata: {error}"))
            .into_message()
        {
            Message::GetData(inventory) => inventory.len(),
            other => panic!("expected getdata, got {other:?}"),
        };
        assert_eq!(getdata_count, SYNC_PROXY_BLOCKS_USIZE);
        match self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"))
            .try_recv()
            .map(bitcoin_rs_p2p::QueuedFrame::into_message)
        {
            Ok(other) => panic!("expected no getheaders, got {other:?}"),
            Err(crossbeam_channel::TryRecvError::Empty) => {}
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                panic!("outbound channel disconnected")
            }
        }

        let mut prebuilt = std::mem::take(&mut self.prebuilt_inbound).into_iter();
        let contiguous = prebuilt
            .next_back()
            .unwrap_or_else(|| panic!("missing prebuilt contiguous block"));
        for inbound in prebuilt {
            self.inbound_blocks_tx
                .send(inbound)
                .unwrap_or_else(|error| panic!("send staged block failed: {error}"));
        }
        self.sync.tick();
        self.inbound_blocks_tx
            .send(contiguous)
            .unwrap_or_else(|error| panic!("send contiguous block failed: {error}"));
        self.sync.tick();

        self.applied_tip
            .load_full()
            .unwrap_or_else(|| panic!("sync proxy did not publish applied tip"))
            .height
    }

    fn run_many_peer_tick(self) -> usize {
        self.sync.tick();
        self.outbound_rxs
            .iter()
            .map(|rx| {
                let mut count = 0_usize;
                while rx.try_recv().is_ok() {
                    count = count.saturating_add(1);
                }
                count
            })
            .sum()
    }

    fn request_after_unsolicited_received(mut self) -> usize {
        let unsolicited = std::mem::take(&mut self.prebuilt_inbound)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing prebuilt unsolicited block"));
        self.inbound_blocks_tx
            .send(unsolicited)
            .unwrap_or_else(|error| panic!("send unsolicited staged block failed: {error}"));
        self.sync.tick();
        let requested = match self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"))
            .try_recv()
            .unwrap_or_else(|error| panic!("expected scan-path getdata: {error}"))
            .into_message()
        {
            Message::GetData(inventory) => inventory
                .into_iter()
                .map(|item| match item {
                    Inventory::WitnessBlock(hash) => {
                        BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
                    }
                    other => panic!("expected witness block inventory, got {other:?}"),
                })
                .collect::<Vec<_>>(),
            other => panic!("expected scan-path getdata, got {other:?}"),
        };
        assert_eq!(requested, self.received_scan_expected);
        requested.len()
    }

    fn run_reverse_scan_overflow(self) -> usize {
        self.sync.tick();
        let requested = match self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing overflow outbound receiver"))
            .try_recv()
            .unwrap_or_else(|error| panic!("expected overflow scan getdata: {error}"))
            .into_message()
        {
            Message::GetData(inventory) => inventory
                .into_iter()
                .map(|item| match item {
                    Inventory::WitnessBlock(hash) => {
                        BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
                    }
                    other => panic!("expected overflow witness inventory, got {other:?}"),
                })
                .collect::<Vec<_>>(),
            other => panic!("expected overflow scan getdata, got {other:?}"),
        };
        let expected = self.blocks[..SYNC_PROXY_BLOCKS_USIZE]
            .iter()
            .map(Block::block_hash)
            .collect::<Vec<_>>();
        assert_eq!(requested, expected);
        requested.len()
    }

    fn run_in_order_inbound(mut self) -> u32 {
        self.sync.tick();
        let getdata_count = match self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"))
            .try_recv()
            .unwrap_or_else(|error| panic!("expected getdata: {error}"))
            .into_message()
        {
            Message::GetData(inventory) => inventory.len(),
            other => panic!("expected getdata, got {other:?}"),
        };
        assert_eq!(getdata_count, SYNC_PROXY_BLOCKS_USIZE);

        for inbound in std::mem::take(&mut self.prebuilt_inbound) {
            self.inbound_blocks_tx
                .send(inbound)
                .unwrap_or_else(|error| panic!("send in-order block failed: {error}"));
        }
        self.sync.tick();

        self.applied_tip
            .load_full()
            .unwrap_or_else(|| panic!("in-order sync proxy did not publish applied tip"))
            .height
    }

    fn run_oversized_inbound_burst(mut self) -> usize {
        self.sync.tick();
        for inbound in std::mem::take(&mut self.prebuilt_inbound) {
            self.inbound_blocks_tx
                .send(inbound)
                .unwrap_or_else(|error| panic!("send oversized burst block failed: {error}"));
        }
        self.sync.tick();
        SYNC_OVERSIZED_BURST_BLOCKS_USIZE.saturating_sub(1)
    }
}

#[derive(Clone, Copy)]
enum ReplayPhase {
    ApplyStart,
    ApplyDone,
}

struct ReplayReport {
    requested: usize,
    applied_height: u32,
}

struct ProductionStateSyncFixture {
    _dir: TempDir,
    state: NodeState,
    outbound_rxs: Vec<crossbeam_channel::Receiver<bitcoin_rs_p2p::QueuedFrame>>,
    blocks: Vec<Block>,
    prebuilt_inbound: Vec<bitcoin_rs_p2p::InboundBlock>,
    expected_getdata_count: usize,
}

impl ProductionStateSyncFixture {
    fn new(peer_count: usize) -> Self {
        Self::with_config(peer_count, production_state_config())
    }

    #[cfg(feature = "fjall")]
    fn new_fjall_all_indexes(peer_count: usize) -> Self {
        let mut config = production_state_config();
        config.storage.backend = bitcoin_rs_storage::StorageBackend::Fjall;
        config.indexes.txindex = true;
        Self::with_config(peer_count, config)
    }

    fn with_config(peer_count: usize, config: NodeConfig) -> Self {
        Self::with_config_and_header_blocks(
            peer_count,
            config,
            |tree| {
                let (blocks, _received_scan_expected) =
                    populate_sync_header_chain(tree, SYNC_PROXY_BLOCKS);
                blocks
            },
            SYNC_PROXY_BLOCKS_USIZE,
        )
    }

    fn window_replay(body_blocks: u32) -> Self {
        let expected_getdata_count = usize::try_from(body_blocks)
            .unwrap_or_else(|error| panic!("invalid window body count: {error}"));
        Self::with_config_and_header_blocks(
            1,
            production_state_config(),
            |tree| populate_sync_header_chain(tree, body_blocks).0,
            expected_getdata_count,
        )
    }

    #[cfg(feature = "fjall")]
    fn new_fjall_all_indexes_spend_heavy() -> Self {
        let mut config = production_state_config();
        config.storage.backend = bitcoin_rs_storage::StorageBackend::Fjall;
        config.indexes.txindex = true;
        let body_blocks = spend_heavy_proxy_blocks()
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>();
        let expected_getdata_count = body_blocks.len();
        Self::with_config_and_header_blocks(
            1,
            config,
            |tree| {
                populate_header_chain_from_blocks(tree, &body_blocks);
                body_blocks
            },
            expected_getdata_count,
        )
    }

    fn with_config_and_header_blocks(
        peer_count: usize,
        mut config: NodeConfig,
        populate_blocks: impl FnOnce(&mut BlockTree) -> Vec<Block>,
        expected_getdata_count: usize,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
        config.data_dir = dir.path().join("node");
        let mut state = NodeState::open(config, None)
            .unwrap_or_else(|error| panic!("open node state failed: {error}"));
        state
            .start_index_workers()
            .unwrap_or_else(|error| panic!("start index workers failed: {error}"));
        let blocks = {
            let block_tree = state.chainstate().block_tree_reader();
            let mut tree = block_tree.write();
            populate_blocks(&mut tree)
        };
        let outbound_rxs = install_synthetic_peers(&state.peer_table(), peer_count);
        Self {
            _dir: dir,
            state,
            outbound_rxs,
            blocks,
            prebuilt_inbound: Vec::new(),
            expected_getdata_count,
        }
    }

    fn prebuild_run(mut self) -> Self {
        self.prebuilt_inbound = self.blocks[1..]
            .iter()
            .rev()
            .chain(std::iter::once(&self.blocks[0]))
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
            .collect();
        self
    }

    fn run(mut self) -> u32 {
        let replay = self.run_phased(|_| {});
        assert_eq!(replay.requested, self.expected_getdata_count);
        replay.applied_height
    }

    fn run_phased(&mut self, mut phase: impl FnMut(ReplayPhase)) -> ReplayReport {
        let sync = self.state.sync();
        sync.tick();
        let requested = self.first_getdata_len();
        let inbound_blocks_tx = self.state.inbound_blocks_sender();
        let mut prebuilt = std::mem::take(&mut self.prebuilt_inbound).into_iter();
        let contiguous = prebuilt
            .next_back()
            .unwrap_or_else(|| panic!("missing prebuilt contiguous block"));
        for inbound in prebuilt {
            inbound_blocks_tx
                .send(inbound)
                .unwrap_or_else(|error| panic!("send production staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(contiguous)
            .unwrap_or_else(|error| panic!("send production contiguous block failed: {error}"));
        phase(ReplayPhase::ApplyStart);
        sync.tick();
        phase(ReplayPhase::ApplyDone);
        let applied_height = self
            .state
            .chainstate()
            .applied_tip_snapshot()
            .unwrap_or_else(|| panic!("production sync proxy did not publish applied tip"))
            .height;
        ReplayReport {
            requested,
            applied_height,
        }
    }

    fn settle_tick(&self) {
        self.state.sync().tick();
    }

    fn stage_for_contiguous_apply(self) -> Self {
        let sync = self.state.sync();
        sync.tick();
        self.assert_getdata_batch();
        let inbound_blocks_tx = self.state.inbound_blocks_sender();
        for block in self.blocks[1..].iter().rev() {
            inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
                .unwrap_or_else(|error| panic!("send production staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_local(
                self.blocks[0].clone(),
            ))
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
                .send(bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
                .unwrap_or_else(|error| panic!("send first partial staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_local(
                self.blocks[0].clone(),
            ))
            .unwrap_or_else(|error| panic!("send first partial contiguous block failed: {error}"));
        sync.tick();

        for block in self.blocks[split + 1..].iter().rev() {
            inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_local(block.clone()))
                .unwrap_or_else(|error| panic!("send second partial staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_local(
                self.blocks[split].clone(),
            ))
            .unwrap_or_else(|error| panic!("send second partial contiguous block failed: {error}"));
        self
    }

    fn apply_staged(self) -> u32 {
        self.state.sync().tick();
        self.state
            .chainstate()
            .applied_tip_snapshot()
            .unwrap_or_else(|| panic!("production sync proxy did not publish applied tip"))
            .height
    }

    fn assert_getdata_batch(&self) {
        assert_eq!(self.first_getdata_len(), self.expected_getdata_count);
    }

    fn first_getdata_len(&self) -> usize {
        let rx = self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"));
        let mut drained_headers = 0_usize;
        loop {
            match rx
                .try_recv()
                .unwrap_or_else(|error| panic!("expected production getdata: {error}"))
                .into_message()
            {
                Message::GetData(inventory) => break inventory.len(),
                Message::GetHeaders(_) => {
                    drained_headers = drained_headers.saturating_add(1);
                    assert!(
                        drained_headers <= 32,
                        "expected production getdata after draining {drained_headers} header requests"
                    );
                    continue;
                }
                other => panic!("expected production getdata, got {other:?}"),
            }
        }
    }
}

fn production_state_config() -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.validation.engine = bench_engine();
    config
}

fn bench_engine() -> bitcoin_rs_node::ValidationEngine {
    let spelling = sample_engine_label();
    let engine = bitcoin_rs_node::ValidationEngine::parse(&spelling)
        .unwrap_or_else(|| panic!("unknown BITCOIN_RS_VALIDATION_ENGINE {spelling:?}"));
    assert!(
        engine.is_supported(),
        "BITCOIN_RS_VALIDATION_ENGINE={spelling:?} selects an engine this build \
         cannot run: compile the capability feature (`kernel`) to benchmark that arm"
    );
    engine
}

fn sample_engine_label() -> String {
    std::env::var("BITCOIN_RS_VALIDATION_ENGINE").unwrap_or_else(|_| "native".into())
}

fn populate_sync_header_chain(
    tree: &mut BlockTree,
    body_blocks: u32,
) -> (Vec<Block>, Vec<BlockHash>) {
    let genesis = Network::Regtest.genesis_block();
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
    let mut received_scan_expected = Vec::with_capacity(SYNC_PROXY_BLOCKS_USIZE);

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
            prev_hash = header.compute_hash();
            header
        };
        tip_id = tree
            .insert_node(Some(tip_id), header, NodeStatus::HeaderValid)
            .unwrap_or_else(|error| panic!("synthetic header insert failed: {error}"));
        if height == 1 || (3..=body_blocks).contains(&height) {
            let node = tree
                .node(tip_id)
                .unwrap_or_else(|error| panic!("synthetic header lookup failed: {error}"));
            received_scan_expected.push(BlockHash::from(node.hash));
        }
    }
    (blocks, received_scan_expected)
}

#[cfg(feature = "fjall")]
fn populate_header_chain_from_blocks(tree: &mut BlockTree, blocks: &[Block]) {
    let genesis = Network::Regtest.genesis_block();
    let genesis_id = tree
        .insert_node(None, genesis.header, NodeStatus::HeaderValid)
        .unwrap_or_else(|error| panic!("regtest genesis header insert failed: {error}"));
    let mut tip_id = genesis_id;
    for block in blocks {
        tip_id = tree
            .insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)
            .unwrap_or_else(|error| panic!("synthetic body header insert failed: {error}"));
    }
}

fn install_synthetic_peers(
    peer_table: &Arc<bitcoin_rs_p2p::PeerTable>,
    peer_count: usize,
) -> Vec<crossbeam_channel::Receiver<bitcoin_rs_p2p::QueuedFrame>> {
    let mut outbound_rxs = Vec::with_capacity(peer_count);
    for index in 0..peer_count {
        let port = u16::try_from(8_333_usize.saturating_add(index))
            .unwrap_or_else(|error| panic!("invalid synthetic peer port: {error}"));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let (outbound_tx, outbound_rx) = unbounded::<bitcoin_rs_p2p::QueuedFrame>();
        peer_table.register(
            bitcoin_rs_primitives::PeerEndpoint::Ip(addr),
            bitcoin_rs_p2p::PeerLease::new(outbound_tx),
        );
        outbound_rxs.push(outbound_rx);
    }
    outbound_rxs
}

fn apply_handles(
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> Chainstate {
    let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.track_coin_stats((*coin_stats).clone());
    let utxo = Arc::new(utxo);
    Chainstate::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        utxo,
        coin_stats,
        Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
    )
}

fn tx_index_for_mode(mode: DerivedIndexMode) -> Option<Arc<DerivedIndexRuntime>> {
    match mode {
        DerivedIndexMode::Disabled => None,
        DerivedIndexMode::Noop => {
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
            Some(Arc::new(DerivedIndexRuntime::new(wake_tx)))
        }
        #[cfg(feature = "rocksdb")]
        DerivedIndexMode::RocksDb => {
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
            Some(Arc::new(DerivedIndexRuntime::new(wake_tx)))
        }
    }
}

fn proxy_blocks(count: u32) -> Vec<Block> {
    let mut blocks = Vec::with_capacity(
        usize::try_from(count).unwrap_or_else(|error| panic!("invalid proxy count: {error}")),
    );
    let genesis = Network::Regtest.genesis_block();
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
    let genesis = Network::Regtest.genesis_block();
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
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: vec![coinbase_transaction(height)],
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining proxy block failed: {error}"));
    block
}

fn child_fanout_coinbase_block(parent: &Block, height: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: vec![fanout_coinbase_transaction(height)],
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining proxy block failed: {error}"));
    block
}

fn child_spend_fanout_block(parent: &Block, height: u32, source_block: &Block) -> Block {
    let source_coinbase = source_block
        .txs
        .first()
        .unwrap_or_else(|| panic!("spend-heavy source block missing coinbase"));
    let source_txid = source_coinbase.txid();
    let mut txs = Vec::with_capacity(
        usize::try_from(SPEND_PROXY_FANOUT.saturating_add(1))
            .unwrap_or_else(|error| panic!("invalid spend proxy fanout: {error}")),
    );
    txs.push(fanout_coinbase_transaction(height));
    for vout in 0..SPEND_PROXY_FANOUT {
        txs.push(spend_proxy_transaction(source_txid, vout));
    }
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs,
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining proxy block failed: {error}"));
    block
}

fn child_header(prev_blockhash: BlockHash, time: u32) -> Header {
    Header {
        version: 4,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
        nonce: 0,
    }
}

fn coinbase_transaction(height: u32) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height).into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: Script::new(),
        }],
    }
}

fn fanout_coinbase_transaction(height: u32) -> Tx {
    let outputs = (0..SPEND_PROXY_FANOUT)
        .map(|_| TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: push_int(1).into(),
        })
        .collect();
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height).into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs,
    }
}

fn spend_proxy_transaction(prev_txid: Txid, vout: u32) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, vout),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: push_int(1).into(),
        }],
    }
}

fn coinbase_script_sig(height: u32) -> Vec<u8> {
    let mut script = Vec::with_capacity(5);
    script.push(4);
    script.extend_from_slice(&height.to_le_bytes());
    script
}

const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

const WITNESS_RESERVED_VALUE: [u8; 32] = [0; 32];

struct SigningKeys {
    secp: Secp256k1<All>,
    p2pkh: Vec<bitcoin::PublicKey>,
    p2wpkh: Vec<bitcoin::PublicKey>,
    p2wsh: Vec<bitcoin::PublicKey>,
}

impl SigningKeys {
    fn new() -> Self {
        let secp = Secp256k1::new();
        let p2pkh = (0..SPEND_PROXY_FANOUT)
            .map(|i| secret_pubkey(&secp, 0xA0 + i as u8))
            .collect();
        let p2wpkh = (0..SPEND_PROXY_FANOUT)
            .map(|i| secret_pubkey(&secp, 0xB0 + i as u8))
            .collect();
        let p2wsh = (0..3).map(|i| secret_pubkey(&secp, 0xC0 + i)).collect();
        Self {
            secp,
            p2pkh,
            p2wpkh,
            p2wsh,
        }
    }
}

fn secret_pubkey(secp: &Secp256k1<All>, byte: u8) -> bitcoin::PublicKey {
    let secret =
        SecretKey::from_slice(&[byte; 32]).unwrap_or_else(|e| panic!("invalid secret key: {e}"));
    bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        secp, &secret,
    ))
}

fn secret_key(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).unwrap_or_else(|e| panic!("invalid secret key: {e}"))
}

fn signed_spend_proxy_blocks() -> Vec<Block> {
    let keys = SigningKeys::new();
    let spend_start = SPEND_PROXY_COINBASE_MATURITY.saturating_add(1);
    let spend_end = spend_start
        .saturating_add(SPEND_PROXY_SPEND_BLOCKS)
        .saturating_sub(1);
    let capacity = usize::try_from(spend_end.saturating_add(1))
        .unwrap_or_else(|e| panic!("invalid spend capacity: {e}"));
    let genesis = Network::Regtest.genesis_block();
    let mut blocks = Vec::with_capacity(capacity);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..=spend_end {
        let block = if height < spend_start {
            child_signed_fanout_coinbase_block(&parent, height, &keys)
        } else {
            let source_height = height.saturating_sub(SPEND_PROXY_COINBASE_MATURITY);
            let source_index = usize::try_from(source_height)
                .unwrap_or_else(|e| panic!("invalid source height: {e}"));
            child_signed_spend_fanout_block(&parent, height, &blocks[source_index], &keys)
        };
        parent = block.clone();
        blocks.push(block);
    }
    blocks
}

fn child_signed_fanout_coinbase_block(parent: &Block, height: u32, keys: &SigningKeys) -> Block {
    let coinbase = signed_fanout_coinbase_transaction(height, keys);
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining proxy block failed: {error}"));
    block
}

fn signed_fanout_coinbase_transaction(height: u32, keys: &SigningKeys) -> Tx {
    let mut outputs = Vec::with_capacity(SPEND_PROXY_FANOUT as usize + 1);
    for i in 0..22u32 {
        let pkh = keys.p2pkh[usize::try_from(i).unwrap()].pubkey_hash();
        let script = OracleScriptBuf::new_p2pkh(&pkh);
        outputs.push(TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: script.as_bytes().to_vec().into(),
        });
    }
    for i in 0..22u32 {
        let pkh = keys.p2wpkh[usize::try_from(i).unwrap()]
            .wpubkey_hash()
            .unwrap();
        let script = OracleScriptBuf::new_p2wpkh(&pkh);
        outputs.push(TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: script.as_bytes().to_vec().into(),
        });
    }
    for i in 0..20u32 {
        let redeem = p2wsh_2of3_redeem_script(keys, i);
        let script_hash = redeem.wscript_hash();
        let script = OracleScriptBuf::new_p2wsh(&script_hash);
        outputs.push(TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: script.as_bytes().to_vec().into(),
        });
    }
    let commitment = witness_commitment_for_coinbase(&outputs);
    outputs.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: witness_commitment_script_pubkey(&commitment).into(),
    });

    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height).into(),
            sequence: Sequence::MAX,
            witness: vec![WITNESS_RESERVED_VALUE.to_vec()].into(),
        }],
        outputs,
    }
}

fn p2wsh_2of3_redeem_script(keys: &SigningKeys, _index: u32) -> OracleScriptBuf {
    OracleBuilder::new()
        .push_int(2)
        .push_key(&keys.p2wsh[0])
        .push_key(&keys.p2wsh[1])
        .push_key(&keys.p2wsh[2])
        .push_int(3)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script()
}

fn witness_commitment_for_coinbase(_outputs: &[TxOut]) -> Hash256 {
    let root = [0u8; 32];
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(&WITNESS_RESERVED_VALUE);
    double_sha256(&buffer)
}

fn witness_commitment_script_pubkey(commitment: &Hash256) -> Vec<u8> {
    let mut script = Vec::with_capacity(38);
    script.extend_from_slice(&WITNESS_COMMITMENT_PREFIX);
    script.extend_from_slice(commitment.as_byte_array());
    script
}

fn child_signed_target_block(
    parent: &Block,
    height: u32,
    keys: &SigningKeys,
    spends: Vec<Tx>,
) -> Block {
    let mut txs = Vec::with_capacity(spends.len().saturating_add(1));
    txs.push(signed_fanout_coinbase_transaction(height, keys));
    txs.extend(spends);
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs,
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    let commitment = block_witness_commitment(&block.txs);
    let coinbase = &mut block.txs[0];
    let last = coinbase
        .outputs
        .last_mut()
        .unwrap_or_else(|| panic!("target coinbase missing commitment output"));
    last.script_pubkey = witness_commitment_script_pubkey(&commitment).into();
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining target block failed: {error}"));
    block
}

fn child_signed_spend_fanout_block(
    parent: &Block,
    height: u32,
    source_block: &Block,
    keys: &SigningKeys,
) -> Block {
    let source_coinbase = source_block
        .txs
        .first()
        .unwrap_or_else(|| panic!("signed-spend source block missing coinbase"));
    let source_txid = source_coinbase.txid();
    let mut spends = Vec::with_capacity(SPEND_PROXY_FANOUT as usize);
    for vout in 0..SPEND_PROXY_FANOUT {
        let prevout_value = SPEND_PROXY_COINBASE_OUTPUT_VALUE;
        spends.push(build_signed_spend_tx(
            source_txid,
            vout,
            prevout_value,
            keys,
        ));
    }
    child_signed_target_block(parent, height, keys, spends)
}

fn block_witness_commitment(txs: &[Tx]) -> Hash256 {
    let mut leaves: Vec<[u8; 32]> = txs
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            if i == 0 {
                [0u8; 32]
            } else {
                *tx.wtxid().as_bytes()
            }
        })
        .collect();
    let root = compute_merkle_root(&mut leaves).unwrap_or([0u8; 32]);
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(&WITNESS_RESERVED_VALUE);
    double_sha256(&buffer)
}

fn build_signed_spend_tx(
    source_txid: Txid,
    vout: u32,
    prevout_value: u64,
    keys: &SigningKeys,
) -> Tx {
    let oracle_txid = OracleTxid::from_byte_array(*source_txid.as_bytes());
    if vout < 22 {
        build_signed_p2pkh_spend(
            oracle_txid,
            vout,
            prevout_value,
            keys,
            usize::try_from(vout).unwrap(),
            SIGNED_SPEND_OUTPUT_VALUE,
        )
    } else if vout < 44 {
        build_signed_p2wpkh_spend(
            oracle_txid,
            vout,
            prevout_value,
            keys,
            usize::try_from(vout - 22).unwrap(),
            SIGNED_SPEND_OUTPUT_VALUE,
        )
    } else {
        build_signed_p2wsh_spend(
            oracle_txid,
            vout,
            prevout_value,
            keys,
            SIGNED_SPEND_OUTPUT_VALUE,
        )
    }
}

fn build_signed_p2pkh_spend(
    source_txid: OracleTxid,
    vout: u32,
    _prevout_value: u64,
    keys: &SigningKeys,
    key_index: usize,
    output_value: u64,
) -> Tx {
    let pubkey = keys.p2pkh[key_index];
    let pkh = pubkey.pubkey_hash();
    let script_pubkey = OracleScriptBuf::new_p2pkh(&pkh);
    let mut tx = OracleTx {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![OracleTxIn {
            previous_output: OracleOutPoint {
                txid: source_txid,
                vout,
            },
            script_sig: OracleScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(output_value),
            script_pubkey: OracleScriptBuf::from_bytes(bench_multisig_output_script(keys)),
        }],
    };
    let cache = SighashCache::new(&tx);
    let sighash = cache
        .legacy_signature_hash(0, &script_pubkey, EcdsaSighashType::All as u32)
        .unwrap_or_else(|e| panic!("p2pkh sighash: {e}"));
    let secret = secret_key(0xA0 + key_index as u8);
    let message = SecpMessage::from_digest(*sighash.as_byte_array());
    let mut sig = keys.secp.sign_ecdsa(&message, &secret);
    sig.normalize_s();
    let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut script_sig = Vec::with_capacity(sig_bytes.len() + 35);
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    let pubkey_bytes = pubkey.inner.serialize();
    script_sig.push(pubkey_bytes.len() as u8);
    script_sig.extend_from_slice(&pubkey_bytes);
    tx.input[0].script_sig = OracleScriptBuf::from_bytes(script_sig);
    to_native_tx(&tx)
}

fn build_signed_p2wpkh_spend(
    source_txid: OracleTxid,
    vout: u32,
    prevout_value: u64,
    keys: &SigningKeys,
    key_index: usize,
    output_value: u64,
) -> Tx {
    let pubkey = keys.p2wpkh[key_index];
    let wpkh = pubkey.wpubkey_hash().unwrap();
    let script_pubkey = OracleScriptBuf::new_p2wpkh(&wpkh);
    let mut tx = OracleTx {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![OracleTxIn {
            previous_output: OracleOutPoint {
                txid: source_txid,
                vout,
            },
            script_sig: OracleScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(output_value),
            script_pubkey: OracleScriptBuf::from_bytes(bench_multisig_output_script(keys)),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &script_pubkey,
            OracleAmount::from_sat(prevout_value),
            EcdsaSighashType::All,
        )
        .unwrap_or_else(|e| panic!("p2wpkh sighash: {e}"));
    let secret = secret_key(0xB0 + key_index as u8);
    let message = SecpMessage::from_digest(*sighash.as_byte_array());
    let mut sig = keys.secp.sign_ecdsa(&message, &secret);
    sig.normalize_s();
    let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    tx.input[0].witness =
        OracleWitness::from_slice(&[sig_bytes, pubkey.inner.serialize().to_vec()]);
    to_native_tx(&tx)
}

fn build_signed_p2wsh_spend(
    source_txid: OracleTxid,
    vout: u32,
    prevout_value: u64,
    keys: &SigningKeys,
    output_value: u64,
) -> Tx {
    let redeem = p2wsh_2of3_redeem_script(keys, 0);
    let script_hash = redeem.wscript_hash();
    let _script_pubkey = OracleScriptBuf::new_p2wsh(&script_hash);
    let mut tx = OracleTx {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![OracleTxIn {
            previous_output: OracleOutPoint {
                txid: source_txid,
                vout,
            },
            script_sig: OracleScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(output_value),
            script_pubkey: OracleScriptBuf::from_bytes(bench_multisig_output_script(keys)),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            &redeem,
            OracleAmount::from_sat(prevout_value),
            EcdsaSighashType::All,
        )
        .unwrap_or_else(|e| panic!("p2wsh sighash: {e}"));
    let mut sigs = Vec::with_capacity(2);
    for &key_byte in &[0xC0u8, 0xC1] {
        let secret = secret_key(key_byte);
        let message = SecpMessage::from_digest(*sighash.as_byte_array());
        let mut sig = keys.secp.sign_ecdsa(&message, &secret);
        sig.normalize_s();
        let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);
        sigs.push(sig_bytes);
    }
    let witness_items: Vec<Vec<u8>> = vec![
        Vec::new(),
        sigs[0].clone(),
        sigs[1].clone(),
        redeem.as_bytes().to_vec(),
    ];
    tx.input[0].witness = OracleWitness::from_slice(&witness_items);
    to_native_tx(&tx)
}

fn to_native_tx(tx: &OracleTx) -> Tx {
    let bytes = bitcoin::consensus::serialize(tx);
    deserialize(&bytes).unwrap_or_else(|e| panic!("oracle transaction must decode natively: {e}"))
}

fn print_signed_spend_proxy_summary(blocks: &[Block]) {
    let (_dir, state) = open_regtest_state();
    let payloads: Vec<BlockPayload> = blocks
        .iter()
        .cloned()
        .map(BlockPayload::from_local)
        .collect();
    let started = Instant::now();
    for payload in &payloads {
        state
            .apply_block(payload)
            .unwrap_or_else(|e| panic!("signed-spend summary apply failed: {e}"));
    }
    let elapsed = started.elapsed();
    let applied_height = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("signed-spend summary did not publish a tip"))
        .height;
    let transaction_count: usize = blocks.iter().map(|b| b.txs.len()).sum();
    println!(
        "sync_pipeline_apply_signed_spend_proxy engine={} blocks={} txs={transaction_count} elapsed={elapsed:?}",
        bench_engine(),
        applied_height.saturating_add(1),
    );
}

fn bench_multisig_output_script(keys: &SigningKeys) -> Vec<u8> {
    OracleBuilder::new()
        .push_int(2)
        .push_key(&keys.p2wsh[0])
        .push_key(&keys.p2wsh[1])
        .push_key(&keys.p2wsh[2])
        .push_int(3)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script()
        .to_bytes()
}

fn legacy_signed_spend_proxy_blocks() -> Vec<Block> {
    let keys = SigningKeys::new();
    let spend_start = SPEND_PROXY_COINBASE_MATURITY.saturating_add(1);
    let spend_end = spend_start
        .saturating_add(SPEND_PROXY_SPEND_BLOCKS)
        .saturating_sub(1);
    let capacity = usize::try_from(spend_end.saturating_add(1))
        .unwrap_or_else(|e| panic!("invalid spend capacity: {e}"));
    let genesis = Network::Regtest.genesis_block();
    let mut blocks = Vec::with_capacity(capacity);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..=spend_end {
        let block = if height < spend_start {
            child_signed_fanout_coinbase_block(&parent, height, &keys)
        } else {
            let source_height = height.saturating_sub(SPEND_PROXY_COINBASE_MATURITY);
            let source_index = usize::try_from(source_height)
                .unwrap_or_else(|e| panic!("invalid source height: {e}"));
            legacy_child_signed_spend_fanout_block(&parent, height, &blocks[source_index], &keys)
        };
        parent = block.clone();
        blocks.push(block);
    }
    blocks
}

fn legacy_child_signed_spend_fanout_block(
    parent: &Block,
    height: u32,
    source_block: &Block,
    keys: &SigningKeys,
) -> Block {
    let source_coinbase = source_block
        .txs
        .first()
        .unwrap_or_else(|| panic!("signed-spend source block missing coinbase"));
    let source_txid = source_coinbase.txid();
    let mut txs = Vec::with_capacity(SPEND_PROXY_FANOUT as usize + 1);
    txs.push(signed_fanout_coinbase_transaction(height, keys));
    for vout in 0..SPEND_PROXY_FANOUT {
        let prevout_value = SPEND_PROXY_COINBASE_OUTPUT_VALUE;
        let spend_tx = legacy_build_signed_spend_tx(source_txid, vout, prevout_value, keys);
        txs.push(spend_tx);
    }
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs,
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    let commitment = block_witness_commitment(&block.txs);
    let coinbase = &mut block.txs[0];
    let last = coinbase
        .outputs
        .last_mut()
        .unwrap_or_else(|| panic!("coinbase missing commitment output"));
    last.script_pubkey = witness_commitment_script_pubkey(&commitment).into();
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining proxy block failed: {error}"));
    block
}

fn legacy_build_signed_spend_tx(
    source_txid: Txid,
    vout: u32,
    prevout_value: u64,
    keys: &SigningKeys,
) -> Tx {
    let oracle_txid = OracleTxid::from_byte_array(*source_txid.as_bytes());
    if vout < 22 {
        legacy_build_signed_p2pkh_spend(
            oracle_txid,
            vout,
            prevout_value,
            keys,
            usize::try_from(vout).unwrap(),
        )
    } else if vout < 44 {
        legacy_build_signed_p2wpkh_spend(
            oracle_txid,
            vout,
            prevout_value,
            keys,
            usize::try_from(vout - 22).unwrap(),
        )
    } else {
        legacy_build_signed_p2wsh_spend(oracle_txid, vout, prevout_value, keys)
    }
}

fn legacy_build_signed_p2pkh_spend(
    source_txid: OracleTxid,
    vout: u32,
    _prevout_value: u64,
    keys: &SigningKeys,
    key_index: usize,
) -> Tx {
    let pubkey = keys.p2pkh[key_index];
    let pkh = pubkey.pubkey_hash();
    let script_pubkey = OracleScriptBuf::new_p2pkh(&pkh);
    let mut tx = OracleTx {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![OracleTxIn {
            previous_output: OracleOutPoint {
                txid: source_txid,
                vout,
            },
            script_sig: OracleScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: OracleBuilder::new().push_int(1).into_script(),
        }],
    };
    let cache = SighashCache::new(&tx);
    let sighash = cache
        .legacy_signature_hash(0, &script_pubkey, EcdsaSighashType::All as u32)
        .unwrap_or_else(|e| panic!("p2pkh sighash: {e}"));
    let secret = secret_key(0xA0 + key_index as u8);
    let message = SecpMessage::from_digest(*sighash.as_byte_array());
    let mut sig = keys.secp.sign_ecdsa(&message, &secret);
    sig.normalize_s();
    let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    let mut script_sig = Vec::with_capacity(sig_bytes.len() + 35);
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    let pubkey_bytes = pubkey.inner.serialize();
    script_sig.push(pubkey_bytes.len() as u8);
    script_sig.extend_from_slice(&pubkey_bytes);
    tx.input[0].script_sig = OracleScriptBuf::from_bytes(script_sig);
    to_native_tx(&tx)
}

fn legacy_build_signed_p2wpkh_spend(
    source_txid: OracleTxid,
    vout: u32,
    prevout_value: u64,
    keys: &SigningKeys,
    key_index: usize,
) -> Tx {
    let pubkey = keys.p2wpkh[key_index];
    let wpkh = pubkey.wpubkey_hash().unwrap();
    let script_pubkey = OracleScriptBuf::new_p2wpkh(&wpkh);
    let mut tx = OracleTx {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![OracleTxIn {
            previous_output: OracleOutPoint {
                txid: source_txid,
                vout,
            },
            script_sig: OracleScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: OracleBuilder::new().push_int(1).into_script(),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &script_pubkey,
            OracleAmount::from_sat(prevout_value),
            EcdsaSighashType::All,
        )
        .unwrap_or_else(|e| panic!("p2wpkh sighash: {e}"));
    let secret = secret_key(0xB0 + key_index as u8);
    let message = SecpMessage::from_digest(*sighash.as_byte_array());
    let mut sig = keys.secp.sign_ecdsa(&message, &secret);
    sig.normalize_s();
    let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    tx.input[0].witness =
        OracleWitness::from_slice(&[sig_bytes, pubkey.inner.serialize().to_vec()]);
    to_native_tx(&tx)
}

fn legacy_build_signed_p2wsh_spend(
    source_txid: OracleTxid,
    vout: u32,
    prevout_value: u64,
    keys: &SigningKeys,
) -> Tx {
    let redeem = p2wsh_2of3_redeem_script(keys, 0);
    let script_hash = redeem.wscript_hash();
    let _script_pubkey = OracleScriptBuf::new_p2wsh(&script_hash);
    let mut tx = OracleTx {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![OracleTxIn {
            previous_output: OracleOutPoint {
                txid: source_txid,
                vout,
            },
            script_sig: OracleScriptBuf::new(),
            sequence: OracleSequence::MAX,
            witness: OracleWitness::new(),
        }],
        output: vec![OracleTxOut {
            value: OracleAmount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: OracleBuilder::new().push_int(1).into_script(),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            &redeem,
            OracleAmount::from_sat(prevout_value),
            EcdsaSighashType::All,
        )
        .unwrap_or_else(|e| panic!("p2wsh sighash: {e}"));
    let mut sigs = Vec::with_capacity(2);
    for &key_byte in &[0xC0u8, 0xC1] {
        let secret = secret_key(key_byte);
        let message = SecpMessage::from_digest(*sighash.as_byte_array());
        let mut sig = keys.secp.sign_ecdsa(&message, &secret);
        sig.normalize_s();
        let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);
        sigs.push(sig_bytes);
    }
    let witness_items: Vec<Vec<u8>> = vec![
        Vec::new(),
        sigs[0].clone(),
        sigs[1].clone(),
        redeem.as_bytes().to_vec(),
    ];
    tx.input[0].witness = OracleWitness::from_slice(&witness_items);
    to_native_tx(&tx)
}

fn connect_admitted_unit_once(
    blocks: &[Block],
    last_index: usize,
    last_block: &Block,
    admission_txs: &[Arc<Tx>],
) -> Duration {
    let (_dir, state) = open_regtest_state();
    for block in &blocks[..last_index] {
        let payload = BlockPayload::from_local(block.clone());
        state
            .apply_block(&payload)
            .unwrap_or_else(|error| panic!("prefix apply failed: {error}"));
    }
    admit_signed_spends(&state, admission_txs);
    assert_admission_residency(&state, admission_txs);
    let last_payload = BlockPayload::from_local(last_block.clone());
    let timed = Instant::now();
    state
        .apply_block(black_box(&last_payload))
        .unwrap_or_else(|error| panic!("admitted connect failed: {error}"));
    timed.elapsed()
}

fn connect_unseen_unit_once(blocks: &[Block], last_index: usize, last_block: &Block) -> Duration {
    let (_dir, state) = open_regtest_state();
    for block in &blocks[..last_index] {
        let payload = BlockPayload::from_local(block.clone());
        state
            .apply_block(&payload)
            .unwrap_or_else(|error| panic!("prefix apply failed: {error}"));
    }
    let last_payload = BlockPayload::from_local(last_block.clone());
    let timed = Instant::now();
    state
        .apply_block(black_box(&last_payload))
        .unwrap_or_else(|error| panic!("unseen connect failed: {error}"));
    timed.elapsed()
}

fn admit_signed_spends(state: &NodeState, txs: &[Arc<Tx>]) {
    let gateway = state.mempool_gateway();
    let chainstate = state.chainstate();
    let chain = ChainAdmissionView::new(
        chainstate.utxo_reader(),
        chainstate.applied_tip_reader(),
        chainstate.block_tree_reader(),
        chainstate.network(),
    );
    let max_feerate = Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB);
    for tx in txs {
        let result = gateway.submit_local_transaction(
            Arc::clone(tx),
            LocalOrigin::Rpc,
            max_feerate,
            unix_time_secs(),
            &chain,
        );
        match result {
            Ok(MutationResult { .. }) => {}
            other => panic!("fixture admission failed: {other:?}"),
        }
    }
}

fn assert_admission_residency(state: &NodeState, txs: &[Arc<Tx>]) {
    let reader = state.mempool_reader();
    let pool = reader.read();
    for tx in txs {
        assert!(
            pool.contains_txid(&tx.txid()),
            "fixture admission did not insert txid {}",
            tx.txid(),
        );
    }
}

fn connect_admission_unit_once(
    blocks: &[Block],
    last_index: usize,
    admission_txs: &[Arc<Tx>],
) -> Duration {
    let (_dir, state) = open_regtest_state();
    for block in &blocks[..last_index] {
        let payload = BlockPayload::from_local(block.clone());
        state
            .apply_block(&payload)
            .unwrap_or_else(|error| panic!("prefix apply failed: {error}"));
    }
    let timed = Instant::now();
    admit_signed_spends(&state, admission_txs);
    let elapsed = timed.elapsed();
    assert_admission_residency(&state, admission_txs);
    elapsed
}

const COUNTED_ROWS: [&str; 3] = [
    "connect_admission_throughput/flat",
    "connect_admitted_signed_spend_block/flat",
    "connect_unseen_signed_spend_block/flat",
];

fn run_counted_row(row: &str) {
    match row {
        "connect_admission_throughput/flat" => {
            let blocks = signed_spend_proxy_blocks();
            let last_index = blocks.len().saturating_sub(1);
            let admission_txs: Vec<Arc<Tx>> = blocks[last_index].txs[1..]
                .iter()
                .map(|tx| Arc::new(tx.clone()))
                .collect();
            measured_samples::run(row, || {
                connect_admission_unit_once(&blocks, last_index, &admission_txs)
            });
        }
        "connect_admitted_signed_spend_block/flat" => {
            let blocks = signed_spend_proxy_blocks();
            let last_index = blocks.len().saturating_sub(1);
            let last_block = blocks[last_index].clone();
            let admission_txs: Vec<Arc<Tx>> = last_block.txs[1..]
                .iter()
                .map(|tx| Arc::new(tx.clone()))
                .collect();
            measured_samples::run(row, || {
                connect_admitted_unit_once(&blocks, last_index, &last_block, &admission_txs)
            });
        }
        "connect_unseen_signed_spend_block/flat" => {
            let blocks = signed_spend_proxy_blocks();
            let last_index = blocks.len().saturating_sub(1);
            let last_block = blocks[last_index].clone();
            measured_samples::run(row, || {
                connect_unseen_unit_once(&blocks, last_index, &last_block)
            });
        }
        other => panic!("unknown counted row: {other}"),
    }
}

fn print_percentiles(label: &str, samples: &[Duration]) {
    if samples.is_empty() {
        return;
    }
    let mut sorted: Vec<Duration> = samples.to_vec();
    sorted.sort();
    let n = sorted.len();
    let percentile = |p: f64| -> Duration {
        let rank = p * (n as f64 - 1.0) / 100.0;
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;
        if lower == upper {
            sorted[lower]
        } else {
            let frac = rank - lower as f64;
            let lo = sorted[lower].as_nanos() as f64;
            let hi = sorted[upper].as_nanos() as f64;
            Duration::from_nanos((lo + (hi - lo) * frac) as u64)
        }
    };
    println!(
        "{label} samples={n} p50={:?} p95={:?} p99={:?} max={:?}",
        percentile(50.0),
        percentile(95.0),
        percentile(99.0),
        sorted[n - 1],
    );
}

const MRP_SAMPLE_MEASURED_FLOOR: Duration = Duration::from_secs(2);

const BLOCK_TEMPLATE_POOL_TXS: usize = 100_000;
const BLOCK_TEMPLATE_BACKGROUND_TXS: usize = 98_000;
const BLOCK_TEMPLATE_TARGET_SPENDS: usize = 2_000;
const BLOCK_TEMPLATE_WARMUPS: usize = 3;
const BLOCK_TEMPLATE_SAMPLES: usize = 10;
const BLOCK_TEMPLATE_FANOUT_WIDTH: u32 = 4_096;
const BLOCK_TEMPLATE_FANOUT_BLOCKS: u32 = 32;
const BLOCK_TEMPLATE_FILLER_BLOCKS: u32 = 100;
const BLOCK_TEMPLATE_FUND_VALUE_SAT: u64 = 1_000_000;
const BLOCK_TEMPLATE_SPEND_VALUE_SAT: u64 = BLOCK_TEMPLATE_FUND_VALUE_SAT - 501;
const BLOCK_TEMPLATE_KEY_SLOTS: u32 = 22;

fn wide_signed_fanout_coinbase_transaction(height: u32, keys: &SigningKeys) -> Tx {
    let width = usize::try_from(BLOCK_TEMPLATE_FANOUT_WIDTH)
        .unwrap_or_else(|error| panic!("invalid wide fanout width: {error}"));
    let mut outputs = Vec::with_capacity(width.saturating_add(1));
    for j in 0..BLOCK_TEMPLATE_FANOUT_WIDTH {
        let slot = usize::try_from(j / 3 % BLOCK_TEMPLATE_KEY_SLOTS)
            .unwrap_or_else(|error| panic!("invalid wide key slot: {error}"));
        let script = match j % 3 {
            0 => OracleScriptBuf::new_p2pkh(&keys.p2pkh[slot].pubkey_hash()),
            1 => {
                let wpubkey_hash = keys.p2wpkh[slot]
                    .wpubkey_hash()
                    .unwrap_or_else(|error| panic!("wide p2wpkh key is uncompressed: {error:?}"));
                OracleScriptBuf::new_p2wpkh(&wpubkey_hash)
            }
            _ => {
                let redeem = p2wsh_2of3_redeem_script(keys, 0);
                OracleScriptBuf::new_p2wsh(&redeem.wscript_hash())
            }
        };
        outputs.push(TxOut {
            value: Amount::from_sat(BLOCK_TEMPLATE_FUND_VALUE_SAT),
            script_pubkey: script.as_bytes().to_vec().into(),
        });
    }
    let commitment = witness_commitment_for_coinbase(&outputs);
    outputs.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: witness_commitment_script_pubkey(&commitment).into(),
    });
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height).into(),
            sequence: Sequence::MAX,
            witness: vec![WITNESS_RESERVED_VALUE.to_vec()].into(),
        }],
        outputs,
    }
}

fn child_wide_fanout_coinbase_block(parent: &Block, height: u32, keys: &SigningKeys) -> Block {
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: vec![wide_signed_fanout_coinbase_transaction(height, keys)],
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining wide fanout block failed: {error}"));
    block
}

fn build_wide_signed_spend_tx(source_txid: Txid, vout: u32, keys: &SigningKeys) -> Tx {
    let oracle_txid = OracleTxid::from_byte_array(*source_txid.as_bytes());
    let slot = usize::try_from(vout / 3 % BLOCK_TEMPLATE_KEY_SLOTS)
        .unwrap_or_else(|error| panic!("invalid wide spend slot: {error}"));
    match vout % 3 {
        0 => build_signed_p2pkh_spend(
            oracle_txid,
            vout,
            BLOCK_TEMPLATE_FUND_VALUE_SAT,
            keys,
            slot,
            BLOCK_TEMPLATE_SPEND_VALUE_SAT,
        ),
        1 => build_signed_p2wpkh_spend(
            oracle_txid,
            vout,
            BLOCK_TEMPLATE_FUND_VALUE_SAT,
            keys,
            slot,
            BLOCK_TEMPLATE_SPEND_VALUE_SAT,
        ),
        _ => build_signed_p2wsh_spend(
            oracle_txid,
            vout,
            BLOCK_TEMPLATE_FUND_VALUE_SAT,
            keys,
            BLOCK_TEMPLATE_SPEND_VALUE_SAT,
        ),
    }
}

struct BlockTemplateCorpus {
    prefix: Vec<Block>,
    background: Vec<Arc<Tx>>,
    target_spends: Vec<Vec<Arc<Tx>>>,
    target_blocks: Vec<Block>,
    target_height: u32,
}

fn wide_spend_at(funding: &[Txid], width: usize, keys: &SigningKeys, global: usize) -> Arc<Tx> {
    let source = funding[global / width];
    let vout =
        u32::try_from(global % width).unwrap_or_else(|error| panic!("invalid wide vout: {error}"));
    Arc::new(build_wide_signed_spend_tx(source, vout, keys))
}

fn build_corpus_targets(
    parent: &Block,
    target_height: u32,
    keys: &SigningKeys,
    funding: &[Txid],
    width: usize,
    runs: usize,
) -> (Vec<Vec<Arc<Tx>>>, Vec<Block>) {
    let mut target_spends = Vec::with_capacity(runs);
    let mut target_blocks = Vec::with_capacity(runs);
    for run in 0..runs {
        let mut spends = Vec::with_capacity(BLOCK_TEMPLATE_TARGET_SPENDS);
        for k in 0..BLOCK_TEMPLATE_TARGET_SPENDS {
            spends.push(wide_spend_at(
                funding,
                width,
                keys,
                BLOCK_TEMPLATE_BACKGROUND_TXS
                    .saturating_add(run.saturating_mul(BLOCK_TEMPLATE_TARGET_SPENDS))
                    .saturating_add(k),
            ));
        }
        let mut plain = Vec::with_capacity(spends.len());
        for spend in &spends {
            plain.push(Tx::clone(spend));
        }
        target_blocks.push(child_signed_target_block(
            parent,
            target_height,
            keys,
            plain,
        ));
        target_spends.push(spends);
    }
    for (run, block) in target_blocks.iter().enumerate() {
        assert_eq!(
            block.txs.len(),
            BLOCK_TEMPLATE_TARGET_SPENDS.saturating_add(1),
            "target {run} must carry coinbase plus 2000 spends"
        );
    }
    for (index, block) in target_blocks.iter().enumerate() {
        for earlier in &target_blocks[..index] {
            assert_ne!(
                block.block_hash(),
                earlier.block_hash(),
                "target blocks must be distinct"
            );
        }
    }
    (target_spends, target_blocks)
}
fn build_block_template_corpus() -> BlockTemplateCorpus {
    let runs = BLOCK_TEMPLATE_WARMUPS.saturating_add(BLOCK_TEMPLATE_SAMPLES);
    let funded =
        usize::try_from(BLOCK_TEMPLATE_FANOUT_BLOCKS.saturating_mul(BLOCK_TEMPLATE_FANOUT_WIDTH))
            .unwrap_or_else(|error| panic!("invalid funding count: {error}"));
    let needed = BLOCK_TEMPLATE_BACKGROUND_TXS
        .saturating_add(runs.saturating_mul(BLOCK_TEMPLATE_TARGET_SPENDS));
    assert!(
        funded >= needed,
        "wide funding funds {funded} outputs, need {needed}"
    );
    assert!(
        u64::from(BLOCK_TEMPLATE_FANOUT_WIDTH).saturating_mul(BLOCK_TEMPLATE_FUND_VALUE_SAT)
            <= 5_000_000_000,
        "wide funding exceeds the regtest subsidy"
    );
    let keys = SigningKeys::new();
    let genesis = Network::Regtest.genesis_block();
    let prefix_capacity = usize::try_from(
        BLOCK_TEMPLATE_FANOUT_BLOCKS
            .saturating_add(BLOCK_TEMPLATE_FILLER_BLOCKS)
            .saturating_add(1),
    )
    .unwrap_or_else(|error| panic!("invalid prefix capacity: {error}"));
    let mut prefix = Vec::with_capacity(prefix_capacity);
    prefix.push(genesis.clone());
    let mut funding = Vec::with_capacity(
        usize::try_from(BLOCK_TEMPLATE_FANOUT_BLOCKS)
            .unwrap_or_else(|error| panic!("invalid funding blocks: {error}")),
    );
    let mut parent = genesis;
    for height in 1..=BLOCK_TEMPLATE_FANOUT_BLOCKS {
        let block = child_wide_fanout_coinbase_block(&parent, height, &keys);
        funding.push(
            block
                .txs
                .first()
                .unwrap_or_else(|| panic!("wide fanout missing coinbase"))
                .txid(),
        );
        parent = block.clone();
        prefix.push(block);
    }
    let filler_start = BLOCK_TEMPLATE_FANOUT_BLOCKS.saturating_add(1);
    let filler_end = BLOCK_TEMPLATE_FANOUT_BLOCKS.saturating_add(BLOCK_TEMPLATE_FILLER_BLOCKS);
    for height in filler_start..=filler_end {
        let block = child_coinbase_block(&parent, height);
        parent = block.clone();
        prefix.push(block);
    }
    let target_height = filler_end.saturating_add(1);
    assert!(
        target_height < 150,
        "target height {target_height} must stay below the regtest subsidy halving at 150"
    );
    let width = usize::try_from(BLOCK_TEMPLATE_FANOUT_WIDTH)
        .unwrap_or_else(|error| panic!("invalid wide fanout width: {error}"));
    let mut background = Vec::with_capacity(BLOCK_TEMPLATE_BACKGROUND_TXS);
    for global in 0..BLOCK_TEMPLATE_BACKGROUND_TXS {
        background.push(wide_spend_at(&funding, width, &keys, global));
    }
    let (target_spends, target_blocks) =
        build_corpus_targets(&parent, target_height, &keys, &funding, width, runs);
    BlockTemplateCorpus {
        prefix,
        background,
        target_spends,
        target_blocks,
        target_height,
    }
}

fn print_block_template_corpus_summary(corpus: &BlockTemplateCorpus) {
    println!(
        "block_to_template corpus: prefix_blocks={} tip_height={} funded_outputs={} background={} targets={}x{} total_txs_per_target={}",
        corpus.prefix.len(),
        corpus.target_height.saturating_sub(1),
        BLOCK_TEMPLATE_FANOUT_BLOCKS.saturating_mul(BLOCK_TEMPLATE_FANOUT_WIDTH),
        corpus.background.len(),
        corpus.target_blocks.len(),
        BLOCK_TEMPLATE_TARGET_SPENDS,
        BLOCK_TEMPLATE_TARGET_SPENDS.saturating_add(1),
    );
}

#[derive(Default)]
struct TailCapture {
    t0: Option<quanta::Instant>,
    tail_begins: u64,
    durable_sync_us: Option<u128>,
    durable_commit_us: Option<u128>,
    publish_profiles: u64,
    on_connect_us: Option<u128>,
    on_connects: u64,
}

impl TailCapture {
    const fn new() -> Self {
        Self {
            t0: None,
            tail_begins: 0,
            durable_sync_us: None,
            durable_commit_us: None,
            publish_profiles: 0,
            on_connect_us: None,
            on_connects: 0,
        }
    }
}

static TAIL_CAPTURE: ParkingMutex<TailCapture> = ParkingMutex::new(TailCapture::new());

struct ProfileSubscriber;

impl tracing::Subscriber for ProfileSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor {
            message: Option<String>,
            sync_us: Option<u128>,
            commit_us: Option<u128>,
            on_connect_us: Option<u128>,
        }

        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.message = Some(format!("{value:?}"));
                }
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.message = Some(value.to_owned());
                }
            }

            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.record_u128(field, u128::from(value));
            }

            fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
                match field.name() {
                    "durable_sync_us" => self.sync_us = Some(value),
                    "durable_commit_us" => self.commit_us = Some(value),
                    "on_connect_us" => self.on_connect_us = Some(value),
                    _ => {}
                }
            }
        }

        let mut visitor = Visitor {
            message: None,
            sync_us: None,
            commit_us: None,
            on_connect_us: None,
        };
        event.record(&mut visitor);
        let Some(message) = visitor.message else {
            return;
        };
        let mut capture = TAIL_CAPTURE.lock();
        if message.contains("apply_block: tail begin") {
            capture.tail_begins = capture.tail_begins.saturating_add(1);
            capture.t0 = Some(quanta::Instant::now());
        } else if message.contains("apply_block: publish profile") {
            capture.publish_profiles = capture.publish_profiles.saturating_add(1);
            capture.durable_sync_us = visitor.sync_us;
            capture.durable_commit_us = visitor.commit_us;
        } else if message.contains("chain_effects: on_connect profile") {
            capture.on_connects = capture.on_connects.saturating_add(1);
            capture.on_connect_us = visitor.on_connect_us;
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

fn reset_tail_capture() {
    *TAIL_CAPTURE.lock() = TailCapture::new();
}

fn take_tail_capture() -> TailCapture {
    std::mem::replace(&mut *TAIL_CAPTURE.lock(), TailCapture::new())
}

struct MeasuredMiningControl {
    inner: Arc<MiningCoordinator>,
    calls: ParkingMutex<Vec<MeasuredTemplateCall>>,
}

struct MeasuredTemplateCall {
    elapsed: Duration,
    transactions: usize,
    previous_block_hash: Hash256,
}

impl MeasuredMiningControl {
    fn new(inner: Arc<MiningCoordinator>) -> Self {
        Self {
            inner,
            calls: ParkingMutex::new(Vec::new()),
        }
    }

    fn take_calls(&self) -> Vec<MeasuredTemplateCall> {
        std::mem::take(&mut *self.calls.lock())
    }
}

impl MiningControl for MeasuredMiningControl {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        let started = quanta::Instant::now();
        let result = self.inner.get_block_template(request);
        let elapsed = started.elapsed();
        if let Ok(BlockTemplateResult::Template(template)) = &result {
            self.calls.lock().push(MeasuredTemplateCall {
                elapsed,
                transactions: template.candidate.transactions.len(),
                previous_block_hash: template.candidate.previous_block_hash,
            });
        }
        result
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        self.inner.mining_info()
    }

    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError> {
        self.inner.network_hash_ps(lookup, height)
    }

    fn submit_block(
        &self,
        payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError> {
        self.inner.submit_block(payload)
    }

    fn submit_header(&self, header: Header) -> Result<(), MiningControlError> {
        self.inner.submit_header(header)
    }

    fn publish_generation(&self) {
        self.inner.publish_generation();
    }

    fn publish_fee_delta_generation(&self, fee_delta_sequence: u64) {
        self.inner.publish_fee_delta_generation(fee_delta_sequence);
    }

    fn generate(
        &self,
        request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        self.inner.generate(request)
    }
}

struct BlockTemplateSetup {
    measured: Arc<MeasuredMiningControl>,
    handler: Handler,
    params: sonic_rs::Value,
    pool_live: usize,
    background_len: usize,
}

fn setup_block_template_sample(
    state: &NodeState,
    corpus: &BlockTemplateCorpus,
    run: usize,
) -> BlockTemplateSetup {
    let coordinator = Arc::new(MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        Vec::new(),
    ));
    state.attach_mining_coordinator(&coordinator);
    let measured = Arc::new(MeasuredMiningControl::new(Arc::clone(&coordinator)));
    let control: Arc<dyn MiningControl> = measured.clone();
    let mut rpc_context = Context::new();
    rpc_context.chain.chain_network = Network::Regtest;
    let handler = Handler::new(Arc::new(rpc_context.with_mining_control(control)));
    let params = json!([{"rules": ["segwit"]}]);
    for block in &corpus.prefix {
        let payload = BlockPayload::from_local(block.clone());
        state
            .apply_block(&payload)
            .unwrap_or_else(|error| panic!("template prefix apply failed: {error}"));
    }
    admit_signed_spends(state, &corpus.background);
    let background_len = state.mempool_reader().read().len();
    assert_eq!(
        background_len, BLOCK_TEMPLATE_BACKGROUND_TXS,
        "background admitted {background_len} transactions"
    );
    assert_admission_residency(state, &corpus.background);
    admit_signed_spends(state, &corpus.target_spends[run]);
    let pool_live = state.mempool_reader().read().len();
    assert_eq!(
        pool_live, BLOCK_TEMPLATE_POOL_TXS,
        "target admission left {pool_live} live transactions"
    );
    assert_admission_residency(state, &corpus.target_spends[run]);
    BlockTemplateSetup {
        measured,
        handler,
        params,
        pool_live,
        background_len,
    }
}
struct BlockTemplateUnit {
    tail_to_reply: Duration,
    apply_call_us: u128,
    durable_sync_us: u128,
    durable_commit_us: u128,
    on_connect_us: u128,
    assembly_us: u128,
    remainder_us: u128,
    pool_live: usize,
    background_len: usize,
    pool_at_template: usize,
    block_txs: usize,
    block_noncoinbase: usize,
    tip_hash_be: String,
}

fn run_block_template_unit(corpus: &BlockTemplateCorpus, run: usize) -> BlockTemplateUnit {
    let (_dir, state) = open_regtest_state();
    let BlockTemplateSetup {
        measured,
        handler,
        params,
        pool_live,
        background_len,
    } = setup_block_template_sample(&state, corpus, run);
    reset_tail_capture();
    let target = &corpus.target_blocks[run];
    let target_payload = BlockPayload::from_local(target.clone());
    let target_hash = target.block_hash().0;
    let call_started = quanta::Instant::now();
    let tip = state
        .apply_block(&target_payload)
        .unwrap_or_else(|error| panic!("target connect failed: {error}"));
    assert_eq!(
        tip.hash, target_hash,
        "connect must publish the target block as the new tip"
    );
    let response = handler.dispatch("getblocktemplate", &params);
    let reply_at = quanta::Instant::now();
    let response =
        response.unwrap_or_else(|error| panic!("getblocktemplate dispatch failed: {error}"));
    let previous = response
        .get("previousblockhash")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("template response lacks previousblockhash"));
    assert_eq!(
        previous,
        tip.hash.to_string_be().as_str(),
        "template response must name the new tip"
    );
    let pool_at_template = state.mempool_reader().read().len();
    assert_eq!(
        pool_at_template, BLOCK_TEMPLATE_BACKGROUND_TXS,
        "connect must remove exactly the target spends"
    );
    let calls = measured.take_calls();
    assert_eq!(calls.len(), 1, "exactly one service call per handler reply");
    let call = &calls[0];
    assert_ne!(
        call.transactions, 0,
        "assembled candidate must select transactions"
    );
    assert_eq!(
        call.previous_block_hash, tip.hash,
        "assembled candidate must name the new tip"
    );
    let assembly_us = call.elapsed.as_micros();
    let capture = take_tail_capture();
    assert_eq!(capture.tail_begins, 1, "one connect tail per sample");
    assert_eq!(capture.publish_profiles, 1, "one head commit per sample");
    assert_eq!(capture.on_connects, 1, "one on-connect per sample");
    let durable_sync_us = capture
        .durable_sync_us
        .unwrap_or_else(|| panic!("missing durable_sync_us"));
    let durable_commit_us = capture
        .durable_commit_us
        .unwrap_or_else(|| panic!("missing durable_commit_us"));
    let on_connect_us = capture
        .on_connect_us
        .unwrap_or_else(|| panic!("missing on_connect_us"));
    let t0 = capture
        .t0
        .unwrap_or_else(|| panic!("missing tail-begin edge"));
    let tail_to_reply_us = reply_at.duration_since(t0).as_micros();
    let apply_call_us = reply_at.duration_since(call_started).as_micros();
    let remainder_us = tail_to_reply_us.saturating_sub(
        durable_sync_us
            .saturating_add(durable_commit_us)
            .saturating_add(on_connect_us)
            .saturating_add(assembly_us),
    );
    BlockTemplateUnit {
        tail_to_reply: reply_at.duration_since(t0),
        apply_call_us,
        durable_sync_us,
        durable_commit_us,
        on_connect_us,
        assembly_us,
        remainder_us,
        pool_live,
        background_len,
        pool_at_template,
        block_txs: target.txs.len(),
        block_noncoinbase: target.txs.len().saturating_sub(1),
        tip_hash_be: tip.hash.to_string_be(),
    }
}

fn report_block_template_sample(run: usize, warmup: bool, units: &[BlockTemplateUnit]) {
    let first = units
        .first()
        .unwrap_or_else(|| panic!("block-to-template sample {run} ran no units"));
    for (index, unit) in units.iter().enumerate() {
        assert_eq!(
            unit.tip_hash_be, first.tip_hash_be,
            "sample {run} unit {index} connected a different tip"
        );
        assert_eq!(
            unit.pool_live, first.pool_live,
            "sample {run} unit {index} saw a different live pool"
        );
    }
    let micros = |us: u128| u64::try_from(us).unwrap_or(u64::MAX);
    let nanos = |duration: Duration| {
        u64::try_from(duration.as_nanos()).unwrap_or_else(|error| {
            panic!("block-to-template unit out of u64 nanoseconds: {error}")
        })
    };
    assert!(
        !units.is_empty(),
        "block-to-template sample {run} ran no units"
    );
    let unit_ns: Vec<u64> = units.iter().map(|unit| nanos(unit.tail_to_reply)).collect();
    let total_ns: u128 = units.iter().map(|unit| unit.tail_to_reply.as_nanos()).sum();
    let total_ns = u64::try_from(total_ns)
        .unwrap_or_else(|error| panic!("block-to-template total out of u64 nanoseconds: {error}"));
    assert!(
        total_ns > 0,
        "block-to-template sample {run} measured zero total"
    );
    assert!(
        total_ns >= u64::try_from(MRP_SAMPLE_MEASURED_FLOOR.as_nanos()).unwrap_or(u64::MAX),
        "block-to-template sample {run} total {total_ns}ns below the 2s floor"
    );
    let count = units.len();
    let splits = |pick: fn(&BlockTemplateUnit) -> u128| -> Vec<u64> {
        units.iter().map(|unit| micros(pick(unit))).collect()
    };
    let line = sonic_rs::to_string(&json!({
        "bench": "block_to_template_baseline",
        "sample": run,
        "warmup": warmup,
        "engine": sample_engine_label(),
        "pool_txs": first.pool_live,
        "background_txs": first.background_len,
        "pool_at_template": first.pool_at_template,
        "block_txs": first.block_txs,
        "block_noncoinbase": first.block_noncoinbase,
        "tip": first.tip_hash_be,
        "unit_ns": unit_ns,
        "unit_count": count,
        "total_ns": total_ns,
        "apply_call_to_reply_us": splits(|unit| unit.apply_call_us),
        "durable_sync_us": splits(|unit| unit.durable_sync_us),
        "durable_commit_us": splits(|unit| unit.durable_commit_us),
        "on_connect_us": splits(|unit| unit.on_connect_us),
        "assembly_us": splits(|unit| unit.assembly_us),
        "remainder_us": splits(|unit| unit.remainder_us),
        "boundary": "in-process RPC Handler::dispatch getblocktemplate response on a per-sample coordinator (parse, readiness, rule negotiation, one service assembly, mandatory-rule checks, JSON render); assembly_us is the single service call the dispatch performs; excludes HTTP transport and JSON-RPC framing/auth only",
    }))
    .unwrap_or_else(|error| panic!("render block-to-template sample: {error}"));
    println!("{line}");
}
fn block_to_template_baseline(_c: &mut Criterion) {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--list" || arg == "--help") {
        return;
    }
    if !args.iter().any(|arg| arg == "block_to_template_baseline") {
        return;
    }
    let corpus = build_block_template_corpus();
    print_block_template_corpus_summary(&corpus);
    assert_eq!(
        corpus.target_blocks.len(),
        BLOCK_TEMPLATE_WARMUPS.saturating_add(BLOCK_TEMPLATE_SAMPLES),
        "one distinct target block per warmup and measured sample"
    );
    tracing::subscriber::set_global_default(ProfileSubscriber)
        .unwrap_or_else(|error| panic!("profile subscriber install failed: {error}"));
    let mut sample_means = Vec::with_capacity(BLOCK_TEMPLATE_SAMPLES);
    for run in 0..corpus.target_blocks.len() {
        let warmup = run < BLOCK_TEMPLATE_WARMUPS;
        let mut units = Vec::new();
        let mut total = Duration::ZERO;
        loop {
            let unit = run_block_template_unit(&corpus, run);
            total += unit.tail_to_reply;
            units.push(unit);
            if total >= MRP_SAMPLE_MEASURED_FLOOR {
                break;
            }
        }
        let mean = total
            .checked_div(
                u32::try_from(units.len())
                    .unwrap_or_else(|error| panic!("bad block-to-template unit count: {error}")),
            )
            .unwrap_or_else(|| panic!("block-to-template sample {run} ran no units"));
        report_block_template_sample(run, warmup, &units);
        if !warmup {
            sample_means.push(mean);
        }
    }
    print_percentiles("block_to_template_tail_to_reply", &sample_means);
}

const TEMPLATE_RENDER_WARMUPS: usize = 3;
const TEMPLATE_RENDER_SAMPLES: usize = 10;

fn template_render_request() -> BlockTemplateRequest {
    BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
        coinbase_budget: None,
    }
}

struct TemplateRenderSetup {
    control: Arc<dyn MiningControl>,
    handler: Handler,
    params: sonic_rs::Value,
    pool_live: usize,
    background_len: usize,
    tip: Arc<TipSnapshot>,
}

fn setup_template_render_sample(
    state: &NodeState,
    corpus: &BlockTemplateCorpus,
    run: usize,
) -> TemplateRenderSetup {
    let coordinator = Arc::new(MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        Vec::new(),
    ));
    state.attach_mining_coordinator(&coordinator);
    let control: Arc<dyn MiningControl> = coordinator;
    let mut rpc_context = Context::new();
    rpc_context.chain.chain_network = Network::Regtest;
    let handler = Handler::new(Arc::new(
        rpc_context.with_mining_control(Arc::clone(&control)),
    ));
    let params = json!([{"rules": ["segwit"]}]);
    for block in &corpus.prefix {
        let payload = BlockPayload::from_local(block.clone());
        state
            .apply_block(&payload)
            .unwrap_or_else(|error| panic!("render prefix apply failed: {error}"));
    }
    admit_signed_spends(state, &corpus.background);
    let background_len = state.mempool_reader().read().len();
    assert_eq!(
        background_len, BLOCK_TEMPLATE_BACKGROUND_TXS,
        "render background admitted {background_len} transactions"
    );
    assert_admission_residency(state, &corpus.background);
    admit_signed_spends(state, &corpus.target_spends[run]);
    let pool_live = state.mempool_reader().read().len();
    assert_eq!(
        pool_live, BLOCK_TEMPLATE_POOL_TXS,
        "render admission left {pool_live} live transactions"
    );
    assert_admission_residency(state, &corpus.target_spends[run]);
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("render sample published no tip"));
    TemplateRenderSetup {
        control,
        handler,
        params,
        pool_live,
        background_len,
        tip,
    }
}
fn render_cold_unit(
    corpus: &BlockTemplateCorpus,
    run: usize,
) -> (
    TempDir,
    NodeState,
    TemplateRenderSetup,
    Duration,
    sonic_rs::Value,
) {
    let (dir, state) = open_regtest_state();
    let setup = setup_template_render_sample(&state, corpus, run);
    let cold_started = quanta::Instant::now();
    let cold_rpc = setup
        .handler
        .dispatch("getblocktemplate", &setup.params)
        .unwrap_or_else(|error| panic!("render cold dispatch failed: {error:?}"));
    let cold = cold_started.elapsed();
    (dir, state, setup, cold, cold_rpc)
}

fn render_service_call(control: &Arc<dyn MiningControl>) -> (Duration, Arc<Candidate>) {
    let svc_started = quanta::Instant::now();
    let svc = control
        .get_block_template(template_render_request())
        .unwrap_or_else(|error| panic!("render service hit failed: {error:?}"));
    let elapsed = svc_started.elapsed();
    let BlockTemplateResult::Template(template) = svc else {
        panic!("render service hit returned a proposal result");
    };
    (elapsed, template.candidate)
}

fn render_warm_dispatch(
    handler: &Handler,
    params: &sonic_rs::Value,
) -> (Duration, sonic_rs::Value) {
    let hit_started = quanta::Instant::now();
    let hit_rpc = handler
        .dispatch("getblocktemplate", params)
        .unwrap_or_else(|error| panic!("render warm dispatch failed: {error:?}"));
    let elapsed = hit_started.elapsed();
    (elapsed, hit_rpc)
}

fn collect_render_cold_arm(
    corpus: &BlockTemplateCorpus,
    run: usize,
    cold_units: &mut Vec<Duration>,
    cold_total: &mut Duration,
) -> (TempDir, NodeState, TemplateRenderSetup, sonic_rs::Value) {
    loop {
        let (dir, state, setup, cold, cold_rpc) = render_cold_unit(corpus, run);
        *cold_total += cold;
        cold_units.push(cold);
        if *cold_total >= MRP_SAMPLE_MEASURED_FLOOR {
            break (dir, state, setup, cold_rpc);
        }
    }
}

fn collect_render_service_arm(
    control: &Arc<dyn MiningControl>,
    service_units: &mut Vec<Duration>,
    service_total: &mut Duration,
) -> (Arc<Candidate>, Arc<Candidate>, usize, u64) {
    let (first_elapsed, first_candidate) = render_service_call(control);
    *service_total += first_elapsed;
    service_units.push(first_elapsed);
    let selected_txs = first_candidate.transactions.len();
    let selected_weight = first_candidate.weight;
    let svc_first = Arc::clone(&first_candidate);
    let svc_last = if *service_total >= MRP_SAMPLE_MEASURED_FLOOR {
        first_candidate
    } else {
        loop {
            let (elapsed, candidate) = render_service_call(control);
            *service_total += elapsed;
            service_units.push(elapsed);
            if *service_total >= MRP_SAMPLE_MEASURED_FLOOR {
                break candidate;
            }
        }
    };
    (svc_first, svc_last, selected_txs, selected_weight)
}

fn collect_render_service2_arm(
    control: &Arc<dyn MiningControl>,
    service2_units: &mut Vec<Duration>,
    service2_total: &mut Duration,
) -> Arc<Candidate> {
    loop {
        let (elapsed, candidate) = render_service_call(control);
        *service2_total += elapsed;
        service2_units.push(elapsed);
        if *service2_total >= MRP_SAMPLE_MEASURED_FLOOR {
            break candidate;
        }
    }
}

fn collect_render_rpc_arm(
    handler: &Handler,
    params: &sonic_rs::Value,
    run: usize,
    rpc_units: &mut Vec<Duration>,
    rpc_total: &mut Duration,
) -> (sonic_rs::Value, sonic_rs::Value) {
    let mut rpc_first: Option<sonic_rs::Value> = None;
    let mut rpc_last: Option<sonic_rs::Value> = None;
    loop {
        let (elapsed, reply) = render_warm_dispatch(handler, params);
        *rpc_total += elapsed;
        rpc_units.push(elapsed);
        if rpc_first.is_none() {
            rpc_first = Some(reply);
        } else {
            rpc_last = Some(reply);
        }
        if *rpc_total >= MRP_SAMPLE_MEASURED_FLOOR {
            break;
        }
    }
    let rpc_first = rpc_first.unwrap_or_else(|| panic!("render sample {run} ran no warm RPC hits"));
    let rpc_last = rpc_last.unwrap_or_else(|| rpc_first.clone());
    (rpc_first, rpc_last)
}

fn run_template_render_sample(
    corpus: &BlockTemplateCorpus,
    run: usize,
    warmup: bool,
) -> (Duration, Duration, Duration, Duration) {
    let mut cold_units: Vec<Duration> = Vec::new();
    let mut cold_total = Duration::ZERO;
    let (_dir, _state, setup, cold_rpc) =
        collect_render_cold_arm(corpus, run, &mut cold_units, &mut cold_total);
    let TemplateRenderSetup {
        control,
        handler,
        params,
        pool_live,
        background_len,
        tip,
    } = setup;
    let tip_hash_be = tip.hash.to_string_be();
    let tip_height = tip.height;
    let mut service_units: Vec<Duration> = Vec::new();
    let mut service_total = Duration::ZERO;
    let (svc_first, svc_last, selected_txs, selected_weight) =
        collect_render_service_arm(&control, &mut service_units, &mut service_total);
    let mut service2_units: Vec<Duration> = Vec::new();
    let mut service2_total = Duration::ZERO;
    let svc2_last = collect_render_service2_arm(&control, &mut service2_units, &mut service2_total);
    assert_render_service_reuse_arcs(&svc_first, &svc_last, &tip.hash);
    assert_render_service_reuse_arcs(&svc_first, &svc2_last, &tip.hash);
    let mut rpc_units: Vec<Duration> = Vec::new();
    let mut rpc_total = Duration::ZERO;
    let (rpc_first, rpc_last) =
        collect_render_rpc_arm(&handler, &params, run, &mut rpc_units, &mut rpc_total);
    assert_render_deterministic_fields(&cold_rpc, &rpc_first);
    assert_render_deterministic_fields(&cold_rpc, &rpc_last);
    let (cold_curtime, hit_curtime, mintime, cold_lp) = assert_render_reply_identity(
        &cold_rpc,
        &rpc_last,
        &tip_hash_be,
        svc_first.template_id.as_str(),
    );
    let mean_of = |total: Duration, units: &[Duration]| {
        total
            .checked_div(
                u32::try_from(units.len())
                    .unwrap_or_else(|error| panic!("bad render unit count: {error}")),
            )
            .unwrap_or_else(|| panic!("render sample {run} ran no units"))
    };
    let report = TemplateRenderReport {
        pool_live,
        background_len,
        tip_hash_be: &tip_hash_be,
        tip_height,
        cold_lp,
        selected_txs,
        selected_weight,
        hit_rpc: &rpc_last,
        cold_curtime,
        hit_curtime,
        mintime,
        cold_units: &cold_units,
        cold_total,
        service_units: &service_units,
        service_total,
        service2_units: &service2_units,
        service2_total,
        rpc_units: &rpc_units,
        rpc_total,
        run,
        warmup,
    };
    report_render_sample(&report);
    (
        mean_of(cold_total, &cold_units),
        mean_of(service_total, &service_units),
        mean_of(service2_total, &service2_units),
        mean_of(rpc_total, &rpc_units),
    )
}

fn assert_render_service_reuse_arcs(
    candidate_a: &Arc<Candidate>,
    candidate_b: &Arc<Candidate>,
    tip_hash: &Hash256,
) {
    assert!(
        Arc::ptr_eq(candidate_a, candidate_b),
        "warm service calls must reuse the cached candidate Arc"
    );
    assert_eq!(
        candidate_a.template_id.as_str(),
        candidate_b.template_id.as_str(),
        "warm service calls must keep the generation identity"
    );
    assert_eq!(
        candidate_a.previous_block_hash, candidate_b.previous_block_hash,
        "warm service calls must name the same tip"
    );
    assert_eq!(
        candidate_a.mempool_sequence, candidate_b.mempool_sequence,
        "warm service calls must keep the mempool sequence"
    );
    assert_eq!(
        candidate_a.height, candidate_b.height,
        "warm service calls must keep the candidate height"
    );
    assert_eq!(
        candidate_a.previous_block_hash, *tip_hash,
        "render candidate must extend the prefix tip"
    );
    assert_ne!(
        candidate_a.transactions.len(),
        0,
        "render candidate must select transactions from the 100k pool"
    );
}

fn assert_render_deterministic_fields(cold_rpc: &sonic_rs::Value, hit_rpc: &sonic_rs::Value) {
    for key in [
        "version",
        "rules",
        "vbavailable",
        "capabilities",
        "vbrequired",
        "previousblockhash",
        "transactions",
        "coinbaseaux",
        "coinbasevalue",
        "longpollid",
        "target",
        "mintime",
        "mutable",
        "noncerange",
        "sigoplimit",
        "sizelimit",
        "weightlimit",
        "bits",
        "height",
        "signet_challenge",
        "default_witness_commitment",
    ] {
        assert_eq!(
            cold_rpc.get(key),
            hit_rpc.get(key),
            "warm RPC hit changed deterministic field {key}"
        );
    }
}

fn assert_render_reply_identity<'a>(
    cold_rpc: &'a sonic_rs::Value,
    hit_rpc: &sonic_rs::Value,
    tip_hash_be: &str,
    template_id: &str,
) -> (u64, u64, u64, &'a str) {
    let cold_curtime = cold_rpc
        .get("curtime")
        .and_then(JsonValueTrait::as_u64)
        .unwrap_or_else(|| panic!("cold render reply lacks curtime"));
    let hit_curtime = hit_rpc
        .get("curtime")
        .and_then(JsonValueTrait::as_u64)
        .unwrap_or_else(|| panic!("warm render reply lacks curtime"));
    let cold_mintime = cold_rpc
        .get("mintime")
        .and_then(JsonValueTrait::as_u64)
        .unwrap_or_else(|| panic!("cold render reply lacks mintime"));
    let hit_mintime = hit_rpc
        .get("mintime")
        .and_then(JsonValueTrait::as_u64)
        .unwrap_or_else(|| panic!("warm render reply lacks mintime"));
    assert_eq!(
        cold_mintime, hit_mintime,
        "mintime is chain-determined and must not move on a warm hit"
    );
    assert!(
        hit_curtime >= cold_curtime,
        "warm-hit curtime {hit_curtime} must not go below cold {cold_curtime}"
    );
    assert!(
        hit_curtime >= hit_mintime,
        "warm-hit curtime {hit_curtime} must sit at or above mintime {hit_mintime}"
    );
    assert!(
        cold_curtime >= cold_mintime,
        "cold curtime {cold_curtime} must sit at or above mintime {cold_mintime}"
    );
    let cold_prev = cold_rpc
        .get("previousblockhash")
        .and_then(JsonValueTrait::as_str)
        .unwrap_or_else(|| panic!("cold render reply lacks previousblockhash"));
    let hit_prev = hit_rpc
        .get("previousblockhash")
        .and_then(JsonValueTrait::as_str)
        .unwrap_or_else(|| panic!("warm render reply lacks previousblockhash"));
    assert_eq!(
        cold_prev, tip_hash_be,
        "cold render reply must name the prefix tip"
    );
    assert_eq!(
        hit_prev, tip_hash_be,
        "warm render reply must name the prefix tip"
    );
    let cold_lp = cold_rpc
        .get("longpollid")
        .and_then(JsonValueTrait::as_str)
        .unwrap_or_else(|| panic!("cold render reply lacks longpollid"));
    let hit_lp = hit_rpc
        .get("longpollid")
        .and_then(JsonValueTrait::as_str)
        .unwrap_or_else(|| panic!("warm render reply lacks longpollid"));
    assert_eq!(
        cold_lp, hit_lp,
        "warm hit must keep the cold reply's generation identity"
    );
    assert_eq!(
        cold_lp, template_id,
        "RPC longpollid must equal the served candidate generation"
    );
    (cold_curtime, hit_curtime, hit_mintime, cold_lp)
}

struct TemplateRenderReport<'a> {
    pool_live: usize,
    background_len: usize,
    tip_hash_be: &'a str,
    tip_height: u32,
    cold_lp: &'a str,
    selected_txs: usize,
    selected_weight: u64,
    hit_rpc: &'a sonic_rs::Value,
    cold_curtime: u64,
    hit_curtime: u64,
    mintime: u64,
    cold_units: &'a [Duration],
    cold_total: Duration,
    service_units: &'a [Duration],
    service_total: Duration,
    service2_units: &'a [Duration],
    service2_total: Duration,
    rpc_units: &'a [Duration],
    rpc_total: Duration,
    run: usize,
    warmup: bool,
}
fn render_report_selection_facts(report: &TemplateRenderReport) -> (usize, usize) {
    let &TemplateRenderReport {
        hit_rpc,
        selected_txs,
        cold_units,
        service_units,
        service2_units,
        rpc_units,
        run,
        ..
    } = report;
    let rpc_array = hit_rpc
        .get("transactions")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("warm render reply lacks transactions array"));
    let rpc_txs = rpc_array.len();
    assert_eq!(
        rpc_txs, selected_txs,
        "RPC transactions must render every selected candidate transaction"
    );
    let mut rpc_data_bytes: usize = 0;
    for index in 0..rpc_array.len() {
        let data_len = rpc_array[index]
            .get("data")
            .and_then(JsonValueTrait::as_str)
            .unwrap_or_else(|| panic!("warm render transaction lacks data"))
            .len();
        rpc_data_bytes = rpc_data_bytes.saturating_add(data_len / 2);
    }
    assert!(
        !cold_units.is_empty(),
        "render sample {run} ran no cold units"
    );
    assert!(
        !service_units.is_empty(),
        "render sample {run} ran no service hits"
    );
    assert!(
        !service2_units.is_empty(),
        "render sample {run} ran no service proof hits"
    );
    assert!(
        !rpc_units.is_empty(),
        "render sample {run} ran no warm RPC hits"
    );
    (rpc_txs, rpc_data_bytes)
}

fn report_render_sample(report: &TemplateRenderReport) {
    let (rpc_txs, rpc_data_bytes) = render_report_selection_facts(report);
    let &TemplateRenderReport {
        pool_live,
        background_len,
        tip_hash_be,
        tip_height,
        cold_lp,
        selected_txs,
        selected_weight,
        hit_rpc: _,
        cold_curtime,
        hit_curtime,
        mintime,
        cold_units,
        cold_total,
        service_units,
        service_total,
        service2_units,
        service2_total,
        rpc_units,
        rpc_total,
        run,
        warmup,
    } = report;
    let nanos = |duration: Duration| {
        u64::try_from(duration.as_nanos())
            .unwrap_or_else(|error| panic!("template-render unit out of u64 nanoseconds: {error}"))
    };
    let unit_ns =
        |units: &[Duration]| -> Vec<u64> { units.iter().map(|unit| nanos(*unit)).collect() };
    let total_ns = |total: Duration, arm: &str| -> u64 {
        assert!(
            total > Duration::ZERO,
            "render sample {run} {arm} measured zero total"
        );
        assert!(
            total >= MRP_SAMPLE_MEASURED_FLOOR,
            "render sample {run} {arm} total {total:?} below the 2s floor"
        );
        u64::try_from(total.as_nanos()).unwrap_or_else(|error| {
            panic!("template-render {arm} total out of u64 nanoseconds: {error}")
        })
    };
    let line = sonic_rs::to_string(&json!({
        "bench": "template_render_baseline",
        "sample": run,
        "warmup": warmup,
        "engine": sample_engine_label(),
        "pool_txs": pool_live,
        "background_txs": background_len,
        "pool_at_template": pool_live,
        "selected_txs": selected_txs,
        "selected_weight": selected_weight,
        "rpc_txs": rpc_txs,
        "rpc_data_bytes": rpc_data_bytes,
        "tip": tip_hash_be,
        "tip_height": tip_height,
        "longpollid": cold_lp,
        "rpc_miss_ns": unit_ns(cold_units),
        "rpc_miss_count": cold_units.len(),
        "rpc_miss_total_ns": total_ns(cold_total, "rpc_miss"),
        "service_hit_ns": unit_ns(service_units),
        "service_hit_count": service_units.len(),
        "service_hit_total_ns": total_ns(service_total, "service_hit"),
        "service_hit2_ns": unit_ns(service2_units),
        "service_hit2_count": service2_units.len(),
        "service_hit2_total_ns": total_ns(service2_total, "service_hit2"),
        "rpc_hit_ns": unit_ns(rpc_units),
        "rpc_hit_count": rpc_units.len(),
        "rpc_hit_total_ns": total_ns(rpc_total, "rpc_hit"),
        "cold_curtime": cold_curtime,
        "hit_curtime": hit_curtime,
        "mintime": mintime,
        "arc_reuse": true,
        "boundary_rpc_miss": "in-process Handler::dispatch cold miss on a fresh state: parse, readiness, rule negotiation, one service assembly (selection plus finish plus projection including signalling_rules), mandatory-rule checks, JSON render (consensus_bytes plus hex per tx); warms the generation cache; excludes HTTP transport and JSON-RPC framing/auth only",
        "boundary_service_hit": "MiningControl::get_block_template hit on the retained generation: signalling_rules plus template_from_candidate projection only; no assembly, no JSON",
        "boundary_rpc_hit": "in-process Handler::dispatch warm hit on the retained generation: parse, readiness, rule negotiation, cache-hit projection, mandatory-rule checks, JSON render; no assembly; excludes HTTP transport and JSON-RPC framing/auth only",
        "time_note": "candidate_context reads the wall clock (current_unix_seconds, no injection); asserted as hit >= cold and both >= mintime, never strict equality",
    }))
    .unwrap_or_else(|error| panic!("render template_render sample: {error}"));
    println!("{line}");
}
fn template_render_baseline(_c: &mut Criterion) {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--list" || arg == "--help") {
        return;
    }
    if !args.iter().any(|arg| arg == "template_render_baseline") {
        return;
    }
    let corpus = build_block_template_corpus();
    print_block_template_corpus_summary(&corpus);
    assert_eq!(
        corpus.target_spends.len(),
        TEMPLATE_RENDER_WARMUPS.saturating_add(TEMPLATE_RENDER_SAMPLES),
        "one distinct resident pool per warmup and measured sample"
    );
    let mut rpc_miss = Vec::with_capacity(TEMPLATE_RENDER_SAMPLES);
    let mut service_hit = Vec::with_capacity(TEMPLATE_RENDER_SAMPLES);
    let mut service_hit2 = Vec::with_capacity(TEMPLATE_RENDER_SAMPLES);
    let mut rpc_hit = Vec::with_capacity(TEMPLATE_RENDER_SAMPLES);
    for run in 0..corpus.target_spends.len() {
        let (miss, hit, hit2, rhit) =
            run_template_render_sample(&corpus, run, run < TEMPLATE_RENDER_WARMUPS);
        if run >= TEMPLATE_RENDER_WARMUPS {
            rpc_miss.push(miss);
            service_hit.push(hit);
            service_hit2.push(hit2);
            rpc_hit.push(rhit);
        }
    }
    print_percentiles("template_render_rpc_miss", &rpc_miss);
    print_percentiles("template_render_service_hit", &service_hit);
    print_percentiles("template_render_service_hit2", &service_hit2);
    print_percentiles("template_render_rpc_hit", &rpc_hit);
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(20));
    targets = sync_pipeline_apply_proxy,
    sync_pipeline_apply_signed_spend_proxy,
    deterministic_initial_sync_proxy,
    block_to_template_baseline,
    template_render_baseline
);

fn mrp_verify() {
    let corpus = build_block_template_corpus();
    print_block_template_corpus_summary(&corpus);
    assert_eq!(
        corpus.target_blocks.len(),
        BLOCK_TEMPLATE_WARMUPS.saturating_add(BLOCK_TEMPLATE_SAMPLES),
        "one distinct target block per warmup and measured sample"
    );
    assert_eq!(
        corpus.target_spends.len(),
        TEMPLATE_RENDER_WARMUPS.saturating_add(TEMPLATE_RENDER_SAMPLES),
        "one distinct resident pool per warmup and measured sample"
    );
    tracing::subscriber::set_global_default(ProfileSubscriber)
        .unwrap_or_else(|error| panic!("profile subscriber install failed: {error}"));
    let unit = run_block_template_unit(&corpus, 0);
    println!(
        "mrp-verify: block_to_template unit ok (tip {}, pool {} live)",
        unit.tip_hash_be, unit.pool_live,
    );
    let (_dir, _state, setup, _, cold_reply) = render_cold_unit(&corpus, 0);
    let (_, candidate_a) = render_service_call(&setup.control);
    let (_, candidate_b) = render_service_call(&setup.control);
    assert_render_service_reuse_arcs(&candidate_a, &candidate_b, &setup.tip.hash);
    let (_, warm_reply) = render_warm_dispatch(&setup.handler, &setup.params);
    assert_render_deterministic_fields(&cold_reply, &warm_reply);
    let (_, _, _, cold_lp) = assert_render_reply_identity(
        &cold_reply,
        &warm_reply,
        setup.tip.hash.to_string_be().as_str(),
        candidate_a.template_id.as_str(),
    );
    println!(
        "mrp-verify: template_render unit ok (tip {}, pool {} live, generation {cold_lp})",
        setup.tip.hash.to_string_be(),
        setup.pool_live,
    );
    let blocks = signed_spend_proxy_blocks();
    let last_index = blocks.len().saturating_sub(1);
    let last_block = &blocks[last_index];
    let admission_txs: Vec<Arc<Tx>> = last_block.txs[1..]
        .iter()
        .map(|tx| Arc::new(tx.clone()))
        .collect();
    let admitted = admission_txs.len();
    {
        let (_dir, state) = open_regtest_state();
        for block in &blocks[..last_index] {
            let payload = BlockPayload::from_local(block.clone());
            state
                .apply_block(&payload)
                .unwrap_or_else(|error| panic!("mrp-verify prefix apply failed: {error}"));
        }
        admit_signed_spends(&state, &admission_txs);
        assert_admission_residency(&state, &admission_txs);
        let last_payload = BlockPayload::from_local(last_block.clone());
        let tip = state
            .apply_block(&last_payload)
            .unwrap_or_else(|error| panic!("mrp-verify admitted connect failed: {error}"));
        assert_eq!(
            tip.hash,
            last_block.block_hash().0,
            "mrp-verify admitted connect must publish the final block"
        );
    }
    println!("mrp-verify: connect_admitted unit ok ({admitted} admitted spends connected)");
    {
        let (_dir, state) = open_regtest_state();
        for block in &blocks[..last_index] {
            let payload = BlockPayload::from_local(block.clone());
            state
                .apply_block(&payload)
                .unwrap_or_else(|error| panic!("mrp-verify prefix apply failed: {error}"));
        }
        let last_payload = BlockPayload::from_local(last_block.clone());
        let tip = state
            .apply_block(&last_payload)
            .unwrap_or_else(|error| panic!("mrp-verify unseen connect failed: {error}"));
        assert_eq!(
            tip.hash,
            last_block.block_hash().0,
            "mrp-verify unseen connect must publish the final block"
        );
    }
    println!("mrp-verify: connect_unseen unit ok (final block connected without admission)");
    {
        let (_dir, state) = open_regtest_state();
        for block in &blocks[..last_index] {
            let payload = BlockPayload::from_local(block.clone());
            state
                .apply_block(&payload)
                .unwrap_or_else(|error| panic!("mrp-verify prefix apply failed: {error}"));
        }
        admit_signed_spends(&state, &admission_txs);
        assert_admission_residency(&state, &admission_txs);
    }
    println!("mrp-verify: admission_throughput unit ok ({admitted} gateway submits resident)");
    print_mrp_node_identity(&corpus, &unit, &setup);
    println!("mrp-verify: PASS");
}

fn print_mrp_node_identity(
    corpus: &BlockTemplateCorpus,
    unit: &BlockTemplateUnit,
    setup: &TemplateRenderSetup,
) {
    let engine = sample_engine_label();
    let tips: Vec<String> = corpus
        .target_blocks
        .iter()
        .map(|block| block.block_hash().0.to_string_be())
        .collect();
    let mut line = b"mrp-verify: node_identity ".to_vec();
    sonic_rs::to_writer(
        &mut line,
        &sonic_rs::json!({
            "block_to_template_baseline": {
                "background_txs": unit.background_len,
                "block_noncoinbase": unit.block_noncoinbase,
                "block_txs": unit.block_txs,
                "engine": engine,
                "pool_at_template": unit.pool_at_template,
                "pool_txs": unit.pool_live,
                "tips": tips,
            },
            "template_render_baseline": {
                "background_txs": setup.background_len,
                "engine": engine,
                "pool_at_template": setup.pool_live,
                "pool_txs": setup.pool_live,
                "tip": setup.tip.hash.to_string_be(),
                "tip_height": setup.tip.height,
            },
        }),
    )
    .unwrap_or_else(|error| panic!("render node identity pins: {error}"));
    line.push(b'\n');
    std::io::stdout()
        .lock()
        .write_all(&line)
        .unwrap_or_else(|error| panic!("write node identity pins: {error}"));
}

fn mrp_verify_counted() {
    {
        let blocks = signed_spend_proxy_blocks();
        let last_index = blocks.len().saturating_sub(1);
        let last_block = blocks[last_index].clone();
        let admission_txs: Vec<Arc<Tx>> = last_block.txs[1..]
            .iter()
            .map(|tx| Arc::new(tx.clone()))
            .collect();
        let admitted = admission_txs.len();
        connect_admitted_unit_once(&blocks, last_index, &last_block, &admission_txs);
        println!(
            "mrp-verify-counted: connect_admitted_signed_spend_block/flat unit ok ({admitted} admitted spends connected)"
        );
    }
    {
        let blocks = signed_spend_proxy_blocks();
        let last_index = blocks.len().saturating_sub(1);
        let last_block = blocks[last_index].clone();
        connect_unseen_unit_once(&blocks, last_index, &last_block);
        println!(
            "mrp-verify-counted: connect_unseen_signed_spend_block/flat unit ok (final block connected without admission)"
        );
    }
    {
        let blocks = signed_spend_proxy_blocks();
        let last_index = blocks.len().saturating_sub(1);
        let admission_txs: Vec<Arc<Tx>> = blocks[last_index].txs[1..]
            .iter()
            .map(|tx| Arc::new(tx.clone()))
            .collect();
        let admitted = admission_txs.len();
        connect_admission_unit_once(&blocks, last_index, &admission_txs);
        println!(
            "mrp-verify-counted: connect_admission_throughput/flat unit ok ({admitted} gateway submits resident)"
        );
    }
    measured_samples::verify_stopping_rule();
    println!("mrp-verify-counted: stopping-rule arithmetic ok");
    println!("mrp-verify-counted: PASS");
}

fn counted_cli_row(args: &[String]) -> &str {
    let fail = |message: &str| -> ! {
        eprintln!("mrp-counted: {message}");
        eprintln!(
            "usage: sync_pipeline --mrp-counted <{}>",
            COUNTED_ROWS.join("|")
        );
        std::process::exit(2);
    };
    if args.len() != 2 {
        fail("expected exactly one row ID after --mrp-counted");
    }
    if args[0] != "--mrp-counted" {
        fail("unexpected arguments around --mrp-counted");
    }
    if !COUNTED_ROWS.contains(&args[1].as_str()) {
        fail("unknown counted row ID");
    }
    &args[1]
}

fn require_bare_counted_flag(args: &[String], flag: &str) {
    if args.len() != 1 {
        eprintln!("{flag}: expected no additional arguments");
        std::process::exit(2);
    }
}

const WINDOW_GROUP_BLOCKS: u32 = 64;
const WINDOW_WARMUP_UNITS: usize = 5;
const WINDOW_MEASURED_UNITS: usize = 100;
const WINDOW_CPU_TICK_NS: u64 = 10_000_000;
const WINDOW_ATTRIBUTION_SCHEMA: &str = "bitcoin-rs-window-attribution-v1";

#[derive(Clone, Copy)]
enum WindowArm {
    Control,
    Candidate,
}

impl WindowArm {
    const fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Candidate => "candidate",
        }
    }

    fn parse(label: &str) -> Option<Self> {
        [Self::Control, Self::Candidate]
            .into_iter()
            .find(|arm| arm.label() == label)
    }
}

#[derive(Clone, Copy)]
struct WindowScenario {
    id: &'static str,
    body_blocks: u32,
}

impl WindowScenario {
    fn groups(self) -> usize {
        usize::try_from(self.body_blocks.div_ceil(WINDOW_GROUP_BLOCKS))
            .unwrap_or_else(|error| panic!("invalid window group count: {error}"))
    }
}

const WINDOW_SCENARIOS: [WindowScenario; 2] = [
    WindowScenario {
        id: "single_group",
        body_blocks: WINDOW_GROUP_BLOCKS,
    },
    WindowScenario {
        id: "multi_group",
        body_blocks: 2 * WINDOW_GROUP_BLOCKS,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowSpanKind {
    TransitionHeld,
    FlushWait,
    FlushFailed,
    ApplyIdle,
    DownloadBlocked,
}

impl WindowSpanKind {
    const fn ledger_path(self) -> &'static str {
        match self {
            Self::TransitionHeld => "apply.window.transition_held",
            Self::FlushWait => "apply.window.flush_wait",
            Self::FlushFailed => "apply.window.flush_failed",
            Self::ApplyIdle => "p2p.window.apply_idle",
            Self::DownloadBlocked => "p2p.window.download_blocked_by_apply",
        }
    }
}

struct WindowSpan {
    kind: WindowSpanKind,
    end: quanta::Instant,
    duration_ns: u64,
    blocks: Option<u64>,
}

static WINDOW_SPANS: ParkingMutex<Vec<WindowSpan>> = ParkingMutex::new(Vec::new());

struct WindowSpanSubscriber;

impl WindowSpanSubscriber {
    fn watches(metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_event()
            && (metadata.fields().field("transition_held_us").is_some()
                || metadata.fields().field("flush_wait_us").is_some())
    }
}

#[derive(Default)]
struct WindowSpanVisitor {
    transition_held_us: Option<u128>,
    flush_wait_us: Option<u128>,
    blocks: Option<u64>,
    failed: bool,
}

impl tracing::field::Visit for WindowSpanVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
        if field.name() == "flush_error" {
            self.failed = true;
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "blocks" => self.blocks = Some(value),
            "transition_held_us" => self.transition_held_us = Some(u128::from(value)),
            "flush_wait_us" => self.flush_wait_us = Some(u128::from(value)),
            _ => {}
        }
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        match field.name() {
            "transition_held_us" => self.transition_held_us = Some(value),
            "flush_wait_us" => self.flush_wait_us = Some(value),
            _ => {}
        }
    }
}

impl tracing::Subscriber for WindowSpanSubscriber {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if Self::watches(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        Self::watches(metadata)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let end = quanta::Instant::now();
        let mut visitor = WindowSpanVisitor::default();
        event.record(&mut visitor);
        let micros_to_nanos =
            |micros: u128| u64::try_from(micros.saturating_mul(1_000)).unwrap_or(u64::MAX);
        let span = match (visitor.transition_held_us, visitor.flush_wait_us) {
            (Some(micros), None) => WindowSpan {
                kind: WindowSpanKind::TransitionHeld,
                end,
                duration_ns: micros_to_nanos(micros),
                blocks: None,
            },
            (None, Some(micros)) => WindowSpan {
                kind: if visitor.failed {
                    WindowSpanKind::FlushFailed
                } else {
                    WindowSpanKind::FlushWait
                },
                end,
                duration_ns: micros_to_nanos(micros),
                blocks: visitor.blocks,
            },
            _ => return,
        };
        WINDOW_SPANS.lock().push(span);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct WindowSeriesRecorder;

impl metrics::Recorder for WindowSeriesRecorder {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn register_counter(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::noop()
    }

    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        let kind = match key.name() {
            "node.sync.apply_idle_seconds" => WindowSpanKind::ApplyIdle,
            "node.sync.download_blocked_by_apply_seconds" => WindowSpanKind::DownloadBlocked,
            _ => return metrics::Histogram::noop(),
        };
        metrics::Histogram::from_arc(Arc::new(WindowSeriesHistogram { kind }))
    }
}

struct WindowSeriesHistogram {
    kind: WindowSpanKind,
}

impl metrics::HistogramFn for WindowSeriesHistogram {
    fn record(&self, seconds: f64) {
        let end = quanta::Instant::now();
        WINDOW_SPANS.lock().push(WindowSpan {
            kind: self.kind,
            end,
            duration_ns: (seconds * 1e9).round() as u64,
            blocks: None,
        });
    }
}

struct WindowUnit {
    started: quanta::Instant,
    apply_started: quanta::Instant,
    wall: Duration,
    apply_wall: Duration,
    settle_wall: Duration,
    cpu_ticks: u64,
    rss_start_bytes: u64,
    rss_peak_bytes: u64,
    requested: usize,
    applied_height: u32,
    corpus_sha256: Sha256Hex,
    spans: Vec<WindowSpan>,
}

impl WindowUnit {
    fn spans_of(&self, kind: WindowSpanKind) -> impl Iterator<Item = &WindowSpan> {
        self.spans.iter().filter(move |span| span.kind == kind)
    }

    fn durations_ns(&self, kind: WindowSpanKind) -> Vec<u64> {
        self.spans_of(kind).map(|span| span.duration_ns).collect()
    }

    fn cpu_ns(&self) -> u64 {
        self.cpu_ticks.saturating_mul(WINDOW_CPU_TICK_NS)
    }

    fn window_transition_held_us(&self) -> u64 {
        self.spans_of(WindowSpanKind::TransitionHeld)
            .map(|span| span.duration_ns / 1_000)
            .max()
            .unwrap_or(0)
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn read_proc_text(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn proc_field(path: &str, field: &str) -> String {
    read_proc_text(path)
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map_or_else(
            || panic!("{field} missing from {path}"),
            |rest| rest.trim().to_owned(),
        )
}

fn proc_kib(path: &str, field: &str) -> u64 {
    proc_field(path, field)
        .split_ascii_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("{field} in {path} is not a KiB count"))
}

fn process_cpu_ticks() -> u64 {
    let stat = read_proc_text("/proc/self/stat");
    let after_comm = stat
        .rsplit_once(')')
        .map_or_else(|| panic!("malformed /proc/self/stat"), |(_, rest)| rest);
    let mut fields = after_comm.split_ascii_whitespace().skip(11);
    let mut next_ticks = |name: &str| -> u64 {
        fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{name} missing from /proc/self/stat"))
    };
    let user = next_ticks("utime");
    let system = next_ticks("stime");
    user.saturating_add(system)
}

fn reset_peak_rss() -> u64 {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/clear_refs")
        .and_then(|mut file| file.write_all(b"5"))
        .unwrap_or_else(|error| panic!("reset peak RSS through /proc/self/clear_refs: {error}"));
    let resident_kib = proc_kib("/proc/self/status", "VmRSS:");
    let peak_kib = proc_kib("/proc/self/status", "VmHWM:");
    assert!(
        peak_kib.saturating_sub(resident_kib) <= 1024,
        "VmHWM is {peak_kib} KiB after the reset but VmRSS is {resident_kib} KiB: \
         this kernel did not reset the peak resident set"
    );
    resident_kib.saturating_mul(1024)
}

fn window_toolchain_identity() -> sonic_rs::Value {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = std::process::Command::new(&rustc)
        .arg("-vV")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "run {} -vV for the toolchain identity: {error}",
                rustc.display()
            )
        });
    assert!(output.status.success(), "{} -vV failed", rustc.display());
    let features: Vec<&str> = [
        ("fjall", cfg!(feature = "fjall")),
        ("rocksdb", cfg!(feature = "rocksdb")),
        ("redb", cfg!(feature = "redb")),
        ("kernel", cfg!(feature = "kernel")),
        ("zmq", cfg!(feature = "zmq")),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect();
    json!({
        "rustc": String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        "profile": "bench",
        "debug_assertions": cfg!(debug_assertions),
        "features": features,
        "allocator": "system",
        "validation_engine": sample_engine_label(),
    })
}

fn window_host_identity() -> sonic_rs::Value {
    let tmpdir = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|error| panic!("resolve the temporary directory: {error}"));
    let mounts = read_proc_text("/proc/self/mounts");
    let (device, mount_point, fstype) = mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let device = fields.next()?;
            let mount_point = fields.next()?;
            let fstype = fields.next()?;
            tmpdir
                .starts_with(mount_point)
                .then_some((device, mount_point, fstype))
        })
        .max_by_key(|(_, mount_point, _)| mount_point.len())
        .unwrap_or_else(|| panic!("no mount holds {}", tmpdir.display()));
    assert!(
        !matches!(fstype, "tmpfs" | "ramfs"),
        "{} is on {fstype}: set TMPDIR to a disk-backed directory so group flushes are durable",
        tmpdir.display()
    );
    json!({
        "kernel": read_proc_text("/proc/sys/kernel/osrelease").trim(),
        "cpus_allowed_list": proc_field("/proc/self/status", "Cpus_allowed_list:"),
        "mem_total_kib": proc_kib("/proc/meminfo", "MemTotal:"),
        "storage": {
            "tmpdir": tmpdir.display().to_string(),
            "mount_point": mount_point,
            "fstype": fstype,
            "device": device,
        },
    })
}

fn run_window_unit(scenario: WindowScenario) -> WindowUnit {
    let mut fixture =
        ProductionStateSyncFixture::window_replay(scenario.body_blocks).prebuild_run();
    let corpus_bytes: Vec<u8> = fixture.blocks.iter().flat_map(consensus_bytes).collect();
    let corpus_sha256 = Sha256Hex::digest(&corpus_bytes);
    let recorder = WindowSeriesRecorder;
    WINDOW_SPANS.lock().clear();
    let rss_start_bytes = reset_peak_rss();
    let cpu_before = process_cpu_ticks();
    let started = quanta::Instant::now();
    let mut apply_started = started;
    let mut apply_done = started;
    let mut settled = started;
    let mut report = None;
    metrics::with_local_recorder(&recorder, || {
        report = Some(fixture.run_phased(|phase| match phase {
            ReplayPhase::ApplyStart => apply_started = quanta::Instant::now(),
            ReplayPhase::ApplyDone => apply_done = quanta::Instant::now(),
        }));
        fixture.settle_tick();
        settled = quanta::Instant::now();
    });
    let cpu_after = process_cpu_ticks();
    let rss_peak_bytes = proc_kib("/proc/self/status", "VmHWM:").saturating_mul(1024);
    let spans = std::mem::take(&mut *WINDOW_SPANS.lock());
    let report = report.unwrap_or_else(|| panic!("window replay produced no report"));
    drop(fixture);
    WindowUnit {
        started,
        apply_started,
        wall: settled.duration_since(started),
        apply_wall: apply_done.duration_since(apply_started),
        settle_wall: settled.duration_since(apply_done),
        cpu_ticks: cpu_after.saturating_sub(cpu_before),
        rss_start_bytes,
        rss_peak_bytes,
        requested: report.requested,
        applied_height: report.applied_height,
        corpus_sha256,
        spans,
    }
}

fn assert_window_unit(scenario: WindowScenario, unit: &WindowUnit) {
    let body_blocks = usize::try_from(scenario.body_blocks)
        .unwrap_or_else(|error| panic!("invalid window body count: {error}"));
    assert_eq!(
        unit.applied_height, scenario.body_blocks,
        "{}: the replay must apply every body block",
        scenario.id
    );
    assert!(
        unit.requested >= body_blocks,
        "{}: the first getdata asked for {} blocks, fewer than the {body_blocks} replayed",
        scenario.id,
        unit.requested
    );
    assert_eq!(
        unit.spans_of(WindowSpanKind::FlushFailed).count(),
        0,
        "{}: a group flush failed during the replay",
        scenario.id
    );
    assert_eq!(
        unit.spans_of(WindowSpanKind::FlushWait).count(),
        scenario.groups(),
        "{}: expected one group flush per started group of {WINDOW_GROUP_BLOCKS} blocks",
        scenario.id
    );
    let flushed: u64 = unit
        .spans_of(WindowSpanKind::FlushWait)
        .filter_map(|span| span.blocks)
        .sum();
    assert_eq!(
        flushed,
        u64::from(scenario.body_blocks),
        "{}: group flushes must cover every body block",
        scenario.id
    );
    assert!(
        unit.spans_of(WindowSpanKind::TransitionHeld)
            .next()
            .is_some(),
        "{}: no transition_held_us event; this binary lacks the chainstate timing spans",
        scenario.id
    );
}

fn quantiles_json(values: &[u64]) -> sonic_rs::Value {
    if let Some(quantiles) = evidence::Quantiles::of(values) {
        json!({
            "n": quantiles.n,
            "p50": quantiles.p50,
            "p95": quantiles.p95,
            "p99": quantiles.p99,
            "max": quantiles.max,
            "p99_supported": quantiles.p99_supported(),
        })
    } else {
        json!({ "n": 0, "observed": false })
    }
}

fn window_unit_json(index: usize, origin: quanta::Instant, unit: &WindowUnit) -> sonic_rs::Value {
    let micros = |kind: WindowSpanKind| -> Vec<u64> {
        unit.spans_of(kind)
            .map(|span| span.duration_ns / 1_000)
            .collect()
    };
    json!({
        "unit": index,
        "warmup": index < WINDOW_WARMUP_UNITS,
        "started_offset_ns": duration_nanos(unit.started.duration_since(origin)),
        "wall_ns": duration_nanos(unit.wall),
        "apply_wall_ns": duration_nanos(unit.apply_wall),
        "settle_wall_ns": duration_nanos(unit.settle_wall),
        "cpu_ticks": unit.cpu_ticks,
        "cpu_ns": unit.cpu_ns(),
        "rss_start_bytes": unit.rss_start_bytes,
        "rss_peak_bytes": unit.rss_peak_bytes,
        "requested_blocks": unit.requested,
        "applied_height": unit.applied_height,
        "transition_held_us": micros(WindowSpanKind::TransitionHeld),
        "flush_wait_us": micros(WindowSpanKind::FlushWait),
        "flush_blocks": unit
            .spans_of(WindowSpanKind::FlushWait)
            .filter_map(|span| span.blocks)
            .collect::<Vec<u64>>(),
        "apply_idle_ns": unit.durations_ns(WindowSpanKind::ApplyIdle),
        "download_blocked_by_apply_ns": unit.durations_ns(WindowSpanKind::DownloadBlocked),
    })
}

fn window_summary_json(measured: &[WindowUnit]) -> sonic_rs::Value {
    let walls: Vec<u64> = measured
        .iter()
        .map(|unit| duration_nanos(unit.wall))
        .collect();
    let apply_walls: Vec<u64> = measured
        .iter()
        .map(|unit| duration_nanos(unit.apply_wall))
        .collect();
    let settle_walls: Vec<u64> = measured
        .iter()
        .map(|unit| duration_nanos(unit.settle_wall))
        .collect();
    let cpu: Vec<u64> = measured.iter().map(WindowUnit::cpu_ns).collect();
    let rss_peak: Vec<u64> = measured.iter().map(|unit| unit.rss_peak_bytes).collect();
    let rss_over_start: Vec<u64> = measured
        .iter()
        .map(|unit| unit.rss_peak_bytes.saturating_sub(unit.rss_start_bytes))
        .collect();
    let transition_held_us: Vec<u64> = measured
        .iter()
        .map(WindowUnit::window_transition_held_us)
        .collect();
    let pooled = |kind: WindowSpanKind| -> Vec<u64> {
        measured
            .iter()
            .flat_map(|unit| unit.durations_ns(kind))
            .collect()
    };
    let flush_wait_us: Vec<u64> = pooled(WindowSpanKind::FlushWait)
        .into_iter()
        .map(|nanos| nanos / 1_000)
        .collect();
    let cpu_total_ns = cpu
        .iter()
        .fold(0_u64, |total, nanos| total.saturating_add(*nanos));
    let observed_units = |kind: WindowSpanKind| {
        measured
            .iter()
            .filter(|unit| unit.spans_of(kind).next().is_some())
            .count()
    };
    json!({
        "units": measured.len(),
        "wall_ns": quantiles_json(&walls),
        "apply_wall_ns": quantiles_json(&apply_walls),
        "settle_wall_ns": quantiles_json(&settle_walls),
        "cpu_ns": quantiles_json(&cpu),
        "cpu_total_ns": cpu_total_ns,
        "cpu_resolution_ns": WINDOW_CPU_TICK_NS,
        "rss_peak_bytes": quantiles_json(&rss_peak),
        "rss_peak_over_start_bytes": quantiles_json(&rss_over_start),
        "transition_held_us": quantiles_json(&transition_held_us),
        "flush_wait_us": quantiles_json(&flush_wait_us),
        "apply_idle_ns": quantiles_json(&pooled(WindowSpanKind::ApplyIdle)),
        "apply_idle_observed_units": observed_units(WindowSpanKind::ApplyIdle),
        "download_blocked_by_apply_ns": quantiles_json(&pooled(WindowSpanKind::DownloadBlocked)),
        "download_blocked_by_apply_observed_units": observed_units(WindowSpanKind::DownloadBlocked),
    })
}

fn window_sample(identity: &EvidenceIdentity, path: &str, start_ns: u64, end_ns: u64) -> Sample {
    Sample {
        path: path.into(),
        owner: "node".into(),
        identity: identity.clone(),
        interval: Interval {
            kind: IntervalKind::Inside,
            start_ns,
            end_ns: end_ns.max(start_ns),
        },
        cpu_ns: None,
        elapsed_ns: end_ns.saturating_sub(start_ns),
        rss_peak_bytes: None,
        io_bytes: None,
        storage_bytes: None,
    }
}

fn window_evidence_samples(
    identity: &EvidenceIdentity,
    origin: quanta::Instant,
    unit: &WindowUnit,
) -> Vec<Sample> {
    let offset = |at: quanta::Instant| duration_nanos(at.duration_since(origin));
    let mut samples = Vec::with_capacity(unit.spans.len().saturating_add(2));
    let started = offset(unit.started);
    samples.push(Sample {
        cpu_ns: Some(unit.cpu_ns()),
        rss_peak_bytes: Some(unit.rss_peak_bytes),
        ..window_sample(
            identity,
            "apply.window.replay_wall",
            started,
            started.saturating_add(duration_nanos(unit.wall)),
        )
    });
    let apply_started = offset(unit.apply_started);
    samples.push(window_sample(
        identity,
        "apply.window.apply_tick",
        apply_started,
        apply_started.saturating_add(duration_nanos(unit.apply_wall)),
    ));
    for span in &unit.spans {
        let end = offset(span.end);
        samples.push(window_sample(
            identity,
            span.kind.ledger_path(),
            end.saturating_sub(span.duration_ns),
            end,
        ));
    }
    samples
}

fn run_window_attribution(arm: WindowArm, scenario: WindowScenario) {
    let host = window_host_identity();
    let toolchain = window_toolchain_identity();
    tracing::subscriber::set_global_default(WindowSpanSubscriber)
        .unwrap_or_else(|error| panic!("window span subscriber install failed: {error}"));
    let run_started_unix_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system clock before the epoch: {error}"))
        .as_nanos();
    let origin = quanta::Instant::now();
    let total_units = WINDOW_WARMUP_UNITS.saturating_add(WINDOW_MEASURED_UNITS);
    let mut units = Vec::with_capacity(total_units);
    for _ in 0..total_units {
        let unit = run_window_unit(scenario);
        assert_window_unit(scenario, &unit);
        units.push(unit);
    }
    let corpus_sha256 = units[0].corpus_sha256;
    assert!(
        units.iter().all(|unit| unit.corpus_sha256 == corpus_sha256),
        "{}: replay blocks differ between units",
        scenario.id
    );
    let mut identity = EvidenceIdentity::of_process(&production_state_config())
        .unwrap_or_else(|error| panic!("evidence identity: {error}"));
    identity.corpus = Some(CorpusIdentity {
        id: format!("sync_pipeline.window_replay.{}", scenario.id),
        manifest_sha256: corpus_sha256,
    });
    let measured = &units[WINDOW_WARMUP_UNITS..];

    let cell = format!("window_attribution.{}.{}", scenario.id, arm.label());
    let ledger_path = bench_ledger_path("window_attribution.toml");
    let mut ledger = load_bench_ledger(&ledger_path);
    if !ledger.cells.iter().any(|candidate| candidate.id == cell) {
        ledger.cells.push(Cell {
            id: cell.clone(),
            samples: Vec::new(),
        });
    }
    for unit in measured {
        for sample in window_evidence_samples(&identity, origin, unit) {
            ledger
                .record(&cell, sample)
                .unwrap_or_else(|error| panic!("record window sample: {error}"));
        }
    }
    store_bench_ledger(&ledger_path, &ledger);

    let record = json!({
        "schema": WINDOW_ATTRIBUTION_SCHEMA,
        "claim_scope": "diagnostic: deterministic regtest replay; mechanism and measurement surface only, not mainnet speed, fills no product cell",
        "arm": arm.label(),
        "scenario": scenario.id,
        "body_blocks": scenario.body_blocks,
        "group_blocks": WINDOW_GROUP_BLOCKS,
        "groups": scenario.groups(),
        "run_started_unix_ns": run_started_unix_ns.to_string(),
        "warmup_units": WINDOW_WARMUP_UNITS,
        "measured_units": WINDOW_MEASURED_UNITS,
        "identity": identity,
        "toolchain": toolchain,
        "host": host,
        "ledger": { "path": ledger_path.display().to_string(), "cell": cell },
        "summary": window_summary_json(measured),
        "units": units
            .iter()
            .enumerate()
            .map(|(index, unit)| window_unit_json(index, origin, unit))
            .collect::<Vec<_>>(),
    });
    let record_dir = bench_ledger_path("window_attribution");
    std::fs::create_dir_all(&record_dir)
        .unwrap_or_else(|error| panic!("window attribution record dir: {error}"));
    let record_path = record_dir.join(format!(
        "{}.{}.{run_started_unix_ns}.json",
        arm.label(),
        scenario.id
    ));
    let rendered = sonic_rs::to_vec_pretty(&record)
        .unwrap_or_else(|error| panic!("render window attribution record: {error}"));
    std::fs::write(&record_path, rendered)
        .unwrap_or_else(|error| panic!("write window attribution record: {error}"));

    println!(
        "window_attribution arm={} scenario={} measured_units={} record={}",
        arm.label(),
        scenario.id,
        measured.len(),
        record_path.display()
    );
    let walls: Vec<Duration> = measured.iter().map(|unit| unit.wall).collect();
    let apply_walls: Vec<Duration> = measured.iter().map(|unit| unit.apply_wall).collect();
    print_percentiles("window_attribution_wall", &walls);
    print_percentiles("window_attribution_apply_tick", &apply_walls);
}

fn window_attribution_cli(args: &[String]) -> (WindowArm, WindowScenario) {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|arg| *arg != "--bench")
        .collect();
    let fail = |message: &str| -> ! {
        eprintln!("window-attribution: {message}");
        eprintln!(
            "usage: sync_pipeline --window-attribution <control|candidate> <{}>",
            WINDOW_SCENARIOS.map(|scenario| scenario.id).join("|")
        );
        std::process::exit(2);
    };
    if args.len() != 3 || args[0] != "--window-attribution" {
        fail("expected exactly --window-attribution <arm> <scenario>");
    }
    let Some(arm) = WindowArm::parse(args[1]) else {
        fail("unknown arm");
    };
    let Some(scenario) = WINDOW_SCENARIOS
        .iter()
        .copied()
        .find(|scenario| scenario.id == args[2])
    else {
        fail("unknown scenario");
    };
    (arm, scenario)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--mrp-list-counted") {
        require_bare_counted_flag(&args, "--mrp-list-counted");
        for row in COUNTED_ROWS {
            println!("{row}");
        }
        return;
    }
    if args.iter().any(|arg| arg == "--mrp-counted") {
        let row = counted_cli_row(&args);
        run_counted_row(row);
        return;
    }
    if args.iter().any(|arg| arg == "--window-attribution") {
        let (arm, scenario) = window_attribution_cli(&args);
        run_window_attribution(arm, scenario);
        return;
    }
    if args.iter().any(|arg| arg == "--mrp-verify-counted") {
        require_bare_counted_flag(&args, "--mrp-verify-counted");
        mrp_verify_counted();
        return;
    }
    if args.iter().any(|arg| arg == "--mrp-verify") {
        mrp_verify();
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
