//! Deterministic initial-sync proxy benchmark.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
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
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::push_int;
// seam: getdata inventory items stay rust-bitcoin at the p2p wire boundary.
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
pub mod evidence;

// seam: the shared measured-work sampler for MRP counted rows. The file is
// owned by `tools/benchmark-support` and copied identically into every
// control root; this bench consumes it by relative path.
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
use bitcoin_rs_primitives::{consensus_bytes, deserialize};
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

/// Signed-spend output value: the 501-sat fee (`78_125_000 - 78_124_499`) clears the
/// mempool's 1,000 sat/kvB minimum-relay floor in every spend class, so the
/// same transactions the connect arms apply are also admissible through the
/// gateway.
const SIGNED_SPEND_OUTPUT_VALUE: u64 = 78_124_499;

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
                for block in &blocks {
                    state
                        .apply_block(black_box(block))
                        .unwrap_or_else(|error| panic!("pruned proxy apply failed: {error}"));
                }
                let tip = state
                    .chainstate()
                    .applied_tip_snapshot()
                    .unwrap_or_else(|| panic!("pruned proxy apply did not publish a tip"));
                let record = state
                    .blocks()
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
    c.bench_function("sync_pipeline_apply_spend_heavy_proxy", |b| {
        b.iter_batched(
            open_regtest_state,
            |(_dir, state)| {
                for block in &spend_blocks {
                    state
                        .apply_block(black_box(block))
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

/// Signed-spend proxy benchmark: the same 117-block skeleton as
/// `spend_heavy_proxy_blocks`, but every spend input carries a real ECDSA
/// signature verified by the script engine. Spend classes are P2PKH (legacy
/// ECDSA), P2WPKH (BIP143), and P2WSH 2-of-3 multisig (BIP143). Signatures are
/// produced with rust-bitcoin 0.32's `SighashCache` + secp256k1 as an
/// independent oracle, then consensus-serialized and decoded into native
/// `Tx` (the `to_native` pattern from `crates/script/tests/proptest.rs`).
///
/// Criterion 0.8 cannot report p95/p99/max, so a manual timed sample loop
/// collects per-sweep durations and prints the percentile table; Criterion
/// keeps the headline median for comparability with the existing docs.
fn sync_pipeline_apply_signed_spend_proxy(c: &mut Criterion) {
    let blocks = legacy_signed_spend_proxy_blocks();
    print_signed_spend_proxy_summary(&blocks);

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
                for block in &blocks {
                    state
                        .apply_block(black_box(block))
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

/// Appends one identity-bearing sample per sweep to the bench evidence
/// ledger under `target/benchmarks/`.
///
/// Every number carries the binary, configuration, corpus, backend and
/// durability it was taken under, so a later comparison can match or reject
/// it; the ledger is append-only across runs.
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
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/benchmarks/sync_pipeline.toml");
    let mut ledger = match std::fs::read_to_string(&path) {
        Ok(text) => Ledger::parse(&text).unwrap_or_else(|error| panic!("bench ledger: {error}")),
        Err(_) => Ledger {
            schema: LEDGER_SCHEMA.into(),
            cells: Vec::new(),
            contract: std::collections::BTreeMap::new(),
        },
    };
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
    std::fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))
        .unwrap_or_else(|error| panic!("bench evidence dir: {error}"));
    let rendered = ledger
        .render()
        .unwrap_or_else(|error| panic!("render bench ledger: {error}"));
    std::fs::write(&path, rendered).unwrap_or_else(|error| panic!("write bench ledger: {error}"));
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
    let started = Instant::now();
    for block in blocks {
        state
            .apply_block(block)
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
        .blocks()
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
    let started = Instant::now();
    for block in blocks {
        state
            .apply_block(block)
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
        .blocks()
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
    /// Inbound payloads pre-cloned and pre-serialized during (untimed) setup, in
    /// the exact order the timed scenario sends them. Built off the production
    /// path so the timed region measures only the channel handoff plus `tick`.
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

    /// Pre-clones and pre-serializes the inbound payloads `run` sends, in send
    /// order: heights `2..=N` reversed, then height 1 last (sent after tick 2).
    fn prebuild_run(mut self) -> Self {
        self.prebuilt_inbound = self.blocks[1..]
            .iter()
            .rev()
            .chain(std::iter::once(&self.blocks[0]))
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
            .collect();
        self
    }

    /// Pre-builds the single unsolicited payload `request_after_unsolicited_received`
    /// stages (block height 2).
    fn prebuild_unsolicited(mut self) -> Self {
        self.prebuilt_inbound = vec![bitcoin_rs_p2p::InboundBlock::from_decoded(
            self.blocks[1].clone(),
        )];
        self
    }

    /// Pre-builds the in-order inbound payloads (`run_in_order_inbound`): every
    /// block in ascending height order.
    fn prebuild_in_order(mut self) -> Self {
        self.prebuilt_inbound = self
            .blocks
            .iter()
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
            .collect();
        self
    }

    /// Pre-builds the oversized burst payloads (`run_oversized_inbound_burst`):
    /// heights `2..=N` reversed.
    fn prebuild_oversized_burst(mut self) -> Self {
        self.prebuilt_inbound = self.blocks[1..]
            .iter()
            .rev()
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
            .collect();
        self
    }

    fn new_reverse_scan_overflow(tx_index_mode: DerivedIndexMode) -> Self {
        let mut fixture =
            Self::new_with_block_count(tx_index_mode, 0, SYNC_REVERSE_SCAN_OVERFLOW_BODY_BLOCKS);
        // The bench stages 128 received blocks and still needs to request a
        // full pending window, so the received-block budget must cover both
        // the staged blocks and the new requests.
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
                .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
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

        // prebuilt_inbound holds heights 2..=N reversed, then height 1 last.
        // Send the out-of-order tail, tick, then deliver the contiguous head and
        // tick again — same send order and tick interleaving as before, but the
        // clone+serialize now happens in setup, not the timed region.
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

struct ProductionStateSyncFixture {
    _dir: TempDir,
    state: NodeState,
    outbound_rxs: Vec<crossbeam_channel::Receiver<bitcoin_rs_p2p::QueuedFrame>>,
    blocks: Vec<Block>,
    /// Inbound payloads pre-cloned and pre-serialized during (untimed) setup for
    /// the `run` scenario, in send order (heights `2..=N` reversed, then height
    /// 1 last). Left empty for the apply-tick scenarios, which stage in setup.
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

    /// Pre-clones and pre-serializes the inbound payloads `run` sends, in send
    /// order: heights `2..=N` reversed, then height 1 last (sent after tick 2).
    fn prebuild_run(mut self) -> Self {
        self.prebuilt_inbound = self.blocks[1..]
            .iter()
            .rev()
            .chain(std::iter::once(&self.blocks[0]))
            .map(|block| bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
            .collect();
        self
    }

    fn run(mut self) -> u32 {
        let sync = self.state.sync();
        sync.tick();
        self.assert_getdata_batch();
        let inbound_blocks_tx = self.state.inbound_blocks_sender();
        // prebuilt_inbound holds heights 2..=N reversed, then height 1 last.
        // Send the out-of-order tail, tick, then deliver the contiguous head and
        // tick again — same send order and tick interleaving, with clone+serialize
        // moved to setup.
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
        sync.tick();
        self.state
            .chainstate()
            .applied_tip_snapshot()
            .unwrap_or_else(|| panic!("production sync proxy did not publish applied tip"))
            .height
    }

    fn stage_for_contiguous_apply(self) -> Self {
        let sync = self.state.sync();
        sync.tick();
        self.assert_getdata_batch();
        let inbound_blocks_tx = self.state.inbound_blocks_sender();
        for block in self.blocks[1..].iter().rev() {
            inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
                .unwrap_or_else(|error| panic!("send production staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_decoded(
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
                .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
                .unwrap_or_else(|error| panic!("send first partial staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_decoded(
                self.blocks[0].clone(),
            ))
            .unwrap_or_else(|error| panic!("send first partial contiguous block failed: {error}"));
        sync.tick();

        for block in self.blocks[split + 1..].iter().rev() {
            inbound_blocks_tx
                .send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
                .unwrap_or_else(|error| panic!("send second partial staged block failed: {error}"));
        }
        sync.tick();
        inbound_blocks_tx
            .send(bitcoin_rs_p2p::InboundBlock::from_decoded(
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
        let rx = self
            .outbound_rxs
            .first()
            .unwrap_or_else(|| panic!("missing primary outbound receiver"));
        let mut drained_headers = 0_usize;
        let getdata_count = loop {
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
        };
        assert_eq!(getdata_count, self.expected_getdata_count);
    }
}

fn production_state_config() -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.p2p.listen.clear();
    config.indexes.txindex = false;
    config.validation.engine = bench_engine();
    config
}

/// The engine this bench run selects, exactly once.
///
/// Selection is runtime configuration, never a compiled-feature side effect:
/// `BITCOIN_RS_VALIDATION_ENGINE` names the arm (`native` or `kernel`) and
/// defaults to `native`. The kernel arm must both compile the capability
/// (`--features fjall,kernel`) and select `kernel` here; selecting an engine
/// this build cannot run panics loudly instead of silently benchmarking the
/// other arm. Recorded in every summary line and covered by each evidence
/// sample's resolved-configuration identity.
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

/// The raw engine label that evidence samples and the `--mrp-verify` pin line
/// report: `BITCOIN_RS_VALIDATION_ENGINE` verbatim, `native` when unset.
/// Unlike `bench_engine` it neither validates nor normalizes, so a
/// non-canonical spelling stays visible to the registration's engine pin.
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
        peer_table.register(addr, bitcoin_rs_p2p::PeerLease::new(outbound_tx));
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

// ---------------------------------------------------------------------------
// Signed-spend corpus: real ECDSA signatures verified by the script engine.
// ---------------------------------------------------------------------------

/// BIP141 witness commitment prefix: `OP_RETURN OP_PUSH36 BIP141_COMMITMENT_TAG`.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// BIP141 reserved witness value for the coinbase input.
const WITNESS_RESERVED_VALUE: [u8; 32] = [0; 32];

/// Signing keys for the three spend classes, all derived deterministically.
struct SigningKeys {
    secp: Secp256k1<All>,
    /// P2PKH: one key per funded output.
    p2pkh: Vec<bitcoin::PublicKey>,
    /// P2WPKH: one compressed key per funded output.
    p2wpkh: Vec<bitcoin::PublicKey>,
    /// P2WSH 2-of-3: three keys shared across all P2WSH outputs.
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

/// Builds the 117-block signed-spend corpus.
///
/// Heights 1..100: fanout coinbase blocks funding 64 outputs split across P2PKH,
/// P2WPKH, and P2WSH script classes. Heights 101..116: spend blocks that consume
/// the coinbase outputs from 100 blocks back, each carrying a real ECDSA signature
/// and paying a 501-sat fee to a standard bare-multisig output (mempool-
/// admissible; see `build_signed_spend_tx`).
/// Witness-bearing blocks carry a BIP141 commitment output on the coinbase.
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

/// Coinbase block funding 64 outputs across P2PKH, P2WPKH, and P2WSH.
///
/// The first 22 outputs are P2PKH (legacy), the next 22 are P2WPKH (segwit v0),
/// and the remaining 20 are P2WSH 2-of-3 multisig. Because this block carries
/// witness-paying outputs, the coinbase includes a BIP141 witness commitment
/// output and a 32-byte reserved witness element.
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
    // P2PKH outputs (indices 0..22).
    for i in 0..22u32 {
        let pkh = keys.p2pkh[usize::try_from(i).unwrap()].pubkey_hash();
        let script = OracleScriptBuf::new_p2pkh(&pkh);
        outputs.push(TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: script.as_bytes().to_vec().into(),
        });
    }
    // P2WPKH outputs (indices 22..44).
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
    // P2WSH 2-of-3 outputs (indices 44..64).
    for i in 0..20u32 {
        let redeem = p2wsh_2of3_redeem_script(keys, i);
        let script_hash = redeem.wscript_hash();
        let script = OracleScriptBuf::new_p2wsh(&script_hash);
        outputs.push(TxOut {
            value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
            script_pubkey: script.as_bytes().to_vec().into(),
        });
    }
    // BIP141 witness commitment output.
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

/// P2WSH 2-of-3 multisig redeem script: `OP_2 PK1 PK2 PK3 OP_3 OP_CHECKMULTISIG`.
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

/// Computes the BIP141 witness commitment for a coinbase that has no witness
/// transactions besides itself. The witness merkle root uses all-zero for the
/// coinbase leaf and the wtxid of every other transaction — but the coinbase is
/// the only transaction in these blocks, so the root is all-zero and the
/// commitment is `SHA256d(zeros || reserved)`.
fn witness_commitment_for_coinbase(_outputs: &[TxOut]) -> Hash256 {
    // Single-tx block: witness merkle root = [0; 32].
    let root = [0u8; 32];
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(&WITNESS_RESERVED_VALUE);
    double_sha256(&buffer)
}

/// Builds the BIP141 witness commitment scriptPubKey: `6a24aa21a9ed || commitment`.
fn witness_commitment_script_pubkey(commitment: &Hash256) -> Vec<u8> {
    let mut script = Vec::with_capacity(38);
    script.extend_from_slice(&WITNESS_COMMITMENT_PREFIX);
    script.extend_from_slice(commitment.as_byte_array());
    script
}

/// Target block: funding-style coinbase plus a caller-supplied spend list.
///
/// The assembly shape is exactly the spend-fanout block's below (BIP34
/// coinbase, witness commitment recomputed over the full tx set, merkle
/// recompute, trivial-PoW mining); parameterizing the spend set lets every
/// measured sample connect a distinct block. The coinbase is the same
/// 64-output funding coinbase the step-4 corpus uses, so its shape is proven.
fn child_signed_target_block(
    parent: &Block,
    height: u32,
    keys: &SigningKeys,
    spends: Vec<Tx>,
) -> Block {
    let mut txs = Vec::with_capacity(spends.len().saturating_add(1));
    // Coinbase for this target block (witness-bearing, with commitment).
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
    // Recompute the coinbase witness commitment now that the full tx set is known.
    let commitment = block_witness_commitment(&block.txs);
    let coinbase = &mut block.txs[0];
    // Replace the placeholder commitment output (last output) with the real one.
    let last = coinbase
        .outputs
        .last_mut()
        .unwrap_or_else(|| panic!("target coinbase missing commitment output"));
    last.script_pubkey = witness_commitment_script_pubkey(&commitment).into();
    // Recompute merkle root after updating the commitment.
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    regtest_fixture::mine_block_to_declared_target(&mut block)
        .unwrap_or_else(|error| panic!("mining target block failed: {error}"));
    block
}

/// Spend block consuming 64 coinbase outputs from 100 blocks back, each with a
/// real signature. The spend transactions are built as rust-bitcoin oracle
/// transactions, signed, then converted to native `Tx` via consensus
/// serialization.
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
    // 64 spend transactions, one per funded output.
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
    // Same bytes as before: identical coinbase, spends, header, commitment,
    // and mining sequence as child_signed_target_block.
    child_signed_target_block(parent, height, keys, spends)
}

/// Computes the BIP141 witness commitment for a block's transaction set.
/// Coinbase leaf is all-zero; every other leaf is the transaction's wtxid.
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

/// Builds and signs a single spend transaction for output `vout` of
/// `source_txid`. The spend class is determined by the output index:
/// 0..22 = P2PKH, 22..44 = P2WPKH, 44..64 = P2WSH 2-of-3. Every spend pays a
/// 501-sat fee to a standard bare 2-of-3 multisig output so the same
/// transactions the connect arms apply also pass mempool admission
/// (`min_relay_fee_sat_per_kvb` 1,000 sat/kvB and the standard-output
/// whitelist in `crates/mempool/src/standardness.rs`); the block-connect
/// fixture alone never required either.
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

/// P2PKH spend: scriptSig = `<sig> <pubkey>`, signed with legacy sighash.
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

/// P2WPKH spend: empty scriptSig, witness = `[sig, pubkey]`, signed with BIP143.
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

/// P2WSH 2-of-3 multisig spend: witness = `[empty_dummy, sig1, sig2, redeem_script]`,
/// signed with BIP143 using the redeem script as the witness script.
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
    // Sign with the first two keys.
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
    // BIP147: empty dummy element before the signatures.
    let witness_items: Vec<Vec<u8>> = vec![
        Vec::new(),
        sigs[0].clone(),
        sigs[1].clone(),
        redeem.as_bytes().to_vec(),
    ];
    tx.input[0].witness = OracleWitness::from_slice(&witness_items);
    to_native_tx(&tx)
}

/// Consensus-bytes round-trip from rust-bitcoin oracle types to native `Tx`.
fn to_native_tx(tx: &OracleTx) -> Tx {
    let bytes = bitcoin::consensus::serialize(tx);
    deserialize(&bytes).unwrap_or_else(|e| panic!("oracle transaction must decode natively: {e}"))
}

fn print_signed_spend_proxy_summary(blocks: &[Block]) {
    let (_dir, state) = open_regtest_state();
    let started = Instant::now();
    for block in blocks {
        state
            .apply_block(block)
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

/// Standard output script for the signed spend set's own outputs.
///
/// Bare 2-of-3 multisig over the fixture's P2WSH key set: the mempool's
/// `is_standard_output_script` whitelist accepts bare multisig of at most
/// three pubkeys, and the 501-sat output is far above the dust threshold. The
/// previous `push_int(1)` output was consensus-valid but fails mempool
/// standardness, so the admitted arm would have panicked on sample one.
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

// ---------------------------------------------------------------------------
// Legacy signed-spend corpus: byte-identical to the pre-step-4 bench.
// ---------------------------------------------------------------------------

/// Builds the legacy 117-block signed-spend corpus this bench measured
/// before the step-4 harness: 1-sat fees (`SPEND_PROXY_SPEND_OUTPUT_VALUE`)
/// and `push_int(1)` spend outputs. Consensus-valid and block-connectable,
/// but not mempool-admissible (fee floor, standard-output whitelist), so the
/// step-4 connect arms use `signed_spend_proxy_blocks` instead. Only
/// `sync_pipeline_apply_signed_spend_proxy` uses this corpus, keeping its
/// history comparable; the step-4 arms stay byte-identical to the accepted
/// baseline.
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

/// Legacy spend block: the pre-step-4 fanout shape with 1-sat, `push_int(1)`
/// spends. Funding coinbases are shared with the step-4 corpus, so sighashes
/// match the historical bodies exactly.
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

/// Legacy spend dispatcher: same classes as `build_signed_spend_tx`, with
/// the pre-step-4 outputs.
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

/// Legacy P2PKH spend: 1-sat fee to `push_int(1)`, legacy sighash.
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

/// Legacy P2WPKH spend: 1-sat fee to `push_int(1)`, BIP143.
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

/// Legacy P2WSH 2-of-3 spend: 1-sat fee to `push_int(1)`, BIP143.
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

/// Step-4 measurement gate (`script-execution-cache`): connect of a block
/// whose non-coinbase transactions were admitted through the real mempool
/// gateway, timed as last-apply only.
///
/// Per unit: a fresh `NodeState`, every block but the last applied untimed,
/// every non-coinbase transaction of the last block admitted through
/// `MempoolGateway::submit_local_transaction` (the production
/// `sendrawtransaction` path, real `ChainAdmissionView`, no seams) untimed,
/// then only `apply_block(last)` is timed. Counted sampling replaces the
/// Criterion registration (`--mrp-counted`, full ID
/// `connect_admitted_signed_spend_block/flat`): one second of measured work
/// per sample, one warmup sample, ten measured samples, and the per-unit
/// timed span stays apply-only; the companion
/// `connect_unseen_signed_spend_block` skips admission and is the miss
/// control.
///
/// Runs one whole unit with exactly the timed span above. The temp state
/// drops at return, outside every timer.
fn connect_admitted_unit_once(
    blocks: &[Block],
    last_index: usize,
    last_block: &Block,
    admission_txs: &[Arc<Tx>],
) -> Duration {
    let (_dir, state) = open_regtest_state();
    for block in &blocks[..last_index] {
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("prefix apply failed: {error}"));
    }
    admit_signed_spends(&state, admission_txs);
    assert_admission_residency(&state, admission_txs);
    let timed = Instant::now();
    state
        .apply_block(black_box(last_block))
        .unwrap_or_else(|error| panic!("admitted connect failed: {error}"));
    timed.elapsed()
}

/// Step-4 miss control: the identical block connected without any mempool
/// admission, so its script checks always run. Counted sampling replaces the
/// Criterion registration (`--mrp-counted`, full ID
/// `connect_unseen_signed_spend_block/flat`) with the same per-sample
/// protocol as the admitted arm.
///
/// Runs one whole unit with exactly the timed span above: fresh state,
/// untimed prefix to the penultimate tip, then the timed connect of the
/// unseen block. The temp state drops at return, outside every timer.
fn connect_unseen_unit_once(blocks: &[Block], last_index: usize, last_block: &Block) -> Duration {
    let (_dir, state) = open_regtest_state();
    for block in &blocks[..last_index] {
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("prefix apply failed: {error}"));
    }
    let timed = Instant::now();
    state
        .apply_block(black_box(last_block))
        .unwrap_or_else(|error| panic!("unseen connect failed: {error}"));
    timed.elapsed()
}

/// Admits the signed spend set through the production gateway. Never timed.
///
/// A submission that does not commit means the fixture drifted; the connect
/// arm would then measure a different block than the throughput arm admits.
/// Residency is asserted by the caller after admission, outside any timed
/// span.
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

/// Asserts every spend is pool-resident. Called once outside timed spans.
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

/// Step-4 throughput arm: the same signed spend set through the production
/// gateway, timed as gateway submits only, so the second verification pass's
/// cost is visible before and after the cache lands. One residency check per
/// unit runs after the timed span closes. Counted sampling replaces the
/// Criterion registration (`--mrp-counted`, full ID
/// `connect_admission_throughput/flat`) with the same per-sample protocol as
/// the admitted arm.
///
/// Runs one whole unit with exactly the timed span above: fresh state,
/// untimed prefix to the penultimate tip, the timed gateway submissions, then
/// the residency check outside the timer. The temp state drops at return.
fn connect_admission_unit_once(
    blocks: &[Block],
    last_index: usize,
    admission_txs: &[Arc<Tx>],
) -> Duration {
    let (_dir, state) = open_regtest_state();
    for block in &blocks[..last_index] {
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("prefix apply failed: {error}"));
    }
    let timed = Instant::now();
    admit_signed_spends(&state, admission_txs);
    let elapsed = timed.elapsed();
    assert_admission_residency(&state, admission_txs);
    elapsed
}

/// Full counted row IDs, in dispatch order. The MRP measured-work stopping
/// correction converts exactly these three T4 rows from Criterion
/// registration to counted sampling; every other row keeps its Criterion or
/// standalone protocol, and no duplicate Criterion registration remains for
/// the converted rows.
const COUNTED_ROWS: [&str; 3] = [
    "connect_admission_throughput/flat",
    "connect_admitted_signed_spend_block/flat",
    "connect_unseen_signed_spend_block/flat",
];

/// Runs one counted row by full ID through the shared
/// `measured_samples::run` sampler: one warmup sample plus ten measured
/// samples, each accumulating whole independent units (fresh state per unit)
/// until one second of measured work. The caller has already validated the
/// ID against `COUNTED_ROWS`.
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

/// Prints p50/p95/p99/max from the collected per-sweep durations.
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

// ---------------------------------------------------------------------------
// Step-21 block-to-template baseline: admitted 100k pool, coinbase-plus-2000
// target blocks, connect tail through the first new-tip template.
// ---------------------------------------------------------------------------

/// MRP standalone floor: whole independent units repeat inside one sample
/// until the measured total reaches this duration. No pilot counts, no
/// post-hoc tuning: the loop always runs at least one unit and stops at the
/// first unit that reaches the floor. Setup stays outside every timer.
const MRP_SAMPLE_MEASURED_FLOOR: Duration = Duration::from_secs(2);

/// Step-21 live pool before connect: 98,000 background spends plus one sample's
/// 2,000 target spends, all admitted through the production gateway path at the
/// current wall-clock time, never direct inserts.
const BLOCK_TEMPLATE_POOL_TXS: usize = 100_000;
/// Step-21 background fill: admitted once per sample; the sample's target
/// spends bring the live pool to exactly `BLOCK_TEMPLATE_POOL_TXS` before
/// connect, and connect removes exactly the targets afterwards.
const BLOCK_TEMPLATE_BACKGROUND_TXS: usize = 98_000;
/// Step-21 non-coinbase spends per measured target block (2001 txs total).
const BLOCK_TEMPLATE_TARGET_SPENDS: usize = 2_000;
/// Step-21 warmup connects: same path, reported, excluded from totals.
const BLOCK_TEMPLATE_WARMUPS: usize = 3;
/// Step-21 measured independent connect/reply samples.
const BLOCK_TEMPLATE_SAMPLES: usize = 10;
/// Step-21 funded outputs per funding coinbase (P2PKH/P2WPKH/P2WSH cycling).
const BLOCK_TEMPLATE_FANOUT_WIDTH: u32 = 4_096;
/// Step-21 funding fanout blocks: 32 x 4096 = `131_072` funded outputs cover the
/// 98k background fill plus 13 x 2000 target spends; the rest stays unspent.
const BLOCK_TEMPLATE_FANOUT_BLOCKS: u32 = 32;
/// Step-21 coinbase-only maturation fillers: every funding output is mature at
/// the prefix tip (latest funding height 32 + 100 <= tip height 132), and every
/// block stays below the regtest subsidy halving at height 150, so all
/// coinbases claim against the 50 BTC subsidy.
const BLOCK_TEMPLATE_FILLER_BLOCKS: u32 = 100;
/// Step-21 funding output value: 4096 outputs must fit the 50 BTC subsidy.
const BLOCK_TEMPLATE_FUND_VALUE_SAT: u64 = 1_000_000;
/// Step-21 spend output value: the same 501-sat fee as the proven spend corpus,
/// so fee rates (and gateway admission) match the step-4 arms exactly.
const BLOCK_TEMPLATE_SPEND_VALUE_SAT: u64 = BLOCK_TEMPLATE_FUND_VALUE_SAT - 501;
/// Step-21 key slots: each signing key funds many outputs; output `j` funds
/// class `j % 3` from slot `(j / 3) % 22`.
const BLOCK_TEMPLATE_KEY_SLOTS: u32 = 22;

/// Funding coinbase with `BLOCK_TEMPLATE_FANOUT_WIDTH` spendable outputs.
///
/// Output `j` funds class `j % 3` (0 = P2PKH, 1 = P2WPKH, 2 = P2WSH) from key
/// slot `(j / 3) % 22`; `build_wide_signed_spend_tx` of output `j` signs with
/// the matching key. Scripts reuse the exact constructors the per-class spend
/// builders verify against; only the outpoint differs per spend.
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
    // BIP141 witness commitment output (the spending blocks carry witnesses).
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

/// Funding block: wide coinbase only. The placeholder commitment is already
/// correct for a coinbase-only block, as in `child_signed_fanout_coinbase_block`.
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

/// Builds the spend of wide-funding output `vout` of `source_txid`, dispatching
/// on the same class/slot rule the funding coinbase funds with. Signatures are
/// fresh per outpoint, so every spend is a distinct valid transaction.
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

/// Frozen step-21 corpus: one deterministic prefix, one 98k background spend
/// set, and 13 disjoint 2000-spend target sets with their distinct blocks.
/// Built once, shared across samples; every sample replays it in a fresh state.
struct BlockTemplateCorpus {
    prefix: Vec<Block>,
    background: Vec<Arc<Tx>>,
    target_spends: Vec<Vec<Arc<Tx>>>,
    target_blocks: Vec<Block>,
    target_height: u32,
}

/// Spends wide-funding output `global` with the class and key the funding
/// coinbase assigned it, signing fresh so every spend is distinct.
fn wide_spend_at(funding: &[Txid], width: usize, keys: &SigningKeys, global: usize) -> Arc<Tx> {
    let source = funding[global / width];
    let vout =
        u32::try_from(global % width).unwrap_or_else(|error| panic!("invalid wide vout: {error}"));
    Arc::new(build_wide_signed_spend_tx(source, vout, keys))
}

/// Builds the per-run target spend sets with their distinct blocks, verifying
/// each block carries coinbase plus 2000 spends and hashes distinctly.
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

/// Prints the frozen corpus identity: counts only, no applies (the protocol run
/// below applies the prefix once per sample).
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

/// Production span fields captured for one measured sample. The whole protocol
/// runs on the bench thread; the static is drained per sample, so prefix
/// applies never leak into a measurement.
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

/// Bench-side tracing subscriber: records only the step-21 profile events by
/// their message literal and micros fields. Everything else is ignored.
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

/// Bench-local measured `MiningControl`: forwards every call to the real
/// per-sample coordinator and records the wall time plus candidate facts of
/// each `get_block_template` call. No fake service: every other trait method
/// forwards unchanged, and the default `submit_block_with_bytes` fallback is
/// left alone.
struct MeasuredMiningControl {
    inner: Arc<MiningCoordinator>,
    calls: ParkingMutex<Vec<MeasuredTemplateCall>>,
}

/// Facts recorded for one `get_block_template` call.
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

    /// Recorded service calls, oldest first. Drained once per sample after the
    /// handler reply lands, outside the measured interval.
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

    fn submit_block(&self, block: Block) -> Result<BlockValidationResult, MiningControlError> {
        self.inner.submit_block(block)
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

/// Untimed serving stack, prefix, and admission for one Step-21 sample.
///
/// Builds the production stack as node birth does, replays the corpus prefix,
/// and admits the background plus the run's target spends (100k live). The
/// measured connect tail runs in `run_block_template_unit`.
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
    // The coordinator attaches to the node's generation signal, so connect
    // publishes through the production wake path. The decorator records the
    // wall time and candidate facts of the single service call the measured
    // dispatch below performs.
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
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("template prefix apply failed: {error}"));
    }
    // Untimed: 98k background admissions at the current wall-clock time.
    admit_signed_spends(state, &corpus.background);
    let background_len = state.mempool_reader().read().len();
    assert_eq!(
        background_len, BLOCK_TEMPLATE_BACKGROUND_TXS,
        "background admitted {background_len} transactions"
    );
    assert_admission_residency(state, &corpus.background);
    // Untimed: this sample's 2000 target spends on the same clock, bringing
    // the live pool to exactly 100k before connect.
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
/// Results of one measured T2 unit: timing splits plus identity counters.
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

/// One measured T2 unit: fresh state, untimed serving stack plus prefix plus
/// admission, then the timed connect tail through the first new-tip template
/// response. The sample driver repeats whole units (reusing the sample's
/// corpus index, so the frozen corpus is unchanged) until the measured total
/// reaches `MRP_SAMPLE_MEASURED_FLOOR`; every unit is independent.
///
/// Setup asserts fail closed: 98k background plus 2000 targets (100k live)
/// before connect with every target spend resident, 98k after connect, the new
/// tip equals the target hash, and both the recorded service call and the
/// handler response name the new tip with a non-empty selection. Span capture
/// asserts exactly one tail-begin, publish-profile, and on-connect event per
/// unit, and the decorator asserts exactly one service call per reply. All
/// setup runs outside the timer; the asserts below run after the reply edge
/// except the tip check, which is part of the measured path as before.
fn run_block_template_unit(corpus: &BlockTemplateCorpus, run: usize) -> BlockTemplateUnit {
    let (_dir, state) = open_regtest_state();
    let BlockTemplateSetup {
        measured,
        handler,
        params,
        pool_live,
        background_len,
    } = setup_block_template_sample(&state, corpus, run);
    // Measured: connect tail through the first new-tip template reply.
    reset_tail_capture();
    let target = &corpus.target_blocks[run];
    let call_started = quanta::Instant::now();
    let tip = state
        .apply_block(target)
        .unwrap_or_else(|error| panic!("target connect failed: {error}"));
    assert_eq!(
        tip.hash,
        target.block_hash().0,
        "connect must publish the target block as the new tip"
    );
    // Protocol endpoint: the first real in-process RPC handler response,
    // covering request parsing, readiness, rule negotiation, the single
    // measured service assembly, mandatory-rule checks, and JSON rendering.
    // Exactly one dispatch runs per sample: no prewarming call fills the
    // cache first, so the recorded service call is the reply's own assembly.
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
    // Remainder inside the total: journal emission, head publication
    // (`publish_applied`), handler negotiation and JSON rendering above the
    // timed assembly, and bench overhead. Attributed nowhere; reported for
    // the split to close.
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

/// Prints the per-sample JSONL ledger line for one Step-21 sample.
///
/// Carries every unit duration as exact integer nanoseconds (`unit_ns`), the
/// unit count, and the exact measured total (`total_ns`; the parser derives
/// the mean as `total_ns / unit_count`), plus the per-unit production splits
/// (still `*_us` with explicit microsecond units); the boundary excludes HTTP
/// transport and JSON-RPC framing/auth only. All units of one sample share
/// the sample's corpus index, so pool facts and the tip are asserted equal
/// across units and reported once.
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
/// Step-21 block-to-template baseline: connect tail through the first new-tip
/// template response on a 100k live pool.
///
/// Workload: real native regtest `NodeState`, 98,000 background spends plus one
/// sample's 2,000 target spends (100,000 live) admitted through the production
/// `sendrawtransaction` gateway path at the current wall-clock time with
/// validated spendable prevouts; each sample connects a distinct valid block
/// (coinbase + 2000 admitted spends, 2001 txs) in a fresh state, then takes the
/// first response from the real in-process RPC handler
/// (`Handler::dispatch("getblocktemplate", …)` on a `Context` carrying the
/// per-sample `MiningCoordinator`, regtest network) with
/// `[{"rules": ["segwit"]}]`.
///
/// Measured interval: the production `apply_block: tail begin` event
/// (`PublishMode::Now` arm entry) through the handler response, split into the
/// existing `durable_sync_us` / `durable_commit_us` spans, the new
/// `on_connect_us` span, and decorator-measured `assembly_us` (the single
/// service call the dispatch performs: selection plus finish plus projection
/// on a cold cache). The remainder inside the
/// total covers journal emission, head publication (`publish_applied`), handler
/// negotiation and JSON rendering above the timed assembly, and bench overhead.
/// Outside the boundary by construction: HTTP transport and JSON-RPC
/// framing/auth only.
///
/// Protocol: standalone and explicitly selected. This function builds the
/// corpus and runs 3 warmups plus 10 measured samples exactly once, and only
/// when the bench binary receives the exact `block_to_template_baseline`
/// argument; otherwise it returns before any workload or registration.
/// Inside each sample, whole independent units (fresh state each, same corpus
/// index) repeat until the measured total reaches
/// `MRP_SAMPLE_MEASURED_FLOOR`; at least one unit always runs. Nothing is
/// registered with criterion and no criterion measurement is reported:
/// per-sample JSON lines (`unit_ns`, `unit_count`, `total_ns`; the parser
/// derives the mean as `total_ns / unit_count`) plus the p50/p95/p99/max
/// summary over measured sample means on stdout are the ledger.
/// Invocation: `cargo bench -p bitcoin-rs-node --bench sync_pipeline
/// block_to_template_baseline -- --nocapture` (default features: fjall).
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

// ---------------------------------------------------------------------------
// Step-8 template-render baseline: repeated same-generation service and RPC
// hits on a fixed 100k resident pool, plus a cold-miss control.
// ---------------------------------------------------------------------------

/// Step-8 warmup replies: same path, reported, excluded from summaries.
const TEMPLATE_RENDER_WARMUPS: usize = 3;
/// Step-8 measured warm-cache samples.
const TEMPLATE_RENDER_SAMPLES: usize = 10;

/// Transport-neutral template request the warm-cache arms repeat.
///
/// Mode `Template` with no capabilities, no caller rules, and no long-poll id.
/// The RPC arms pass the equivalent `[{"rules": ["segwit"]}]` params through
/// `Handler::dispatch`, which parses to the same mode; caller rules gate the
/// mandatory-rule check, not assembly.
fn template_render_request() -> BlockTemplateRequest {
    BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
        coinbase_budget: None,
    }
}

/// Untimed serving stack, prefix, and admission for one Step-8 sample.
///
/// Builds the production stack as node birth does, replays the corpus prefix,
/// and admits the background plus the run's target spends (100k live, nothing
/// connects). The concrete coordinator moves into the trait object, so the
/// handler and control share its single strong owner while the generation
/// signal keeps only weak references. The measured arms run in
/// `run_template_render_sample`.
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
        state
            .apply_block(block)
            .unwrap_or_else(|error| panic!("render prefix apply failed: {error}"));
    }
    // Untimed: 98k background admissions at the current wall-clock time.
    admit_signed_spends(state, &corpus.background);
    let background_len = state.mempool_reader().read().len();
    assert_eq!(
        background_len, BLOCK_TEMPLATE_BACKGROUND_TXS,
        "render background admitted {background_len} transactions"
    );
    assert_admission_residency(state, &corpus.background);
    // Untimed: this sample's 2000 target spends on the same clock, bringing the
    // live pool to exactly 100k. Nothing connects: the tip stays the prefix
    // tip and the pool stays resident for every measured arm.
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
/// One measured T3 cold unit: fresh state, untimed serving stack plus prefix
/// plus admission, then the timed first (cold-miss) dispatch, which assembles
/// on a cold cache (selection plus finish plus projection including
/// `signalling_rules`) and renders the full JSON reply. Returns the owned
/// prepared generation with its cold reply; the sample driver retains the
/// last cold unit's generation for the warm arms, so every identity compare
/// stays within one state. Never a sequence-wake invalidation: the miss is a
/// genuinely cold cache in a fresh state, and the setup asserts (98k
/// background plus the run's 2000 target spends, 100k live, every spend
/// resident, prefix tip, no connect) run untimed before the dispatch.
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

/// Times one warm service call: `signalling_rules` plus
/// `template_from_candidate` projection only, with no JSON serialization.
/// Assembly is done on the retained generation; this is a pure hit. Returns
/// the shared candidate `Arc` (moved, never cloned) so the driver can prove
/// reuse without duplicating the selection.
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

/// Times one warm RPC dispatch on the retained generation: parse, readiness,
/// rule negotiation, the cache-hit projection, mandatory-rule checks, and
/// JSON render (`consensus_bytes` plus hex per transaction). No assembly.
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

/// Cold arm of one warm-cache sample: fresh-state cold units until the
/// measured total reaches the floor. Returns the last prepared generation
/// for the warm arms. Setup stays outside every timer; each unit boundary
/// is inside `render_cold_unit`.
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

/// Service-hit arm on the fixed generation: repeated trait calls until the
/// measured total reaches the floor. Returns the first and last shared
/// candidate `Arc`s plus the selection facts. Every timed span is inside
/// `render_service_call`.
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

/// Service-hit stability arm on the same generation: continued repeats
/// until the measured total reaches the floor. Returns the last shared
/// candidate `Arc`. Every timed span is inside `render_service_call`.
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

/// RPC warm-hit arm on the fixed generation: repeated dispatches until the
/// measured total reaches the floor. Returns the first and last replies;
/// a single-unit arm reuses the one reply for both roles. Every timed span
/// is inside `render_warm_dispatch`.
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

/// Runs one independent warm-cache sample: fresh-state cold units until the
/// cold total reaches `MRP_SAMPLE_MEASURED_FLOOR`, then warm service/RPC rows
/// repeated on the retained fixed generation until each arm's total reaches
/// the same floor. The last cold unit's prepared generation serves every warm
/// arm, so all measured arms serve one fixed generation.
///
/// Setup asserts fail closed per cold unit (100k live, every spend resident,
/// prefix tip, no connect). Identity asserts fail closed after the timers:
/// the first and last warm service calls of each arm reuse one cached
/// `Arc<Candidate>` with an unchanged generation, and the first and last
/// warm RPC replies match the cold reply on every deterministic field while
/// `curtime` is checked for permitted evolution, never strict equality.
/// Returns the four arm means in order `(rpc_miss, service_hit, service_hit2,
/// rpc_hit)`.
fn run_template_render_sample(
    corpus: &BlockTemplateCorpus,
    run: usize,
    warmup: bool,
) -> (Duration, Duration, Duration, Duration) {
    // Cold arm: fresh-state units to the floor; retain the last prepared
    // generation for the warm arms below.
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
    // Arm 2, service hits: repeated trait calls on the fixed generation. The
    // driver retains the first and last shared candidate `Arc`s (moved, never
    // cloned) plus the selection facts for the ledger.
    let mut service_units: Vec<Duration> = Vec::new();
    let mut service_total = Duration::ZERO;
    let (svc_first, svc_last, selected_txs, selected_weight) =
        collect_render_service_arm(&control, &mut service_units, &mut service_total);
    // Arm 3, service-hit stability: continued repeats on the same generation.
    // Every call must share the arm-2 candidate `Arc`, proving the timed
    // calls were pure hits.
    let mut service2_units: Vec<Duration> = Vec::new();
    let mut service2_total = Duration::ZERO;
    let svc2_last = collect_render_service2_arm(&control, &mut service2_units, &mut service2_total);
    assert_render_service_reuse_arcs(&svc_first, &svc_last, &tip.hash);
    assert_render_service_reuse_arcs(&svc_first, &svc2_last, &tip.hash);
    // Arm 4, RPC warm hits: repeated dispatches rendering the same generation.
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

/// Proves repeated warm service calls shared one cached candidate.
///
/// Asserts `Arc` pointer reuse plus unchanged generation identity, tip, and
/// height, and that the candidate extends the sample tip with a non-empty
/// selection.
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

/// Asserts every deterministic field matches between the cold and warm
/// replies, including the full `transactions` array whose `data` hex a
/// precomputed-hex field must preserve. `curtime` is excluded here and
/// checked separately for permitted evolution.
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

/// Checks warm-hit time evolution and generation identity, returning the
/// stamped times and the cold generation id for the ledger.
///
/// `curtime` is never strictly equated: the candidate clock reads the wall
/// clock at assembly with no injection point, so a same-generation hit only
/// promises monotonicity (`hit >= cold`) with both stamps at or above the
/// chain-determined `mintime`.
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

/// Ledger inputs for one Step-8 sample line. Borrows the rendered reply, the
/// generation id, the tip hash, and every arm's unit slices; every other
/// field is a copied scalar.
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
/// Assertion phase of the per-sample ledger line: selection facts plus the
/// fail-closed sample checks. Returns the rendered transaction count and the
/// `data` byte total. No timers run here; the JSON emission stays in
/// `report_render_sample` with identical fields and units.
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

/// Records selection facts and prints the per-sample JSONL ledger line.
///
/// Every arm carries its unit durations as exact integer nanoseconds
/// (`<arm>_ns`), the unit count (`<arm>_count`), and the exact measured total
/// (`<arm>_total_ns`; the parser derives the mean as `total / count`). The
/// rendered transaction count must equal the semantic selection, and the
/// `data` byte total bounds the serialization work Step 8.1 targets.
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
/// Step-8 template-render baseline: repeated same-generation hits on a 100k
/// resident pool.
///
/// Workload: real native regtest `NodeState`, 98,000 background spends plus one
/// sample's 2,000 target spends (100,000 live) admitted through the production
/// `sendrawtransaction` gateway path at the current wall-clock time with
/// validated spendable prevouts, on the shared frozen Step-21 corpus
/// (`build_block_template_corpus`; prefix tip 132, heights below the regtest
/// halving at 150). Nothing connects: the tip stays the prefix tip and the
/// pool stays resident, so every measured arm serves one fixed generation
/// through the real production `MiningCoordinator` (via the `MiningControl`
/// trait) and the real in-process RPC `Handler::dispatch("getblocktemplate",
/// [{"rules": ["segwit"]}])`.
///
/// Arms per sample, timed separately with `quanta` and reported as distinct
/// JSONL fields, each with its exact unit durations (`<arm>_ns`), unit count
/// (`<arm>_count`), and exact measured total (`<arm>_total_ns`; the parser
/// derives the mean as `total / count`): `rpc_miss_ns` (cold dispatches, each
/// a fresh state: assembly plus render), `service_hit_ns` (trait calls after
/// the miss: projection only), `service_hit2_ns` (continued trait calls:
/// `Arc` reuse proof and hit stability), `rpc_hit_ns` (warm dispatches:
/// render on the warm cache). Every arm repeats to `MRP_SAMPLE_MEASURED_FLOOR`; cold units
/// use fresh states while warm rows repeat on the last cold unit's retained
/// fixed generation. The service-hit versus RPC-hit difference isolates the
/// per-reply serialization cost Step 8.1 targets (`consensus_bytes` plus hex
/// per transaction in `render_template_transactions`); the signalling skip
/// lives inside the service-hit projection. Identity: `Arc::ptr_eq` plus
/// unchanged `template_id`, tip hash, mempool sequence, and height across the
/// first and last warm service call of each arm; strict equality on every
/// deterministic RPC field (including the full `transactions` array) between
/// the cold reply and the first and last warm replies, with `curtime` checked
/// for permitted
/// evolution (`hit >= cold`, both `>= mintime`), never strict equality,
/// because the candidate clock has no injection point. Counts recorded per
/// sample: resident pool, selected transactions and candidate weight,
/// rendered transactions and `data` byte total.
///
/// Protocol: standalone and explicitly selected. This function builds the
/// corpus and runs 3 warmups plus 10 measured samples exactly once, and only
/// when the bench binary receives the exact `template_render_baseline`
/// argument; otherwise it returns before any workload or registration.
/// Nothing is registered with criterion and no criterion measurement is
/// reported: per-sample JSON lines plus per-arm p50/p95/p99/max summaries
/// over measured sample means on stdout are the ledger. The same command runs
/// the baseline and the candidate trees; the parent labels the runs.
/// Invocation: `cargo bench -p bitcoin-rs-node --bench sync_pipeline
/// template_render_baseline -- --nocapture` (default features: fjall).
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

// MRP Criterion config: the explicit Criterion configuration below sets the
// sample, warmup, and measurement budgets for the legacy rows. The three T4
// arms moved from Criterion registration to counted
// sampling (`--mrp-counted`, shared `measured_samples` sampler); their full
// IDs stay `<arm>/flat`, with one warmup sample plus ten measured samples of
// one second of measured work each. The standalone T2/T3 rows above register
// nothing with Criterion; their duration rule is the per-sample
// `MRP_SAMPLE_MEASURED_FLOOR` loop.
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

/// Untimed MRP verification entrypoint (`--mrp-verify`, called from `main`
/// below). Executes the real unit/identity/assertion paths and proves,
/// without running Criterion or emitting timing samples:
/// - T2: one full unit on corpus target 0 (fresh state, untimed serving
///   stack plus prefix plus 100k admission, timed-path connect tail through
///   the first new-tip template reply) with every setup, tip, pool, service,
///   and span assertion;
/// - T3: one cold unit on corpus target 0 plus two warm service calls and
///   one warm dispatch on its retained generation, with the `Arc` reuse,
///   deterministic-field, and reply-identity assertions;
/// - T4: one fresh-state unit per Criterion arm (admitted connect with
///   gateway admission plus residency, unseen connect, admission
///   throughput with residency) through the production paths.
///
/// Panics (fail-closed, nonzero exit) on any mismatch; prints deterministic
/// `mrp-verify` lines, then one `mrp-verify: node_identity {json}` line (the
/// registration's `node_identity` pins, built from the corpus, unit, and cold
/// setup verified above, so it adds no timed work), and a final
/// `mrp-verify: PASS` on success.
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
            state
                .apply_block(block)
                .unwrap_or_else(|error| panic!("mrp-verify prefix apply failed: {error}"));
        }
        admit_signed_spends(&state, &admission_txs);
        assert_admission_residency(&state, &admission_txs);
        let tip = state
            .apply_block(last_block)
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
            state
                .apply_block(block)
                .unwrap_or_else(|error| panic!("mrp-verify prefix apply failed: {error}"));
        }
        let tip = state
            .apply_block(last_block)
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
            state
                .apply_block(block)
                .unwrap_or_else(|error| panic!("mrp-verify prefix apply failed: {error}"));
        }
        admit_signed_spends(&state, &admission_txs);
        assert_admission_residency(&state, &admission_txs);
    }
    println!("mrp-verify: admission_throughput unit ok ({admitted} gateway submits resident)");
    print_mrp_node_identity(&corpus, &unit, &setup);
    println!("mrp-verify: PASS");
}

/// Prints the untimed `mrp-verify` node-identity pins: the raw engine label
/// verbatim, both baselines' tips, and the pool/block shape counters. Object
/// keys are emitted in sorted order so separate binaries produce
/// byte-identical output for cross-binary byte comparison.
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
    serde_json::to_writer(
        &mut line,
        &serde_json::json!({
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

/// Untimed counted-verification entrypoint (`--mrp-verify-counted`, called
/// from `main` below). Executes each converted real unit exactly once through
/// the production paths with the counted arms' exact timer boundaries, then
/// exercises the shared stopping-rule arithmetic on deterministic durations.
/// Emits no `MRP_COUNTED_SAMPLE` records and no timing measurements.
///
/// Panics (fail-closed, nonzero exit) on any mismatch; prints deterministic
/// `mrp-verify-counted` lines and a final `mrp-verify-counted: PASS` on
/// success.
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

/// Validates the `--mrp-counted` invocation shape before any benchmark
/// framework use: the flag first, exactly one ID argument, no other
/// arguments, and a known counted row. Malformed or unknown IDs exit nonzero
/// without entering Criterion.
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

/// Rejects any single-flag counted invocation that carries extra arguments,
/// before the benchmark framework starts.
fn require_bare_counted_flag(args: &[String], flag: &str) {
    if args.len() != 1 {
        eprintln!("{flag}: expected no additional arguments");
        std::process::exit(2);
    }
}

/// Binary entrypoint: `--mrp-verify` runs the untimed real-fixture
/// verification path with no Criterion involvement and no timing output;
/// `--mrp-list-counted` lists the counted row IDs without fixture
/// construction or sampling; `--mrp-counted ROW_ID` runs one counted row
/// through the shared measured-work sampler; `--mrp-verify-counted` runs
/// each converted real unit once plus the stopping-rule arithmetic without
/// sample records. Malformed counted invocations are rejected before the
/// benchmark framework starts. Every other invocation runs the Criterion
/// benchmarks exactly as `criterion_main!` did.
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
