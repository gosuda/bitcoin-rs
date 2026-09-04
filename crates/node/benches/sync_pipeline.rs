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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_script::script::push_int;
// seam: getdata inventory items stay rust-bitcoin at the p2p wire boundary.
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::secp256k1::{All, Message as SecpMessage, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Amount, OutPoint as OracleOutPoint, ScriptBuf as OracleScriptBuf, Sequence as OracleSequence,
    Transaction as OracleTx, TxIn as OracleTxIn, TxOut as OracleTxOut, Txid as OracleTxid, Witness,
    absolute, opcodes, script::Builder as OracleBuilder, transaction,
};
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
use bitcoin_rs_index::BlockSource as _;
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_node::{
    BlockSync, Network, NoOpZmqPublisher, NodeConfig, TxIndexRuntime,
    apply::ApplyHandles,
    state::NodeState,
    sync::{SyncBudget, default_sync_budget},
};
use bitcoin_rs_p2p::Message;
use bitcoin_rs_primitives::deserialize;
use bitcoin_rs_rpc::context::{BlockBodySource, BlockLog, BlockRecord};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::Mutex as ParkingMutex;
use parking_lot::{Mutex, RwLock};
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
                        .applied_tip()
                        .load_full()
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
    let blocks = signed_spend_proxy_blocks();
    print_signed_spend_proxy_summary(&blocks);

    const SIGNED_SPEND_SAMPLES: usize = 30;
    let samples: ParkingMutex<Vec<Duration>> =
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
                samples.lock().push(sweep_start.elapsed());
                black_box(
                    state
                        .applied_tip()
                        .load_full()
                        .unwrap_or_else(|| panic!("signed-spend proxy did not publish a tip"))
                        .height,
                );
            }
            start.elapsed()
        })
    });

    print_percentiles("signed_spend_proxy", &samples.lock());
}

fn deterministic_initial_sync_proxy(c: &mut Criterion) {
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_pure_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::Disabled).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_indexed_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::Noop).prebuild_run(),
                |fixture| black_box(fixture.run()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_received_scan_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::Disabled).prebuild_unsolicited(),
                |fixture| black_box(fixture.request_after_unsolicited_received()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_deep_headers_reverse_scan_overflow_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new_reverse_scan_overflow(TxIndexMode::Disabled),
                |fixture| black_box(fixture.run_reverse_scan_overflow()),
                BatchSize::SmallInput,
            );
        },
    );
    c.bench_function(
        "deterministic_initial_sync_proxy_in_order_inbound_128_blocks",
        |b| {
            b.iter_batched(
                || SyncFixture::new(TxIndexMode::Disabled).prebuild_in_order(),
                |fixture| black_box(fixture.run_in_order_inbound()),
                BatchSize::SmallInput,
            );
        },
    );
    bench_production_state_sync(c);
    c.bench_function("deterministic_initial_sync_proxy_many_peers_512", |b| {
        b.iter_batched(
            || SyncFixture::new_with_peers(TxIndexMode::Disabled, SYNC_PROXY_PEERS),
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
                        TxIndexMode::Disabled,
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
                || SyncFixture::new(TxIndexMode::RocksDb).prebuild_run(),
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

fn block_source_height_lookup(c: &mut Criterion) {
    let source = block_source_fixture(SYNC_PROXY_HEADER_HEIGHT);
    c.bench_function("block_source_height_lookup_tail_4096", |b| {
        b.iter(|| {
            black_box(
                source
                    .block_at_height(black_box(SYNC_PROXY_HEADER_HEIGHT))
                    .unwrap_or_else(|| panic!("missing block at tail height")),
            );
        });
    });
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
        .applied_tip()
        .load_full()
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
        "sync_pipeline_apply_spend_heavy_proxy blocks={} txs={transaction_count} elapsed={elapsed:?} recorded_body_bytes={recorded_body_bytes}",
        applied_height.saturating_add(1),
    );
}

fn block_source_fixture(max_height: u32) -> bitcoin_rs_node::NodeBlockSource {
    let block = Network::Regtest.genesis_block();
    let records = (0..=max_height)
        .map(|height| BlockRecord::from_block(height, &block))
        .collect();
    bitcoin_rs_node::NodeBlockSource::new(Arc::new(RwLock::new(records))).with_block_body_source(
        Arc::new(InstalledBlockBody {
            hash: block.block_hash(),
            bytes: consensus_bytes(&block),
        }),
    )
}

struct InstalledBlockBody {
    hash: BlockHash,
    bytes: Vec<u8>,
}

impl BlockBodySource for InstalledBlockBody {
    fn block_body(&self, _height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        (hash == self.hash).then(|| self.bytes.clone())
    }
}

fn open_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    config.txindex = false;
    let state = NodeState::open(config, None)
        .unwrap_or_else(|error| panic!("open node state failed: {error}"));
    (dir, state)
}

#[cfg(feature = "rocksdb")]
fn open_pruned_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    "rocksdb".clone_into(&mut config.storage_backend);
    config.txindex = false;
    config.prune_target_mb = 1;
    let state = NodeState::open(config, None)
        .unwrap_or_else(|error| panic!("open pruned node state failed: {error}"));
    (dir, state)
}

struct SyncFixture {
    sync: BlockSync,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    outbound_rxs: Vec<crossbeam_channel::Receiver<Message>>,
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
enum TxIndexMode {
    Disabled,
    Noop,
    #[cfg(feature = "rocksdb")]
    RocksDb,
}

impl SyncFixture {
    fn new(tx_index_mode: TxIndexMode) -> Self {
        Self::new_with_peers(tx_index_mode, 1)
    }

    fn new_with_peers(tx_index_mode: TxIndexMode, peer_count: usize) -> Self {
        Self::new_with_block_count(tx_index_mode, peer_count, SYNC_PROXY_BLOCKS)
    }

    fn new_with_block_count(
        tx_index_mode: TxIndexMode,
        peer_count: usize,
        block_count: u32,
    ) -> Self {
        let mut tree = BlockTree::new();
        let (blocks, received_scan_expected) = populate_sync_header_chain(&mut tree, block_count);

        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let (_inbound_headers_tx, inbound_headers_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let tx_index_runtime = tx_index_for_mode(tx_index_mode);
        let handles = apply_handles(
            Arc::clone(&chain_tip),
            Arc::clone(&applied_tip),
            Arc::clone(&block_tree),
            tx_index_runtime,
        );
        let sync = BlockSync::new(
            handles,
            Arc::clone(&peer_table),
            inbound_headers_rx,
            inbound_blocks_rx,
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

    fn new_reverse_scan_overflow(tx_index_mode: TxIndexMode) -> Self {
        let mut fixture =
            Self::new_with_block_count(tx_index_mode, 0, SYNC_REVERSE_SCAN_OVERFLOW_BODY_BLOCKS);
        // The bench stages 128 received blocks and still needs to request the
        // full 128-block pending window, so the received-block budget must
        // cover both the staged blocks and the new requests.
        fixture.sync.install_budget(SyncBudget {
            max_received_blocks: 256,
            ..default_sync_budget()
        });
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
    outbound_rxs: Vec<crossbeam_channel::Receiver<Message>>,
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
        "fjall".clone_into(&mut config.storage_backend);
        config.txindex = true;
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
        "fjall".clone_into(&mut config.storage_backend);
        config.txindex = true;
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
            let block_tree = state.block_tree();
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
            .applied_tip()
            .load_full()
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
            .applied_tip()
            .load_full()
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
    config.p2p_listen.clear();
    config.txindex = false;
    config
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
) -> Vec<crossbeam_channel::Receiver<Message>> {
    let mut outbound_rxs = Vec::with_capacity(peer_count);
    for index in 0..peer_count {
        let port = u16::try_from(8_333_usize.saturating_add(index))
            .unwrap_or_else(|error| panic!("invalid synthetic peer port: {error}"));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let (outbound_tx, outbound_rx) = unbounded::<Message>();
        peer_table.register(addr, bitcoin_rs_p2p::PeerLease::new(outbound_tx));
        outbound_rxs.push(outbound_rx);
    }
    outbound_rxs
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    tx_index_runtime: Option<Arc<TxIndexRuntime>>,
) -> ApplyHandles {
    let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.set_listener(Box::new((*coin_stats).clone()));
    let utxo = Arc::new(utxo);
    let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
    let mempool_gateway = bitcoin_rs_mempool::MempoolGateway::shared(Arc::clone(&mempool));
    ApplyHandles::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        utxo,
        coin_stats,
        tx_index_runtime,
        mempool,
        mempool_gateway,
        Arc::new(bitcoin_rs_node::mining::MiningGenerationSignal::new()),
        Arc::new(RwLock::new(BlockLog::new())),
        Arc::new(RwLock::new(HashMap::<Txid, Tx>::new())),
        Arc::new(NoOpZmqPublisher),
        Arc::new(bitcoin_rs_node::state::ChainEventPublisher::detached(0).0),
    )
}

fn tx_index_for_mode(mode: TxIndexMode) -> Option<Arc<TxIndexRuntime>> {
    match mode {
        TxIndexMode::Disabled => None,
        TxIndexMode::Noop => {
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
            Some(Arc::new(TxIndexRuntime::new(wake_tx)))
        }
        #[cfg(feature = "rocksdb")]
        TxIndexMode::RocksDb => {
            let (wake_tx, _wake_rx) = crossbeam_channel::bounded(1);
            Some(Arc::new(TxIndexRuntime::new(wake_tx)))
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
            version: 1,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase_transaction(height)],
    };
    block.header.merkle_root = block_merkle_root(&block);
    mine_block_to_declared_target(&mut block);
    block
}

fn child_fanout_coinbase_block(parent: &Block, height: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![fanout_coinbase_transaction(height)],
    };
    block.header.merkle_root = block_merkle_root(&block);
    mine_block_to_declared_target(&mut block);
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
            version: 1,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs,
    };
    block.header.merkle_root = block_merkle_root(&block);
    mine_block_to_declared_target(&mut block);
    block
}

fn child_header(prev_blockhash: BlockHash, time: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time,
        bits: 0x207f_ffff,
        nonce: 0,
    }
}

fn coinbase_transaction(height: u32) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: coinbase_script_sig(height),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 50_0000_0000,
            script_pubkey: Vec::new(),
        }],
    }
}

fn fanout_coinbase_transaction(height: u32) -> Tx {
    let outputs = (0..SPEND_PROXY_FANOUT)
        .map(|_| TxOut {
            value: SPEND_PROXY_COINBASE_OUTPUT_VALUE,
            script_pubkey: push_int(1),
        })
        .collect();
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: coinbase_script_sig(height),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs,
    }
}

fn spend_proxy_transaction(prev_txid: Txid, vout: u32) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, vout),
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: SPEND_PROXY_SPEND_OUTPUT_VALUE,
            script_pubkey: push_int(1),
        }],
    }
}

fn coinbase_script_sig(height: u32) -> Vec<u8> {
    let mut script = Vec::with_capacity(5);
    script.push(4);
    script.extend_from_slice(&height.to_le_bytes());
    script
}

fn mine_block_to_declared_target(block: &mut Block) {
    while !pow_met(block.header.bits, &block.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .unwrap_or_else(|| panic!("exhausted nonce while mining proxy block"));
    }
}

/// Consensus merkle root over the block's txids: pairwise double-SHA256 with
/// the last leaf duplicated on odd levels.
fn block_merkle_root(block: &Block) -> Hash256 {
    let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        leaves = next;
    }
    Hash256::from_le_bytes(&leaves[0])
}

/// Decodes a 256-bit compact target into little-endian bytes. Negative,
/// overflowed, and zero-mantissa encodings decode to an unreachable zero.
fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let mut target = [0_u8; 32];
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent > 34 {
        return target;
    }
    let mantissa_bytes = mantissa.to_le_bytes();
    if exponent >= 3 {
        let offset = exponent - 3;
        for (index, byte) in mantissa_bytes.iter().enumerate().take(3) {
            if let Some(slot) = target.get_mut(offset + index) {
                *slot = *byte;
            }
        }
    } else {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&shifted.to_le_bytes());
    }
    target
}

/// Returns true when `hash` is at or below the compact target, comparing the
/// little-endian byte arrays from the most significant end.
fn pow_met(bits: u32, hash: &BlockHash) -> bool {
    let target = compact_to_target(bits);
    let hash_le = hash.as_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
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
/// the coinbase outputs from 100 blocks back, each carrying a real ECDSA signature.
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
            version: 1,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = block_merkle_root(&block);
    mine_block_to_declared_target(&mut block);
    block
}

fn signed_fanout_coinbase_transaction(height: u32, keys: &SigningKeys) -> Tx {
    let mut outputs = Vec::with_capacity(SPEND_PROXY_FANOUT as usize + 1);
    // P2PKH outputs (indices 0..22).
    for i in 0..22u32 {
        let pkh = keys.p2pkh[usize::try_from(i).unwrap()].pubkey_hash();
        let script = OracleScriptBuf::new_p2pkh(&pkh);
        outputs.push(TxOut {
            value: SPEND_PROXY_COINBASE_OUTPUT_VALUE,
            script_pubkey: script.as_bytes().to_vec(),
        });
    }
    // P2WPKH outputs (indices 22..44).
    for i in 0..22u32 {
        let pkh = keys.p2wpkh[usize::try_from(i).unwrap()]
            .wpubkey_hash()
            .unwrap();
        let script = OracleScriptBuf::new_p2wpkh(&pkh);
        outputs.push(TxOut {
            value: SPEND_PROXY_COINBASE_OUTPUT_VALUE,
            script_pubkey: script.as_bytes().to_vec(),
        });
    }
    // P2WSH 2-of-3 outputs (indices 44..64).
    for i in 0..20u32 {
        let redeem = p2wsh_2of3_redeem_script(keys, i);
        let script_hash = redeem.wscript_hash();
        let script = OracleScriptBuf::new_p2wsh(&script_hash);
        outputs.push(TxOut {
            value: SPEND_PROXY_COINBASE_OUTPUT_VALUE,
            script_pubkey: script.as_bytes().to_vec(),
        });
    }
    // BIP141 witness commitment output.
    let commitment = witness_commitment_for_coinbase(&outputs);
    outputs.push(TxOut {
        value: 0,
        script_pubkey: witness_commitment_script_pubkey(&commitment),
    });

    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: coinbase_script_sig(height),
            sequence: u32::MAX,
            witness: vec![WITNESS_RESERVED_VALUE.to_vec()],
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
    let mut txs = Vec::with_capacity(SPEND_PROXY_FANOUT as usize + 1);
    // Coinbase for this spend block (witness-bearing, with commitment).
    txs.push(signed_fanout_coinbase_transaction(height, keys));
    // 64 spend transactions, one per funded output.
    for vout in 0..SPEND_PROXY_FANOUT {
        let prevout_value = SPEND_PROXY_COINBASE_OUTPUT_VALUE;
        let spend_tx = build_signed_spend_tx(source_txid, vout, prevout_value, keys);
        txs.push(spend_tx);
    }
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash: parent.block_hash(),
            merkle_root: Hash256::default(),
            time: parent.header.time.saturating_add(1),
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs,
    };
    block.header.merkle_root = block_merkle_root(&block);
    // Recompute the coinbase witness commitment now that the full tx set is known.
    let commitment = block_witness_commitment(&block.txs);
    let coinbase = &mut block.txs[0];
    // Replace the placeholder commitment output (last output) with the real one.
    let last = coinbase
        .outputs
        .last_mut()
        .unwrap_or_else(|| panic!("coinbase missing commitment output"));
    last.script_pubkey = witness_commitment_script_pubkey(&commitment);
    // Recompute merkle root after updating the commitment.
    block.header.merkle_root = block_merkle_root(&block);
    mine_block_to_declared_target(&mut block);
    block
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
    let root = merkle_root_bytes(&mut leaves);
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(&root);
    buffer[32..].copy_from_slice(&WITNESS_RESERVED_VALUE);
    double_sha256(&buffer)
}

/// Pairwise double-SHA256 merkle root with last-leaf duplication on odd levels.
fn merkle_root_bytes(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    while leaves.len() > 1 {
        let len = leaves.len();
        let mut next = Vec::with_capacity(len.div_ceil(2));
        for pos in 0..len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(len - 1)];
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        *leaves = next;
    }
    leaves[0]
}

/// Builds and signs a single spend transaction for output `vout` of
/// `source_txid`. The spend class is determined by the output index:
/// 0..22 = P2PKH, 22..44 = P2WPKH, 44..64 = P2WSH 2-of-3.
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
        )
    } else if vout < 44 {
        build_signed_p2wpkh_spend(
            oracle_txid,
            vout,
            prevout_value,
            keys,
            usize::try_from(vout - 22).unwrap(),
        )
    } else {
        build_signed_p2wsh_spend(oracle_txid, vout, prevout_value, keys)
    }
}

/// P2PKH spend: scriptSig = `<sig> <pubkey>`, signed with legacy sighash.
fn build_signed_p2pkh_spend(
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
            witness: Witness::new(),
        }],
        output: vec![OracleTxOut {
            value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
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

/// P2WPKH spend: empty scriptSig, witness = `[sig, pubkey]`, signed with BIP143.
fn build_signed_p2wpkh_spend(
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
            witness: Witness::new(),
        }],
        output: vec![OracleTxOut {
            value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: OracleBuilder::new().push_int(1).into_script(),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            0,
            &script_pubkey,
            Amount::from_sat(prevout_value),
            EcdsaSighashType::All,
        )
        .unwrap_or_else(|e| panic!("p2wpkh sighash: {e}"));
    let secret = secret_key(0xB0 + key_index as u8);
    let message = SecpMessage::from_digest(*sighash.as_byte_array());
    let mut sig = keys.secp.sign_ecdsa(&message, &secret);
    sig.normalize_s();
    let mut sig_bytes = sig.serialize_der().as_ref().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);
    tx.input[0].witness = Witness::from_slice(&[sig_bytes, pubkey.inner.serialize().to_vec()]);
    to_native_tx(&tx)
}

/// P2WSH 2-of-3 multisig spend: witness = `[empty_dummy, sig1, sig2, redeem_script]`,
/// signed with BIP143 using the redeem script as the witness script.
fn build_signed_p2wsh_spend(
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
            witness: Witness::new(),
        }],
        output: vec![OracleTxOut {
            value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
            script_pubkey: OracleBuilder::new().push_int(1).into_script(),
        }],
    };
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            &redeem,
            Amount::from_sat(prevout_value),
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
    tx.input[0].witness = Witness::from_slice(&witness_items);
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
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("signed-spend summary did not publish a tip"))
        .height;
    let transaction_count: usize = blocks.iter().map(|b| b.txs.len()).sum();
    println!(
        "sync_pipeline_apply_signed_spend_proxy blocks={} txs={transaction_count} elapsed={elapsed:?}",
        applied_height.saturating_add(1),
    );
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

criterion_group!(
    benches,
    sync_pipeline_apply_proxy,
    sync_pipeline_apply_signed_spend_proxy,
    deterministic_initial_sync_proxy,
    block_source_height_lookup
);
criterion_main!(benches);
