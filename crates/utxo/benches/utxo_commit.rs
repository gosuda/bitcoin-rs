//! Synthetic UTXO commit benchmark.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

// PERF: A/B allocator experiment. With `--features bench-mimalloc` the whole
// bench binary (criterion harness + workload) allocates through mimalloc; with
// the feature off it uses the system allocator. This is the only delta between
// the A and B runs — workloads, scenarios, and sample counts are unchanged.
#[cfg(feature = "bench-mimalloc")]
#[global_allocator]
static GLOBAL_MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoChangeListener, UtxoSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const ENTRY_COUNT: u64 = 10_000;
const INTERLEAVED_TXID_COUNT: u32 = 256;
const INTERLEAVED_VOUTS_PER_TXID: u32 = 16;
const SPEND_PROXY_FANOUT: usize = 64;
const SPEND_PROXY_SOURCE_HEIGHT: u32 = 1;
const SPEND_PROXY_SPEND_HEIGHT: u32 = 101;
const SPEND_PROXY_COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_PROXY_SPEND_OUTPUT_VALUE: u64 = 78_124_999;

#[derive(Copy, Clone, Debug)]
enum ShardShape {
    Existing,
    Uniform,
    TwoShard,
    FourShard,
    Concentrated,
}

#[derive(Clone)]
struct SyntheticEntry {
    outpoint: OutPoint,
    txout: TxOut,
    coinbase: bool,
    height: u32,
}

struct SyntheticWorkload {
    spends: Vec<SyntheticEntry>,
    adds: Vec<SyntheticEntry>,
    distribution: [usize; 256],
}

struct NoopListener;

impl UtxoChangeListener for NoopListener {
    fn on_insert(&self, _op: &OutPoint, _txout: &TxOut, _height: u32, _coinbase: bool) {}

    fn on_remove(&self, _op: &OutPoint, _txout: &TxOut, _height: u32) {}
}

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(11).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn shaped_txid(seed: u64, index: u64, shape: ShardShape) -> Hash256 {
    let mut hash = txid(seed);
    match shape {
        ShardShape::Existing => {}
        ShardShape::Uniform => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = u8::try_from(index % 256).unwrap_or(0);
            hash = Hash256::from_le_bytes(&bytes);
        }
        ShardShape::TwoShard => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = u8::try_from(index % 2).unwrap_or(0);
            hash = Hash256::from_le_bytes(&bytes);
        }
        ShardShape::FourShard => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = u8::try_from(index % 4).unwrap_or(0);
            hash = Hash256::from_le_bytes(&bytes);
        }
        ShardShape::Concentrated => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = 0x2a;
            hash = Hash256::from_le_bytes(&bytes);
        }
    }
    hash
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(seed).to_le_bytes());
    TxOut {
        value: Amount::from_sat(5_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn synthetic_workload(seed: u64, shape: ShardShape) -> SyntheticWorkload {
    let mut rng = seed;
    let mut spends = Vec::with_capacity(usize::try_from(ENTRY_COUNT).unwrap_or(0));
    let mut adds = Vec::with_capacity(usize::try_from(ENTRY_COUNT).unwrap_or(0));
    let mut distribution = [0_usize; 256];

    for i in 0_u64..ENTRY_COUNT {
        let spend_seed = next_u64(&mut rng);
        let outpoint = OutPoint::new(shaped_txid(spend_seed, i, shape), 0);
        spends.push(SyntheticEntry {
            outpoint,
            txout: txout(spend_seed),
            coinbase: false,
            height: 1,
        });
    }

    for i in 0_u64..ENTRY_COUNT {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let outpoint = OutPoint::new(shaped_txid(add_seed, i, shape), 0);
        let shard = usize::from(outpoint.txid.prefix8()[0]);
        distribution[shard] = distribution[shard].saturating_add(1);
        adds.push(SyntheticEntry {
            outpoint,
            txout: txout(add_seed),
            coinbase: false,
            height: 2,
        });
    }

    SyntheticWorkload {
        spends,
        adds,
        distribution,
    }
}

fn preload_set(workload: &SyntheticWorkload, seed: u64) -> UtxoSet {
    let set = UtxoSet::new();
    let mut preload = BlockChanges::default();
    for spend in &workload.spends {
        preload.add(utxo_add(spend));
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed)) {
        panic!("synthetic preload failed: {error}");
    }
    set
}

fn block_changes(workload: &SyntheticWorkload) -> BlockChanges {
    let mut changes = BlockChanges::default();
    for spend in &workload.spends {
        changes.remove(spend.outpoint);
    }
    for add in &workload.adds {
        changes.add(utxo_add(add));
    }
    changes
}

fn same_txid_churn_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let live_txid = txid(seed);
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();

    for vout in 0_u32..256 {
        let seed = seed.wrapping_add(u64::from(vout));
        preload.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(seed),
            false,
            1,
        ));
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("same-txid preload failed: {error}");
    }

    for vout in 0_u32..128 {
        changes.remove(OutPoint::new(live_txid, vout));
    }
    for vout in 256_u32..384 {
        let seed = seed.wrapping_add(u64::from(vout));
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(seed),
            false,
            2,
        ));
    }

    (set, changes)
}

fn same_txid_full_spend_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let live_txid = txid(seed);
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();

    for vout in 0_u32..64 {
        let seed = seed.wrapping_add(u64::from(vout));
        let outpoint = OutPoint::new(live_txid, vout);
        preload.add(UtxoAdd::new(outpoint, txout(seed), false, 1));
        changes.remove(outpoint);
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("same-txid full-spend preload failed: {error}");
    }

    (set, changes)
}

fn same_txid_high_vout_full_spend_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let live_txid = txid(seed);
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();

    for vout in 64_u32..128 {
        let seed = seed.wrapping_add(u64::from(vout));
        let outpoint = OutPoint::new(live_txid, vout);
        preload.add(UtxoAdd::new(outpoint, txout(seed), false, 1));
        changes.remove(outpoint);
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("same-txid high-vout full-spend preload failed: {error}");
    }

    (set, changes)
}

fn spend_fanout_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let source_txid = txid(seed);
    let mut preload = BlockChanges::with_capacity(SPEND_PROXY_FANOUT, 0);
    let mut changes =
        BlockChanges::with_capacity(SPEND_PROXY_FANOUT.saturating_mul(2), SPEND_PROXY_FANOUT);

    for vout in 0..SPEND_PROXY_FANOUT {
        let outpoint = OutPoint::new(source_txid, u32::try_from(vout).unwrap_or(0));
        preload.add(UtxoAdd::new(
            outpoint,
            spend_proxy_coinbase_txout(),
            true,
            SPEND_PROXY_SOURCE_HEIGHT,
        ));
        changes.remove(outpoint);
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("spend-fanout preload failed: {error}");
    }

    let coinbase_txid = txid(seed.wrapping_add(2));
    for vout in 0..SPEND_PROXY_FANOUT {
        changes.add(UtxoAdd::new(
            OutPoint::new(coinbase_txid, u32::try_from(vout).unwrap_or(0)),
            spend_proxy_coinbase_txout(),
            true,
            SPEND_PROXY_SPEND_HEIGHT,
        ));
    }
    for index in 0..SPEND_PROXY_FANOUT {
        changes.add(UtxoAdd::new(
            OutPoint::new(
                txid(
                    seed.wrapping_add(3)
                        .wrapping_add(u64::try_from(index).unwrap_or(0)),
                ),
                0,
            ),
            spend_proxy_spend_txout(),
            false,
            SPEND_PROXY_SPEND_HEIGHT,
        ));
    }

    (set, changes)
}

fn interleaved_same_txid_churn_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();
    let mut txids = Vec::with_capacity(usize::try_from(INTERLEAVED_TXID_COUNT).unwrap_or(0));

    for tx_index in 0_u32..INTERLEAVED_TXID_COUNT {
        txids.push(shaped_txid(
            seed.wrapping_add(u64::from(tx_index)),
            u64::from(tx_index),
            ShardShape::TwoShard,
        ));
    }

    for vout in 0_u32..INTERLEAVED_VOUTS_PER_TXID {
        for (tx_index, txid) in txids.iter().enumerate() {
            let tx_index = u64::try_from(tx_index).unwrap_or(0);
            let outpoint = OutPoint::new(*txid, vout);
            preload.add(UtxoAdd::new(
                outpoint,
                txout(seed.wrapping_add(tx_index).wrapping_add(u64::from(vout))),
                false,
                1,
            ));
            changes.remove(outpoint);
        }
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("interleaved same-txid preload failed: {error}");
    }

    for vout in INTERLEAVED_VOUTS_PER_TXID..INTERLEAVED_VOUTS_PER_TXID.saturating_mul(2) {
        for (tx_index, txid) in txids.iter().enumerate() {
            let tx_index = u64::try_from(tx_index).unwrap_or(0);
            changes.add(UtxoAdd::new(
                OutPoint::new(*txid, vout),
                txout(
                    seed.wrapping_add(0x1000)
                        .wrapping_add(tx_index)
                        .wrapping_add(u64::from(vout)),
                ),
                false,
                2,
            ));
        }
    }

    (set, changes)
}

fn utxo_add(entry: &SyntheticEntry) -> UtxoAdd {
    UtxoAdd::new(
        entry.outpoint,
        entry.txout.clone(),
        entry.coinbase,
        entry.height,
    )
}

fn synthetic_case(seed: u64, shape: ShardShape) -> (UtxoSet, BlockChanges, [usize; 256]) {
    let workload = synthetic_workload(seed, shape);
    let set = preload_set(&workload, seed);
    let changes = block_changes(&workload);
    (set, changes, workload.distribution)
}

fn synthetic_listener_case(seed: u64, shape: ShardShape) -> (UtxoSet, BlockChanges) {
    let workload = synthetic_workload(seed, shape);
    let mut set = preload_set(&workload, seed);
    set.set_listener(Box::new(NoopListener));
    let changes = block_changes(&workload);
    (set, changes)
}

fn spend_proxy_coinbase_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn spend_proxy_spend_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn summarize_distribution(distribution: &[usize; 256]) -> (usize, usize, usize) {
    let mut active = 0_usize;
    let mut min_non_zero = usize::MAX;
    let mut max = 0_usize;
    for &count in distribution {
        if count == 0 {
            continue;
        }
        active = active.saturating_add(1);
        min_non_zero = min_non_zero.min(count);
        max = max.max(count);
    }
    if active == 0 {
        min_non_zero = 0;
    }
    (active, min_non_zero, max)
}

fn distribution_prepass(seed: u64, shape: ShardShape) -> [usize; 256] {
    let mut rng = seed;
    for _ in 0_u64..ENTRY_COUNT {
        let _ = next_u64(&mut rng);
    }
    let mut distribution = [0_usize; 256];
    for i in 0_u64..ENTRY_COUNT {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let txid = shaped_txid(add_seed, i, shape);
        let shard = usize::from(txid.prefix8()[0]);
        distribution[shard] = distribution[shard].saturating_add(1);
    }
    distribution
}

const fn percentile(samples: &[Duration], numerator: usize, denominator: usize) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let last = samples.len().saturating_sub(1);
    let index = last.saturating_mul(numerator) / denominator;
    samples[index]
}

fn print_synthetic_summary(name: &str, shape: ShardShape) {
    let mut prepass_samples = Vec::with_capacity(9);
    let mut commit_samples = Vec::with_capacity(9);
    let distribution = distribution_prepass(0x5555_aaaa_ffff_0000, shape);
    for seed in 0_u64..9 {
        let prepass_start = Instant::now();
        let _ = distribution_prepass(seed + 1, shape);
        prepass_samples.push(prepass_start.elapsed());

        let (set, changes, _) = synthetic_case(seed + 1, shape);
        let start = Instant::now();
        if let Err(error) = set.commit_block(black_box(&changes), &txid(seed)) {
            panic!("synthetic commit failed: {error}");
        }
        commit_samples.push(start.elapsed());
    }
    prepass_samples.sort_unstable();
    commit_samples.sort_unstable();
    let (active, min_non_zero, max) = summarize_distribution(&distribution);
    println!(
        "utxo_commit_{name} prepass p50={:?} p95={:?} p99={:?} commit p50={:?} p95={:?} p99={:?} active_shards={active} min_non_zero_shard_entries={min_non_zero} max_shard_entries={max}",
        percentile(&prepass_samples, 50, 100),
        percentile(&prepass_samples, 95, 100),
        percentile(&prepass_samples, 99, 100),
        percentile(&commit_samples, 50, 100),
        percentile(&commit_samples, 95, 100),
        percentile(&commit_samples, 99, 100),
    );
}

fn bench_uniform_noop_listener(c: &mut Criterion) {
    c.bench_function("utxo_commit/uniform_noop_listener", |b| {
        b.iter_batched(
            || synthetic_listener_case(0x00ab_cdef, ShardShape::Uniform),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic listener commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_two_shard(c: &mut Criterion) {
    c.bench_function("utxo_commit/two_shard", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::TwoShard),
            |(set, changes, _distribution)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic two-shard commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_four_shard(c: &mut Criterion) {
    c.bench_function("utxo_commit/four_shard", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::FourShard),
            |(set, changes, _distribution)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic four-shard commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_two_shard_noop_listener(c: &mut Criterion) {
    c.bench_function("utxo_commit/two_shard_noop_listener", |b| {
        b.iter_batched(
            || synthetic_listener_case(0x00ab_cdef, ShardShape::TwoShard),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic two-shard listener commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_concentrated_noop_listener(c: &mut Criterion) {
    c.bench_function("utxo_commit/concentrated_noop_listener", |b| {
        b.iter_batched(
            || synthetic_listener_case(0x00ab_cdef, ShardShape::Concentrated),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic concentrated listener commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_churn_noop_listener(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_churn_noop_listener", |b| {
        b.iter_batched(
            || {
                let (mut set, changes) = same_txid_churn_case(0x0102_0304);
                set.set_listener(Box::new(NoopListener));
                (set, changes)
            },
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0112_1314)) {
                    panic!("same-txid churn listener commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_full_spend(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_full_spend", |b| {
        b.iter_batched(
            || same_txid_full_spend_case(0x0203_0405),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0212_1314)) {
                    panic!("same-txid full-spend commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_full_spend_noop_listener(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_full_spend_noop_listener", |b| {
        b.iter_batched(
            || {
                let (mut set, changes) = same_txid_full_spend_case(0x0203_0405);
                set.set_listener(Box::new(NoopListener));
                (set, changes)
            },
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0212_1314)) {
                    panic!("same-txid full-spend listener commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_high_vout_full_spend(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_high_vout_full_spend", |b| {
        b.iter_batched(
            || same_txid_high_vout_full_spend_case(0x0506_0708),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0512_1314)) {
                    panic!("same-txid high-vout full-spend commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_high_vout_full_spend_noop_listener(c: &mut Criterion) {
    c.bench_function(
        "utxo_commit/same_txid_high_vout_full_spend_noop_listener",
        |b| {
            b.iter_batched(
                || {
                    let (mut set, changes) = same_txid_high_vout_full_spend_case(0x0506_0708);
                    set.set_listener(Box::new(NoopListener));
                    (set, changes)
                },
                |(set, changes)| {
                    if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0512_1314)) {
                        panic!("same-txid high-vout full-spend listener commit failed: {error}");
                    }
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn bench_spend_fanout(c: &mut Criterion) {
    c.bench_function("utxo_commit/spend_fanout_64", |b| {
        b.iter_batched(
            || spend_fanout_case(0x0405_0607),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0412_1314)) {
                    panic!("spend-fanout commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("utxo_commit/spend_fanout_64_noop_listener", |b| {
        b.iter_batched(
            || {
                let (mut set, changes) = spend_fanout_case(0x0405_0607);
                set.set_listener(Box::new(NoopListener));
                (set, changes)
            },
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0412_1314)) {
                    panic!("spend-fanout listener commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_cases(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_churn", |b| {
        b.iter_batched(
            || same_txid_churn_case(0x0102_0304),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0112_1314)) {
                    panic!("same-txid churn commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    bench_same_txid_churn_noop_listener(c);
    bench_same_txid_full_spend(c);
    bench_same_txid_full_spend_noop_listener(c);
    bench_same_txid_high_vout_full_spend(c);
    bench_same_txid_high_vout_full_spend_noop_listener(c);
    bench_spend_fanout(c);
    c.bench_function("utxo_commit/interleaved_same_txid_churn", |b| {
        b.iter_batched(
            || interleaved_same_txid_churn_case(0x0304_0506),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0312_1314)) {
                    panic!("interleaved same-txid churn commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function(
        "utxo_commit/interleaved_same_txid_churn_noop_listener",
        |b| {
            b.iter_batched(
                || {
                    let (mut set, changes) = interleaved_same_txid_churn_case(0x0304_0506);
                    set.set_listener(Box::new(NoopListener));
                    (set, changes)
                },
                |(set, changes)| {
                    if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0312_1314)) {
                        panic!("interleaved same-txid churn listener commit failed: {error}");
                    }
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn utxo_commit_synthetic_block(c: &mut Criterion) {
    print_synthetic_summary("existing", ShardShape::Existing);
    c.bench_function("utxo_commit/existing", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::Existing),
            |(set, changes, _distribution)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    c.bench_function("utxo_build_commit/existing", |b| {
        b.iter_batched(
            || {
                let workload = synthetic_workload(0x00ab_cdef, ShardShape::Existing);
                let set = preload_set(&workload, 0x00ab_cdef);
                (set, workload)
            },
            |(set, workload)| {
                let changes = block_changes(black_box(&workload));
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic build+commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    bench_same_txid_cases(c);

    print_synthetic_summary("uniform", ShardShape::Uniform);
    c.bench_function("utxo_commit/uniform", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::Uniform),
            |(set, changes, _distribution)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    bench_uniform_noop_listener(c);
    bench_two_shard(c);
    bench_four_shard(c);
    bench_two_shard_noop_listener(c);
    c.bench_function("utxo_build_commit/uniform", |b| {
        b.iter_batched(
            || {
                let workload = synthetic_workload(0x00ab_cdef, ShardShape::Uniform);
                let set = preload_set(&workload, 0x00ab_cdef);
                (set, workload)
            },
            |(set, workload)| {
                let changes = block_changes(black_box(&workload));
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic build+commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });

    print_synthetic_summary("concentrated", ShardShape::Concentrated);
    c.bench_function("utxo_commit/concentrated", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::Concentrated),
            |(set, changes, _distribution)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    bench_concentrated_noop_listener(c);
    c.bench_function("utxo_build_commit/concentrated", |b| {
        b.iter_batched(
            || {
                let workload = synthetic_workload(0x00ab_cdef, ShardShape::Concentrated);
                let set = preload_set(&workload, 0x00ab_cdef);
                (set, workload)
            },
            |(set, workload)| {
                let changes = block_changes(black_box(&workload));
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic build+commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, utxo_commit_synthetic_block);
criterion_main!(benches);
