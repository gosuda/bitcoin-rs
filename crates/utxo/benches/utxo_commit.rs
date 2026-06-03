//! Synthetic UTXO commit benchmark.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const ENTRY_COUNT: u64 = 10_000;

#[derive(Copy, Clone, Debug)]
enum ShardShape {
    Existing,
    Uniform,
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
