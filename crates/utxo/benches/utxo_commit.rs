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

fn next_u64(state: &mut u64) -> u64 {
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

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(seed).to_le_bytes());
    TxOut {
        value: Amount::from_sat(5_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn synthetic_case(seed: u64) -> (UtxoSet, BlockChanges, [usize; 256]) {
    let set = UtxoSet::new();
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();
    let mut rng = seed;
    let mut distribution = [0_usize; 256];

    for _ in 0_u64..10_000 {
        let spend_seed = next_u64(&mut rng);
        let outpoint = OutPoint::new(txid(spend_seed), 0);
        preload.add(UtxoAdd::new(outpoint, txout(spend_seed), false, 1));
        changes.remove(outpoint);
    }

    if let Err(error) = set.commit_block(&preload, &txid(seed)) {
        panic!("synthetic preload failed: {error}");
    }

    for i in 0_u64..10_000 {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let outpoint = OutPoint::new(txid(add_seed), 0);
        let shard = usize::from(outpoint.txid.prefix8()[0]);
        distribution[shard] = distribution[shard].saturating_add(1);
        changes.add(UtxoAdd::new(outpoint, txout(add_seed), false, 2));
    }

    (set, changes, distribution)
}

const fn percentile(samples: &[Duration], numerator: usize, denominator: usize) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let last = samples.len().saturating_sub(1);
    let index = last.saturating_mul(numerator) / denominator;
    samples[index]
}

fn print_synthetic_summary() {
    let mut samples = Vec::with_capacity(9);
    let (_, _, distribution) = synthetic_case(0x5555_aaaa_ffff_0000);
    for seed in 0_u64..9 {
        let (set, changes, _) = synthetic_case(seed + 1);
        let start = Instant::now();
        if let Err(error) = set.commit_block(black_box(&changes), &txid(seed)) {
            panic!("synthetic commit failed: {error}");
        }
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    println!(
        "utxo_commit_synthetic_block warmup p50={:?} p95={:?} p99={:?} entries_per_shard={:?}",
        percentile(&samples, 50, 100),
        percentile(&samples, 95, 100),
        percentile(&samples, 99, 100),
        distribution
    );
}

fn utxo_commit_synthetic_block(c: &mut Criterion) {
    print_synthetic_summary();
    c.bench_function("utxo_commit_synthetic_block", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef),
            |(set, changes, _distribution)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, utxo_commit_synthetic_block);
criterion_main!(benches);
