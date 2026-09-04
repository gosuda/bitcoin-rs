//! Production-shaped UTXO commit benchmarks.
//!
//! The retained cases exercise the public `UtxoSet::commit_block` path with a
//! normal mixed-shard block, a concentrated worst-case block, and a spend-heavy
//! block. Correctness edge cases belong in the UTXO test suite rather than in
//! long-lived benchmark arms.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

#[global_allocator]
static GLOBAL_MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::hint::black_box;

use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const ENTRY_COUNT: u64 = 10_000;
const SPEND_PROXY_FANOUT: usize = 64;
const SPEND_PROXY_SOURCE_HEIGHT: u32 = 1;
const SPEND_PROXY_SPEND_HEIGHT: u32 = 101;
const SPEND_PROXY_COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_PROXY_SPEND_OUTPUT_VALUE: u64 = 78_124_999;

#[derive(Copy, Clone, Debug)]
enum ShardShape {
    Existing,
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

fn shaped_txid(seed: u64, shape: ShardShape) -> Hash256 {
    let mut hash = txid(seed);
    if matches!(shape, ShardShape::Concentrated) {
        let mut bytes = hash.to_le_bytes();
        bytes[0] = 0x2a;
        hash = Hash256::from_le_bytes(&bytes);
    }
    hash
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(seed).to_le_bytes());
    TxOut {
        value: Amount::from_sat(5_000 + seed),
        script_pubkey: script.into(),
    }
}

fn synthetic_workload(seed: u64, shape: ShardShape) -> SyntheticWorkload {
    let mut rng = seed;
    let mut spends = Vec::with_capacity(usize::try_from(ENTRY_COUNT).unwrap_or(0));
    let mut adds = Vec::with_capacity(usize::try_from(ENTRY_COUNT).unwrap_or(0));

    for _ in 0_u64..ENTRY_COUNT {
        let spend_seed = next_u64(&mut rng);
        let outpoint = OutPoint::new(shaped_txid(spend_seed, shape).into(), 0);
        spends.push(SyntheticEntry {
            outpoint,
            txout: txout(spend_seed),
            coinbase: false,
            height: 1,
        });
    }

    for i in 0_u64..ENTRY_COUNT {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let outpoint = OutPoint::new(shaped_txid(add_seed, shape).into(), 0);
        adds.push(SyntheticEntry {
            outpoint,
            txout: txout(add_seed),
            coinbase: false,
            height: 2,
        });
    }

    SyntheticWorkload { spends, adds }
}

fn utxo_add(entry: &SyntheticEntry) -> UtxoAdd {
    UtxoAdd::new(
        entry.outpoint,
        entry.txout.clone(),
        entry.coinbase,
        entry.height,
    )
}

fn synthetic_case(seed: u64, shape: ShardShape) -> (UtxoSet, BlockChanges) {
    let workload = synthetic_workload(seed, shape);
    let set = UtxoSet::new();
    let mut preload = BlockChanges::default();
    for spend in &workload.spends {
        preload.add(utxo_add(spend));
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed)) {
        panic!("synthetic preload failed: {error}");
    }

    let mut changes = BlockChanges::default();
    for spend in &workload.spends {
        changes.remove(spend.outpoint);
    }
    for add in &workload.adds {
        changes.add(utxo_add(add));
    }
    (set, changes)
}

fn spend_proxy_coinbase_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
        script_pubkey: vec![0x51].into(),
    }
}

fn spend_proxy_spend_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
        script_pubkey: vec![0x51].into(),
    }
}

fn spend_fanout_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let source_txid = txid(seed);
    let mut preload = BlockChanges::with_capacity(SPEND_PROXY_FANOUT, 0);
    let mut changes =
        BlockChanges::with_capacity(SPEND_PROXY_FANOUT.saturating_mul(2), SPEND_PROXY_FANOUT);

    for vout in 0..SPEND_PROXY_FANOUT {
        let outpoint = OutPoint::new(source_txid.into(), u32::try_from(vout).unwrap_or(0));
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
            OutPoint::new(coinbase_txid.into(), u32::try_from(vout).unwrap_or(0)),
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
                )
                .into(),
                0,
            ),
            spend_proxy_spend_txout(),
            false,
            SPEND_PROXY_SPEND_HEIGHT,
        ));
    }

    (set, changes)
}

fn bench_synthetic(c: &mut Criterion, name: &str, shape: ShardShape) {
    c.bench_function(name, |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, shape),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
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
}

fn utxo_commit(c: &mut Criterion) {
    bench_synthetic(c, "utxo_commit/existing", ShardShape::Existing);
    bench_synthetic(c, "utxo_commit/concentrated", ShardShape::Concentrated);
    bench_spend_fanout(c);
}

criterion_group!(benches, utxo_commit);
criterion_main!(benches);
