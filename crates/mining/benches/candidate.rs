//! End-to-end mining candidate benchmarks for package selection and coinbase finish.
//!
//! Each iteration selects from the pool's maintained chunk index and assembles
//! the observable candidate result. Budgets stay unset until a measured p95
//! plus run-to-run noise is recorded.
//!
//! Fixtures:
//! - `end_to_end/{0,64,512,2048,20000,50000,100000}`: the historical pool —
//!   every eighth transaction spends its immediate predecessor (two-member
//!   clusters), the rest are independent roots; extending it to 100,000
//!   entries answers the mature-pool scaling question.
//! - `chains/depth-25`: 20,000 transactions as 800 explicit 25-deep chains, so
//!   each 25-member cluster exercises the linearization solver at the cluster
//!   limit the step 19 template-miss gate reads.
//!
//! The `mining_snapshot_operation` group is the operation baseline for
//! `mining_snapshot` — the whole-pool copy mining takes per template cache
//! miss. `iter_custom` times only the call: an `Instant` wraps it and the
//! snapshot drops after the elapsed read, so neither the 100,000-entry
//! teardown nor construction sits inside the reported time. `pool` is a
//! direct `Mempool`, so the baseline names the copy operation, not a
//! lock-acquisition claim. Step 19's indexed selection reports against the
//! same call-only boundary.
//!
//! PERF: Criterion emits public harness items whose docs are irrelevant to the
//! benchmark report.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::{CandidateContext, assemble_candidate, select_template_body};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

/// Independent-transaction pool sizes for the cache-miss scaling question.
///
/// 0, 64, 512, and 2,048 keep the historical curve points (the 2,048 numbers
/// above are the same workload as before); 20,000, 50,000, and 100,000 pin the
/// mature-pool medians the step 19 gate reads. Construction is untimed setup.
const INDEPENDENT_POOL_SIZES: [usize; 7] = [0, 64, 512, 2_048, 20_000, 50_000, 100_000];

/// The 25-deep-chain pool size: 800 chains of 25 transactions.
const CHAIN_POOL_CHAINS: usize = 800;
const CHAIN_DEPTH: usize = 25;

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 250,
        version: 0x2000_0001,
        bits: CompactTarget::from_consensus(0x1d00_ffff),
        min_time: 10,
        current_time: 20,
        locktime_cutoff: 10,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

fn distinct_tx(seed: u64, parent: Option<Txid>) -> Tx {
    let mut previous = [0_u8; 32];
    previous[..8].copy_from_slice(&seed.to_le_bytes());
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&previous))),
                0,
            ),
            script_sig: Script::from(Vec::new()),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::from_stack(Vec::new()),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from(seed.to_le_bytes().to_vec()),
        }],
    }
}

/// Builds a pool of `count` transactions where every eighth transaction spends
/// its immediate predecessor (two-member clusters, the historical fixture) and
/// the rest are independent roots.
fn snapshot_with(count: usize) -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let mut last_txid = None;
    for seed in 0..count {
        let parent = last_txid.filter(|_| seed.is_multiple_of(8) && seed > 0);
        last_txid = Some(insert_fixture_tx(
            &mut pool,
            u64::try_from(seed).expect("pool size fits u64"),
            parent,
        ));
    }
    assert_eq!(
        pool.mining_snapshot().entries.len(),
        count,
        "fixture pool must retain every inserted transaction"
    );
    pool
}

/// Builds `chains` chains of `CHAIN_DEPTH` transactions each: a fresh root
/// transaction, then 24 children each spending the previous txid, one
/// 25-member cluster per chain — the historical fixture that exercises the
/// solver.
fn chained_snapshot() -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for chain in 0..CHAIN_POOL_CHAINS {
        let mut last_txid = None;
        for depth in 0..CHAIN_DEPTH {
            let seed = u64::try_from(chain * CHAIN_DEPTH + depth).expect("chain pool fits u64");
            last_txid = Some(insert_fixture_tx(&mut pool, seed, last_txid));
        }
    }
    let chains = CHAIN_POOL_CHAINS;
    let depth = CHAIN_DEPTH;
    assert_eq!(
        pool.mining_snapshot().entries.len(),
        chains * depth,
        "chained fixture pool must retain every inserted transaction"
    );
    pool
}

/// Inserts one fixture transaction spending `parent` (or a distinct synthetic
/// outpoint) with the historical entry fields, and returns the inserted
/// transaction's txid — recomputing it later would be wrong, because the
/// parent hash is folded into the txid.
fn insert_fixture_tx(pool: &mut Mempool, seed: u64, parent: Option<Txid>) -> Txid {
    let tx = distinct_tx(seed, parent);
    let txid = tx.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx),
        200,
        10_000 + seed,
        seed,
        100,
        0,
    ))
    .unwrap_or_else(|error| panic!("fixture insert {seed} failed: {error}"));
    txid
}

fn assemble_candidate_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("assemble_candidate");
    group.sample_size(10);
    let ctx = context();
    let payout = [0x51_u8];
    for &count in &INDEPENDENT_POOL_SIZES {
        let pool = snapshot_with(count);
        let assembled = assemble_candidate(&ctx, &pool, &payout)
            .unwrap_or_else(|error| panic!("fixture assemble {count} failed: {error}"));
        assert!(
            assembled.transactions.len() <= count,
            "selection must not invent transactions"
        );
        group.bench_function(BenchmarkId::new("end_to_end", count), |b| {
            b.iter(|| {
                black_box(
                    assemble_candidate(&ctx, &pool, &payout)
                        .unwrap_or_else(|error| panic!("assemble failed: {error}")),
                )
            });
        });
    }
    let pool = chained_snapshot();
    let assembled = assemble_candidate(&ctx, &pool, &payout)
        .unwrap_or_else(|error| panic!("fixture assemble chains failed: {error}"));
    assert!(
        assembled.transactions.len() <= CHAIN_POOL_CHAINS * CHAIN_DEPTH,
        "selection must not invent transactions"
    );
    group.bench_function(BenchmarkId::new("end_to_end", "chains/depth-25"), |b| {
        b.iter(|| {
            black_box(
                assemble_candidate(&ctx, &pool, &payout)
                    .unwrap_or_else(|error| panic!("assemble failed: {error}")),
            )
        });
    });
    group.finish();
}

/// Times the read-guard hold of `select_template_body` at the 100,000-entry
/// pool. The guard is acquired untimed; one `Instant` wraps the selection
/// call plus the guard release, so the reported time is selection under the
/// lock scope. `SelectedBody` drops untimed, and no coinbase, Merkle, or
/// witness work runs under the guard.
fn indexed_selection_read_guard_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("indexed_selection_read_guard");
    group.sample_size(10);
    let pool = parking_lot::RwLock::new(snapshot_with(100_000));
    let ctx = context();
    let payout = [0x51_u8];
    let guarded = pool.read();
    let warmed = select_template_body(&guarded, &ctx, &payout)
        .unwrap_or_else(|error| panic!("fixture selection failed: {error}"));
    drop(guarded);
    drop(warmed);
    group.bench_function(BenchmarkId::new("read_guard", 100_000), |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let guard = pool.read();
                let start = Instant::now();
                let body = select_template_body(&guard, &ctx, &payout)
                    .unwrap_or_else(|error| panic!("selection failed: {error}"));
                drop(guard);
                total += start.elapsed();
                black_box(body.transactions.len());
                drop(body);
            }
            total
        });
    });
    group.finish();
}

/// The `mining_snapshot_operation` group is the operation baseline for
/// `mining_snapshot` — the whole-pool copy mining takes per template cache
/// miss. `iter_custom` times only the call: an `Instant` wraps it and the
/// snapshot drops after the elapsed read, so neither the 100,000-entry
/// teardown nor construction sits inside the reported time. `pool` is a
/// direct `Mempool`, so the baseline names the copy operation, not a
/// lock-acquisition claim. Step 19's indexed selection reports against the
/// same call-only boundary.
fn snapshot_operation_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("mining_snapshot_operation");
    group.sample_size(10);
    for &count in &INDEPENDENT_POOL_SIZES {
        if count == 0 {
            continue;
        }
        let pool = snapshot_with(count);
        let warmed = pool.mining_snapshot();
        assert_eq!(
            warmed.entries.len(),
            count,
            "warm-up snapshot must already name the fixture size"
        );
        drop(warmed);
        group.bench_function(BenchmarkId::new("mining_snapshot", count), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    let snapshot = pool.mining_snapshot();
                    total += start.elapsed();
                    black_box(snapshot.entries.len());
                    drop(snapshot);
                }
                total
            });
        });
    }
    let pool = chained_snapshot();
    let warmed = pool.mining_snapshot();
    assert_eq!(
        warmed.entries.len(),
        CHAIN_POOL_CHAINS * CHAIN_DEPTH,
        "warm-up snapshot must already name the chained fixture size"
    );
    drop(warmed);
    group.bench_function(
        BenchmarkId::new("mining_snapshot", "chains/depth-25"),
        |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let start = Instant::now();
                    let snapshot = pool.mining_snapshot();
                    total += start.elapsed();
                    black_box(snapshot.entries.len());
                    drop(snapshot);
                }
                total
            });
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    assemble_candidate_bench,
    snapshot_operation_bench,
    indexed_selection_read_guard_bench
);
criterion_main!(benches);
