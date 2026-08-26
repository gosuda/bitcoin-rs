//! Mempool priority-index refactor-set benchmark.
//!
//! Both arms run over one identical fixture in one process, so the before/after
//! ratio comes from a single run and cannot be confounded by the rebuild and
//! baseline drift recorded in
//! `docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.
//!
//! `before_sorted` is `SortedParetoFront`, the flat vector that did a linear
//! `remove` and a full `sort_by` on every insert. `after_ordered` is
//! `ParetoFront`, the ordered set that replaced it.
//!
//! `mempool_insert_entry` is the end-to-end path an attacker actually drives:
//! `Mempool::insert_entry` calls `recompute_all_metadata`, which rebuilds the
//! whole priority index for every accepted transaction. It is benchmarked at
//! smaller sizes than the index arms because that outer rebuild is quadratic
//! *independently* of the index — which is the point of measuring it separately.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
// A fixture that fails to build has no meaningful degraded mode: a fill that
// silently indexed nothing would be timed as a win.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits, ParetoFront, SortedParetoFront};
use criterion::{Criterion, criterion_group, criterion_main};

/// Index fill sizes. The largest is far below a Core-default mempool (~10^5
/// transactions at `-maxmempool=300MB`); the quadratic arm cannot be measured
/// there in reasonable time, which is itself the finding.
const FILL_SIZES: [u64; 4] = [1_000, 4_000, 16_000, 50_000];

/// End-to-end sizes.
///
/// The first three are the sizes the quadratic `insert_entry` could be measured
/// at before the metadata refresh was made incremental — 3,200 transactions took
/// a second — and are kept so the two revisions of this page compare directly.
/// The last two are only reachable now, and are what pins the exponent.
const POOL_SIZES: [u64; 5] = [200, 800, 3_200, 12_800, 51_200];

fn spread_fee(seed: u64) -> u64 {
    // Not monotonic in the seed: an index fed entries already in priority order
    // never has to reorder anything, and would benchmark the best case only.
    (seed.wrapping_mul(2_654_435_761) % 100_000).saturating_add(1)
}

fn distinct_tx(seed: u64) -> Transaction {
    let mut previous = [0_u8; 32];
    previous[..8].copy_from_slice(&seed.to_le_bytes());
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            // Distinct prevouts: entries that conflict would be rejected rather
            // than accepted, and the fill would measure the rejection path.
            previous_output: OutPoint::new(Txid::from_byte_array(previous), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(seed.to_le_bytes().to_vec()),
        }],
    }
}

fn entry(seed: u64) -> MempoolEntry {
    MempoolEntry::new(Arc::new(distinct_tx(seed)), 200, spread_fee(seed), seed, 0)
}

fn bench_index_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool_pareto");
    group.sample_size(10);

    for size in FILL_SIZES {
        let entries = (0..size).map(entry).collect::<Vec<_>>();

        // Prove both arms index the same fixture before timing either. An arm
        // that dropped entries would be timed as a spectacular, meaningless win.
        let mut check_before = SortedParetoFront::new();
        let mut check_after = ParetoFront::new();
        for (index, item) in entries.iter().enumerate().take(1_000) {
            let id = u32::try_from(index).expect("fixture id fits u32");
            check_before.insert(id, item);
            check_after.insert(id, item);
        }
        assert_eq!(
            check_before.top_n(check_before.len()).collect::<Vec<_>>(),
            check_after.top_n(check_after.len()).collect::<Vec<_>>(),
            "the arms order differently; the benchmark would be meaningless"
        );

        group.bench_function(format!("before_sorted/fill/{size}"), |b| {
            b.iter(|| {
                let mut front = SortedParetoFront::new();
                for (index, item) in entries.iter().enumerate() {
                    front.insert(u32::try_from(index).unwrap_or(u32::MAX), item);
                }
                black_box(front.len())
            });
        });
        group.bench_function(format!("after_ordered/fill/{size}"), |b| {
            b.iter(|| {
                let mut front = ParetoFront::new();
                for (index, item) in entries.iter().enumerate() {
                    front.insert(u32::try_from(index).unwrap_or(u32::MAX), item);
                }
                black_box(front.len())
            });
        });
    }

    group.finish();
}

fn bench_mempool_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool_insert_entry");
    group.sample_size(10);

    for size in POOL_SIZES {
        let entries = (0..size).map(entry).collect::<Vec<_>>();
        group.bench_function(format!("fill/{size}"), |b| {
            b.iter(|| {
                let mut pool = Mempool::new(MempoolLimits::default());
                for item in &entries {
                    let _ = pool.insert_entry(item.clone());
                }
                black_box(pool.len())
            });
        });
    }

    group.finish();
}

fn bench_lowest_fee_rate_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool_lowest_fee_rate");
    group.sample_size(10);

    let size: u64 = 51_200;
    let entries = (0..size).map(entry).collect::<Vec<_>>();
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        max_total_bytes: 0,
        ..MempoolLimits::default()
    });
    for item in &entries {
        pool.insert_entry(item.clone())
            .expect("lookup fixture insert");
    }
    assert_eq!(
        pool.len(),
        usize::try_from(size).expect("size fits usize"),
        "lookup fixture must keep every entry"
    );

    let scanned = pool
        .entries
        .iter()
        .map(|(_index, entry)| entry.fee_rate)
        .min();
    assert_eq!(
        scanned,
        pool.lowest_fee_rate(),
        "matched lookup arms must observe the same floor"
    );

    group.bench_function("before_scan/lookup/51200", |b| {
        b.iter(|| {
            black_box(
                pool.entries
                    .iter()
                    .map(|(_index, entry)| entry.fee_rate)
                    .min(),
            )
        });
    });
    group.bench_function("after_maintained/lookup/51200", |b| {
        b.iter(|| black_box(pool.lowest_fee_rate()));
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_index_fill, bench_mempool_fill, bench_lowest_fee_rate_lookup
}
criterion_main!(benches);
