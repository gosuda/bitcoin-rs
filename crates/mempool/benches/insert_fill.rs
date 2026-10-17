//! Production-path mempool insert-fill benchmark (`insert_fill`).
//!
//! `mempool_insert_entry` is the end-to-end path an attacker actually drives:
//! `Mempool::insert_entry` accounts the entry through the derived-state owners
//! and refreshes package metadata incrementally over the affected closure
//! (`refresh_metadata`), so an acceptance pays for its neighborhood, not a
//! full rebuild of the priority index. The full-rebuild pass,
//! `recompute_all_metadata`, is test-only.
//!
//! Operation baselines. Named after the operation, not a lock-acquisition
//! claim — `pool` is a direct `Mempool`, so no lock state is involved.
//! - `fill/{size}`: `size` independent transactions into an empty pool —
//!   singleton acceptance cost as the pool matures (200 … 51,200). The relay
//!   floor is lifted (`min_relay_fee_sat_per_kvb: 0`), every insert must
//!   succeed, and the resulting pool must hold exactly `size` entries.
//! - `fill/63-member-cluster`: untimed setup builds a fresh pool with one
//!   62-deep chain (a single 62-member component) and the 63rd member's
//!   transaction; the timed body is only the 63rd member's insert. Setup
//!   asserts 62 live members; the insert asserts success and 63 live members
//!   after the timer.
//!
//! PERF: Criterion emits public harness items whose docs are irrelevant to the
//! benchmark report.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

/// Pool sizes large enough to cover admission from a small node to a mature
/// transaction pool while keeping the smoke compile/run target bounded.
const POOL_SIZES: [u64; 5] = [200, 800, 3_200, 12_800, 51_200];

fn spread_fee(seed: u64) -> u64 {
    (seed.wrapping_mul(2_654_435_761) % 100_000).saturating_add(1)
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
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: seed.to_le_bytes().to_vec().into(),
        }],
    }
}

fn entry(seed: u64) -> MempoolEntry {
    MempoolEntry::new(
        Arc::new(distinct_tx(seed, None)),
        200,
        spread_fee(seed),
        seed,
        0,
        0,
    )
}

fn bench_mempool_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool_insert_entry");
    group.sample_size(10);

    for size in POOL_SIZES {
        group.bench_function(format!("fill/{size}"), |b| {
            b.iter(|| {
                let mut pool = Mempool::new(MempoolLimits {
                    min_relay_fee_sat_per_kvb: 0,
                    ..MempoolLimits::default()
                });
                for seed in 0..size {
                    pool.insert_entry(entry(seed))
                        .expect("independent fixture insert must succeed");
                }
                assert_eq!(pool.len(), usize::try_from(size).expect("size fits usize"));
                black_box(pool.len())
            });
        });
    }

    // One 63-member cluster: untimed setup builds the 62-member component and
    // the 63rd member's entry; the timer covers only the insert. The timed
    // closure borrows the pool, so the 63-member teardown lands outside the
    // measurement.
    group.bench_function("fill/63-member-cluster", |b| {
        b.iter_batched_ref(
            || {
                let mut pool = Mempool::new(MempoolLimits {
                    min_relay_fee_sat_per_kvb: 0,
                    ..MempoolLimits::default()
                });
                let mut last_txid = None;
                for seed in 0..62 {
                    let tx = distinct_tx(seed, last_txid);
                    let txid = tx.txid();
                    pool.insert_entry(MempoolEntry::new(
                        Arc::new(tx),
                        200,
                        spread_fee(seed),
                        seed,
                        0,
                        0,
                    ))
                    .expect("chain fixture insert must succeed");
                    last_txid = Some(txid);
                }
                assert_eq!(pool.len(), 62, "setup must build exactly 62 members");
                let tip = last_txid.expect("62-chain has a tip");
                let child = MempoolEntry::new(
                    Arc::new(distinct_tx(62, Some(tip))),
                    200,
                    spread_fee(62),
                    62,
                    0,
                    0,
                );
                (pool, Some(child))
            },
            |(pool, child)| {
                pool.insert_entry(child.take().expect("prepared child is consumed once"))
                    .expect("63rd member insert must succeed");
                assert_eq!(pool.len(), 63, "cluster insert must add the 63rd member");
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_mempool_fill);
criterion_main!(benches);
