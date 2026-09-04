//! Production-path mempool priority-index benchmark.
//!
//! `mempool_insert_entry` is the end-to-end path an attacker actually drives:
//! `Mempool::insert_entry` calls `recompute_all_metadata`, which rebuilds the
//! whole priority index for every accepted transaction.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
// A fixture that fails to build has no meaningful degraded mode: a fill that
// silently indexed nothing would be timed as a win.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use criterion::{Criterion, criterion_group, criterion_main};

/// Pool sizes large enough to cover admission from a small node to a mature
/// transaction pool while keeping the smoke compile/run target bounded.
const POOL_SIZES: [u64; 5] = [200, 800, 3_200, 12_800, 51_200];

fn spread_fee(seed: u64) -> u64 {
    // Not monotonic in the seed: already ordered entries would benchmark only
    // the priority index's best case.
    (seed.wrapping_mul(2_654_435_761) % 100_000).saturating_add(1)
}

fn distinct_tx(seed: u64) -> Tx {
    let mut previous = [0_u8; 32];
    previous[..8].copy_from_slice(&seed.to_le_bytes());
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            // Distinct prevouts: entries that conflict would be rejected rather
            // than accepted, and the fill would measure the rejection path.
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&previous)), 0),
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
    MempoolEntry::new(Arc::new(distinct_tx(seed)), 200, spread_fee(seed), seed, 0)
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

criterion_group!(benches, bench_mempool_fill);
criterion_main!(benches);
