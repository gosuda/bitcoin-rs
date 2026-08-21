//! Mempool priority-index insertion cost.
//!
//! `ParetoFront::insert` does a linear `remove` and then re-sorts the whole
//! index, so filling a mempool of `n` transactions costs O(n^2 log n). This
//! measures the fill at several mempool sizes so the exponent is measured
//! rather than argued.
//!
//! The sizes are chosen against a real mempool: Bitcoin Core's default
//! `-maxmempool=300MB` holds on the order of 10^5 transactions, and the sizes
//! here stop well short of that because the quadratic term makes the full
//! figure impractical to measure directly — which is itself the finding.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin::{
    Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};
use bitcoin_rs_mempool::{MempoolEntry, ParetoFront};
use criterion::{Criterion, criterion_group, criterion_main};

/// Entry counts to fill. A quadratic fill makes the largest size the slowest by
/// far, which is the point being measured.
const FILL_SIZES: [usize; 4] = [1_000, 4_000, 16_000, 50_000];

fn entry(seed: u64) -> MempoolEntry {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(seed.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let vsize = 200_u32;
    // Fee rates spread rather than sorted, so the re-sort has real work to do
    // and the insert never lands at a fixed end of the index.
    let fee = (seed.wrapping_mul(2_654_435_761) % 100_000).saturating_add(1);
    MempoolEntry::new(Arc::new(tx), vsize, fee, seed, 0)
}

fn bench_pareto_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool_pareto");
    group.sample_size(10);

    for size in FILL_SIZES {
        let entries = (0..size as u64).map(entry).collect::<Vec<_>>();
        group.bench_function(format!("fill/{size}"), |b| {
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

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_pareto_fill
}
criterion_main!(benches);
