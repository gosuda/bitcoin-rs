//! Refactor-set benchmark for the mempool `spentby` answer.
//!
//! `getrawmempool true` renders a `spentby` list for every entry in the pool.
//! The handler used to answer each one by walking every other entry's inputs,
//! so the whole response cost `O(pool inputs)` per entry — quadratic in the
//! pool — while holding the mempool read lock that transaction acceptance
//! needs. The replacement asks the `spending` index instead.
//!
//! Both arms of the refactor set run in one group over one identical pool:
//! `before_scan` is the scan, written out here so it cannot drift into calling
//! the code it is being compared against; `after_index` is the shipped path.
//! The group is parameterised by pool size because the claim is about the
//! *shape* of the curve, not a single number — `before_scan` should roughly
//! quadruple when the pool doubles while `after_index` roughly doubles.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]
// A fixture that fails to build has no meaningful degraded mode here: a pool
// that silently stayed empty would be timed as a fast return and reported as a
// win. Panicking is the correct outcome, so `expect` is confined to setup.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{EntryId, Mempool, MempoolEntry, MempoolLimits};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..outputs)
            .map(|vout| TxOut {
                value: Amount::from_sat(10_000 + u64::from(vout) + tag * 1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            })
            .collect(),
    }
}

/// A pool of `pairs` independent parent -> child packages, so every parent has
/// exactly one spender and no package exceeds the ancestor policy limits. The
/// spend graph is deliberately shallow: the cost being measured is *finding*
/// the spenders, not walking a deep package.
fn pool_with(pairs: u64) -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        ..MempoolLimits::default()
    });
    for pair in 0..pairs {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&pair.to_le_bytes());
        let funding = OutPoint::new(Txid::from_byte_array(seed), 0);
        let parent = tx_with(&[funding], 2, pair);
        let parent_txid = parent.compute_txid();
        let child = tx_with(&[OutPoint::new(parent_txid, 0)], 1, pair);
        for tx in [parent, child] {
            let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
            pool.insert_entry(entry)
                .expect("benchmark fixture insert must succeed");
        }
    }
    pool
}

/// The answer the RPC handler used to compute, spelled out rather than shared
/// with the implementation.
fn spentby_by_scan(pool: &Mempool) -> Vec<Vec<String>> {
    let mut rendered = Vec::with_capacity(pool.len());
    for (_index, entry) in &pool.entries {
        let txid = entry.tx.compute_txid();
        let mut spentby = Vec::new();
        for (_candidate_index, candidate) in &pool.entries {
            for input in &candidate.tx.input {
                if input.previous_output.txid == txid {
                    spentby.push(candidate.tx.compute_txid().to_string());
                    break;
                }
            }
        }
        spentby.sort();
        spentby.dedup();
        rendered.push(spentby);
    }
    rendered
}

/// The shipped path: the cached txid for the key, the `spending` index for the
/// spenders.
fn spentby_by_index(pool: &Mempool) -> Vec<Vec<String>> {
    let mut rendered = Vec::with_capacity(pool.len());
    for (index, _entry) in &pool.entries {
        let id = EntryId::try_from(index).expect("entry index must fit an EntryId");
        let mut spentby: Vec<String> = pool
            .spender_txids(id)
            .iter()
            .map(ToString::to_string)
            .collect();
        spentby.sort();
        spentby.dedup();
        rendered.push(spentby);
    }
    rendered
}

fn bench_spentby(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("mempool_spentby");
    for pairs in [256_u64, 1_024, 2_048] {
        let pool = pool_with(pairs);
        let entries = pool.len();

        // Same fixture, same answer: a difference here would mean one arm is
        // measuring less work than the other.
        assert_eq!(
            spentby_by_scan(&pool),
            spentby_by_index(&pool),
            "the two arms must render the same spentby lists"
        );

        group.bench_with_input(
            BenchmarkId::new("before_scan", entries),
            &pool,
            |b, pool| {
                b.iter(|| black_box(spentby_by_scan(black_box(pool))));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("after_index", entries),
            &pool,
            |b, pool| {
                b.iter(|| black_box(spentby_by_index(black_box(pool))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_spentby);
criterion_main!(benches);
