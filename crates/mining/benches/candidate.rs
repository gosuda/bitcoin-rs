//! Candidate assembly benchmarks for package selection and coinbase finish.
//!
//! Times [`assemble_candidate`] against a pre-captured mining snapshot. Snapshot
//! capture and mempool insertion are fixtures, not the measured path: those are
//! distinct seams. Budgets stay unset until a measured p95 plus run-to-run
//! noise is recorded.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits, MempoolMiningSnapshot};
use bitcoin_rs_mining::{CandidateContext, assemble_candidate};
use bitcoin_rs_primitives::{Hash256, Network, OutPoint, Tx, TxIn, TxOut, Txid};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

const POOL_SIZES: [usize; 4] = [0, 64, 512, 2_048];

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 250,
        version: 0x2000_0001,
        bits: 0x1d00_ffff,
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
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&previous))),
                0,
            ),
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 10_000,
            script_pubkey: seed.to_le_bytes().to_vec(),
        }],
    }
}

fn snapshot_with(count: usize) -> MempoolMiningSnapshot {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let mut last_txid = None;
    for seed in 0..count {
        let parent = last_txid.filter(|_| seed.is_multiple_of(8) && seed > 0);
        let tx = distinct_tx(u64::try_from(seed).expect("pool size fits u64"), parent);
        let txid = tx.txid();
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx),
            200,
            10_000 + u64::try_from(seed).expect("pool size fits u64"),
            u64::try_from(seed).expect("pool size fits u64"),
            100,
        ))
        .unwrap_or_else(|error| panic!("fixture insert {seed} failed: {error}"));
        last_txid = Some(txid);
    }
    let snapshot = pool.mining_snapshot();
    assert_eq!(
        snapshot.entries.len(),
        count,
        "fixture pool must retain every inserted transaction"
    );
    snapshot
}

fn assemble_candidate_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("assemble_candidate");
    group.sample_size(10);
    let ctx = context();
    let payout = [0x51_u8];
    for &count in &POOL_SIZES {
        let snapshot = snapshot_with(count);
        let assembled = assemble_candidate(&ctx, &snapshot, &payout)
            .unwrap_or_else(|error| panic!("fixture assemble {count} failed: {error}"));
        assert!(
            assembled.transactions.len() <= count,
            "selection must not invent transactions"
        );
        group.bench_function(BenchmarkId::new("snapshot_entries", count), |b| {
            b.iter(|| {
                black_box(
                    assemble_candidate(&ctx, &snapshot, &payout)
                        .unwrap_or_else(|error| panic!("assemble failed: {error}")),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, assemble_candidate_bench);
criterion_main!(benches);
