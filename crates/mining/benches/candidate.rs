//! Candidate assembly benchmark.
//!
//! No invented performance budget. This fixture only measures the current
//! `assemble_candidate` path so later B1/M3 work can freeze envelopes from
//! observed distributions rather than guesses.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::{CandidateContext, assemble_candidate};
use bitcoin_rs_primitives::{Hash256, Network};
use criterion::{Criterion, criterion_group, criterion_main};

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x33; 32]),
        height: 120_000,
        version: 0x2000_0000,
        bits: 0x1d00_ffff,
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

fn independent(label: u64) -> Transaction {
    let mut previous = [0_u8; 32];
    previous[..8].copy_from_slice(&label.to_le_bytes());
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(previous), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(label.to_le_bytes().to_vec()),
        }],
    }
}

fn child(label: u64, parent: Txid) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(parent, 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: ScriptBuf::from_bytes(label.to_le_bytes().to_vec()),
        }],
    }
}

fn fill_independent(size: u64) -> Mempool {
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for index in 0..size {
        mempool
            .insert_entry(MempoolEntry::new(
                Arc::new(independent(index)),
                200,
                1_000 + (index % 97),
                index,
                100,
            ))
            .expect("independent fixture inserts");
    }
    mempool
}

fn fill_chains(chains: u64, depth: u64) -> Mempool {
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for chain in 0..chains {
        let mut parent = independent(chain.saturating_mul(1_000));
        let mut parent_txid = parent.compute_txid();
        mempool
            .insert_entry(MempoolEntry::new(Arc::new(parent), 180, 2_000, chain, 100))
            .expect("chain root inserts");
        for depth_index in 1..depth {
            parent = child(chain.saturating_mul(1_000) + depth_index, parent_txid);
            parent_txid = parent.compute_txid();
            mempool
                .insert_entry(MempoolEntry::new(
                    Arc::new(parent),
                    180,
                    2_000 + depth_index,
                    chain.saturating_mul(1_000) + depth_index,
                    100,
                ))
                .expect("chain child inserts");
        }
    }
    mempool
}

fn bench_candidate(c: &mut Criterion) {
    let mut group = c.benchmark_group("mining_candidate");
    group.sample_size(10);

    let empty = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })
    .mining_snapshot();
    let independent_snapshot = fill_independent(2_000).mining_snapshot();
    let chain_snapshot = fill_chains(64, 8).mining_snapshot();
    let payout = ScriptBuf::from_bytes(vec![0x51]);
    let context = context();
    let mut congested = context.clone();
    congested.max_weight = 50_000;
    congested.max_size = 50_000;

    group.bench_function("empty", |b| {
        b.iter(|| {
            black_box(
                assemble_candidate(black_box(&context), black_box(&empty), black_box(&payout))
                    .expect("empty candidate"),
            )
        });
    });
    group.bench_function("independent_2000", |b| {
        b.iter(|| {
            black_box(
                assemble_candidate(
                    black_box(&context),
                    black_box(&independent_snapshot),
                    black_box(&payout),
                )
                .expect("independent candidate"),
            )
        });
    });
    group.bench_function("chains_64x8", |b| {
        b.iter(|| {
            black_box(
                assemble_candidate(
                    black_box(&context),
                    black_box(&chain_snapshot),
                    black_box(&payout),
                )
                .expect("chain candidate"),
            )
        });
    });
    group.bench_function("full_capacity_2000", |b| {
        b.iter(|| {
            black_box(
                assemble_candidate(
                    black_box(&congested),
                    black_box(&independent_snapshot),
                    black_box(&payout),
                )
                .expect("full-capacity candidate"),
            )
        });
    });

    group.finish();
}

criterion_group!(benches, bench_candidate);
criterion_main!(benches);
