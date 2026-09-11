//! Parse-once fact derivation and decoded lazy witness-ID benchmarks.
//! Run the identical harness at its introduction commit and the optimized
//! descendant in separate target directories. No historical-chain fixture is
//! needed. This microbenchmark is not an apply-path or full-replay verdict.
#![allow(missing_docs)]

#[path = "../tests/support/block_facts_fixture.rs"]
mod fixtures;

use std::hint::black_box;

use bitcoin_rs_consensus::{BlockView, block_view::BlockFacts};
use bitcoin_rs_primitives::layout::ParsedBlock;
use bitcoin_rs_primitives::{Tx, consensus_bytes};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn block_facts(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_facts");
    // name, tx count, inputs, outputs, script bytes, witness modulus.
    // Each fixture isolates a relevant source of copying or metadata work.
    for (name, txs, inputs, outputs, script, witness) in [
        ("legacy_small", 1, 1, 2, 25, 0),
        ("legacy_1024", 1024, 1, 2, 25, 0),
        ("segwit_1024", 1024, 1, 2, 25, 1),
        ("mixed_1024", 1024, 1, 2, 25, 2),
        ("legacy_large_script", 1, 1, 1, 65_536, 0),
        ("segwit_large_script", 1, 1, 1, 65_536, 1),
        ("segwit_253_inputs", 8, 253, 2, 0, 1),
        ("segwit_253_outputs", 8, 1, 253, 0, 1),
    ] {
        let block = fixtures::fixture(txs, inputs, outputs, script, witness);
        let bytes = consensus_bytes(&block);
        let parsed = ParsedBlock::parse_exact(&bytes)
            .unwrap_or_else(|error| panic!("benchmark layout: {error}"));
        let checked = BlockFacts::from_parsed(&parsed);
        fixtures::assert_oracle(&bytes, &checked);
        assert!(!checked.merkle_mutated());
        group.throughput(Throughput::Bytes(
            u64::try_from(bytes.len()).unwrap_or_else(|error| panic!("fixture size: {error}")),
        ));
        group.bench_function(BenchmarkId::new("derive", name), |b| {
            b.iter(|| black_box(BlockFacts::from_parsed(black_box(&parsed))));
        });
        group.bench_function(BenchmarkId::new("parse_and_derive", name), |b| {
            b.iter(|| {
                let layout = ParsedBlock::parse_exact(black_box(&bytes))
                    .unwrap_or_else(|error| panic!("benchmark layout: {error}"));
                black_box(BlockFacts::from_parsed(&layout))
            });
        });
    }
    group.finish();
}

fn lazy_witness_ids(c: &mut Criterion) {
    let mut group = c.benchmark_group("lazy_witness_ids");
    for (name, witness) in [("legacy", 0), ("segwit", 1), ("mixed", 2)] {
        let block = fixtures::fixture(1024, 1, 2, 25, witness);
        let txids = block.txs.iter().map(Tx::txid).collect();
        let baseline = BlockFacts::from_txids(&block.txs, txids);
        let mut checked = BlockView::from_facts(&block.txs, baseline.clone());
        let bytes = consensus_bytes(&block);
        let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)
            .unwrap_or_else(|error| panic!("benchmark oracle: {error}"));
        assert_eq!(checked.witness_ids().len(), oracle.txdata.len());
        for (actual, expected) in checked.witness_ids().iter().zip(&oracle.txdata) {
            assert_eq!(actual.to_string(), expected.compute_wtxid().to_string());
        }
        group.throughput(Throughput::Elements(1024));
        group.bench_function(name, |b| {
            // Reset the lazy cache outside timing. Each iteration measures a
            // genuine first fill, not the already-populated fast return.
            b.iter_batched_ref(
                || BlockView::from_facts(&block.txs, baseline.clone()),
                |view| {
                    black_box(view.witness_ids());
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, block_facts, lazy_witness_ids);
criterion_main!(benches);
