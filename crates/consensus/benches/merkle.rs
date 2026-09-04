//! Merkle root computation benchmarks for the AVX2-capable reducer.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin_rs_consensus::verify_block::block_merkle_root_matches_txids;
use bitcoin_rs_primitives::{Block, Hash256, Header, Txid, encode::double_sha256};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn make_txids(count: usize) -> Vec<Txid> {
    (0..count)
        .map(|i| {
            let mut bytes = [0u8; 32];
            let value = match u32::try_from(i) {
                Ok(value) => value,
                Err(error) => panic!("benchmark size must fit u32: {error}"),
            };
            bytes[0..4].copy_from_slice(&value.to_le_bytes());
            Txid(Hash256::from_le_bytes(&bytes))
        })
        .collect()
}

fn scalar_merkle(level: &mut Vec<Txid>) -> Option<(Txid, bool)> {
    if level.is_empty() {
        return None;
    }
    let mut mutated = false;
    while level.len() > 1 {
        mutated |= level.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        let original_len = level.len();
        for parent in 0..original_len.div_ceil(2) {
            let left = level[2 * parent];
            let right = level[(2 * parent + 1).min(original_len - 1)];
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(left.as_bytes());
            pair[32..].copy_from_slice(right.as_bytes());
            level[parent] = Txid(double_sha256(&pair));
        }
        level.truncate(original_len.div_ceil(2));
    }
    Some((level[0], mutated))
}

/// Differential oracle: computes the merkle root via the `bitcoin` crate's
/// `calculate_root` to validate the benchmark inputs. Cross-binary by design.
fn oracle_merkle_root(input: &[Txid]) -> Hash256 {
    use bitcoin::hashes::Hash as _;
    let bitcoin_txids: Vec<bitcoin::Txid> = input
        .iter()
        .map(|txid| bitcoin::Txid::from_byte_array(*txid.as_bytes()))
        .collect();
    match bitcoin::merkle_tree::calculate_root(bitcoin_txids.iter().copied()) {
        Some(root) => Hash256::from_le_bytes(&root.to_byte_array()),
        None => panic!("benchmark inputs must be nonempty"),
    }
}

fn benchmark_block(merkle_root: Hash256) -> Block {
    Block {
        header: Header {
            version: 1,
            prev_blockhash: bitcoin_rs_primitives::BlockHash::default(),
            merkle_root,
            time: 0,
            bits: 0,
            nonce: 0,
        },
        txs: Vec::new(),
    }
}

fn validate_benchmark_input(block: &Block, input: &[Txid]) {
    assert!(block_merkle_root_matches_txids(block, input));

    let mut scalar = input.to_vec();
    let expected = Txid(block.header.merkle_root);
    assert_eq!(scalar_merkle(&mut scalar), Some((expected, false)));
}

fn merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    for &leaf_count in &[1, 2, 15, 16, 17, 31, 32, 33] {
        let input = make_txids(leaf_count);
        let root = oracle_merkle_root(&input);
        let block = benchmark_block(root);
        validate_benchmark_input(&block, &input);
        let mut scratch = input.clone();
        group.bench_function(BenchmarkId::new("avx2_dispatch_leaves", leaf_count), |b| {
            b.iter(|| {
                black_box(block_merkle_root_matches_txids(&block, &input));
            });
        });
        group.bench_function(BenchmarkId::new("scalar_leaves", leaf_count), |b| {
            b.iter(|| {
                scratch.clone_from(&input);
                black_box(scalar_merkle(&mut scratch));
            });
        });
    }
    for &parent_count in &[8, 64, 1024] {
        let leaf_count = parent_count * 2;
        let input = make_txids(leaf_count);
        let root = oracle_merkle_root(&input);
        let block = benchmark_block(root);
        validate_benchmark_input(&block, &input);
        group.bench_function(
            BenchmarkId::new("current_dispatch_parents", parent_count),
            |b| {
                b.iter(|| {
                    black_box(block_merkle_root_matches_txids(&block, &input));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, merkle_tree);
criterion_main!(benches);
