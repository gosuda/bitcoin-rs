//! Block-record lookup cost under `getblock` and `getblockheader`.
//!
//! `Context::record_for_hash` resolves a hash to a block record. Step 1 asks the
//! block tree, which answers with the height — and then scanned the block-record
//! log linearly for the matching `(hash, height)` pair, even though the log is
//! ordered by height and the height was in hand.
//!
//! That log grows one entry per block forever, so `getblock`, `getblockheader`,
//! `getblockstats`, `getrawtransaction` with a blockhash, the REST block
//! endpoint and `gettxoutproof`'s explicit-hash path each paid a walk
//! proportional to chain length. `verifychain` pays one per block it checks.
//!
//! Both arms of the refactor set run here over one fixture in one process, so
//! the ratio cannot be confounded by the rebuild and baseline drift recorded in
//! `docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.
//! `before_scan` is the linear find that was there; `after_search` is
//! [`record_at_height_hash`], the binary search plus duplicate-height walk that
//! replaced it.
//!
//! Two lookup positions are measured. A hash at the *end* of the log is the
//! worst case for a forward scan and the one a tip-following client asks for; a
//! hash in the *middle* costs the scan half as much and is what a wallet
//! rescanning history asks for. Measuring only one would flatter the scan in
//! whichever direction was chosen.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
// A fixture that fails to build has no meaningful degraded mode: a lookup that
// silently found nothing would be timed as a spectacular, empty win.
#![allow(clippy::expect_used)]

use std::hint::black_box;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockRecord, record_at_height_hash};
use criterion::{Criterion, criterion_group, criterion_main};

/// Log lengths to measure. The last is a mainnet tip at the time of writing;
/// the smaller ones are there so the slope can be read off rather than inferred
/// from a single point.
const LOG_LENGTHS: [u32; 4] = [10_000, 100_000, 500_000, 963_124];

fn hash_for(height: u32) -> Hash256 {
    let mut hash = [0_u8; 32];
    hash[..4].copy_from_slice(&height.to_le_bytes());
    Hash256::from_le_bytes(&hash)
}

fn records(count: u32) -> Vec<BlockRecord> {
    (0..count)
        .map(|height| {
            let mut record = BlockRecord::synthetic(height, hash_for(height));
            // A real record carries the facts a scan reads past. Leaving them
            // zero would still walk the log, but would not fault in the bytes
            // the comparison actually touches.
            record.body_size = 1_000_000 + (height as usize % 400_000);
            record.tx_count = 1 + (height as usize % 3_000);
            record.time = 1_231_006_505 + height * 600;
            record
        })
        .collect()
}

/// The scan that was in `record_for_hash`, kept here as the `before` arm and as
/// the oracle the search is checked against.
///
/// Written out rather than called through the crate: it is two lines, and an
/// oracle that shares code with the implementation cannot disagree with it.
fn scan_for(records: &[BlockRecord], height: u32, hash: Hash256) -> Option<&BlockRecord> {
    records
        .iter()
        .find(|candidate| candidate.hash == hash && candidate.height == height)
}

fn bench_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_record_lookup");
    group.sample_size(20);

    for count in LOG_LENGTHS {
        let log = records(count);

        for (label, height) in [("tip", count.saturating_sub(1)), ("middle", count / 2)] {
            let hash = hash_for(height);

            // Prove both arms find the same record before timing either.
            assert_eq!(
                scan_for(&log, height, hash).map(|record| record.time),
                record_at_height_hash(&log, height, hash).map(|record| record.time),
                "the arms disagree at {label}; the benchmark would be meaningless"
            );

            group.bench_function(format!("before_scan/{label}/{count}"), |b| {
                b.iter(|| black_box(scan_for(&log, height, hash).map(|record| record.time)));
            });
            group.bench_function(format!("after_search/{label}/{count}"), |b| {
                b.iter(|| {
                    black_box(record_at_height_hash(&log, height, hash).map(|record| record.time))
                });
            });
        }
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_lookup
}
criterion_main!(benches);
