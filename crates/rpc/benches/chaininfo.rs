//! Whole-log fold cost on the chain-info RPCs.
//!
//! `getblockchaininfo` and `getchaintxstats` used to fold every block record the
//! node holds. The log grows one entry per block forever, so the cost of a call
//! that reports a handful of scalars was linear in chain length — and it was
//! paid under the log's read lock, which is the lock block application takes to
//! append.
//!
//! Both arms of the refactor set run here over one fixture in one process, so
//! the ratio cannot be confounded by the rebuild and baseline drift recorded in
//! `docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.
//! `before_fold` is `fold_block_records`, the walk that was replaced;
//! `after_indexed` is the running sums on `BlockLog` plus the windowed search
//! that replaced it. `dispatch` is the end-to-end RPC call as it stands now.
//!
//! Records are metadata-only, which is what a production node stores: the fold
//! reads `body_size`, `height`, `tx_count` and `time`, and nothing else.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
// A fixture that fails to build has no meaningful degraded mode.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockRecord, Context, Handler, chain_stats, fold_block_records};
use criterion::{Criterion, criterion_group, criterion_main};
use sonic_rs::json;

/// Log lengths to measure. The last is a mainnet tip at the time of writing;
/// the smaller ones are there so the slope can be read off rather than inferred
/// from a single point.
const LOG_LENGTHS: [u32; 4] = [10_000, 100_000, 500_000, 963_124];

/// `getchaintxstats`s default window: ~1 month of 10-minute blocks.
const DEFAULT_WINDOW: u64 = 30 * 24 * 6;

fn context_with_records(count: u32) -> Arc<Context> {
    let ctx = Arc::new(Context::new());
    {
        let mut blocks = ctx.blocks.write();
        blocks.reserve(count as usize);
        for height in 0..count {
            let mut hash = [0_u8; 32];
            hash[..4].copy_from_slice(&height.to_le_bytes());
            let mut record = BlockRecord::synthetic(height, Hash256::from_le_bytes(&hash));
            // A real record carries the facts the fold reads. Leaving them zero
            // would still walk the log, but would not fault in the bytes the
            // fold actually touches.
            record.body_size = 1_000_000 + (height as usize % 400_000);
            record.tx_count = 1 + (height as usize % 3_000);
            record.time = 1_231_006_505 + height * 600;
            blocks.push(record);
        }
    }
    ctx
}

/// The end of the log, as a node's applied tip.
///
/// Without this the fixture's applied height is zero, and `getchaintxstats`
/// measures a one-block chain with a 963k-record log behind it — a shape no node
/// is ever in. It also hides the cost being measured: the window collapses to a
/// single block.
fn applied_tip_for(ctx: &Arc<Context>, count: u32) -> u32 {
    let height = count.saturating_sub(1);
    let mut hash = [0_u8; 32];
    hash[..4].copy_from_slice(&height.to_le_bytes());
    ctx.set_applied_tip(TipSnapshot {
        tip_id: NodeId::new(0),
        height,
        hash: Hash256::from_le_bytes(&hash),
        chainwork: ChainWork::default(),
    });
    height
}

fn bench_chaininfo(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_info_fold");
    group.sample_size(20);

    for count in LOG_LENGTHS {
        let ctx = context_with_records(count);
        let handler = Handler::new(Arc::clone(&ctx));

        // `getchaintxstats`'s defaults, resolved against this fixture.
        let applied = applied_tip_for(&ctx, count);
        let window = u64::from(applied)
            .saturating_add(1)
            .saturating_sub(DEFAULT_WINDOW.min(u64::from(applied).saturating_add(1)));

        // Prove the arms agree on this fixture before timing either. An arm that
        // answered a different number would otherwise be timed as a win.
        {
            let log = ctx.blocks.read();
            let oracle = fold_block_records(&log, applied, Some(window));
            let indexed = chain_stats(&log, applied, window);
            assert_eq!(
                log.size_on_disk(),
                oracle.size_on_disk,
                "the arms disagree on size_on_disk; the benchmark would be meaningless"
            );
            assert_eq!(
                (
                    indexed.total_tx_count,
                    indexed.window_tx_count,
                    indexed.tip_time,
                    indexed.earliest_window_time
                ),
                (
                    oracle.total_tx_count,
                    oracle.window_tx_count,
                    oracle.tip_time,
                    oracle.earliest_window_time
                ),
                "the arms disagree on the chain stats; the benchmark would be meaningless"
            );
        }

        group.bench_function(format!("before_fold/{count}"), |b| {
            b.iter(|| {
                let log = ctx.blocks.read();
                black_box(fold_block_records(&log, applied, Some(window)))
            });
        });
        group.bench_function(format!("after_indexed/{count}"), |b| {
            b.iter(|| {
                let log = ctx.blocks.read();
                black_box((log.size_on_disk(), chain_stats(&log, applied, window)))
            });
        });

        group.bench_function(format!("getblockchaininfo/{count}"), |b| {
            b.iter(|| {
                black_box(
                    handler
                        .dispatch("getblockchaininfo", &json!([]))
                        .expect("getblockchaininfo failed"),
                )
            });
        });
        group.bench_function(format!("getchaintxstats/{count}"), |b| {
            b.iter(|| {
                black_box(
                    handler
                        .dispatch("getchaintxstats", &json!([]))
                        .expect("getchaintxstats failed"),
                )
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_chaininfo
}
criterion_main!(benches);
