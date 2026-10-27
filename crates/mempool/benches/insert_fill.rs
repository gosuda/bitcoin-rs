//! Internal pool-insert fill benchmark (`insert_fill`).
//!
//! `mempool_insert_entry` measures the internal pool path, not production
//! admission: it calls `Mempool::insert_entry` directly with fabricated
//! entries (no prevouts, standardness, or script checks), which production
//! only reaches through `MempoolGateway::submit_transaction`. Within that
//! scope the insert accounts the entry through the derived-state owners and
//! refreshes package metadata incrementally over the affected closure
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
//! - `fill/63-member-cluster` (counted): untimed setup builds a fresh pool
//!   with one 62-deep chain (a single 62-member component) and the 63rd
//!   member's transaction; each measured unit is only the 63rd member's
//!   insert and its success and residency assertions. Pool teardown is untimed.
//!   Setup asserts 62 live members; the insert asserts success and 63 live
//!   members inside the timer.
//!
//! PERF: Criterion emits public harness items whose docs are irrelevant to the
//! benchmark report.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_rs_mempool::{BlockRemovalPlan, Mempool, MempoolEntry, MempoolLimits, RemovalReason};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use criterion::{Criterion, SamplingMode, criterion_group};

#[path = "../../../tools/benchmark-support/measured_samples.rs"]
mod measured_samples;

#[path = "../../../tools/benchmark-support/snapshot_order.rs"]
mod snapshot_order;

/// Counted-sampling row: one untimed 63-member cluster setup, then whole
/// timed units of only the 63rd member's insert, its success and residency
/// assertions, with the pool teardown outside the timer.
const COUNTED_CLUSTER_ROW: &str = "mempool_insert_entry/fill/63-member-cluster";

/// Builds the untimed 63-member cluster workload shared by the counted row
/// and `--mrp-verify`: a fresh pool with one 62-deep chain (a single
/// 62-member component) and the 63rd member's entry, asserting 62 live
/// members. Returns the pool and the prepared child.
fn cluster_fixture() -> (Mempool, MempoolEntry) {
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
    snapshot_order::assert_snapshot_topological(&pool);
    let snapshot = pool.mining_snapshot();
    let tip = last_txid.expect("62-chain has a tip");
    let tip_entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.txid == tip)
        .expect("62-chain tip stays resident");
    assert_eq!(
        tip_entry.ancestors.len(),
        61,
        "tip must descend from all 61 predecessors in one connected chain"
    );
    let child = MempoolEntry::new(
        Arc::new(distinct_tx(62, Some(tip))),
        200,
        spread_fee(62),
        62,
        0,
        0,
    );
    (pool, child)
}

/// Runs one whole counted cluster unit with the original timer boundary: the
/// prepared `(pool, child)` pair is built untimed, the measured span covers
/// the 63rd member's insert plus its success and residency assertions, the
/// elapsed read lands before the pool drop, and the 63-member teardown stays
/// outside the timer.
fn measured_cluster_unit(prepared: (Mempool, MempoolEntry)) -> Duration {
    let (mut pool, child) = prepared;
    let start = Instant::now();
    pool.insert_entry(child)
        .expect("63rd member insert must succeed");
    assert_eq!(pool.len(), 63, "cluster insert must add the 63rd member");
    let elapsed = start.elapsed();
    drop(pool);
    black_box(elapsed);
    elapsed
}

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
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(20));

    for size in POOL_SIZES {
        group.bench_function(format!("fill/{size}"), |b| {
            b.iter(|| {
                let pool = fill_pool(size);
                black_box(pool.len())
            });
        });
    }

    group.finish();
}

/// Runs the counted `fill/63-member-cluster` row: one untimed 63-member
/// cluster setup, then whole timed units of only the 63rd member's insert
/// plus its success and residency assertions, the 63-member teardown outside
/// the timer.
fn cluster_counted() {
    measured_samples::run(COUNTED_CLUSTER_ROW, || {
        measured_cluster_unit(cluster_fixture())
    });
}

criterion_group!(benches, bench_mempool_fill);

/// The counted CLI action selected by one validated invocation.
enum CountedAction {
    /// `--mrp-list-counted`: print the owned row, no fixtures.
    List,
    /// `--mrp-verify-counted`: the real unit once, no sample records.
    Verify,
    /// `--mrp-counted ROW_ID`: run the one row through the counted sampler.
    Run,
}

/// Counted CLI over the args collected once: `--mrp-counted ROW_ID` selects
/// exactly the one known row, `--mrp-list-counted` and
/// `--mrp-verify-counted` take no rows, and any other argument is malformed.
/// Returns the counted action when one was requested, or `None` for the
/// default Criterion path.
fn counted_cli_action(args: &[String]) -> Option<Result<CountedAction, &'static str>> {
    const COUNTED_FLAGS: [&str; 3] = [
        "--mrp-counted",
        "--mrp-list-counted",
        "--mrp-verify-counted",
    ];
    const MALFORMED_INVOCATION: &str = "malformed invocation: expected --mrp-list-counted, --mrp-verify-counted, \
         or --mrp-counted ROW_ID naming the one counted row, with no other arguments";
    if !args.iter().any(|arg| COUNTED_FLAGS.contains(&arg.as_str())) {
        return None;
    }
    Some(match args {
        [only] if only == "--mrp-list-counted" => Ok(CountedAction::List),
        [only] if only == "--mrp-verify-counted" => Ok(CountedAction::Verify),
        [flag, row] if flag == "--mrp-counted" && row == COUNTED_CLUSTER_ROW => {
            Ok(CountedAction::Run)
        }
        _ => Err(MALFORMED_INVOCATION),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match counted_cli_action(&args) {
        Some(Ok(CountedAction::List)) => {
            println!("mrp_counted {COUNTED_CLUSTER_ROW}");
            return;
        }
        Some(Ok(CountedAction::Verify)) => {
            mrp_verify_counted();
            return;
        }
        Some(Ok(CountedAction::Run)) => {
            cluster_counted();
            return;
        }
        Some(Err(malformed)) => panic!("mrp_counted {malformed}"),
        None => {}
    }
    if args.iter().any(|arg| arg == "--mrp-verify") {
        mrp_verify();
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}

/// Untimed counted verification for `--mrp-verify-counted`: the real cluster
/// unit once, then the shared stopping-rule arithmetic — no campaign sample
/// records, no timing output.
fn mrp_verify_counted() {
    let (pool, child) = cluster_fixture();
    measured_cluster_unit((pool, child));
    measured_samples::verify_stopping_rule();
    println!("mrp_verify_counted {COUNTED_CLUSTER_ROW} pass");
}

/// Builds the `fill/{size}` workload: `size` independent transactions at the
/// lifted relay floor, with the residency assertion. The Criterion `fill/{size}`
/// iteration times it; the `--mrp-verify` paths call it untimed.
fn fill_pool(size: u64) -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for seed in 0..size {
        pool.insert_entry(entry(seed))
            .expect("independent fixture insert must succeed");
    }
    assert_eq!(
        pool.len(),
        usize::try_from(size).expect("size fits usize"),
        "fill residency must hold every inserted transaction"
    );
    pool
}

fn mrp_verify_cluster() {
    let (mut chain, child) = cluster_fixture();
    chain
        .insert_entry(child)
        .expect("63rd member insert must succeed");
    assert_eq!(chain.len(), 63, "cluster insert must add the 63rd member");
    snapshot_order::assert_snapshot_topological(&chain);
    println!(
        "mrp_verify fill/63-member-cluster entries={} order_fp={:016x}",
        chain.len(),
        snapshot_order::snapshot_order_fingerprint(&chain)
    );
}

fn mrp_verify_removal_plan() {
    let projected_source = fill_pool(800);
    let victim = distinct_tx(3, None).txid();
    let victim_id = projected_source
        .entry_id_by_txid(&victim)
        .expect("victim stays resident");
    let plan = BlockRemovalPlan {
        removals: vec![(victim_id, RemovalReason::BlockInclusion)],
        fee_deltas_cleared: 0,
    };
    let mut projected_state = snapshot_order::FNV_OFFSET;
    let mut projected_count = 0_usize;
    for chunk in projected_source.chunks_after(&plan).iter() {
        for txid in chunk.txids {
            projected_state = snapshot_order::fold_bytes(projected_state, txid.as_bytes());
            projected_count += 1;
        }
    }
    let mut removed = fill_pool(800);
    let victim_tx = removed
        .entry_by_txid(&victim)
        .expect("victim stays resident")
        .tx
        .clone();
    let victim_ref: &Tx = &victim_tx;
    removed.remove_for_block(std::slice::from_ref(&victim_ref), &[victim], 1, 0);
    assert_eq!(
        removed.len(),
        799,
        "the block must confirm exactly one entry"
    );
    assert_eq!(
        projected_count,
        removed.len(),
        "the projection must name every surviving entry"
    );
    let live = removed.mining_snapshot();
    let mut live_state = snapshot_order::FNV_OFFSET;
    for entry in &live.entries {
        live_state = snapshot_order::fold_bytes(live_state, entry.txid.as_bytes());
    }
    assert_eq!(
        live.entries.len(),
        projected_count,
        "projection and removal must retain the same survivors"
    );
    assert_eq!(
        projected_state, live_state,
        "projected chunk order must equal the post-removal order"
    );
    println!(
        "mrp_verify removal_plan/800 survivors={projected_count} plan_fp={projected_state:016x}"
    );
}

/// Untimed MRP verification for `--mrp-verify`: the real fill, cluster,
/// prioritisation, error, and removal-plan fixtures with residency,
/// topological, and deterministic-fingerprint assertions. Prints
/// fingerprints only, never timing data.
fn mrp_verify() {
    for size in POOL_SIZES {
        let pool = fill_pool(size);
        snapshot_order::assert_snapshot_topological(&pool);
        println!(
            "mrp_verify fill/{size} entries={} order_fp={:016x}",
            pool.len(),
            snapshot_order::snapshot_order_fingerprint(&pool)
        );
    }

    mrp_verify_cluster();

    let mut prioritised = fill_pool(800);
    let target = distinct_tx(7, None).txid();
    prioritised
        .prioritise(target, 5_000)
        .expect("fixed overlay applies");
    prioritised
        .prioritise(target, -2_000)
        .expect("a negative delta subtracts");
    let overlay = prioritised
        .entry_by_txid(&target)
        .expect("prioritised entry stays resident");
    assert_eq!(overlay.fee_delta, 3_000, "overlays must accumulate");
    assert!(
        prioritised
            .prioritised_transactions()
            .iter()
            .any(|record| record.txid == target && record.fee_delta == 3_000),
        "the overlay must stay listed"
    );
    snapshot_order::assert_snapshot_topological(&prioritised);
    println!(
        "mrp_verify prioritise/800 entries={} order_fp={:016x}",
        prioritised.len(),
        snapshot_order::snapshot_order_fingerprint(&prioritised)
    );

    let mut duplicated = fill_pool(200);
    let duplicate = duplicated.insert_entry(entry(0));
    assert!(
        matches!(
            duplicate,
            Err(bitcoin_rs_mempool::MempoolError::DuplicateTransaction)
        ),
        "re-inserting a resident transaction must fail as a duplicate"
    );
    let mut relay_floor = Mempool::new(MempoolLimits::default());
    assert!(
        relay_floor.insert_entry(entry(0)).is_err(),
        "a 1-sat fee must fail the default relay floor"
    );
    assert_eq!(relay_floor.len(), 0, "a refused insert must admit nothing");
    println!("mrp_verify errors duplicate=DuplicateTransaction relay_floor=refused");

    mrp_verify_removal_plan();
}
