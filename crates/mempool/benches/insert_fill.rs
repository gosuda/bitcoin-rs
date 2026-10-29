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

const COUNTED_CLUSTER_ROW: &str = "mempool_insert_entry/fill/63-member-cluster";

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

fn cluster_counted() {
    measured_samples::run(COUNTED_CLUSTER_ROW, || {
        measured_cluster_unit(cluster_fixture())
    });
}

criterion_group!(benches, bench_mempool_fill);

enum CountedAction {
    List,
    Verify,
    Run,
}

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

fn mrp_verify_counted() {
    let (pool, child) = cluster_fixture();
    measured_cluster_unit((pool, child));
    measured_samples::verify_stopping_rule();
    println!("mrp_verify_counted {COUNTED_CLUSTER_ROW} pass");
}

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
