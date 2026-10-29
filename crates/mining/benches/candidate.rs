#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_rs_mempool::{BlockRemovalPlan, Mempool, MempoolEntry, MempoolLimits, RemovalReason};
use bitcoin_rs_mining::{
    CandidateContext, SelectedBody, assemble_candidate, select_template_body,
    select_template_body_after,
};
use bitcoin_rs_primitives::{
    Amount, CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness,
};
use criterion::{BenchmarkId, Criterion, SamplingMode, criterion_group};

#[path = "../../../tools/benchmark-support/measured_samples.rs"]
mod measured_samples;

#[path = "../../../tools/benchmark-support/snapshot_order.rs"]
mod snapshot_order;

const INDEPENDENT_POOL_SIZES: [usize; 7] = [0, 64, 512, 2_048, 20_000, 50_000, 100_000];

const CHAIN_POOL_CHAINS: usize = 800;
const CHAIN_DEPTH: usize = 25;

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 250,
        version: 0x2000_0001,
        bits: CompactTarget::from_consensus(0x1d00_ffff),
        min_time: 10,
        current_time: 20,
        locktime_cutoff: 10,
        staged_parent_mtp: 10,
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
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| Txid(Hash256::from_le_bytes(&previous))),
                0,
            ),
            script_sig: Script::from(Vec::new()),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::from_stack(Vec::new()),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from(seed.to_le_bytes().to_vec()),
        }],
    }
}

fn snapshot_with(count: usize) -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let mut last_txid = None;
    for seed in 0..count {
        let parent = last_txid.filter(|_| seed.is_multiple_of(8) && seed > 0);
        last_txid = Some(insert_fixture_tx(
            &mut pool,
            u64::try_from(seed).expect("pool size fits u64"),
            parent,
        ));
    }
    assert_eq!(
        pool.mining_snapshot().entries.len(),
        count,
        "fixture pool must retain every inserted transaction"
    );
    pool
}

fn chained_snapshot() -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for chain in 0..CHAIN_POOL_CHAINS {
        let mut last_txid = None;
        for depth in 0..CHAIN_DEPTH {
            let seed = u64::try_from(chain * CHAIN_DEPTH + depth).expect("chain pool fits u64");
            last_txid = Some(insert_fixture_tx(&mut pool, seed, last_txid));
        }
    }
    let chains = CHAIN_POOL_CHAINS;
    let depth = CHAIN_DEPTH;
    assert_eq!(
        pool.mining_snapshot().entries.len(),
        chains * depth,
        "chained fixture pool must retain every inserted transaction"
    );
    pool
}

fn insert_fixture_tx(pool: &mut Mempool, seed: u64, parent: Option<Txid>) -> Txid {
    let tx = distinct_tx(seed, parent);
    let txid = tx.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx),
        200,
        10_000 + seed,
        seed,
        100,
        0,
    ))
    .unwrap_or_else(|error| panic!("fixture insert {seed} failed: {error}"));
    txid
}

fn assemble_candidate_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("assemble_candidate");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(20));
    let ctx = context();
    let payout = [0x51_u8];
    for &count in &INDEPENDENT_POOL_SIZES {
        let pool = snapshot_with(count);
        let assembled = assemble_candidate(&ctx, &pool, &payout)
            .unwrap_or_else(|error| panic!("fixture assemble {count} failed: {error}"));
        assert!(
            assembled.transactions.len() <= count,
            "selection must not invent transactions"
        );
        group.bench_function(BenchmarkId::new("end_to_end", count), |b| {
            b.iter(|| {
                black_box(
                    assemble_candidate(&ctx, &pool, &payout)
                        .unwrap_or_else(|error| panic!("assemble failed: {error}")),
                )
            });
        });
    }
    let pool = chained_snapshot();
    let assembled = assemble_candidate(&ctx, &pool, &payout)
        .unwrap_or_else(|error| panic!("fixture assemble chains failed: {error}"));
    assert!(
        assembled.transactions.len() <= CHAIN_POOL_CHAINS * CHAIN_DEPTH,
        "selection must not invent transactions"
    );
    group.bench_function(BenchmarkId::new("end_to_end", "chains/depth-25"), |b| {
        b.iter(|| {
            black_box(
                assemble_candidate(&ctx, &pool, &payout)
                    .unwrap_or_else(|error| panic!("assemble failed: {error}")),
            )
        });
    });
    group.finish();
}

fn counted_guard_unit(
    pool: &parking_lot::RwLock<Mempool>,
    ctx: &CandidateContext,
    payout: &[u8],
) -> Duration {
    let guard = pool.read();
    let start = Instant::now();
    let body = select_template_body(&guard, ctx, payout, None)
        .unwrap_or_else(|error| panic!("selection failed: {error}"));
    drop(guard);
    let elapsed = start.elapsed();
    black_box(body.transactions.len());
    drop(body);
    elapsed
}

fn indexed_selection_read_guard_counted() {
    let row = "indexed_selection_read_guard/read_guard/100000";
    let pool = parking_lot::RwLock::new(snapshot_with(100_000));
    let ctx = context();
    let payout = [0x51_u8];
    let guarded = pool.read();
    let _warmed = select_template_body(&guarded, &ctx, &payout, None)
        .unwrap_or_else(|error| panic!("fixture selection failed: {error}"));
    drop(guarded);
    measured_samples::run(row, || counted_guard_unit(&pool, &ctx, &payout));
}

fn counted_rows_owned() -> Vec<&'static str> {
    vec![
        "mining_snapshot_operation/mining_snapshot/64",
        "mining_snapshot_operation/mining_snapshot/512",
        "mining_snapshot_operation/mining_snapshot/2048",
        "mining_snapshot_operation/mining_snapshot/20000",
        "mining_snapshot_operation/mining_snapshot/50000",
        "mining_snapshot_operation/mining_snapshot/100000",
        "mining_snapshot_operation/mining_snapshot/chains/depth-25",
        "indexed_selection_read_guard/read_guard/100000",
    ]
}

enum CountedAction {
    List,
    Verify,
    Run(usize),
}

fn counted_cli_action(
    args: &[String],
    rows: &[&'static str],
) -> Option<Result<CountedAction, &'static str>> {
    const COUNTED_FLAGS: [&str; 3] = [
        "--mrp-counted",
        "--mrp-list-counted",
        "--mrp-verify-counted",
    ];
    if !args.iter().any(|arg| COUNTED_FLAGS.contains(&arg.as_str())) {
        return None;
    }
    let flag = args.first().map(String::as_str);
    if flag == Some("--mrp-list-counted") && args.len() == 1 {
        return Some(Ok(CountedAction::List));
    }
    if flag == Some("--mrp-verify-counted") && args.len() == 1 {
        return Some(Ok(CountedAction::Verify));
    }
    if flag == Some("--mrp-counted") && args.len() == 2 {
        let Some(at) = rows.iter().position(|known| *known == args[1].as_str()) else {
            return Some(Err(
                "malformed invocation: unknown counted row for this binary",
            ));
        };
        return Some(Ok(CountedAction::Run(at)));
    }
    Some(Err(
        "malformed invocation: expected one counted flag or --mrp-counted ROW_ID",
    ))
}

fn counted_snapshot_unit(pool: &Mempool, unit_count: usize) -> Duration {
    let start = Instant::now();
    let snapshot = pool.mining_snapshot();
    let elapsed = start.elapsed();
    black_box(snapshot.entries.len());
    assert_eq!(
        snapshot.entries.len(),
        unit_count,
        "counted snapshot unit must name the fixture size"
    );
    drop(snapshot);
    elapsed
}

fn warmed_snapshot_fixture(count: usize) -> Mempool {
    let pool = snapshot_with(count);
    let warmed = pool.mining_snapshot();
    assert_eq!(
        warmed.entries.len(),
        count,
        "warm-up snapshot must already name the fixture size"
    );
    drop(warmed);
    pool
}

fn warmed_chained_fixture() -> Mempool {
    let pool = chained_snapshot();
    let warmed = pool.mining_snapshot();
    assert_eq!(
        warmed.entries.len(),
        CHAIN_POOL_CHAINS * CHAIN_DEPTH,
        "warm-up snapshot must already name the chained fixture size"
    );
    drop(warmed);
    pool
}

fn snapshot_row(row: &str, unit_count: usize) {
    let pool = warmed_snapshot_fixture(unit_count);
    measured_samples::run(row, || counted_snapshot_unit(&pool, unit_count));
}

fn chained_snapshot_row(row: &str) {
    let pool = warmed_chained_fixture();
    measured_samples::run(row, || {
        counted_snapshot_unit(&pool, CHAIN_POOL_CHAINS * CHAIN_DEPTH)
    });
}

fn snapshot_operation_counted(requested: &str) {
    if requested.ends_with("chains/depth-25") {
        chained_snapshot_row(requested);
        return;
    }
    let count = requested
        .rsplit('/')
        .next()
        .and_then(|suffix| suffix.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("counted snapshot row must carry a numeric size: {requested}"));
    snapshot_row(requested, count);
}

criterion_group!(benches, assemble_candidate_bench);

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rows = counted_rows_owned();
    match counted_cli_action(&args, &rows) {
        Some(Ok(CountedAction::List)) => {
            for row in rows {
                println!("mrp_counted {row}");
            }
            return;
        }
        Some(Ok(CountedAction::Verify)) => {
            mrp_verify_counted();
            return;
        }
        Some(Ok(CountedAction::Run(at))) => {
            let id = rows[at];
            if id.starts_with("mining_snapshot_operation/") {
                snapshot_operation_counted(id);
            } else {
                indexed_selection_read_guard_counted();
            }
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

fn verify_snapshot_unit(count: usize) {
    let pool = warmed_snapshot_fixture(count);
    counted_snapshot_unit(&pool, count);
}

fn verify_guard_unit(ctx: &CandidateContext, payout: &[u8]) {
    let pool = parking_lot::RwLock::new(snapshot_with(100_000));
    let guarded = pool.read();
    let warmed = select_template_body(&guarded, ctx, payout, None)
        .unwrap_or_else(|error| panic!("fixture selection failed: {error}"));
    drop(guarded);
    drop(warmed);
    counted_guard_unit(&pool, ctx, payout);
}

fn mrp_verify_counted() {
    let ctx = context();
    let payout = [0x51_u8];

    for &count in &INDEPENDENT_POOL_SIZES {
        if count == 0 {
            continue;
        }
        verify_snapshot_unit(count);
        println!("mrp_verify_counted mining_snapshot_operation/mining_snapshot/{count} pass");
    }
    verify_chained_snapshot_unit();
    println!("mrp_verify_counted mining_snapshot_operation/mining_snapshot/chains/depth-25 pass");

    verify_guard_unit(&ctx, &payout);
    println!("mrp_verify_counted indexed_selection_read_guard/read_guard/100000 pass");

    measured_samples::verify_stopping_rule();
    println!("mrp_verify_counted stopping_rule pass");
}

fn verify_chained_snapshot_unit() {
    let pool = warmed_chained_fixture();
    counted_snapshot_unit(&pool, CHAIN_POOL_CHAINS * CHAIN_DEPTH);
}

fn body_fingerprint(body: &SelectedBody) -> u64 {
    let mut state = snapshot_order::FNV_OFFSET;
    for tx in &body.transactions {
        state = snapshot_order::fold_bytes(state, tx.txid.as_bytes());
        state = snapshot_order::fold_u64(state, tx.fee);
    }
    state
}

fn assert_selection_sound(pool: &Mempool, body: &SelectedBody) {
    for tx in &body.transactions {
        assert!(
            pool.contains_txid(&tx.txid),
            "selection must not invent transactions"
        );
    }
    snapshot_order::assert_snapshot_topological(pool);
}

fn childless_victim(pool: &Mempool) -> (Txid, Arc<Tx>) {
    let snapshot = pool.mining_snapshot();
    let mut spent: std::collections::HashSet<Txid> = std::collections::HashSet::new();
    for entry in &snapshot.entries {
        for input in &entry.tx.inputs {
            spent.insert(input.previous_output.txid);
        }
    }
    for entry in &snapshot.entries {
        if !spent.contains(&entry.txid) {
            return (entry.txid, Arc::clone(&entry.tx));
        }
    }
    panic!("a non-empty fixture pool always holds a childless entry");
}

fn mrp_verify_end_to_end(ctx: &CandidateContext, payout: &[u8]) {
    for &count in &[64_usize, 512] {
        let pool = snapshot_with(count);
        assert_eq!(
            pool.mining_snapshot().entries.len(),
            count,
            "fixture pool must retain every inserted transaction"
        );
        let candidate = assemble_candidate(ctx, &pool, payout)
            .unwrap_or_else(|error| panic!("fixture assemble {count} failed: {error}"));
        let selected = select_template_body(&pool, ctx, payout, None)
            .unwrap_or_else(|error| panic!("fixture selection {count} failed: {error}"));
        assert!(
            !selected.transactions.is_empty(),
            "fixture selection {count} must select at least one transaction"
        );
        assert_selection_sound(&pool, &selected);
        assert_eq!(
            candidate
                .transactions
                .iter()
                .map(|tx| tx.txid)
                .collect::<Vec<_>>(),
            selected
                .transactions
                .iter()
                .map(|tx| tx.txid)
                .collect::<Vec<_>>(),
            "assembly and bare selection must agree on the body"
        );
        println!(
            "mrp_verify end_to_end/{count} entries={count} order_fp={:016x} body_fp={:016x}",
            snapshot_order::snapshot_order_fingerprint(&pool),
            body_fingerprint(&selected)
        );
    }

    let chains = chained_snapshot();
    assert_eq!(
        chains.mining_snapshot().entries.len(),
        CHAIN_POOL_CHAINS * CHAIN_DEPTH,
        "chained fixture pool must retain every inserted transaction"
    );
    let chained = select_template_body(&chains, ctx, payout, None)
        .unwrap_or_else(|error| panic!("chained selection failed: {error}"));
    assert!(
        !chained.transactions.is_empty(),
        "chained fixture selection must select at least one transaction"
    );
    assert_selection_sound(&chains, &chained);
    println!(
        "mrp_verify end_to_end/chains/depth-25 entries={} order_fp={:016x} body_fp={:016x}",
        chains.len(),
        snapshot_order::snapshot_order_fingerprint(&chains),
        body_fingerprint(&chained)
    );
}

fn mrp_verify_removal_plan(ctx: &CandidateContext, payout: &[u8]) {
    let source = snapshot_with(512);
    let (victim_txid, victim_tx) = childless_victim(&source);
    let victim_id = source
        .entry_id_by_txid(&victim_txid)
        .expect("victim stays resident");
    let plan = BlockRemovalPlan {
        removals: vec![(victim_id, RemovalReason::BlockInclusion)],
        fee_deltas_cleared: 0,
    };
    let projected = select_template_body_after(&source, &plan, ctx, payout)
        .unwrap_or_else(|error| panic!("projected selection failed: {error}"));
    assert!(
        !projected.transactions.is_empty(),
        "projected selection must select at least one transaction"
    );
    assert!(
        projected
            .transactions
            .iter()
            .all(|tx| tx.txid != victim_txid),
        "projected selection must exclude the removed victim"
    );
    let mut twin = snapshot_with(512);
    let victim_ref: &Tx = &victim_tx;
    twin.remove_for_block(std::slice::from_ref(&victim_ref), &[victim_txid], 250, 20);
    assert_eq!(
        twin.len(),
        511,
        "removing a childless entry must confirm exactly one entry"
    );
    let actual = select_template_body(&twin, ctx, payout, None)
        .unwrap_or_else(|error| panic!("post-removal selection failed: {error}"));
    assert_eq!(
        projected
            .transactions
            .iter()
            .map(|tx| tx.txid)
            .collect::<Vec<_>>(),
        actual
            .transactions
            .iter()
            .map(|tx| tx.txid)
            .collect::<Vec<_>>(),
        "projected selection must equal selection after the real removal"
    );
    println!(
        "mrp_verify removal_plan/512 survivors=511 plan_fp={:016x}",
        body_fingerprint(&projected)
    );
}

fn mrp_verify() {
    let ctx = context();
    let payout = [0x51_u8];

    mrp_verify_end_to_end(&ctx, &payout);

    let mature = snapshot_with(100_000);
    assert_eq!(
        mature.mining_snapshot().entries.len(),
        100_000,
        "mature fixture pool must retain every inserted transaction"
    );
    snapshot_order::assert_snapshot_topological(&mature);
    println!(
        "mrp_verify residency/100000 entries=100000 order_fp={:016x}",
        snapshot_order::snapshot_order_fingerprint(&mature)
    );

    mrp_verify_removal_plan(&ctx, &payout);
}
