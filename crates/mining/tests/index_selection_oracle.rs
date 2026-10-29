#![expect(
    clippy::expect_used,
    reason = "integration fixtures fail loudly on a broken precondition"
)]

#[path = "support/fixtures.rs"]
mod common;

use std::collections::HashSet;
use std::ops::Range;

use bitcoin_rs_mempool::{Mempool, SnapshotEntry};
use bitcoin_rs_mining::{Candidate, CandidateContext, assemble_candidate};
use bitcoin_rs_primitives::{Hash256, LockTime, OutPoint, Sequence, Tx, Txid};
use common::{
    Forged, PAYOUT, insert_forged, selected_fees, serialized_size, total_sigop_cost, tx,
    zero_fee_pool,
};
use proptest::prelude::*;

const NON_FINAL_LOCKTIME: u32 = 500_000_100;
const LOCKTIME_CUTOFF: u32 = 500_000_000;

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xe1; 32]),
        locktime_cutoff: LOCKTIME_CUTOFF,
        ..common::context()
    }
}

fn selected(candidate: &Candidate) -> Vec<Txid> {
    candidate.transactions.iter().map(|tx| tx.txid).collect()
}

#[derive(Clone, Copy, Debug)]
struct Reservation {
    weight: u64,
    size: u64,
    sigops: u64,
}

impl Reservation {
    fn of(context: &CandidateContext) -> Self {
        let empty = assemble_candidate(context, &zero_fee_pool(), PAYOUT)
            .expect("an empty pool assembles under the generous context");
        Self {
            weight: empty.weight,
            size: serialized_size(&empty),
            sigops: total_sigop_cost(&empty),
        }
    }
}

fn count_bytes(body: usize) -> u64 {
    match body + 1 {
        0..=252 => 1,
        253..=65_535 => 3,
        _ => 5,
    }
}

fn final_in_next_block(context: &CandidateContext, pooled: &HashSet<Txid>, tx: &Tx) -> bool {
    let lock_time = tx.lock_time.to_consensus();
    let absolute = lock_time == 0 || {
        let threshold = if lock_time < 500_000_000 {
            context.height
        } else {
            context.locktime_cutoff
        };
        lock_time < threshold
            || tx
                .inputs
                .iter()
                .all(|input| input.sequence.to_consensus() == 0xFFFF_FFFF)
    };
    let relative = !context.csv_active
        || tx.version < 2
        || tx.inputs.iter().all(|input| {
            let sequence = input.sequence.to_consensus();
            let locked = sequence & (1 << 31) == 0 && sequence & 0xFFFF != 0;
            !(pooled.contains(&input.previous_output.txid) && locked)
        });
    absolute && relative
}

const BLOCK_MIN_TX_FEE_SAT_PER_KVB: i128 = 1;

type Run = Range<usize>;

struct Oracle<'a> {
    context: &'a CandidateContext,
    entries: &'a [SnapshotEntry],
    charged: Vec<u64>,
    pooled: HashSet<Txid>,
    taken: Vec<bool>,
    order: Vec<Txid>,
    fees: u64,
    weight: u64,
    size: u64,
    sigops: u64,
}

impl Oracle<'_> {
    fn modified_fee(&self, run: &Run) -> i128 {
        self.entries[run.start..run.end]
            .iter()
            .map(|entry| i128::from(entry.fee) + i128::from(entry.fee_delta))
            .sum()
    }

    fn charged_weight(&self, run: &Run) -> u64 {
        self.charged[run.start..run.end].iter().sum()
    }

    fn pays_block_min_fee(&self, run: &Run) -> bool {
        let vsize = i128::from(self.charged_weight(run).div_ceil(4));
        self.modified_fee(run) * 1_000 >= BLOCK_MIN_TX_FEE_SAT_PER_KVB * vsize
    }

    fn blocked(&self, run: &Run) -> bool {
        self.entries[run.start..run.end]
            .iter()
            .flat_map(|entry| entry.ancestors.iter())
            .any(|&ancestor| {
                let ancestor = usize::try_from(ancestor).expect("snapshot position fits");
                !self.taken[ancestor] && !run.contains(&ancestor)
            })
    }

    fn is_final(&self, run: &Run) -> bool {
        self.entries[run.start..run.end]
            .iter()
            .all(|entry| final_in_next_block(self.context, &self.pooled, &entry.tx))
    }

    fn grown_by(&self, run: &Run) -> Option<(u64, u64, u64)> {
        let members = &self.entries[run.start..run.end];
        let growth = count_bytes(self.order.len() + members.len()) - count_bytes(self.order.len());
        let weight =
            self.weight + members.iter().map(|entry| entry.weight).sum::<u64>() + growth * 4;
        let size = self.size
            + members
                .iter()
                .map(|entry| u64::from(entry.size))
                .sum::<u64>()
            + growth;
        let sigops = self.sigops
            + members
                .iter()
                .map(|entry| u64::from(entry.sigop_cost))
                .sum::<u64>();
        (weight <= self.context.max_weight
            && size <= self.context.max_size
            && sigops <= self.context.max_sigops)
            .then_some((weight, size, sigops))
    }

    fn take(&mut self, run: &Run) {
        let (weight, size, sigops) = self.grown_by(run).expect("the run fits");
        self.weight = weight;
        self.size = size;
        self.sigops = sigops;
        for position in run.start..run.end {
            self.taken[position] = true;
            self.order.push(self.entries[position].txid);
            self.fees += self.entries[position].fee;
        }
    }
}

fn oracle(
    context: &CandidateContext,
    pool: &Mempool,
    reservation: Reservation,
) -> (Vec<Txid>, u64) {
    let snapshot = pool.mining_snapshot();
    let mut oracle = Oracle {
        context,
        entries: &snapshot.entries,
        charged: snapshot
            .entries
            .iter()
            .map(|entry| {
                pool.entry_by_txid(&entry.txid)
                    .expect("snapshot entry is pooled")
                    .policy_weight()
            })
            .collect(),
        pooled: snapshot.entries.iter().map(|entry| entry.txid).collect(),
        taken: vec![false; snapshot.entries.len()],
        order: Vec::new(),
        fees: 0,
        weight: reservation.weight,
        size: reservation.size,
        sigops: reservation.sigops,
    };

    let mut runs: Vec<Run> = Vec::new();
    let mut start = 0_usize;
    for chunk in pool.chunks_by_feerate() {
        let run = start..start + chunk.len();
        assert_eq!(
            chunk.modified_fee,
            oracle.modified_fee(&run),
            "indexed chunk fee equals its member sums"
        );
        assert_eq!(
            chunk.charged_weight,
            oracle.charged_weight(&run),
            "indexed chunk weight equals its member sums"
        );
        start = run.end;
        runs.push(run);
    }
    assert_eq!(
        start,
        snapshot.entries.len(),
        "chunks partition the snapshot"
    );

    let mut skipped: Vec<Run> = Vec::new();
    for run in runs {
        if !oracle.pays_block_min_fee(&run) {
            break;
        }
        if oracle.blocked(&run) || !oracle.is_final(&run) {
            continue;
        }
        if oracle.grown_by(&run).is_none() {
            skipped.push(run);
            continue;
        }
        oracle.take(&run);
    }
    for run in skipped {
        let longest = (1..=run.len())
            .rev()
            .map(|len| run.start..run.start + len)
            .find(|prefix| {
                oracle.pays_block_min_fee(prefix)
                    && !oracle.blocked(prefix)
                    && oracle.grown_by(prefix).is_some()
            });
        if let Some(prefix) = longest {
            oracle.take(&prefix);
        }
    }
    (oracle.order, oracle.fees)
}

#[derive(Clone, Copy, Debug)]
struct Spec {
    parent: Option<usize>,
    fee: u64,
    weight: u64,
    exact_vsize: bool,
    size: u32,
    sigops: u32,
    non_final_locktime: bool,
    lock_kind: u8,
    delta: i64,
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        prop::option::of(0_usize..24),
        prop_oneof![3 => 5_000_u64..60_000, 1 => Just(0_u64)],
        prop::sample::select(vec![400_u64, 800, 2_000, 8_000, 401, 1_997, 2_001]),
        any::<bool>(),
        prop::sample::select(vec![100_u32, 200, 1_000]),
        0_u32..40,
        0_u8..6,
        0_u8..4,
        prop::sample::select(vec![0_i64, 0, 0, -4_000, -2_000, 3_000, 90_000, -65_000]),
    )
        .prop_map(
            |(parent, fee, weight, exact_vsize, size, sigops, locktime, lock_kind, delta)| Spec {
                parent,
                fee,
                weight,
                exact_vsize,
                size,
                sigops,
                non_final_locktime: locktime == 0,
                lock_kind,
                delta,
            },
        )
}

fn spec_tx(label: u8, parent: Option<Txid>, spec: &Spec) -> Tx {
    let mut transaction = tx(label, 1_000, parent);
    if let Some(parent) = parent {
        for input in &mut transaction.inputs {
            input.previous_output = OutPoint::new(parent, u32::from(label));
        }
    }
    let sequence = match spec.lock_kind {
        1 => Sequence::from_consensus(1),
        2 => Sequence::from_consensus(0x8000_0005),
        _ => Sequence::MAX,
    };
    for input in &mut transaction.inputs {
        input.sequence = sequence;
    }
    if spec.non_final_locktime {
        transaction.lock_time = LockTime::from_consensus(NON_FINAL_LOCKTIME);
        for input in &mut transaction.inputs {
            if input.sequence == Sequence::MAX {
                input.sequence = Sequence::from_consensus(0xFFFF_FFFE);
            }
        }
    }
    transaction
}

fn build_pool(specs: &[Spec]) -> Mempool {
    let mut pool = zero_fee_pool();
    let mut txids: Vec<Txid> = Vec::new();
    for (index, spec) in specs.iter().enumerate() {
        let label = u8::try_from(index).expect("at most 24 specs");
        let parent = spec
            .parent
            .filter(|_| index > 0)
            .map(|choice| txids[choice % index]);
        let transaction = spec_tx(label, parent, spec);
        txids.push(transaction.txid());
        let forged = Forged::new(spec.fee, spec.weight, spec.size).with_sigops(spec.sigops);
        let forged = if spec.exact_vsize {
            let vsize = u32::try_from(spec.weight.div_ceil(4)).expect("weight fits vsize");
            forged.with_vsize(vsize)
        } else {
            forged
        };
        insert_forged(&mut pool, transaction, forged)
            .expect("generated entries stay inside admission limits");
    }
    for (txid, spec) in txids.iter().zip(specs) {
        if spec.delta != 0 {
            pool.prioritise(*txid, spec.delta)
                .expect("overlay stays inside i64");
        }
    }
    pool
}

proptest! {
    #[test]
    fn indexed_selection_matches_the_independent_oracle(
        specs in prop::collection::vec(spec(), 1..24),
        csv_active in any::<bool>(),
        weight_extra in prop::sample::select(vec![0_u64, 500, 1_200, 3_000, 20_000, 3_000_000]),
        size_extra in prop::sample::select(vec![0_u64, 150, 400, 1_500, 10_000, 3_000_000]),
        sigop_extra in prop::sample::select(vec![0_u64, 20, 60, 400, 70_000]),
    ) {
        let pool = build_pool(&specs);
        let base = CandidateContext { csv_active, ..context() };
        let reservation = Reservation::of(&base);
        let limited = CandidateContext {
            max_weight: reservation.weight + weight_extra,
            max_size: reservation.size + size_extra,
            max_sigops: reservation.sigops + sigop_extra,
            ..base
        };
        let candidate = assemble_candidate(&limited, &pool, PAYOUT)
            .expect("limits cover the reservation");
        let (order, fees) = oracle(&limited, &pool, reservation);
        prop_assert_eq!(selected(&candidate), order);
        prop_assert_eq!(selected_fees(&candidate), fees);
    }
}

#[test]
fn skipped_ancestor_chunk_blocks_a_later_descendant_chunk() {
    let mut pool = zero_fee_pool();
    let a = tx(1, 1_000, None);
    let b = tx(2, 1_000, None);
    let c = tx(3, 1_000, Some(b.txid()));
    let d = tx(4, 1_000, Some(c.txid()));
    let a_txid = a.txid();
    insert_forged(&mut pool, a, Forged::new(10_000, 400, 100)).expect("A admits");
    insert_forged(&mut pool, b, Forged::new(100, 20_000, 100)).expect("B admits");
    insert_forged(&mut pool, c, Forged::new(50_000, 400, 100)).expect("C admits");
    insert_forged(&mut pool, d, Forged::new(10, 400, 100)).expect("D admits");

    let base = context();
    let reservation = Reservation::of(&base);
    let limited = CandidateContext {
        max_weight: reservation.weight + 2_000,
        ..base
    };
    let candidate = assemble_candidate(&limited, &pool, PAYOUT).expect("template");
    assert_eq!(selected(&candidate), vec![a_txid]);
    assert_eq!(oracle(&limited, &pool, reservation).0, vec![a_txid]);
}

#[test]
fn overlays_rank_by_modified_fee_and_pay_actual_fees() {
    let mut pool = zero_fee_pool();
    let dear = tx(1, 1_000, None);
    let cheap = tx(2, 1_000, None);
    let mid = tx(3, 1_000, None);
    let (dear_txid, cheap_txid, mid_txid) = (dear.txid(), cheap.txid(), mid.txid());
    insert_forged(&mut pool, dear, Forged::new(9_000, 400, 100)).expect("dear admits");
    insert_forged(&mut pool, cheap, Forged::new(1_000, 400, 100)).expect("cheap admits");
    insert_forged(&mut pool, mid, Forged::new(5_000, 400, 100)).expect("mid admits");
    pool.prioritise(cheap_txid, 20_000)
        .expect("positive overlay applies");
    pool.prioritise(dear_txid, -6_000)
        .expect("negative overlay applies");

    let base = context();
    let reservation = Reservation::of(&base);
    let candidate = assemble_candidate(&base, &pool, PAYOUT).expect("template");
    assert_eq!(selected(&candidate), vec![cheap_txid, mid_txid, dear_txid]);
    assert_eq!(selected_fees(&candidate), 15_000);
    let (order, fees) = oracle(&base, &pool, reservation);
    assert_eq!(order, selected(&candidate));
    assert_eq!(fees, 15_000);
}

fn exact(fee: u64, weight: u64) -> Forged {
    let vsize = u32::try_from(weight.div_ceil(4)).expect("test weight fits vsize");
    Forged::new(fee, weight, vsize).with_vsize(vsize)
}

#[test]
fn aggregate_floor_rescues_a_zero_fee_parent_and_ends_the_walk() {
    let mut pool = zero_fee_pool();
    let parent = tx(1, 1_000, None);
    let child = tx(2, 1_000, Some(parent.txid()));
    let idle = tx(3, 1_000, None);
    let (parent_txid, child_txid) = (parent.txid(), child.txid());
    insert_forged(&mut pool, parent, exact(0, 400)).expect("parent admits");
    insert_forged(&mut pool, child, exact(5_000, 400)).expect("child admits");
    insert_forged(&mut pool, idle, exact(0, 400)).expect("idle admits");

    let base = context();
    let reservation = Reservation::of(&base);
    let candidate = assemble_candidate(&base, &pool, PAYOUT).expect("template");
    assert_eq!(selected(&candidate), vec![parent_txid, child_txid]);
    assert_eq!(selected_fees(&candidate), 5_000);
    let (order, fees) = oracle(&base, &pool, reservation);
    assert_eq!(order, selected(&candidate));
    assert_eq!(fees, 5_000);
}

#[test]
fn tail_prefix_meets_the_minimum_on_exactly_rounded_aggregate_weight() {
    let mut pool = zero_fee_pool();
    let parent = tx(1, 1_000, None);
    let middle = tx(2, 1_000, Some(parent.txid()));
    let last = tx(3, 1_000, Some(middle.txid()));
    let (parent_txid, middle_txid) = (parent.txid(), middle.txid());
    insert_forged(&mut pool, parent, exact(0, 1_997)).expect("parent admits");
    insert_forged(&mut pool, middle, exact(1, 2_001)).expect("middle admits");
    insert_forged(&mut pool, last, exact(10_000, 5_000)).expect("last admits");
    assert_eq!(
        pool.chunks_by_feerate().count(),
        1,
        "increasing fees keep the chain in one chunk"
    );

    let base = context();
    let reservation = Reservation::of(&base);
    let limited = CandidateContext {
        max_weight: reservation.weight + 5_000,
        ..base
    };
    let candidate = assemble_candidate(&limited, &pool, PAYOUT).expect("template");
    assert_eq!(selected(&candidate), vec![parent_txid, middle_txid]);
    assert_eq!(selected_fees(&candidate), 1);
    let (order, fees) = oracle(&limited, &pool, reservation);
    assert_eq!(order, selected(&candidate));
    assert_eq!(fees, 1);
}

#[test]
fn tail_prefix_that_misses_the_minimum_is_not_selected() {
    let mut pool = zero_fee_pool();
    let parent = tx(1, 1_000, None);
    let child = tx(2, 1_000, Some(parent.txid()));
    insert_forged(&mut pool, parent, exact(0, 400)).expect("parent admits");
    insert_forged(&mut pool, child, exact(100_000, 1_000)).expect("child admits");
    assert_eq!(
        pool.chunks_by_feerate().count(),
        1,
        "the child's rate merges the pair into one chunk"
    );

    let base = context();
    let reservation = Reservation::of(&base);
    let limited = CandidateContext {
        max_weight: reservation.weight + 900,
        ..base
    };
    let candidate = assemble_candidate(&limited, &pool, PAYOUT).expect("template");
    let empty: [Txid; 0] = [];
    assert_eq!(selected(&candidate), empty);
    let (order, fees) = oracle(&limited, &pool, reservation);
    assert_eq!(order, empty);
    assert_eq!(fees, 0);
}
