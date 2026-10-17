#![expect(
    clippy::expect_used,
    reason = "integration fixtures fail loudly on a broken precondition"
)]
//! Indexed template selection against an independent oracle.
//!
//! `assemble_candidate` walks the pool's maintained chunk index under one
//! guard and checks only direct parents. The oracle below re-derives the same
//! selection from copied facts: the whole-pool snapshot's transitive ancestor
//! positions, its own finality and BIP68 rules, its own limit arithmetic, its
//! own sum-then-round block-minimum-fee test, and its own tail pass over the
//! chunks the walk skipped for resources. It shares only the chunk partition
//! (owned and checked by the mempool's own from-scratch oracle) and the pool's
//! public per-entry charged weight, and it asserts that every chunk's indexed
//! aggregates equal the sums of its members. A divergence therefore names the
//! selection: parent skips, per-chunk finality, weight/size/sigop skips,
//! signed-fee order, the aggregate fee floor, or the prefix tail.

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

/// Locktime above the height threshold: compared with the timestamp cutoff.
const NON_FINAL_LOCKTIME: u32 = 500_000_100;
/// Timestamp cutoff below [`NON_FINAL_LOCKTIME`].
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

/// Header-plus-coinbase numbers an empty template already uses.
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

/// Bytes of the block transaction count for `body` non-coinbase transactions.
fn count_bytes(body: usize) -> u64 {
    match body + 1 {
        0..=252 => 1,
        253..=65_535 => 3,
        _ => 5,
    }
}

/// Oracle finality: absolute locktime against the cutoff, and a positive
/// relative lock on an input whose parent is pooled (the parent confirms in
/// the same next block, so any nonzero lock is unmet).
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

/// Core `DEFAULT_BLOCK_MIN_TX_FEE`: the lowest rate a chunk or chunk prefix
/// may pay, in satoshis per kvB of virtual size.
const BLOCK_MIN_TX_FEE_SAT_PER_KVB: i128 = 1;

/// A run of snapshot positions: one chunk, or a prefix of one.
type Run = Range<usize>;

/// The oracle's body under construction, over the whole-pool snapshot.
struct Oracle<'a> {
    context: &'a CandidateContext,
    entries: &'a [SnapshotEntry],
    /// Policy-charged weight of each snapshot entry (the pool's public
    /// accessor); summed exactly before any rounding.
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
    /// Actual fee plus signed overlay, summed over `run`.
    fn modified_fee(&self, run: &Run) -> i128 {
        self.entries[run.start..run.end]
            .iter()
            .map(|entry| i128::from(entry.fee) + i128::from(entry.fee_delta))
            .sum()
    }

    /// Charged weight summed over `run`.
    fn charged_weight(&self, run: &Run) -> u64 {
        self.charged[run.start..run.end].iter().sum()
    }

    /// Whether `floor(modified_fee * 1000 / vsize) >= BLOCK_MIN_TX_FEE_SAT_PER_KVB`
    /// for the run's summed fee and `vsize = ceil(summed charged weight / 4)`.
    /// For a positive `vsize` and an integer minimum that is
    /// `modified_fee * 1000 >= minimum * vsize`, for negative fees too.
    fn pays_block_min_fee(&self, run: &Run) -> bool {
        let vsize = i128::from(self.charged_weight(run).div_ceil(4));
        self.modified_fee(run) * 1_000 >= BLOCK_MIN_TX_FEE_SAT_PER_KVB * vsize
    }

    /// Whether a transitive ancestor outside `run` is not selected yet.
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

    /// Totals after appending `run`, or `None` when a limit would be passed.
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

    /// Appends `run`, which must have passed [`Self::grown_by`].
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

/// Oracle selection: ordered txids and their actual-fee sum.
///
/// Main walk: chunks in index order; stop at the first chunk whose summed
/// rate is below the block minimum; skip a chunk with an unselected outside
/// ancestor or a non-final member; take a chunk that fits; remember one that
/// does not. Tail pass: for each remembered chunk in index order, take its
/// longest prefix that fits, is final, has its outside ancestors selected, and
/// pays the block minimum as a prefix.
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
    // `skipped` holds only chunks recorded solely because they did not fit:
    // a blocked or non-final chunk never enters, so the tail rechecks neither.
    // A production bug that recorded such a chunk would surface here as an
    // order/fees divergence rather than being masked by a recheck.
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

/// One generated pool entry: tree shape, resources, locks, and overlay.
#[derive(Clone, Copy, Debug)]
struct Spec {
    /// Parent among earlier entries (modulo their count), when any.
    parent: Option<usize>,
    /// Zero reaches the aggregate fee floor; a child's fee can still lift a
    /// zero-fee parent's chunk over it.
    fee: u64,
    weight: u64,
    /// `true`: `vsize = ceil(weight / 4)`, so the charged weight is the exact
    /// (often odd) weight and aggregate rounding differs from per-member
    /// rounding. `false`: the common 100 vB basis.
    exact_vsize: bool,
    size: u32,
    sigops: u32,
    non_final_locktime: bool,
    /// 0/3: final sequence; 1: one-block relative lock; 2: lock disabled.
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

/// Each child spends its own vout of the parent, so no two entries conflict.
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

/// Builds a pool of parent-tree transactions, then applies the overlays.
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
    /// The indexed selection equals the oracle's, in order and in fees, for
    /// pools with chains, forks, non-final locktimes, unmet unconfirmed BIP68
    /// locks, forced weight/size/sigop skips (which feed the prefix tail),
    /// zero-fee members, odd weights whose aggregate rounding differs from
    /// per-member rounding, and negative and positive overlays that put whole
    /// chunks and chunk prefixes below the block minimum fee.
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

/// A skipped chunk blocks its descendants in later chunks: A fits; the
/// B+C chunk is too heavy for the limit and is skipped; D (child of C) would
/// fit by itself but its parent chunk is unselected, so D is skipped too.
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

/// Overlays rank by modified fee while actual fees fund the coinbase: a
/// positive overlay lifts a cheap transaction over a dearer one, and a
/// negative overlay that leaves the modified fee positive drops one below it.
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
    // Modified fees: cheap 21_000, mid 5_000, dear 3_000.
    assert_eq!(selected(&candidate), vec![cheap_txid, mid_txid, dear_txid]);
    assert_eq!(selected_fees(&candidate), 15_000);
    let (order, fees) = oracle(&base, &pool, reservation);
    assert_eq!(order, selected(&candidate));
    assert_eq!(fees, 15_000);
}

/// Forged facts whose charged weight is exactly `weight`: `vsize` is the
/// weight rounded up to whole vbytes, as for a real transaction.
fn exact(fee: u64, weight: u64) -> Forged {
    let vsize = u32::try_from(weight.div_ceil(4)).expect("test weight fits vsize");
    Forged::new(fee, weight, vsize).with_vsize(vsize)
}

/// The block minimum fee applies to a chunk's summed fee, never to one member:
/// a zero-fee parent rides in on its child's fee, while a zero-fee standalone
/// chunk ends the walk.
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

/// Prefix rates sum exact charged weights once, then round. A 1,997 WU parent
/// and a 2,001 WU child charge 3,998 WU together, exactly 1,000 vB, so a
/// 1 sat aggregate meets the 1 sat/kvB minimum; the members' own vsizes
/// (500 + 501) would sum to 1,001 vB and miss it. The whole three-member
/// chunk (8,998 WU) overflows the 5,000 WU budget, so the tail takes the
/// two-member prefix.
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

/// A tail prefix must itself pay the block minimum. The zero-fee parent's
/// prefix fits the 900 WU left, but the chunk's rate comes from the child's
/// fee, which that prefix does not carry.
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
