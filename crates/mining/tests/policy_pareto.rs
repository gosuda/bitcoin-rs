#![allow(clippy::expect_used)]
//! Package selection, limits, and adversarial candidate tests.

#[path = "support/fixtures.rs"]
mod common;

use std::collections::{HashMap, HashSet};
use std::error::Error;

use bitcoin_rs_mempool::{ChunkView, EntryId, Mempool};
use bitcoin_rs_mining::{
    Candidate, CandidateContext, MiningError, assemble_candidate, select_template_body,
    select_template_body_after,
};
use bitcoin_rs_primitives::{Block, Hash256, Header, LockTime, Network, Sequence, Txid};
use common::{
    Forged, PAYOUT, insert, insert_forged, selected_fees, serialized_size, total_sigop_cost, tx,
    zero_fee_pool,
};
use proptest::prelude::*;

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xcd; 32]),
        ..common::context()
    }
}

fn limits(max_weight: u64, max_size: u64, max_sigops: u64) -> CandidateContext {
    CandidateContext {
        max_weight,
        max_size,
        max_sigops,
        ..context()
    }
}

fn selected(candidate: &Candidate) -> Vec<Txid> {
    candidate.transactions.iter().map(|tx| tx.txid).collect()
}

#[test]
fn selects_independent_transactions_in_modified_fee_order() -> Result<(), Box<dyn Error>> {
    let mut mempool = zero_fee_pool();
    for index in 0_u32..50 {
        let fee = u64::from(50_u32 - index) * 1_000;
        insert(
            &mut mempool,
            tx(u8::try_from(index)?, 1_000, None),
            100 + (index % 5),
            fee,
            u64::from(index),
            800_000,
        )?;
    }

    let snapshot = mempool.mining_snapshot();
    let candidate = assemble_candidate(&context(), &mempool, PAYOUT)?;
    assert_eq!(candidate.transactions.len(), 50);

    // Pool index order is authoritative; the candidate must preserve package
    // order from walking that priority index.
    assert_eq!(
        selected(&candidate),
        snapshot
            .entries
            .iter()
            .map(|entry| entry.txid)
            .collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn package_selection_is_dependency_closed_and_topological() -> Result<(), Box<dyn Error>> {
    let mut mempool = zero_fee_pool();
    let parent = tx(1, 50_000, None);
    let parent_txid = parent.txid();
    insert(&mut mempool, parent, 200, 1_000, 1, 100)?;
    // High-fee child should outrank the parent individually and pull it in.
    insert(
        &mut mempool,
        tx(2, 40_000, Some(parent_txid)),
        200,
        10_000,
        2,
        100,
    )?;

    let candidate = assemble_candidate(&context(), &mempool, PAYOUT)?;
    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(candidate.transactions[0].txid, parent_txid);
    assert_eq!(candidate.transactions[1].depends, vec![1]);
    assert_eq!(selected_fees(&candidate), 11_000);
    Ok(())
}

#[test]
fn modified_fees_rank_but_actual_fees_fund_coinbase() -> Result<(), Box<dyn Error>> {
    let mut mempool = zero_fee_pool();
    let low = tx(1, 1_000, None);
    let low_txid = low.txid();
    insert(&mut mempool, low, 200, 1_000, 1, 100)?;
    insert(&mut mempool, tx(2, 1_000, None), 200, 2_000, 2, 100)?;
    mempool.prioritise(low_txid, 10_000)?;

    let snapshot = mempool.mining_snapshot();
    assert_eq!(snapshot.entries[0].txid, low_txid);

    let candidate = assemble_candidate(&context(), &mempool, PAYOUT)?;
    assert_eq!(candidate.transactions[0].txid, low_txid);
    assert_eq!(candidate.transactions[0].fee, 1_000);
    assert_eq!(selected_fees(&candidate), 3_000);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(100, Network::Regtest.subsidy_halving_interval())
            + 3_000
    );
    Ok(())
}

#[test]
fn weight_size_and_sigop_limits_are_independent() -> Result<(), Box<dyn Error>> {
    // Each oversized entry exceeds exactly one dimension of its own context.
    // Forged weight/size override the wire numbers; vsize stays 100 so the
    // oversized entry still ranks first and is skipped atomically.
    let cases = [
        (
            1_u8,
            10_000_u64,
            100_u32,
            0_u32,
            limits(2_000, 4_000_000, 80_000),
        ),
        (
            2_u8,
            100_u64,
            10_000_u32,
            0_u32,
            limits(4_000_000, 2_000, 80_000),
        ),
        (
            3_u8,
            100_u64,
            100_u32,
            10_000_u32,
            limits(4_000_000, 4_000_000, 100),
        ),
    ];
    for (label, weight, size, sigop_cost, context) in cases {
        let mut pool = zero_fee_pool();
        insert_forged(
            &mut pool,
            tx(label, 1_000, None),
            Forged::new(5_000, weight, size).with_sigops(sigop_cost),
        )?;
        let fitting = tx(4, 1_000, None);
        let fitting_txid = fitting.txid();
        insert_forged(
            &mut pool,
            fitting,
            Forged::new(1_000, 100, 100).with_sigops(1),
        )?;
        let candidate = assemble_candidate(&context, &pool, PAYOUT)?;
        assert_eq!(selected(&candidate), vec![fitting_txid]);
    }
    Ok(())
}

// POL-05/06: one chunk is indivisible, and its positive unconfirmed BIP68
// lock is not final at the next block. The valid parent cannot be retried
// separately after the whole child-parent chunk is skipped; with CSV inactive
// the same lock is ignored and the chunk is selected whole.
#[test]
fn unconfirmed_bip68_lock_skips_its_whole_chunk_only_while_csv_is_active()
-> Result<(), Box<dyn Error>> {
    for (csv_active, expected) in [(true, 0), (false, 2)] {
        let mut pool = zero_fee_pool();
        let parent_tx = tx(1, 1_000, None);
        let parent_txid = parent_tx.txid();
        insert_forged(&mut pool, parent_tx, Forged::new(1_000, 400, 100))?;
        let mut child_tx = tx(2, 1_000, Some(parent_txid));
        child_tx.inputs[0].sequence = Sequence::from_consensus(1);
        insert_forged(&mut pool, child_tx, Forged::new(10_000, 400, 100))?;
        let candidate = assemble_candidate(
            &CandidateContext {
                csv_active,
                ..context()
            },
            &pool,
            PAYOUT,
        )?;
        assert_eq!(
            candidate.transactions.len(),
            expected,
            "csv_active={csv_active} must select {expected} transactions"
        );
    }
    Ok(())
}

// POL-05: CandidateContext resource limits apply to a complete chunk.
// Exact configured limits fit; one excess unit skips both child and parent.
// Core 31.1 node/miner.cpp::addChunks likewise skips the whole chunk after
// its limit check, rather than extracting a parent from the failed chunk.
#[test]
fn exact_resource_limits_accept_dependency_closed_package() -> Result<(), Box<dyn Error>> {
    let empty = zero_fee_pool();
    let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;

    let parent_txid = tx(1, 1_000, None).txid();
    let child_txid = tx(2, 1_000, Some(parent_txid)).txid();
    let exact_limits = limits(
        reservation.weight + 100,
        serialized_size(&reservation) + 100,
        total_sigop_cost(&reservation) + 10,
    );

    let mut pool = zero_fee_pool();
    insert_forged(
        &mut pool,
        tx(1, 1_000, None),
        Forged::new(1_000, 40, 40).with_vsize(40).with_sigops(4),
    )?;
    insert_forged(
        &mut pool,
        tx(2, 1_000, Some(parent_txid)),
        Forged::new(10_000, 60, 60).with_vsize(60).with_sigops(6),
    )?;
    let exact = assemble_candidate(&exact_limits, &pool, PAYOUT)?;
    assert_eq!(selected(&exact), vec![parent_txid, child_txid]);
    assert_eq!(exact.weight, exact_limits.max_weight);

    // Step 20 tail fill: one excess unit skips the whole 2-transaction chunk in
    // the main walk, but the fitting parent prefix fills the tail. The parent
    // alone (40 WU / 40 B / 4 sigops, modified rate far above 1 sat/kvB) fits
    // exactly in the 100-unit budget, so each over-limit chunk yields [parent].
    for (weight, size, sigop_cost) in [(61_u64, 60_u32, 6_u32), (60, 61, 6), (60, 60, 7)] {
        let mut over = zero_fee_pool();
        insert_forged(
            &mut over,
            tx(1, 1_000, None),
            Forged::new(1_000, 40, 40).with_vsize(40).with_sigops(4),
        )?;
        insert_forged(
            &mut over,
            tx(2, 1_000, Some(parent_txid)),
            Forged::new(10_000, weight, size)
                .with_vsize(60)
                .with_sigops(sigop_cost),
        )?;
        let candidate = assemble_candidate(&exact_limits, &over, PAYOUT)?;
        assert_eq!(
            selected(&candidate),
            vec![parent_txid],
            "one excess unit must skip the whole chunk and fill the tail with its parent prefix"
        );
    }
    Ok(())
}

#[test]
fn coinbase_reservation_accepts_exact_limits_and_rejects_one_over() -> Result<(), Box<dyn Error>> {
    let payout = vec![0xac];
    let empty = zero_fee_pool();
    let reservation = assemble_candidate(&context(), &empty, &payout)?;
    assert!(reservation.weight > 0);
    assert!(serialized_size(&reservation) > 0);
    assert!(total_sigop_cost(&reservation) > 0);

    let exact_limits = limits(
        reservation.weight,
        serialized_size(&reservation),
        total_sigop_cost(&reservation),
    );
    let exact = assemble_candidate(&exact_limits, &empty, &payout)?;
    assert_eq!(exact.weight, exact_limits.max_weight);

    let one_over = [
        (
            "weight",
            limits(
                reservation.weight - 1,
                serialized_size(&reservation),
                total_sigop_cost(&reservation),
            ),
        ),
        (
            "size",
            limits(
                reservation.weight,
                serialized_size(&reservation) - 1,
                total_sigop_cost(&reservation),
            ),
        ),
        (
            "sigops",
            limits(
                reservation.weight,
                serialized_size(&reservation),
                total_sigop_cost(&reservation) - 1,
            ),
        ),
    ];
    for (field, context) in one_over {
        assert!(matches!(
            assemble_candidate(&context, &empty, &payout),
            Err(MiningError::CapacityExhausted { field: actual }) if actual == field
        ));
    }
    Ok(())
}

#[test]
fn non_final_packages_are_skipped() -> Result<(), Box<dyn Error>> {
    let mut non_final = tx(2, 1_000, None);
    non_final.lock_time = LockTime::from_consensus(500_000_100);
    for input in &mut non_final.inputs {
        input.sequence = Sequence::ZERO;
    }

    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, non_final, Forged::new(9_000, 400, 100))?;
    insert_forged(&mut pool, tx(1, 1_000, None), Forged::new(1_000, 400, 100))?;
    let candidate = assemble_candidate(
        &CandidateContext {
            locktime_cutoff: 500_000_000,
            ..context()
        },
        &pool,
        PAYOUT,
    )?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(selected_fees(&candidate), 1_000);
    Ok(())
}

#[test]
fn oversized_residual_package_is_skipped_atomically() -> Result<(), Box<dyn Error>> {
    // Coinbase reservation is ~476 WU with the default payout+commitment. Choose
    // limits so parent alone and parent+child both overflow, while `other` fits.
    let parent_txid = tx(1, 1_000, None).txid();
    let mut child_tx = tx(2, 1_000, Some(parent_txid));
    child_tx.lock_time = LockTime::ZERO;
    let other_txid = tx(3, 1_000, None).txid();

    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, tx(1, 1_000, None), Forged::new(100, 99_600, 100))?;
    insert_forged(&mut pool, child_tx, Forged::new(10_000, 20_000, 100))?;
    insert_forged(&mut pool, tx(3, 1_000, None), Forged::new(1_000, 400, 100))?;

    let candidate = assemble_candidate(&limits(100_000, 4_000_000, 80_000), &pool, PAYOUT)?;
    assert_eq!(selected(&candidate), vec![other_txid]);
    Ok(())
}

/// Once a positive dimension is exactly full, later packages are skipped.
/// Limits add the filler's forged 1,000 to the empty candidate's weight or
/// serialized size (the candidate already counts the transaction-count byte),
/// so the filler fills one dimension exactly and the leftover cannot fit.
#[test]
fn stops_candidate_package_construction_once_a_positive_dimension_is_full()
-> Result<(), Box<dyn Error>> {
    let empty = zero_fee_pool();
    let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
    for context in [
        limits(reservation.weight + 1_000, 4_000_000, 80_000),
        limits(4_000_000, serialized_size(&reservation) + 1_000, 80_000),
    ] {
        let mut pool = zero_fee_pool();
        insert_forged(
            &mut pool,
            tx(1, 1_000, None),
            Forged::new(5_000_000, 1_000, 1_000).with_vsize(1_000),
        )?;
        insert_forged(
            &mut pool,
            tx(2, 1_000, None),
            Forged::new(4_000, 10, 10).with_vsize(10),
        )?;
        let candidate = assemble_candidate(&context, &pool, PAYOUT)?;
        assert_eq!(candidate.transactions.len(), 1);
        assert_eq!(candidate.transactions[0].fee, 5_000_000);
    }
    Ok(())
}

/// Even an empty body needs one byte to encode its reserved coinbase count.
#[test]
fn transaction_count_reservation_rejects_zero_size_capacity() {
    let pool = zero_fee_pool();
    assert!(matches!(
        assemble_candidate(&limits(4_000_000, 0, 80_000), &pool, PAYOUT),
        Err(MiningError::CapacityExhausted { field: actual }) if actual == "size"
    ));
}

// Step 20 helpers: forged facts whose charged weight equals the wire weight,
// so the prefix rate denominator is unambiguous without a private accessor.
// `vsize` is set to `weight.div_ceil(4)` and `size` to the same vbytes, which
// keeps the size dimension non-binding unless a test tightens it.
fn consistent(fee: u64, weight: u64) -> Forged {
    let vsize = u32::try_from(weight.div_ceil(4)).expect("test weight fits vsize");
    Forged::new(fee, weight, vsize).with_vsize(vsize)
}

fn compact_len(total: usize) -> u64 {
    if total < 253 {
        1
    } else if total < 65_536 {
        3
    } else if total < 4_294_967_296 {
        5
    } else {
        9
    }
}

fn chunk_has_missing_ancestor(chunk: &ChunkView<'_>, selected: &HashSet<EntryId>) -> bool {
    for member in chunk.members {
        for parent in chunk.parents_of(*member) {
            if !selected.contains(&parent) && !chunk.members.contains(&parent) {
                return true;
            }
        }
    }
    false
}

// Whole-chunk-only oracle for the tail proptest: the main walk without any
// tail pass. It walks the maintained index in order, stops at the first chunk
// below the 1 sat/kvB aggregate floor, skips chunks with an unselected outside
// ancestor, and skips chunks that would overflow weight/size/sigops including
// CompactSize count growth. Fixtures are always final, so finality passes.
fn whole_chunk_oracle_fees(
    pool: &Mempool,
    ctx: &CandidateContext,
    res_weight: u64,
    res_size: u64,
    res_sigops: u64,
) -> u64 {
    let mut selected: HashSet<EntryId> = HashSet::new();
    let mut ordered_len = 0_usize;
    let mut used_weight = res_weight;
    let mut used_size = res_size;
    let mut used_sigops = res_sigops;
    let mut fees = 0_u64;
    for chunk in pool.chunks_by_feerate() {
        let vsize = chunk.charged_weight.div_ceil(4);
        if vsize == 0 {
            break;
        }
        let rate = (chunk.modified_fee * 1_000).div_euclid(i128::from(vsize));
        if rate < 1 {
            break;
        }
        if chunk_has_missing_ancestor(&chunk, &selected) {
            continue;
        }
        let mut sum_weight = 0_u64;
        let mut sum_size = 0_u64;
        let mut sum_sigops = 0_u64;
        let mut sum_fees = 0_u64;
        for (_, entry) in chunk.entries() {
            sum_weight = sum_weight.saturating_add(entry.weight);
            sum_size = sum_size.saturating_add(u64::from(entry.size));
            sum_sigops = sum_sigops.saturating_add(u64::from(entry.sigop_cost));
            sum_fees = sum_fees.saturating_add(entry.fee);
        }
        let next_len = ordered_len.saturating_add(chunk.len());
        let growth = compact_len(1_usize.saturating_add(next_len))
            .saturating_sub(compact_len(1_usize.saturating_add(ordered_len)));
        let next_weight = used_weight
            .saturating_add(sum_weight)
            .saturating_add(growth.saturating_mul(4));
        let next_size = used_size.saturating_add(sum_size).saturating_add(growth);
        let next_sigops = used_sigops.saturating_add(sum_sigops);
        if next_weight > ctx.max_weight || next_size > ctx.max_size || next_sigops > ctx.max_sigops
        {
            continue;
        }
        for member in chunk.members {
            selected.insert(*member);
        }
        ordered_len = next_len;
        used_weight = next_weight;
        used_size = next_size;
        used_sigops = next_sigops;
        fees = fees.saturating_add(sum_fees);
    }
    fees
}

fn candidate_positions(candidate: &Candidate) -> HashMap<Txid, usize> {
    let mut positions = HashMap::new();
    for (index, tx) in candidate.transactions.iter().enumerate() {
        positions.insert(tx.txid, index);
    }
    positions
}

// Step 20: a standalone negative-modified-fee chunk is absent while the same
// size positive chunk is present. The negative chunk sorts last and stops the
// walk; the positive chunk is selected and its actual fee funds the coinbase.
#[test]
fn negative_modified_fee_standalone_chunk_is_excluded_while_same_size_positive_is_included()
-> Result<(), Box<dyn Error>> {
    let mut pool = zero_fee_pool();
    let negative = tx(10, 1_000, None);
    let negative_txid = negative.txid();
    insert_forged(&mut pool, negative, consistent(5_000, 400))?;
    let positive = tx(11, 1_000, None);
    let positive_txid = positive.txid();
    insert_forged(&mut pool, positive, consistent(5_000, 400))?;
    pool.prioritise(negative_txid, -10_000)?;

    let candidate = assemble_candidate(&context(), &pool, PAYOUT)?;
    assert_eq!(selected(&candidate), vec![positive_txid]);
    assert_eq!(selected_fees(&candidate), 5_000);
    Ok(())
}

// Step 20: a two-transaction chunk whose aggregate modified fee is negative is
// excluded as a whole, while the same shape with positive fees is included.
#[test]
fn negative_modified_fee_chunk_is_excluded_as_a_whole() -> Result<(), Box<dyn Error>> {
    let parent_txid = tx(12, 1_000, None).txid();
    let child_txid = tx(13, 1_000, Some(parent_txid)).txid();

    let mut negative = zero_fee_pool();
    insert_forged(&mut negative, tx(12, 1_000, None), consistent(1_000, 400))?;
    insert_forged(
        &mut negative,
        tx(13, 1_000, Some(parent_txid)),
        consistent(1_000, 400),
    )?;
    negative.prioritise(parent_txid, -5_000)?;
    let excluded = assemble_candidate(&context(), &negative, PAYOUT)?;
    assert!(
        excluded.transactions.is_empty(),
        "negative aggregate chunk must be absent"
    );

    let mut positive = zero_fee_pool();
    insert_forged(&mut positive, tx(12, 1_000, None), consistent(1_000, 400))?;
    insert_forged(
        &mut positive,
        tx(13, 1_000, Some(parent_txid)),
        consistent(1_000, 400),
    )?;
    let included = assemble_candidate(&context(), &positive, PAYOUT)?;
    assert_eq!(selected(&included), vec![parent_txid, child_txid]);
    Ok(())
}

// Step 20: aggregation, not per-transaction rates. A zero-fee parent alone is
// below the floor and absent, but the same parent with a high-fee child forms
// one chunk whose aggregate rate passes and both are selected parent-first.
#[test]
fn zero_fee_parent_is_rescued_by_child_aggregate() -> Result<(), Box<dyn Error>> {
    let parent_txid = tx(14, 1_000, None).txid();
    let child_txid = tx(15, 1_000, Some(parent_txid)).txid();

    let mut alone = zero_fee_pool();
    insert_forged(&mut alone, tx(14, 1_000, None), consistent(0, 400))?;
    let excluded = assemble_candidate(&context(), &alone, PAYOUT)?;
    assert!(
        excluded.transactions.is_empty(),
        "zero-fee standalone chunk must be absent"
    );

    let mut rescued = zero_fee_pool();
    insert_forged(&mut rescued, tx(14, 1_000, None), consistent(0, 400))?;
    insert_forged(
        &mut rescued,
        tx(15, 1_000, Some(parent_txid)),
        consistent(5_000, 400),
    )?;
    let candidate = assemble_candidate(&context(), &rescued, PAYOUT)?;
    assert_eq!(selected(&candidate), vec![parent_txid, child_txid]);
    assert_eq!(selected_fees(&candidate), 5_000);
    Ok(())
}

// Step 20: a negative-modified parent is rescued when the child fees carry the
// chunk aggregate above the floor. The parent alone would stop the walk.
#[test]
fn negative_modified_parent_is_rescued_by_child_fees() -> Result<(), Box<dyn Error>> {
    let parent_txid = tx(16, 1_000, None).txid();
    let child_txid = tx(17, 1_000, Some(parent_txid)).txid();

    let mut alone = zero_fee_pool();
    insert_forged(&mut alone, tx(16, 1_000, None), consistent(1_000, 400))?;
    alone.prioritise(parent_txid, -2_000)?;
    let excluded = assemble_candidate(&context(), &alone, PAYOUT)?;
    assert!(
        excluded.transactions.is_empty(),
        "negative standalone parent must be absent"
    );

    let mut rescued = zero_fee_pool();
    insert_forged(&mut rescued, tx(16, 1_000, None), consistent(1_000, 400))?;
    insert_forged(
        &mut rescued,
        tx(17, 1_000, Some(parent_txid)),
        consistent(10_000, 400),
    )?;
    rescued.prioritise(parent_txid, -2_000)?;
    let candidate = assemble_candidate(&context(), &rescued, PAYOUT)?;
    assert_eq!(selected(&candidate), vec![parent_txid, child_txid]);
    assert_eq!(selected_fees(&candidate), 11_000);
    Ok(())
}

// Step 20: the required tail shape. A 1,200 WU parent-child chunk does not fit
// in 1,000 WU remaining, so the main walk skips it whole and the tail fills
// the 600 WU parent prefix. Both rates are far above the floor.
#[test]
fn tail_fills_weight_with_prefix_of_skipped_chunk() -> Result<(), Box<dyn Error>> {
    let empty = zero_fee_pool();
    let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
    let ctx = limits(reservation.weight + 1_000, 4_000_000, 80_000);

    let parent_txid = tx(18, 1_000, None).txid();
    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, tx(18, 1_000, None), consistent(10_000, 600))?;
    insert_forged(
        &mut pool,
        tx(19, 1_000, Some(parent_txid)),
        consistent(10_000, 600),
    )?;

    let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
    assert_eq!(selected(&candidate), vec![parent_txid]);
    assert_eq!(selected_fees(&candidate), 10_000);
    assert_eq!(candidate.weight, reservation.weight + 600);
    Ok(())
}

// Step 20: prefix rates sum exact charged weights once, then round. Parent
// 1,997 WU (vsize 500) plus child 2,001 WU (vsize 501) charge 3,998 WU, whose
// ceiling is 1,000 vB; a 1 sat aggregate therefore meets the floor. Summing
// rounded vsizes gives 1,001 vB and a zero rate, which would wrongly skip the
// prefix. The test chain forces one chunk with increasing fees, overflows the
// whole 8,998 WU chunk in a 5,000 WU budget, and requires the tail to select
// the exact-rounded [parent, child] prefix.
#[test]
fn tail_prefix_rate_uses_exact_charged_weight_not_summed_vsize() -> Result<(), Box<dyn Error>> {
    let empty = zero_fee_pool();
    let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
    let ctx = limits(reservation.weight + 5_000, 4_000_000, 80_000);

    let parent_txid = tx(20, 1_000, None).txid();
    let middle_txid = tx(21, 1_000, Some(parent_txid)).txid();
    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, tx(20, 1_000, None), consistent(0, 1_997))?;
    insert_forged(
        &mut pool,
        tx(21, 1_000, Some(parent_txid)),
        consistent(1, 2_001),
    )?;
    insert_forged(
        &mut pool,
        tx(22, 1_000, Some(middle_txid)),
        consistent(10_000, 5_000),
    )?;

    let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
    assert_eq!(selected(&candidate), vec![parent_txid, middle_txid]);
    assert_eq!(selected_fees(&candidate), 1);
    Ok(())
}

// Step 20: parent closure for the tail. The 1,200 WU parent does not fit in
// 1,000 WU remaining, so its chunk is not even recorded (no prefix could fit)
// and the fitting child that spends it stays unavailable.
#[test]
fn tail_skips_child_when_parent_prefix_cannot_fit() -> Result<(), Box<dyn Error>> {
    let empty = zero_fee_pool();
    let reservation = assemble_candidate(&context(), &empty, PAYOUT)?;
    let ctx = limits(reservation.weight + 1_000, 4_000_000, 80_000);

    let parent_txid = tx(30, 1_000, None).txid();
    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, tx(30, 1_000, None), consistent(20_000, 1_200))?;
    insert_forged(
        &mut pool,
        tx(31, 1_000, Some(parent_txid)),
        consistent(5_000, 400),
    )?;

    let candidate = assemble_candidate(&ctx, &pool, PAYOUT)?;
    assert!(
        candidate.transactions.is_empty(),
        "child must stay unavailable when its parent prefix cannot fit"
    );
    Ok(())
}

// Step 20: finality is not retried in the tail. A low-fee final parent with a
// high-fee future-locktime child forms one non-final chunk (increasing fees
// keep the chain together); the main walk skips it for finality and the tail
// must not rescue the final parent prefix. Equal fees would split the chain
// into a final parent chunk plus a non-final child chunk and select [parent]
// through the main walk instead.
#[test]
fn tail_does_not_rescue_prefix_from_non_final_chunk() -> Result<(), Box<dyn Error>> {
    let parent_txid = tx(40, 1_000, None).txid();
    let mut child = tx(41, 1_000, Some(parent_txid));
    child.lock_time = LockTime::from_consensus(500_000_100);
    for input in &mut child.inputs {
        input.sequence = Sequence::ZERO;
    }

    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, tx(40, 1_000, None), consistent(1_000, 400))?;
    insert_forged(&mut pool, child, consistent(10_000, 400))?;
    let candidate = assemble_candidate(
        &CandidateContext {
            locktime_cutoff: 500_000_000,
            ..context()
        },
        &pool,
        PAYOUT,
    )?;
    assert!(
        candidate.transactions.is_empty(),
        "non-final chunk must stay skipped whole, without tail rescue"
    );
    Ok(())
}

proptest! {
    #[test]
    fn independent_selection_is_deterministic(
        fees in prop::collection::vec(1_000_u64..50_000, 1..30),
    ) {
        let mut pool = zero_fee_pool();
        for (index, fee) in fees.iter().enumerate() {
            // The vec holds at most 30 entries, so the label always fits.
            let label = u8::try_from(index).expect("proptest vec is bounded");
            insert_forged(&mut pool, tx(label, 1_000, None), Forged::new(*fee, 400, 100))
                .expect("pool admits fixture");
        }
        let left = assemble_candidate(&context(), &pool, PAYOUT).expect("left assembly");
        let right = assemble_candidate(&context(), &pool, PAYOUT).expect("right assembly");
        assert_eq!(selected(&left), selected(&right));
        assert_eq!(selected_fees(&left), selected_fees(&right));
        assert_eq!(left.weight, right.weight);
        assert_eq!(
            left.into_unsolved_block()
                .expect("assembly serializes")
                .txs,
            right
                .into_unsolved_block()
                .expect("assembly serializes")
                .txs
        );
        assert_eq!(total_sigop_cost(&left), total_sigop_cost(&right));
        assert_eq!(left.coinbase_value, right.coinbase_value);
    }

    // Step 20: over random small pools under weight pressure, the tail pass
    // only adds transactions. Fees are at least the whole-chunk-only oracle,
    // every in-pool parent precedes its child, and the candidate respects the
    // weight, size, and sigop limits. All fixtures are final, so finality
    // passes and the oracle omits it by construction.
    #[test]
    fn tail_pass_never_loses_fees_and_preserves_invariants(
        inputs in prop::collection::vec(
            (0_u64..20_000, 400_u64..2_000, 0_usize..8, -5_000_i64..5_000),
            1..12,
        ),
    ) {
        let mut pool = zero_fee_pool();
        let mut txids: Vec<Txid> = Vec::new();
        let mut total_weight = 0_u64;
        for (index, (fee, weight, parent_slot, _delta)) in inputs.iter().enumerate() {
            let label = u8::try_from(index).expect("proptest pool is bounded");
            let parent = if index == 0 {
                None
            } else {
                let slot = parent_slot % (index + 1);
                if slot == index {
                    None
                } else {
                    Some(txids[slot % index])
                }
            };
            let built = tx(label, 1_000, parent);
            txids.push(built.txid());
            total_weight = total_weight.saturating_add(*weight);
            insert_forged(&mut pool, built, consistent(*fee, *weight))
                .expect("pool admits fixture");
        }
        for (index, (_, _, _, delta)) in inputs.iter().enumerate() {
            if *delta != 0 {
                pool.prioritise(txids[index], *delta)
                    .expect("prioritise applies");
            }
        }

        let empty = zero_fee_pool();
        let reservation = assemble_candidate(&context(), &empty, PAYOUT)
            .expect("empty reservation assembles");
        let res_size = serialized_size(&reservation);
        let res_sigops = total_sigop_cost(&reservation);
        let ctx = limits(
            reservation.weight.saturating_add(total_weight / 2),
            4_000_000,
            80_000,
        );
        let candidate = assemble_candidate(&ctx, &pool, PAYOUT).expect("candidate assembles");
        let oracle = whole_chunk_oracle_fees(
            &pool,
            &ctx,
            reservation.weight,
            res_size,
            res_sigops,
        );
        prop_assert!(
            selected_fees(&candidate) >= oracle,
            "tail fees {} must cover whole-chunk oracle {oracle}",
            selected_fees(&candidate)
        );
        prop_assert!(candidate.weight <= ctx.max_weight, "weight within limits");
        prop_assert!(
            serialized_size(&candidate) <= ctx.max_size,
            "size within limits"
        );
        prop_assert!(
            total_sigop_cost(&candidate) <= ctx.max_sigops,
            "sigops within limits"
        );
        let positions = candidate_positions(&candidate);
        let selected_set: HashSet<Txid> =
            positions.keys().copied().collect();
        for (index, entry) in candidate.transactions.iter().enumerate() {
            for input in &entry.tx.inputs {
                let parent = input.previous_output.txid;
                if pool.contains_txid(&parent) {
                    prop_assert!(
                        selected_set.contains(&parent),
                        "parent closure holds"
                    );
                    let parent_pos = positions[&parent];
                    prop_assert!(parent_pos < index, "topological order holds");
                }
            }
            for dep in &entry.depends {
                let dep_index = usize::try_from(*dep).expect("depends fits usize");
                prop_assert!(dep_index <= index, "depends precedes child");
            }
        }
    }
}

#[test]
fn projected_selection_treats_staged_parent_as_confirmed_for_bip68() -> Result<(), Box<dyn Error>> {
    let parent_tx = tx(1, 1_000, None);
    let parent_txid = parent_tx.txid();
    let mut child_tx = tx(2, 1_000, Some(parent_txid));
    child_tx.inputs[0].sequence = Sequence::from_consensus(1);
    let child_txid = child_tx.txid();

    let mut pool = zero_fee_pool();
    insert_forged(&mut pool, parent_tx.clone(), Forged::new(1_000, 400, 100))?;
    insert_forged(&mut pool, child_tx, Forged::new(10_000, 400, 100))?;

    let ctx = context();
    let live = select_template_body(&pool, &ctx, PAYOUT, None)?;
    assert!(
        live.transactions.is_empty(),
        "unconfirmed relative lock must skip the whole chunk live"
    );

    let block = Block {
        header: Header::default(),
        txs: vec![parent_tx],
    };
    let plan = pool.plan_block_removals(&block);
    assert_eq!(plan.removals.len(), 1, "staged block must plan the parent");
    let projected = select_template_body_after(&pool, &plan, &ctx, PAYOUT)?;

    pool.remove_for_block(&[&block.txs[0]], &[parent_txid], ctx.height, 0);
    let actual = select_template_body(&pool, &ctx, PAYOUT, None)?;

    let projected_txids: Vec<Txid> = projected
        .transactions
        .iter()
        .map(|entry| entry.txid)
        .collect();
    let actual_txids: Vec<Txid> = actual.transactions.iter().map(|entry| entry.txid).collect();
    assert_eq!(projected_txids, vec![child_txid]);
    assert_eq!(actual_txids, vec![child_txid]);
    assert_eq!(projected.fees, actual.fees);
    assert_eq!(projected.weight, actual.weight);
    Ok(())
}
