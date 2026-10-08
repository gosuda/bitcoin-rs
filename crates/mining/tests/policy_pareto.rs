#![allow(clippy::expect_used)]
//! Package selection, limits, and adversarial candidate tests.

#[path = "common/fixtures.rs"]
mod common;

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_mempool::SnapshotEntry;
use bitcoin_rs_mining::{Candidate, CandidateContext, MiningError, assemble_candidate};
use bitcoin_rs_primitives::{Hash256, LockTime, Network, Sequence, Txid};
use common::{PAYOUT, forged_entry, insert, snapshot, tx, zero_fee_pool};
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
    let candidate = assemble_candidate(&context(), &snapshot, PAYOUT)?;
    assert_eq!(candidate.transactions.len(), 50);

    // Snapshot order is authoritative; the candidate must preserve package order
    // from walking that priority index.
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

    let candidate = assemble_candidate(&context(), &mempool.mining_snapshot(), PAYOUT)?;
    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(candidate.transactions[0].txid, parent_txid);
    assert_eq!(candidate.transactions[1].depends, vec![1]);
    assert_eq!(candidate.fees, 11_000);
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

    let candidate = assemble_candidate(&context(), &snapshot, PAYOUT)?;
    assert_eq!(candidate.transactions[0].txid, low_txid);
    assert_eq!(candidate.transactions[0].fee, 1_000);
    assert_eq!(candidate.transactions[0].fee_delta, 10_000);
    assert_eq!(candidate.transactions[0].modified_fee, 11_000);
    assert_eq!(candidate.fees, 3_000);
    assert_eq!(
        candidate.coinbase_value,
        bitcoin_rs_consensus::block_subsidy(100, Network::Regtest.subsidy_halving_interval())
            + 3_000
    );
    Ok(())
}

#[test]
fn weight_size_and_sigop_limits_are_independent() -> Result<(), Box<dyn Error>> {
    let fitting = forged_entry(Arc::new(tx(4, 1_000, None)), 1_000, 0, 100, 100, 1, vec![]);
    // Each oversized entry exceeds exactly one dimension of its own context.
    let cases = [
        (
            forged_entry(
                Arc::new(tx(1, 1_000, None)),
                5_000,
                0,
                10_000,
                100,
                0,
                vec![],
            ),
            limits(2_000, 4_000_000, 80_000),
        ),
        (
            forged_entry(
                Arc::new(tx(2, 1_000, None)),
                5_000,
                0,
                100,
                10_000,
                0,
                vec![],
            ),
            limits(4_000_000, 2_000, 80_000),
        ),
        (
            forged_entry(
                Arc::new(tx(3, 1_000, None)),
                5_000,
                0,
                100,
                100,
                10_000,
                vec![],
            ),
            limits(4_000_000, 4_000_000, 100),
        ),
    ];
    for (sequence, (oversized, context)) in cases.into_iter().enumerate() {
        let candidate = assemble_candidate(
            &context,
            &snapshot(u64::try_from(sequence)?, vec![oversized, fitting.clone()]),
            PAYOUT,
        )?;
        assert_eq!(selected(&candidate), vec![fitting.txid]);
    }
    Ok(())
}

// POL-05/06: one fee chunk is indivisible, and its positive unconfirmed
// BIP68 lock is not final at the next block. The valid parent cannot be
// retried separately after the whole child-parent chunk is skipped; with CSV
// inactive the same lock is ignored and the chunk is selected whole.
#[test]
fn unconfirmed_bip68_lock_skips_its_whole_chunk_only_while_csv_is_active()
-> Result<(), Box<dyn Error>> {
    for (csv_active, expected, sequence) in [(true, 0, 12), (false, 2, 13)] {
        let parent = forged_entry(Arc::new(tx(1, 1_000, None)), 1_000, 0, 400, 100, 0, vec![]);
        let mut child_tx = tx(2, 1_000, Some(parent.txid));
        child_tx.inputs[0].sequence = Sequence::from_consensus(1);
        let child = forged_entry(Arc::new(child_tx), 10_000, 0, 400, 100, 0, vec![1]);
        let candidate = assemble_candidate(
            &CandidateContext {
                csv_active,
                ..context()
            },
            &snapshot(sequence, vec![child, parent]),
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

// POL-05: CandidateContext resource limits apply to a complete fee chunk.
// Exact configured limits fit; one excess unit skips both child and parent.
// Core 31.1 node/miner.cpp::addChunks likewise calls SkipBuilderChunk after
// TestChunkBlockLimits, rather than extracting a parent from the failed chunk.
#[test]
fn exact_resource_limits_accept_dependency_closed_package() -> Result<(), Box<dyn Error>> {
    let reservation = assemble_candidate(&context(), &snapshot(4, vec![]), PAYOUT)?;

    let parent = forged_entry(Arc::new(tx(1, 1_000, None)), 1_000, 0, 40, 40, 4, vec![]);
    let child = forged_entry(
        Arc::new(tx(2, 1_000, Some(parent.txid))),
        10_000,
        0,
        60,
        60,
        6,
        vec![1],
    );
    let exact_limits = limits(
        reservation.weight + 100,
        reservation.size + 100,
        reservation.sigop_cost + 10,
    );

    let exact = assemble_candidate(
        &exact_limits,
        &snapshot(5, vec![child.clone(), parent.clone()]),
        PAYOUT,
    )?;
    assert_eq!(selected(&exact), vec![parent.txid, child.txid]);
    assert_eq!(exact.weight, exact_limits.max_weight);
    assert_eq!(exact.size, exact_limits.max_size);
    assert_eq!(exact.sigop_cost, exact_limits.max_sigops);

    let excesses: [fn(&mut SnapshotEntry); 3] = [
        |entry| entry.weight += 1,
        |entry| entry.size += 1,
        |entry| entry.sigop_cost += 1,
    ];
    for (sequence, excess) in excesses.into_iter().enumerate() {
        let mut over_limit = child.clone();
        excess(&mut over_limit);
        let candidate = assemble_candidate(
            &exact_limits,
            &snapshot(
                6 + u64::try_from(sequence)?,
                vec![over_limit, parent.clone()],
            ),
            PAYOUT,
        )?;
        assert!(
            candidate.transactions.is_empty(),
            "one excess unit must skip the whole chunk"
        );
    }
    Ok(())
}

#[test]
fn coinbase_reservation_accepts_exact_limits_and_rejects_one_over() -> Result<(), Box<dyn Error>> {
    let payout = vec![0xac];
    let empty = snapshot(9, vec![]);
    let reservation = assemble_candidate(&context(), &empty, &payout)?;
    assert!(reservation.weight > 0);
    assert!(reservation.size > 0);
    assert!(reservation.sigop_cost > 0);

    let exact_limits = limits(reservation.weight, reservation.size, reservation.sigop_cost);
    let exact = assemble_candidate(&exact_limits, &empty, &payout)?;
    assert_eq!(exact.weight, exact_limits.max_weight);
    assert_eq!(exact.size, exact_limits.max_size);
    assert_eq!(exact.sigop_cost, exact_limits.max_sigops);

    let one_over = [
        (
            "weight",
            limits(
                reservation.weight - 1,
                reservation.size,
                reservation.sigop_cost,
            ),
        ),
        (
            "size",
            limits(
                reservation.weight,
                reservation.size - 1,
                reservation.sigop_cost,
            ),
        ),
        (
            "sigops",
            limits(
                reservation.weight,
                reservation.size,
                reservation.sigop_cost - 1,
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

    let snapshot = snapshot(
        4,
        vec![
            forged_entry(Arc::new(non_final), 9_000, 0, 400, 100, 0, vec![]),
            forged_entry(Arc::new(tx(1, 1_000, None)), 1_000, 0, 400, 100, 0, vec![]),
        ],
    );
    let candidate = assemble_candidate(
        &CandidateContext {
            locktime_cutoff: 500_000_000,
            ..context()
        },
        &snapshot,
        PAYOUT,
    )?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.fees, 1_000);
    Ok(())
}

#[test]
fn malformed_graph_snapshots_fail_with_typed_owner_errors() {
    let missing = snapshot(
        1,
        vec![forged_entry(
            Arc::new(tx(1, 1_000, None)),
            1_000,
            0,
            100,
            100,
            0,
            vec![9],
        )],
    );
    assert!(matches!(
        assemble_candidate(&context(), &missing, PAYOUT),
        Err(MiningError::MissingAncestor { .. })
    ));

    // POL-05 requires an admitted dependency DAG. This fixture bypasses
    // admission: assemble_candidate calls MempoolMiningSnapshot::fee_chunks,
    // whose mempool-owned fee-diagram validator rejects the forged cycle
    // with Dependencies. Mining propagates that failure without making an order.
    let cyclic = snapshot(
        2,
        vec![
            forged_entry(Arc::new(tx(1, 1_000, None)), 1_000, 0, 100, 100, 0, vec![1]),
            forged_entry(Arc::new(tx(2, 1_000, None)), 1_000, 0, 100, 100, 0, vec![0]),
        ],
    );
    assert!(matches!(
        assemble_candidate(&context(), &cyclic, PAYOUT),
        Err(MiningError::FeeDiagram(
            bitcoin_rs_mempool::FeeDiagramError::Dependencies
        ))
    ));
}

#[test]
fn oversized_residual_package_is_skipped_atomically() -> Result<(), Box<dyn Error>> {
    // Coinbase reservation is ~476 WU with the default payout+commitment. Choose
    // limits so parent alone and parent+child both overflow, while `other` fits.
    let parent = forged_entry(Arc::new(tx(1, 1_000, None)), 100, 0, 99_600, 100, 0, vec![]);
    let mut child_tx = tx(2, 1_000, Some(parent.txid));
    child_tx.lock_time = LockTime::ZERO;
    let child = forged_entry(Arc::new(child_tx), 10_000, 0, 20_000, 100, 0, vec![1]);
    let other = forged_entry(Arc::new(tx(3, 1_000, None)), 1_000, 0, 400, 100, 0, vec![]);

    let candidate = assemble_candidate(
        &limits(100_000, 4_000_000, 80_000),
        &snapshot(5, vec![child, parent, other.clone()]),
        PAYOUT,
    )?;
    assert_eq!(selected(&candidate), vec![other.txid]);
    Ok(())
}

proptest! {
    #[test]
    fn independent_selection_is_deterministic(
        fees in prop::collection::vec(1_000_u64..50_000, 1..30),
    ) {
        let entries = fees
            .iter()
            .enumerate()
            .map(|(index, fee)| {
                forged_entry(
                    Arc::new(tx(u8::try_from(index % 250).unwrap_or(0), 1_000, None)),
                    *fee,
                    0,
                    400,
                    100,
                    0,
                    vec![],
                )
            })
            .collect::<Vec<_>>();
        let snapshot = snapshot(11, entries);
        let left = assemble_candidate(&context(), &snapshot, PAYOUT).expect("left assembly");
        let right = assemble_candidate(&context(), &snapshot, PAYOUT).expect("right assembly");
        assert_eq!(selected(&left), selected(&right));
        assert_eq!(left.fees, right.fees);
        assert_eq!(left.weight, right.weight);
        assert_eq!(left.size, right.size);
        assert_eq!(left.sigop_cost, right.sigop_cost);
        assert_eq!(left.coinbase_value, right.coinbase_value);
    }
}
