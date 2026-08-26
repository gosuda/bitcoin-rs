#![allow(clippy::expect_used)]
//! Package selection, limits, and adversarial candidate tests.

use std::error::Error;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolLimits, MempoolMiningSnapshot, SnapshotEntry,
};
use bitcoin_rs_mining::{CandidateContext, MiningError, assemble_candidate};
use bitcoin_rs_primitives::{Hash256, Network};
use proptest::prelude::*;

#[test]
fn selects_independent_transactions_in_modified_fee_order() -> Result<(), Box<dyn Error>> {
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    for index in 0_u32..50 {
        let vsize = 100 + (index % 5);
        let fee = u64::from(50_u32 - index) * 1_000;
        mempool.insert_entry(MempoolEntry::new(
            Arc::new(independent_tx(u8::try_from(index)?)),
            vsize,
            fee,
            u64::from(index),
            800_000,
        ))?;
    }

    let snapshot = mempool.mining_snapshot();
    let candidate = assemble_candidate(
        &context(4_000_000, 4_000_000, 80_000),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(candidate.transactions.len(), 50);

    // Snapshot order is authoritative; the candidate must preserve package order
    // from walking that priority index.
    assert_eq!(
        candidate
            .transactions
            .iter()
            .map(|tx| tx.txid)
            .collect::<Vec<_>>(),
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
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let parent = chained_tx(1, 50_000, None);
    let parent_txid = parent.compute_txid();
    mempool.insert_entry(MempoolEntry::new(Arc::new(parent), 200, 1_000, 1, 100))?;
    // High-fee child should outrank the parent individually and pull it in.
    mempool.insert_entry(MempoolEntry::new(
        Arc::new(chained_tx(2, 40_000, Some(parent_txid))),
        200,
        10_000,
        2,
        100,
    ))?;

    let snapshot = mempool.mining_snapshot();
    let candidate = assemble_candidate(
        &context(4_000_000, 4_000_000, 80_000),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(candidate.transactions.len(), 2);
    assert_eq!(candidate.transactions[0].txid, parent_txid);
    assert_eq!(candidate.transactions[1].depends, vec![1]);
    assert_eq!(candidate.fees, 11_000);
    Ok(())
}

#[test]
fn modified_fees_rank_but_actual_fees_fund_coinbase() -> Result<(), Box<dyn Error>> {
    let mut mempool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let low = independent_tx(1);
    let high = independent_tx(2);
    let low_txid = low.compute_txid();
    mempool.insert_entry(MempoolEntry::new(Arc::new(low), 200, 1_000, 1, 100))?;
    mempool.insert_entry(MempoolEntry::new(Arc::new(high), 200, 2_000, 2, 100))?;
    mempool.prioritise(low_txid, 10_000)?;

    let snapshot = mempool.mining_snapshot();
    assert_eq!(snapshot.entries[0].txid, low_txid);

    let candidate = assemble_candidate(
        &context(4_000_000, 4_000_000, 80_000),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
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
    let heavy = snapshot_entry(
        Arc::new(independent_tx(1)),
        5_000,
        0,
        10_000,
        100,
        0,
        vec![],
    );
    let wide = snapshot_entry(
        Arc::new(independent_tx(2)),
        5_000,
        0,
        100,
        10_000,
        0,
        vec![],
    );
    let busy = snapshot_entry(
        Arc::new(independent_tx(3)),
        5_000,
        0,
        100,
        100,
        10_000,
        vec![],
    );
    let fitting = snapshot_entry(Arc::new(independent_tx(4)), 1_000, 0, 100, 100, 1, vec![]);

    // Weight-only ceiling rejects `heavy`, keeps `fitting`.
    let weight_limited = assemble_candidate(
        &context(2_000, 4_000_000, 80_000),
        &MempoolMiningSnapshot {
            sequence: 1,
            entries: vec![heavy, fitting.clone()],
        },
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(weight_limited.transactions.len(), 1);
    assert_eq!(weight_limited.transactions[0].txid, fitting.txid);

    // Serialized-size ceiling rejects `wide`.
    let size_limited = assemble_candidate(
        &context(4_000_000, 2_000, 80_000),
        &MempoolMiningSnapshot {
            sequence: 2,
            entries: vec![wide, fitting.clone()],
        },
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(size_limited.transactions.len(), 1);
    assert_eq!(size_limited.transactions[0].txid, fitting.txid);

    // Sigop ceiling rejects `busy`.
    let sigop_limited = assemble_candidate(
        &context(4_000_000, 4_000_000, 100),
        &MempoolMiningSnapshot {
            sequence: 3,
            entries: vec![busy, fitting.clone()],
        },
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(sigop_limited.transactions.len(), 1);
    assert_eq!(sigop_limited.transactions[0].txid, fitting.txid);
    Ok(())
}

#[test]
fn bip68_unmet_unconfirmed_parent_package_is_skipped() -> Result<(), Box<dyn Error>> {
    let parent = snapshot_entry(Arc::new(independent_tx(1)), 1_000, 0, 400, 100, 0, vec![]);
    let mut child_tx = chained_tx(2, 1_000, Some(parent.txid));
    child_tx.input[0].sequence = Sequence::from_consensus(1);
    let child = snapshot_entry(Arc::new(child_tx), 10_000, 0, 400, 100, 0, vec![1]);
    let snapshot = MempoolMiningSnapshot {
        sequence: 12,
        entries: vec![child, parent.clone()],
    };
    let candidate = assemble_candidate(
        &context(4_000_000, 4_000_000, 80_000),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.transactions[0].txid, parent.txid);
    Ok(())
}

#[test]
fn bip68_unmet_lock_is_ignored_when_csv_is_inactive() -> Result<(), Box<dyn Error>> {
    let parent = snapshot_entry(Arc::new(independent_tx(1)), 1_000, 0, 400, 100, 0, vec![]);
    let mut child_tx = chained_tx(2, 1_000, Some(parent.txid));
    child_tx.input[0].sequence = Sequence::from_consensus(1);
    let child = snapshot_entry(Arc::new(child_tx), 10_000, 0, 400, 100, 0, vec![1]);
    let snapshot = MempoolMiningSnapshot {
        sequence: 13,
        entries: vec![child, parent],
    };
    let mut inactive = context(4_000_000, 4_000_000, 80_000);
    inactive.csv_active = false;
    let candidate = assemble_candidate(&inactive, &snapshot, &ScriptBuf::from_bytes(vec![0x51]))?;
    assert_eq!(candidate.transactions.len(), 2);
    Ok(())
}

#[test]
fn exact_resource_limits_accept_dependency_closed_package() -> Result<(), Box<dyn Error>> {
    let payout = ScriptBuf::from_bytes(vec![0x51]);
    let empty = MempoolMiningSnapshot {
        sequence: 4,
        entries: vec![],
    };
    let reservation = assemble_candidate(&context(4_000_000, 4_000_000, 80_000), &empty, &payout)?;

    let parent = snapshot_entry(Arc::new(independent_tx(1)), 1_000, 0, 40, 40, 4, vec![]);
    let child = snapshot_entry(
        Arc::new(chained_tx(2, 1_000, Some(parent.txid))),
        10_000,
        0,
        60,
        60,
        6,
        vec![1],
    );
    let exact_limits = context(
        reservation.weight + 100,
        reservation.size + 100,
        reservation.sigop_cost + 10,
    );

    let exact = assemble_candidate(
        &exact_limits,
        &MempoolMiningSnapshot {
            sequence: 5,
            entries: vec![child.clone(), parent.clone()],
        },
        &payout,
    )?;
    assert_eq!(
        exact
            .transactions
            .iter()
            .map(|transaction| transaction.txid)
            .collect::<Vec<_>>(),
        vec![parent.txid, child.txid]
    );
    assert_eq!(exact.weight, exact_limits.max_weight);
    assert_eq!(exact.size, exact_limits.max_size);
    assert_eq!(exact.sigop_cost, exact_limits.max_sigops);

    let mut overweight_child = child.clone();
    overweight_child.weight += 1;
    let overweight = assemble_candidate(
        &exact_limits,
        &MempoolMiningSnapshot {
            sequence: 6,
            entries: vec![overweight_child, parent.clone()],
        },
        &payout,
    )?;
    assert_eq!(
        overweight
            .transactions
            .iter()
            .map(|transaction| transaction.txid)
            .collect::<Vec<_>>(),
        vec![parent.txid]
    );

    let mut oversized_child = child.clone();
    oversized_child.size += 1;
    let oversized = assemble_candidate(
        &exact_limits,
        &MempoolMiningSnapshot {
            sequence: 7,
            entries: vec![oversized_child, parent.clone()],
        },
        &payout,
    )?;
    assert_eq!(
        oversized
            .transactions
            .iter()
            .map(|transaction| transaction.txid)
            .collect::<Vec<_>>(),
        vec![parent.txid]
    );

    let mut excess_sigops_child = child;
    excess_sigops_child.sigop_cost += 1;
    let excess_sigops = assemble_candidate(
        &exact_limits,
        &MempoolMiningSnapshot {
            sequence: 8,
            entries: vec![excess_sigops_child, parent.clone()],
        },
        &payout,
    )?;
    assert_eq!(
        excess_sigops
            .transactions
            .iter()
            .map(|transaction| transaction.txid)
            .collect::<Vec<_>>(),
        vec![parent.txid]
    );
    Ok(())
}

#[test]
fn coinbase_reservation_accepts_exact_limits_and_rejects_one_over() -> Result<(), Box<dyn Error>> {
    let payout = ScriptBuf::from_bytes(vec![0xac]);
    let snapshot = MempoolMiningSnapshot {
        sequence: 9,
        entries: vec![],
    };
    let reservation =
        assemble_candidate(&context(4_000_000, 4_000_000, 80_000), &snapshot, &payout)?;
    assert!(reservation.weight > 0);
    assert!(reservation.size > 0);
    assert!(reservation.sigop_cost > 0);

    let exact_limits = context(reservation.weight, reservation.size, reservation.sigop_cost);
    let exact = assemble_candidate(&exact_limits, &snapshot, &payout)?;
    assert_eq!(exact.weight, exact_limits.max_weight);
    assert_eq!(exact.size, exact_limits.max_size);
    assert_eq!(exact.sigop_cost, exact_limits.max_sigops);

    assert!(matches!(
        assemble_candidate(
            &context(
                reservation.weight - 1,
                reservation.size,
                reservation.sigop_cost,
            ),
            &snapshot,
            &payout,
        ),
        Err(MiningError::CapacityExhausted { field: "weight" })
    ));
    assert!(matches!(
        assemble_candidate(
            &context(
                reservation.weight,
                reservation.size - 1,
                reservation.sigop_cost,
            ),
            &snapshot,
            &payout,
        ),
        Err(MiningError::CapacityExhausted { field: "size" })
    ));
    assert!(matches!(
        assemble_candidate(
            &context(
                reservation.weight,
                reservation.size,
                reservation.sigop_cost - 1,
            ),
            &snapshot,
            &payout,
        ),
        Err(MiningError::CapacityExhausted { field: "sigops" })
    ));
    Ok(())
}

#[test]
fn non_final_packages_are_skipped() -> Result<(), Box<dyn Error>> {
    let mut final_tx = independent_tx(1);
    final_tx.lock_time = absolute::LockTime::ZERO;
    let mut non_final = independent_tx(2);
    non_final.lock_time = absolute::LockTime::from_consensus(500_000_100);
    for input in &mut non_final.input {
        input.sequence = Sequence::ZERO;
    }

    let snapshot = MempoolMiningSnapshot {
        sequence: 4,
        entries: vec![
            snapshot_entry(Arc::new(non_final), 9_000, 0, 400, 100, 0, vec![]),
            snapshot_entry(Arc::new(final_tx), 1_000, 0, 400, 100, 0, vec![]),
        ],
    };
    let mut context = context(4_000_000, 4_000_000, 80_000);
    context.locktime_cutoff = 500_000_000;
    let candidate = assemble_candidate(&context, &snapshot, &ScriptBuf::from_bytes(vec![0x51]))?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.fees, 1_000);
    Ok(())
}

#[test]
fn missing_and_cyclic_ancestors_fail_assembly() {
    let missing = MempoolMiningSnapshot {
        sequence: 1,
        entries: vec![snapshot_entry(
            Arc::new(independent_tx(1)),
            1_000,
            0,
            100,
            100,
            0,
            vec![9],
        )],
    };
    assert!(matches!(
        assemble_candidate(
            &context(4_000_000, 4_000_000, 80_000),
            &missing,
            &ScriptBuf::from_bytes(vec![0x51]),
        ),
        Err(MiningError::MissingAncestor { .. })
    ));

    let cyclic = MempoolMiningSnapshot {
        sequence: 2,
        entries: vec![
            snapshot_entry(Arc::new(independent_tx(1)), 1_000, 0, 100, 100, 0, vec![1]),
            snapshot_entry(Arc::new(independent_tx(2)), 1_000, 0, 100, 100, 0, vec![0]),
        ],
    };
    assert!(matches!(
        assemble_candidate(
            &context(4_000_000, 4_000_000, 80_000),
            &cyclic,
            &ScriptBuf::from_bytes(vec![0x51]),
        ),
        Err(MiningError::DependencyCycle { .. })
    ));
}

#[test]
fn oversized_residual_package_is_skipped_atomically() -> Result<(), Box<dyn Error>> {
    // Coinbase reservation is ~476 WU with the default payout+commitment. Choose
    // limits so parent alone and parent+child both overflow, while `other` fits.
    let parent = snapshot_entry(Arc::new(independent_tx(1)), 100, 0, 99_600, 100, 0, vec![]);
    let mut child_tx = chained_tx(2, 1_000, Some(parent.txid));
    child_tx.lock_time = absolute::LockTime::ZERO;
    let child = snapshot_entry(Arc::new(child_tx), 10_000, 0, 20_000, 100, 0, vec![1]);
    let other = snapshot_entry(Arc::new(independent_tx(3)), 1_000, 0, 400, 100, 0, vec![]);

    let snapshot = MempoolMiningSnapshot {
        sequence: 5,
        entries: vec![child, parent, other.clone()],
    };
    let candidate = assemble_candidate(
        &context(100_000, 4_000_000, 80_000),
        &snapshot,
        &ScriptBuf::from_bytes(vec![0x51]),
    )?;
    assert_eq!(candidate.transactions.len(), 1);
    assert_eq!(candidate.transactions[0].txid, other.txid);
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
                snapshot_entry(
                    Arc::new(independent_tx(u8::try_from(index % 250).unwrap_or(0))),
                    *fee,
                    0,
                    400,
                    100,
                    0,
                    vec![],
                )
            })
            .collect::<Vec<_>>();
        let snapshot = MempoolMiningSnapshot {
            sequence: 11,
            entries,
        };
        let left = assemble_candidate(
            &context(4_000_000, 4_000_000, 80_000),
            &snapshot,
            &ScriptBuf::from_bytes(vec![0x51]),
        )
        .expect("left assembly");
        let right = assemble_candidate(
            &context(4_000_000, 4_000_000, 80_000),
            &snapshot,
            &ScriptBuf::from_bytes(vec![0x51]),
        )
        .expect("right assembly");
        assert_eq!(
            left.transactions.iter().map(|tx| tx.txid).collect::<Vec<_>>(),
            right.transactions.iter().map(|tx| tx.txid).collect::<Vec<_>>()
        );
        assert_eq!(left.fees, right.fees);
        assert_eq!(left.weight, right.weight);
        assert_eq!(left.size, right.size);
        assert_eq!(left.sigop_cost, right.sigop_cost);
        assert_eq!(left.coinbase_value, right.coinbase_value);
    }
}

fn context(max_weight: u64, max_size: u64, max_sigops: u64) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xcd; 32]),
        height: 100,
        version: 0x2000_0000,
        bits: 0x207f_ffff,
        min_time: 1,
        current_time: 2,
        locktime_cutoff: 1,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight,
        max_size,
        max_sigops,
    }
}

fn snapshot_entry(
    tx: Arc<Transaction>,
    fee: u64,
    fee_delta: i64,
    weight: u64,
    size: u32,
    sigop_cost: u32,
    ancestors: Vec<u32>,
) -> SnapshotEntry {
    SnapshotEntry {
        txid: tx.compute_txid(),
        wtxid: tx.compute_wtxid(),
        vsize: size.max(1),
        bip141_vsize: size.max(1),
        size,
        weight,
        sigop_cost,
        fee,
        fee_delta,
        time: 0,
        height: 0,
        ancestor_size: u64::from(size.max(1)),
        ancestor_fee: fee,
        ancestor_fee_delta: i128::from(fee_delta),
        ancestors,
        tx,
    }
}

fn independent_tx(label: u8) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

fn chained_tx(label: u8, value: u64, parent: Option<Txid>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(parent.unwrap_or_else(|| outpoint(label).txid), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

fn outpoint(label: u8) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid::from_byte_array(bytes), 0)
}
