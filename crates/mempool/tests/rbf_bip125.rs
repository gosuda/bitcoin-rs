//! BIP125 replacement-by-fee policy vectors.
// A failed pool or fixture invariant is a test failure, and panicking reports
// it with the offending call site. `expect` is deliberate.
#![allow(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash,
    Witness,
};
use bitcoin_rs_mempool::standardness::{
    AcceptanceRejectReason, PackageTxContext, StandardnessPolicy, evaluate_package_acceptance,
};
use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolError, MempoolLimits, MempoolStats, PolicyError, RbfError,
    ReplacementCandidate,
};

#[derive(Clone, Copy)]
struct OriginalSpec {
    sequence: Sequence,
    fee: u64,
    vsize: u32,
}

#[derive(Clone, Copy)]
struct ReplacementSpec {
    fee: u64,
    vsize: u32,
    min_relay_fee_rate: u64,
    new_unconfirmed_input: bool,
    extra_descendants: u16,
}

struct Case {
    name: &'static str,
    original: OriginalSpec,
    replacement: ReplacementSpec,
    expected: Result<(), RbfError>,
}

const CASES: [Case; 8] = [
    Case {
        name: "accepts direct opt-in replacement",
        original: OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 1_200,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        expected: Ok(()),
    },
    Case {
        name: "rule 1 rejects non-signaling originals",
        original: OriginalSpec {
            sequence: Sequence::MAX,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 1_200,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        expected: Err(RbfError::Rule1NoOptIn),
    },
    Case {
        name: "rule 2 rejects new unconfirmed input",
        original: OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 1_200,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: true,
            extra_descendants: 0,
        },
        expected: Err(RbfError::Rule2NewUnconfirmedInput),
    },
    Case {
        name: "rule 3 requires replacement to pay original absolute fees",
        original: OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 999,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        expected: Err(RbfError::Rule3InsufficientAbsoluteFee),
    },
    Case {
        name: "rule 4 requires incremental relay fee",
        original: OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 1_050,
            vsize: 100,
            min_relay_fee_rate: 1_000,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        expected: Err(RbfError::Rule4InsufficientIncrementalFee),
    },
    Case {
        name: "rule 5 rejects too many evictions",
        original: OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 12_000,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 100,
        },
        expected: Err(RbfError::Rule5TooManyEvictions),
    },
    Case {
        name: "rule 6 requires replacement fee rate to improve",
        original: OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 2_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 2_001,
            vsize: 200,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        expected: Err(RbfError::Rule6InsufficientFeeRate),
    },
    Case {
        name: "accepts inherited opt-in replacement",
        original: OriginalSpec {
            sequence: Sequence::MAX,
            fee: 1_000,
            vsize: 100,
        },
        replacement: ReplacementSpec {
            fee: 1_300,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        expected: Ok(()),
    },
];

#[test]
fn bip125_replacement_rules_are_enforced() -> Result<(), Box<dyn Error>> {
    for case in CASES {
        let inherited = case.name == "accepts inherited opt-in replacement";
        let (pool, replacement_tx) =
            pool_with_conflict(case.original, case.replacement, inherited)?;
        let candidate = ReplacementCandidate::new(
            Arc::new(replacement_tx),
            case.replacement.vsize,
            case.replacement.fee,
            case.replacement.min_relay_fee_rate,
        );
        let actual = pool.check_replacement(&candidate).map(|_| ());
        assert_eq!(actual, case.expected, "{}", case.name);
    }

    Ok(())
}

#[test]
fn package_acceptance_surfaces_bip125_replacement_boundaries() -> Result<(), Box<dyn Error>> {
    let (pool, mut replacement_tx) = pool_with_conflict(
        OriginalSpec {
            sequence: Sequence::MAX,
            fee: 1_000,
            vsize: 100,
        },
        ReplacementSpec {
            fee: 1_200,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        false,
    )?;
    // insert_entry does not enforce standardness, but package acceptance does.
    replacement_tx.output[0].script_pubkey =
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x02; 20]));

    let policy = StandardnessPolicy {
        dust_relay_fee: FeeRate::DUST,
        max_datacarrier_bytes: Some(83),
    };
    let context = PackageTxContext {
        fee: 1_200,
        vsize: 100,
        sigop_cost: 4,
        missing_inputs: false,
    };
    let facts =
        evaluate_package_acceptance(&pool, &policy, &[replacement_tx], &[context], None, 1_000);
    assert_eq!(
        facts.results[0].reject_reason,
        Some(AcceptanceRejectReason::Replacement(RbfError::Rule1NoOptIn))
    );
    assert_eq!(facts.results[0].allowed, Some(false));
    assert_eq!(facts.results[0].sigop_cost, 4);
    Ok(())
}

fn pool_with_conflict(
    original: OriginalSpec,
    replacement: ReplacementSpec,
    inherited: bool,
) -> Result<(Mempool, Transaction), Box<dyn Error>> {
    let limits = if replacement.extra_descendants == 0 {
        MempoolLimits::default()
    } else {
        MempoolLimits {
            max_ancestors: 200,
            max_ancestor_size: 1_000_000,
            max_descendants: 200,
            max_replacement_evictions: 100,
            ..MempoolLimits::default()
        }
    };
    let mut pool = Mempool::new(limits);
    let external_input = outpoint(1, 0);
    let mut original_input = external_input;

    if inherited {
        let parent = tx_from_inputs(10, &[(outpoint(9, 0), Sequence::ENABLE_RBF_NO_LOCKTIME)], 1);
        original_input = OutPoint::new(parent.compute_txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 500, 1, 1))?;
    }

    let original_tx = tx_from_inputs(20, &[(original_input, original.sequence)], 1);
    let original_txid = original_tx.compute_txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(original_tx),
        original.vsize,
        original.fee,
        2,
        1,
    ))?;

    let mut last_parent = OutPoint::new(original_txid, 0);
    for i in 0..replacement.extra_descendants {
        let label = u8::try_from(i % 200)? + 30;
        let child = tx_from_inputs(label, &[(last_parent, Sequence::MAX)], 1);
        last_parent = OutPoint::new(child.compute_txid(), 0);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(child),
            50,
            100,
            u64::from(i) + 3,
            1,
        ))?;
    }

    let mut inputs = vec![(external_input, Sequence::ENABLE_RBF_NO_LOCKTIME)];
    if inherited {
        inputs[0] = (original_input, Sequence::ENABLE_RBF_NO_LOCKTIME);
    }
    if replacement.new_unconfirmed_input {
        inputs.push((
            OutPoint::new(original_txid, 0),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        ));
    }
    let replacement_tx = tx_from_inputs(40, &inputs, 1);

    Ok((pool, replacement_tx))
}

fn tx_from_inputs(label: u8, inputs: &[(OutPoint, Sequence)], outputs: usize) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|(previous_output, sequence)| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: *sequence,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..outputs)
            .map(|i| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![
                    0x51,
                    label,
                    u8::try_from(i).unwrap_or(0),
                ]),
            })
            .collect(),
    }
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid::from_byte_array(bytes), vout)
}

#[test]
fn replace_transaction_leaves_only_the_replacement() -> Result<(), Box<dyn Error>> {
    let (mut pool, replacement_tx) = pool_with_conflict(
        OriginalSpec {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            fee: 1_000,
            vsize: 100,
        },
        ReplacementSpec {
            fee: 1_200,
            vsize: 100,
            min_relay_fee_rate: 1,
            new_unconfirmed_input: false,
            extra_descendants: 0,
        },
        false,
    )?;
    let original_txid = pool
        .iter_txids()
        .into_iter()
        .next()
        .ok_or("original missing")?;
    let replacement_txid = replacement_tx.compute_txid();
    let candidate = ReplacementCandidate::new(Arc::new(replacement_tx), 100, 1_200, 1);
    let _id = pool.replace_transaction(candidate, 10, 1, 4)?;
    assert!(pool.contains_txid(&replacement_txid));
    assert!(!pool.contains_txid(&original_txid));
    assert_eq!(pool.len(), 1);
    Ok(())
}

type PoolFingerprint = (Vec<(Txid, u64, u32, i64)>, MempoolStats, u64);

fn pool_fingerprint(pool: &Mempool) -> PoolFingerprint {
    let mut entries = pool
        .iter_txids()
        .into_iter()
        .map(|txid| {
            let entry = pool
                .entry_by_txid(&txid)
                .expect("txid indexed by iter_txids");
            (txid, entry.fee, entry.vsize, entry.fee_delta)
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|(txid, ..)| *txid);
    (entries, pool.stats(), pool.sequence_number())
}

#[test]
fn replace_transaction_rejection_preserves_pool_state() -> Result<(), Box<dyn Error>> {
    // (a) BIP125 rules pass, but the pool min-relay floor rejects before mutation.
    {
        let mut pool = Mempool::new(MempoolLimits::default());
        let original = tx_from_inputs(20, &[(outpoint(1, 0), Sequence::ENABLE_RBF_NO_LOCKTIME)], 1);
        // Admit under the default floor, then raise it so only the replacement
        // hits BelowMinRelayFee after BIP125 validation succeeds.
        pool.insert_entry(MempoolEntry::new(Arc::new(original), 300, 1_000, 2, 1))?;
        pool.limits.min_relay_fee_sat_per_kvb = 5_000;
        let replacement =
            tx_from_inputs(40, &[(outpoint(1, 0), Sequence::ENABLE_RBF_NO_LOCKTIME)], 1);
        let before = pool_fingerprint(&pool);
        let err = pool
            .replace_transaction(
                ReplacementCandidate::new(Arc::new(replacement), 300, 1_300, 1),
                10,
                1,
                4,
            )
            .expect_err("below-floor replacement must fail");
        assert_eq!(
            err,
            RbfError::Mempool(MempoolError::Policy(PolicyError::BelowMinRelayFee {
                tx_rate: 4_333,
                min_rate: 5_000,
            }))
        );
        assert_eq!(pool_fingerprint(&pool), before);
    }

    // (b) C' spends P while P sits inside the eviction set → EvictedParent.
    {
        let mut pool = Mempool::new(MempoolLimits::default());
        let conflict1 =
            tx_from_inputs(10, &[(outpoint(1, 0), Sequence::ENABLE_RBF_NO_LOCKTIME)], 1);
        let conflict1_txid = conflict1.compute_txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(conflict1), 100, 500, 1, 1))?;
        let parent = tx_from_inputs(11, &[(OutPoint::new(conflict1_txid, 0), Sequence::MAX)], 1);
        let parent_txid = parent.compute_txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 500, 2, 1))?;
        let conflict2 = tx_from_inputs(
            12,
            &[(
                OutPoint::new(parent_txid, 0),
                Sequence::ENABLE_RBF_NO_LOCKTIME,
            )],
            1,
        );
        pool.insert_entry(MempoolEntry::new(Arc::new(conflict2), 100, 500, 3, 1))?;
        // Conflicts with conflict1 on U1 and with conflict2 on P's output.
        let replacement = tx_from_inputs(
            40,
            &[
                (outpoint(1, 0), Sequence::ENABLE_RBF_NO_LOCKTIME),
                (
                    OutPoint::new(parent_txid, 0),
                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                ),
            ],
            1,
        );
        let before = pool_fingerprint(&pool);
        let err = pool
            .replace_transaction(
                ReplacementCandidate::new(Arc::new(replacement), 100, 2_000, 1),
                10,
                1,
                4,
            )
            .expect_err("spending an evicted parent must fail");
        assert_eq!(err, RbfError::Mempool(MempoolError::EvictedParent));
        assert_eq!(pool_fingerprint(&pool), before);
    }

    // (c) Rule 1/3/4/5/6 rejections leave the pool fingerprint untouched.
    for case in CASES.iter().filter(|case| case.expected.is_err()) {
        let (mut pool, replacement_tx) =
            pool_with_conflict(case.original, case.replacement, false)?;
        let before = pool_fingerprint(&pool);
        let err = pool
            .replace_transaction(
                ReplacementCandidate::new(
                    Arc::new(replacement_tx),
                    case.replacement.vsize,
                    case.replacement.fee,
                    case.replacement.min_relay_fee_rate,
                ),
                10,
                1,
                4,
            )
            .expect_err(case.name);
        assert_eq!(Err(err), case.expected, "{}", case.name);
        assert_eq!(pool_fingerprint(&pool), before, "{}", case.name);
    }
    Ok(())
}

#[test]
fn replace_transaction_descendant_limits_use_post_eviction_projection() -> Result<(), Box<dyn Error>>
{
    // P + 23 retained children + conflict C = 25 inclusive. Excluding C leaves
    // room for the replacement that re-spends P; counting C would over-reject.
    let mut pool = Mempool::new(MempoolLimits {
        max_descendants: 25,
        max_replacement_evictions: 100,
        ..MempoolLimits::default()
    });
    let parent = tx_from_inputs(
        10,
        &[(outpoint(1, 0), Sequence::ENABLE_RBF_NO_LOCKTIME)],
        24,
    );
    let parent_txid = parent.compute_txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1))?;
    for i in 0..23_u32 {
        let child = tx_from_inputs(
            u8::try_from(30 + i)?,
            &[(OutPoint::new(parent_txid, i), Sequence::MAX)],
            1,
        );
        pool.insert_entry(MempoolEntry::new(
            Arc::new(child),
            50,
            100,
            u64::from(i) + 2,
            1,
        ))?;
    }
    let conflict = tx_from_inputs(
        60,
        &[(
            OutPoint::new(parent_txid, 23),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )],
        1,
    );
    pool.insert_entry(MempoolEntry::new(Arc::new(conflict), 50, 100, 30, 1))?;
    let replacement = tx_from_inputs(
        40,
        &[(
            OutPoint::new(parent_txid, 23),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )],
        1,
    );
    let replacement_txid = replacement.compute_txid();
    let _id = pool.replace_transaction(
        ReplacementCandidate::new(Arc::new(replacement), 50, 300, 1),
        40,
        1,
        4,
    )?;
    assert!(pool.contains_txid(&replacement_txid));
    assert_eq!(pool.len(), 25);
    Ok(())
}
