//! Signal-independent replacement and retained historical BIP125 policy vectors.
//! Core process evidence lives in `replacement_signaling_matches_pinned_core`.
#![allow(clippy::expect_used)]

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolError, MempoolLimits, MempoolStats, PolicyError, RbfError,
    ReplacementCandidate,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

#[derive(Clone, Copy)]
struct OriginalSpec {
    sequence: u32,
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

const CASES: [Case; 9] = [
    Case {
        name: "accepts direct opt-in replacement",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFD,
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
        name: "accepts non-signaling originals",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFF,
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
        name: "accepts originals at the non-signaling sequence boundary",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFE,
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
        name: "cannot spend an evicted parent",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFD,
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
        expected: Err(RbfError::Mempool(MempoolError::EvictedParent)),
    },
    Case {
        name: "rule 3 requires replacement to pay original absolute fees",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFF,
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
            sequence: 0xFFFF_FFFE,
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
        name: "many victims in one conflicting cluster are allowed",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFD,
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
        expected: Ok(()),
    },
    Case {
        name: "fee diagram must strictly improve",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFD,
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
        expected: Err(RbfError::InsufficientFeerateDiagram),
    },
    Case {
        name: "accepts an original with an unconfirmed parent",
        original: OriginalSpec {
            sequence: 0xFFFF_FFFF,
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
fn retained_replacement_rules_are_enforced() -> Result<(), Box<dyn Error>> {
    for case in CASES {
        let has_parent = case.name == "accepts an original with an unconfirmed parent";
        let (pool, replacement_tx) =
            pool_with_conflict(case.original, case.replacement, has_parent)?;
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

/// POL-05: mixing signaling and nonsignaling conflicts cannot reintroduce
/// a signal requirement. The replacement itself does not signal either.
#[test]
fn replacements_accept_mixed_signaling_conflicts() -> Result<(), Box<dyn Error>> {
    const RBF_SEQUENCE: u32 = 0xffff_fffd;
    const FINAL_SEQUENCE: u32 = 0xffff_ffff;
    for second_sequence in [RBF_SEQUENCE, 0xffff_fffe, FINAL_SEQUENCE] {
        let mut pool = Mempool::new(MempoolLimits::default());
        let first_input = outpoint(1, 0);
        let second_input = outpoint(2, 0);

        let opt_in = tx_from_inputs(20, &[(first_input, RBF_SEQUENCE)], 1);
        pool.insert_entry(MempoolEntry::new(Arc::new(opt_in), 100, 1_000, 1, 1, 0))?;
        let other = tx_from_inputs(21, &[(second_input, second_sequence)], 1);
        pool.insert_entry(MempoolEntry::new(Arc::new(other), 100, 1_000, 2, 1, 0))?;

        // One replacement, conflicting with both of them.
        let replacement = tx_from_inputs(
            40,
            &[
                (first_input, FINAL_SEQUENCE),
                (second_input, FINAL_SEQUENCE),
            ],
            1,
        );
        let candidate = ReplacementCandidate::new(Arc::new(replacement), 200, 10_000, 1);

        assert_eq!(
            pool.check_replacement(&candidate).map(|_| ()),
            Ok(()),
            "second original sequence {second_sequence:#x}"
        );
    }
    Ok(())
}

fn pool_with_conflict(
    original: OriginalSpec,
    replacement: ReplacementSpec,
    has_parent: bool,
) -> Result<(Mempool, Tx), Box<dyn Error>> {
    let limits = if replacement.extra_descendants == 0 {
        MempoolLimits::default()
    } else {
        MempoolLimits {
            // A chain this long is one cluster this long, so the cluster caps
            // have to be lifted alongside the ancestor caps or admission
            // refuses the fixture before the replacement rules are reached.
            // This test is about BIP125, not about cluster limits.
            cluster_count: 400,
            cluster_size_vbytes: 1_000_000,
            ..MempoolLimits::default()
        }
    };
    let mut pool = Mempool::new(limits);
    let external_input = outpoint(1, 0);
    let mut original_input = external_input;

    if has_parent {
        let parent = tx_from_inputs(10, &[(outpoint(9, 0), 0xFFFF_FFFF)], 1);
        original_input = OutPoint::new(parent.txid(), 0);
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 500, 1, 1, 0))?;
    }

    let original_tx = tx_from_inputs(20, &[(original_input, original.sequence)], 1);
    let original_txid = original_tx.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(original_tx),
        original.vsize,
        original.fee,
        2,
        1, 0
    ))?;

    let mut last_parent = OutPoint::new(original_txid, 0);
    for i in 0..replacement.extra_descendants {
        let label = u8::try_from(i % 200)? + 30;
        let child = tx_from_inputs(label, &[(last_parent, 0xFFFF_FFFF)], 1);
        last_parent = OutPoint::new(child.txid(), 0);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(child),
            50,
            100,
            u64::from(i) + 3,
            1, 0
        ))?;
    }

    let mut inputs = vec![(external_input, 0xFFFF_FFFD)];
    if has_parent {
        inputs[0] = (original_input, 0xFFFF_FFFD);
    }
    if replacement.new_unconfirmed_input {
        inputs.push((OutPoint::new(original_txid, 0), 0xFFFF_FFFD));
    }
    let replacement_tx = tx_from_inputs(40, &inputs, 1);

    Ok((pool, replacement_tx))
}

fn tx_from_inputs(label: u8, inputs: &[(OutPoint, u32)], outputs: usize) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|(previous_output, sequence)| TxIn {
                previous_output: *previous_output,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(*sequence),
                witness: Witness::new(),
            })
            .collect(),
        outputs: (0..outputs)
            .map(|i| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51, label, u8::try_from(i).unwrap_or(0)].into(),
            })
            .collect(),
    }
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), vout)
}

#[test]
fn replace_transaction_leaves_only_the_replacement() -> Result<(), Box<dyn Error>> {
    let (mut pool, replacement_tx) = pool_with_conflict(
        OriginalSpec {
            sequence: 0xFFFF_FFFD,
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
    let replacement_txid = replacement_tx.txid();
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
        let original = tx_from_inputs(20, &[(outpoint(1, 0), 0xFFFF_FFFD)], 1);
        // Admit under the default floor, then raise it so only the replacement
        // hits BelowMinRelayFee after BIP125 validation succeeds.
        pool.insert_entry(MempoolEntry::new(Arc::new(original), 300, 1_000, 2, 1, 0))?;
        pool.limits.min_relay_fee_sat_per_kvb = 5_000;
        let replacement = tx_from_inputs(40, &[(outpoint(1, 0), 0xFFFF_FFFD)], 1);
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
        let conflict1 = tx_from_inputs(10, &[(outpoint(1, 0), 0xFFFF_FFFD)], 1);
        let conflict1_txid = conflict1.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(conflict1), 100, 500, 1, 1, 0))?;
        let parent = tx_from_inputs(11, &[(OutPoint::new(conflict1_txid, 0), 0xFFFF_FFFF)], 1);
        let parent_txid = parent.txid();
        pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 500, 2, 1, 0))?;
        let conflict2 = tx_from_inputs(12, &[(OutPoint::new(parent_txid, 0), 0xFFFF_FFFD)], 1);
        pool.insert_entry(MempoolEntry::new(Arc::new(conflict2), 100, 500, 3, 1, 0))?;
        // Conflicts with conflict1 on U1 and with conflict2 on P's output.
        let replacement = tx_from_inputs(
            40,
            &[
                (outpoint(1, 0), 0xFFFF_FFFD),
                (OutPoint::new(parent_txid, 0), 0xFFFF_FFFD),
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

    // (c) Policy rejections leave the pool fingerprint untouched.
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
fn replace_transaction_cluster_limits_use_post_eviction_projection() -> Result<(), Box<dyn Error>> {
    // P + 23 retained children + conflict C = 25 inclusive. Excluding C leaves
    // room for the replacement that re-spends P; counting C would over-reject.
    let mut pool = Mempool::new(MempoolLimits {
        cluster_count: 25,
        ..MempoolLimits::default()
    });
    let parent = tx_from_inputs(10, &[(outpoint(1, 0), 0xFFFF_FFFD)], 24);
    let parent_txid = parent.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1, 0))?;
    for i in 0..23_u32 {
        let child = tx_from_inputs(
            u8::try_from(30 + i)?,
            &[(OutPoint::new(parent_txid, i), 0xFFFF_FFFF)],
            1,
        );
        pool.insert_entry(MempoolEntry::new(
            Arc::new(child),
            50,
            100,
            u64::from(i) + 2,
            1, 0
        ))?;
    }
    let conflict = tx_from_inputs(60, &[(OutPoint::new(parent_txid, 23), 0xFFFF_FFFD)], 1);
    pool.insert_entry(MempoolEntry::new(Arc::new(conflict), 50, 100, 30, 1, 0))?;
    let replacement = tx_from_inputs(40, &[(OutPoint::new(parent_txid, 23), 0xFFFF_FFFD)], 1);
    let replacement_txid = replacement.txid();
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
