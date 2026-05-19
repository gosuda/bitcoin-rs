//! BIP125 replacement-by-fee policy vectors.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits, RbfError, ReplacementCandidate};

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
