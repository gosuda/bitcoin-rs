use super::*;

#[test]
fn maximum_fee_uses_core_amount_rounding_including_one_satoshi_boundaries() {
    for (fee, vsize, rate, rejects) in [
        (2_000, 2_000, 1_000, false),
        (2_001, 2_000, 1_000, true),
        (u64::MAX, 1_000, u64::MAX - 1, true),
        (1, 999, 1, false),
        (2, 999, 1, true),
        (10_000, 200, 0, false),
        (1, 0, 1_000, false),
        (2_100_000_000_000_000, u32::MAX, u64::MAX, false),
    ] {
        assert_eq!(exceeds_max_feerate(fee, vsize, Some(rate)), rejects);
    }
}
use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};
use bitcoin_rs_script::{is_multisig, minimal_non_dust, opcode, push_data};

const DUST_RELAY_FEE_SAT_PER_KVB: u64 = 3_000;
const BROADCAST_MIN_FEE_SAT_PER_KVB: u64 = 1_000;

fn p2pkh(hash20: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(25);
    out.push(opcode::OP_DUP);
    out.push(opcode::OP_HASH160);
    out.push(0x14);
    out.extend_from_slice(hash20);
    out.push(opcode::OP_EQUALVERIFY);
    out.push(opcode::OP_CHECKSIG);
    out
}

fn standard_tx(version: u32) -> Tx {
    Tx {
        version,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: p2pkh(&[7_u8; 20]).into(),
        }],
    }
}

fn policy() -> StandardnessPolicy {
    StandardnessPolicy {
        dust_relay_fee: DUST_RELAY_FEE_SAT_PER_KVB,
        max_datacarrier_bytes: Some(83),
    }
}

#[test]
fn only_versions_one_through_three_are_standard() {
    for (version, expected) in [
        (0_u32, Err(StandardnessError::Version)),
        (1, Ok(())),
        (2, Ok(())),
        (3, Ok(())),
        (4, Err(StandardnessError::Version)),
    ] {
        assert_eq!(
            is_standard_tx(&standard_tx(version), &policy()),
            expected,
            "version {version}"
        );
    }
}

#[test]
fn accepts_op_return_followed_by_a_numeric_push() {
    for op in [opcode::OP_PUSHNUM_1, opcode::OP_RESERVED] {
        let mut tx = standard_tx(1);
        tx.outputs[0].value = Amount::ZERO;
        tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN, op].into();
        tx.outputs.push(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: p2pkh(&[9_u8; 20]).into(),
        });
        assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    }
}

#[test]
fn rejects_op_return_followed_by_an_opcode() {
    let mut tx = standard_tx(1);
    tx.outputs[0].value = Amount::ZERO;
    tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN, opcode::OP_DUP].into();
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::NonStandardOutput)
    );
}

#[test]
fn rejects_bare_multisig_whose_key_is_not_a_pubkey() {
    let mut script = vec![opcode::OP_PUSHNUM_1];
    script.extend(push_data(&[0_u8; 4]));
    script.extend([opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG]);
    assert!(
        is_multisig(&script),
        "the shape check must accept this, or the length check is never reached"
    );

    let mut tx = standard_tx(1);
    tx.outputs[0].script_pubkey = script.into();
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::NonStandardOutput)
    );
}

#[test]
fn accepts_a_well_formed_bare_multisig() {
    let key = [0x02_u8; 33];
    let mut script = vec![opcode::OP_PUSHNUM_1];
    script.extend(push_data(&key));
    script.extend([opcode::OP_PUSHNUM_1, opcode::OP_CHECKMULTISIG]);

    let mut tx = standard_tx(1);
    tx.outputs[0].script_pubkey = script.into();
    assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
}

#[test]
fn accepts_three_of_three_bare_multisig() {
    let key = [0x02_u8; 33];
    let mut script = vec![opcode::OP_PUSHNUM_1 + 2 /* OP_PUSHNUM_3 */];
    for _ in 0..3 {
        script.extend(push_data(&key));
    }
    script.extend([
        opcode::OP_PUSHNUM_1 + 2, /* OP_PUSHNUM_3 */
        opcode::OP_CHECKMULTISIG,
    ]);

    let mut tx = standard_tx(1);
    tx.outputs[0].script_pubkey = script.into();
    assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
}

#[test]
fn rejects_one_of_four_bare_multisig() {
    let key = [0x02_u8; 33];
    let mut script = vec![opcode::OP_PUSHNUM_1];
    for _ in 0..4 {
        script.extend(push_data(&key));
    }
    script.extend([
        opcode::OP_PUSHNUM_1 + 3, /* OP_PUSHNUM_4 */
        opcode::OP_CHECKMULTISIG,
    ]);

    let mut tx = standard_tx(1);
    tx.outputs[0].script_pubkey = script.into();
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::NonStandardOutput)
    );
}

#[test]
fn accepts_a_pay_to_anchor_output() {
    let mut tx = standard_tx(1);
    tx.outputs.push(TxOut {
        value: Amount::from_sat(240),
        script_pubkey: vec![0x51, 0x02, 0x4e, 0x73].into(),
    });
    assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
}

#[test]
fn rejects_a_transaction_below_the_non_witness_minimum() {
    let mut tx = standard_tx(1);
    tx.outputs[0].value = Amount::ZERO;
    tx.outputs[0].script_pubkey = vec![opcode::OP_RETURN].into();
    assert!(
        tx.base_size() < super::MIN_NON_WITNESS_TX_SIZE,
        "the fixture must be undersized or this test proves nothing"
    );
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::TransactionTooSmall)
    );
}

#[test]
fn rejects_non_pushonly_scriptsig() {
    let mut tx = standard_tx(1);
    tx.inputs[0].script_sig = vec![opcode::OP_DUP].into();
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::ScriptSigNotPushOnly)
    );
}

#[test]
fn rejects_oversized_scriptsig() {
    let mut tx = standard_tx(1);
    let big = vec![0_u8; super::MAX_STANDARD_SCRIPTSIG_SIZE];
    tx.inputs[0].script_sig = push_data(&big).into();
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::ScriptSigTooLarge)
    );
}

#[test]
fn accepts_two_nulldata_outputs_within_the_aggregate_limit() {
    let mut tx = standard_tx(1);
    let first = [vec![opcode::OP_RETURN], push_data(b"first")].concat();
    let second = [vec![opcode::OP_RETURN], push_data(b"second")].concat();
    let limit = [&first, &second]
        .into_iter()
        .fold(0_usize, |total, script| {
            total
                + bitcoin_rs_primitives::varint::encoded_len(
                    u64::try_from(script.len()).unwrap_or(u64::MAX),
                )
                + script.len()
        });
    tx.outputs = vec![
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey: first.into(),
        },
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey: second.into(),
        },
    ];
    let aggregate = StandardnessPolicy {
        max_datacarrier_bytes: Some(limit),
        ..policy()
    };

    assert_eq!(is_standard_tx(&tx, &aggregate), Ok(()));
    let over = StandardnessPolicy {
        max_datacarrier_bytes: Some(limit - 1),
        ..aggregate
    };
    assert_eq!(
        is_standard_tx(&tx, &over),
        Err(StandardnessError::DataCarrierBytesExceeded)
    );
    let disabled = StandardnessPolicy {
        max_datacarrier_bytes: None,
        ..aggregate
    };
    assert_eq!(
        is_standard_tx(&tx, &disabled),
        Err(StandardnessError::DataCarrierDisabled)
    );
}

#[test]
fn dust_relay_fee_changes_the_boundary() {
    let mut tx = standard_tx(1);
    let threshold = minimal_non_dust(&tx.outputs[0].script_pubkey, DUST_RELAY_FEE_SAT_PER_KVB);
    tx.outputs[0].value = Amount::from_sat(threshold - 1);

    assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    let lower_fee = StandardnessPolicy {
        dust_relay_fee: BROADCAST_MIN_FEE_SAT_PER_KVB,
        ..policy()
    };
    assert_eq!(is_standard_tx(&tx, &lower_fee), Ok(()));
    assert!(tx_has_dust_outputs(&tx, DUST_RELAY_FEE_SAT_PER_KVB));
    assert!(!tx_has_dust_outputs(&tx, BROADCAST_MIN_FEE_SAT_PER_KVB));
}

#[test]
fn accepts_single_op_return_within_limit() {
    let mut tx = standard_tx(1);
    let script = [vec![opcode::OP_RETURN], push_data(b"ok")].concat();
    tx.outputs.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script.into(),
    });
    assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
}

#[test]
fn only_one_ephemeral_dust_output_is_standard() {
    let mut tx = standard_tx(1);
    tx.outputs[0].value = Amount::from_sat(1);
    assert_eq!(is_standard_tx(&tx, &policy()), Ok(()));
    tx.outputs.push(tx.outputs[0].clone());
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::DustOutput)
    );
}

#[test]
fn rejects_non_standard_output_script() {
    let mut tx = standard_tx(1);
    tx.outputs[0].script_pubkey = vec![0x74].into();
    assert_eq!(
        is_standard_tx(&tx, &policy()),
        Err(StandardnessError::NonStandardOutput)
    );
}

#[test]
fn signed_delta_clamp_prevents_maxfeerate_rejection_and_retains_effective_rate()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pool = Mempool::new(crate::MempoolLimits::default());
    let tx = standard_tx(2);
    let txid = tx.txid();

    pool.prioritise(txid, -3_000)?;
    assert_eq!(pool.modified_fee_for(txid, 1_000)?, -2_000);

    let context = PackageTxContext {
        fee: 1_000,
        vsize: 100,
        sigop_cost: 0,
        missing_inputs: false,
    };

    let fact = evaluate_one(
        &pool,
        &policy(),
        &tx,
        context,
        Some(10_000),
        None,
        &Bip68Admission::default(),
    );

    assert_ne!(
        fact.reject_reason,
        Some(AcceptanceRejectReason::MaxFeeExceeded)
    );
    assert_eq!(fact.modified_fee, Some(-2_000));
    assert_eq!(fact.effective_fee_rate, Some(0));
    Ok(())
}

#[test]
fn three_vsize_meanings_on_sigop_heavy_tx() -> Result<(), Box<dyn std::error::Error>> {
    use crate::accounting::prepared_context;
    use crate::entry::MempoolEntry;
    use alloc::sync::Arc;

    let mut tx = standard_tx(2);
    let sigop_script = Script::from_bytes(vec![opcode::OP_CHECKSIG; 50]);
    tx.outputs.push(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: sigop_script,
    });

    let prevout = (
        tx.inputs[0].previous_output,
        TxOut {
            value: Amount::from_sat(200_000),
            script_pubkey: p2pkh(&[7_u8; 20]).into(),
        },
    );

    let context = prepared_context(&tx, &[prevout], false);
    assert_eq!(context.sigop_cost, 204);

    let unadjusted_weight = tx.weight();
    let vsize_bip141 = u32::try_from(tx.vsize())?;
    assert_eq!(
        vsize_bip141,
        u32::try_from(Tx::vsize_from_weight(unadjusted_weight))?
    );

    let vsize_adjusted = context.vsize;
    assert_eq!(vsize_adjusted, 1_020);
    assert!(vsize_adjusted > vsize_bip141);

    let entry = MempoolEntry::new(
        Arc::new(tx.clone()),
        vsize_adjusted,
        context.fee,
        1,
        1,
        context.sigop_cost,
    );

    assert_eq!(entry.vsize, vsize_adjusted);
    assert_eq!(entry.vsize, 1_020);
    assert_eq!(entry.bip141_vsize, vsize_bip141);
    assert_eq!(entry.bip141_vsize, u32::try_from(tx.vsize())?);
    assert_eq!(entry.weight, unadjusted_weight);
    Ok(())
}
