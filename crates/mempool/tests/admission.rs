extern crate alloc;

use super::TestError;
use alloc::sync::Arc;
use bitcoin_rs_consensus::ValidationEngine;
use std::sync::mpsc;
use std::thread;

use bitcoin_rs_mempool::standardness::{AcceptanceRejectReason, PackageTxContext};
use bitcoin_rs_mempool::{
    AdmissionOrigin, AdmissionRequest, AdmitError, AdmitOutcome, Mempool, MempoolEntry,
    MempoolGateway, MempoolLimits, arm_admission_park, reset_admission_park,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::opcode;

const P2PKH_SCRIPT: &[u8] = &[
    opcode::OP_DUP,
    opcode::OP_HASH160,
    0x14,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    opcode::OP_EQUALVERIFY,
    opcode::OP_CHECKSIG,
];

fn p2sh_true_script() -> Vec<u8> {
    p2sh_script_pubkey(&[
        0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e,
        0xba, 0x30, 0xcd, 0x5a, 0x4b,
    ])
}

fn true_redeem_script_sig() -> Vec<u8> {
    bitcoin_rs_script::push_data(&[opcode::OP_PUSHNUM_1])
}

fn p2sh_script_pubkey(hash: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(23);
    out.push(opcode::OP_HASH160);
    out.push(0x14);
    out.extend_from_slice(hash);
    out.push(opcode::OP_EQUAL);
    out
}

fn p2wsh_script_pubkey(hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(34);
    out.push(opcode::OP_0);
    out.push(0x20);
    out.extend_from_slice(hash);
    out
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

fn tx_one_input(
    prevout: OutPoint,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    output_value: u64,
    output_script: Vec<u8>,
) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::from_stack(witness),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: Script::from_bytes(output_script),
        }],
    }
}

#[expect(clippy::expect_used, reason = "helper assumes even generation")]
fn admission_request(
    gateway: &MempoolGateway,
    tx: &Tx,
    context: PackageTxContext,
    prevouts: Vec<(OutPoint, TxOut)>,
) -> AdmissionRequest {
    AdmissionRequest {
        tx: Arc::new(tx.clone()),
        context,
        prevouts,
        prevout_meta: hashbrown::HashMap::new(),
        csv_active: false,
        next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
        locktime_cutoff: 0,
        max_feerate_sat_per_kvb: None,
        time: 1,
        height: 1,
        origin: AdmissionOrigin::Rpc,
        expected_generation: gateway.stable_generation().expect("generation is even"),
        expected_sequence: gateway.read().sequence_number(),
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "test invariants are checked with expect"
)]
fn stale_policy_verdict_becomes_retryable() -> Result<(), TestError> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        ValidationEngine::Native,
        None,
    ));

    let prev = outpoint(1, 0);
    let tx = tx_one_input(
        prev,
        true_redeem_script_sig(),
        Vec::new(),
        99_000,
        P2PKH_SCRIPT.to_vec(),
    );
    let context = PackageTxContext {
        fee: 1_000,
        vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
        sigop_cost: 0,
        missing_inputs: false,
    };
    let prevouts = vec![(
        prev,
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(p2sh_true_script()),
        },
    )];
    let request = admission_request(&gateway, &tx, context, prevouts);

    let (parked_tx, parked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let target = Arc::as_ptr(&gateway).expose_provenance();
    arm_admission_park(target, parked_tx, release_rx);

    let gateway_for_thread = Arc::clone(&gateway);
    let admission = thread::spawn(move || gateway_for_thread.admit_transaction(request));

    parked_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("admission must park at the gateway seam");

    let unrelated = tx_one_input(
        outpoint(2, 0),
        Vec::new(),
        Vec::new(),
        99_000,
        P2PKH_SCRIPT.to_vec(),
    );
    gateway.insert_entry(
        AdmissionOrigin::Rpc,
        MempoolEntry::new(Arc::new(unrelated), 100, 100_000_000, 1, 1, 0),
    )?;

    release_tx.send(()).expect("release the parked admission");

    let result = admission.join().expect("admission thread did not panic");

    reset_admission_park();

    assert_eq!(
        result,
        Err(AdmitError::MempoolChanged),
        "a stale policy verdict must be downgraded to the retryable transient error"
    );
    Ok(())
}

#[test]
fn p2sh_sigop_cost_exceeds_standard_limit() {
    assert_eq!(
        bitcoin_rs_mempool::standardness::MAX_STANDARD_TX_SIGOPS_COST,
        16_000,
        "POL-04 and Core 31.1 policy.h"
    );
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        ValidationEngine::Native,
        None,
    ));

    let prev = outpoint(3, 0);
    let witness_script = vec![opcode::OP_CHECKMULTISIG; 900];
    let tx = tx_one_input(
        prev,
        bitcoin_rs_script::push_data(&p2wsh_script_pubkey(&[0x42; 32])),
        vec![witness_script],
        99_000,
        P2PKH_SCRIPT.to_vec(),
    );
    let context = PackageTxContext {
        fee: 1_000,
        vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
        sigop_cost: 0,
        missing_inputs: false,
    };
    let prevouts = vec![(
        prev,
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(p2sh_script_pubkey(&[0x42; 20])),
        },
    )];
    let request = admission_request(&gateway, &tx, context, prevouts);

    let result = gateway.admit_transaction(request);

    assert_eq!(
        result,
        Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
        "Core counts 20 sigops for each CHECKMULTISIG in a P2SH-wrapped P2WSH witness script, so 900 exceed the 16,000 standard cost"
    );
    assert_eq!(
        gateway.read().len(),
        0,
        "rejected tx must not enter the pool"
    );
}

#[test]
fn p2wsh_sigop_cost_exceeds_standard_limit() {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        ValidationEngine::Native,
        None,
    ));

    let prev = outpoint(4, 0);
    let witness_script = vec![opcode::OP_CHECKMULTISIG; 800];
    let tx = tx_one_input(
        prev,
        Vec::new(),
        vec![vec![0_u8; 72], witness_script],
        99_000,
        P2PKH_SCRIPT.to_vec(),
    );
    let context = PackageTxContext {
        fee: 1_000,
        vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
        sigop_cost: 0,
        missing_inputs: false,
    };
    let prevouts = vec![(
        prev,
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(p2wsh_script_pubkey(&[0x42; 32])),
        },
    )];
    let request = admission_request(&gateway, &tx, context, prevouts);

    let result = gateway.admit_transaction(request);

    assert_eq!(
        result,
        Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
        "P2WSH witness sigops counted from the prevout must trigger the standard limit"
    );
    assert_eq!(
        gateway.read().len(),
        0,
        "rejected tx must not enter the pool"
    );
}

#[test]
fn overlay_resolved_parent_sigops_trigger_standard_limit() -> Result<(), TestError> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        ValidationEngine::Native,
        None,
    ));

    let parent = tx_one_input(
        outpoint(5, 0),
        Vec::new(),
        Vec::new(),
        100_000,
        p2sh_script_pubkey(&[0x42; 20]),
    );
    let parent_txid = parent.txid();
    gateway.insert_entry(
        AdmissionOrigin::Rpc,
        MempoolEntry::new(Arc::new(parent), 100, 100_000_000, 1, 1, 0),
    )?;

    let witness_script = vec![opcode::OP_CHECKMULTISIG; 900];
    let child = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![
            TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: Script::from_bytes(bitcoin_rs_script::push_data(&p2wsh_script_pubkey(
                    &[0x42; 32],
                ))),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![witness_script]),
            },
            TxIn {
                previous_output: outpoint(6, 0),
                script_sig: Script::from_bytes(true_redeem_script_sig()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            },
        ],
        outputs: vec![TxOut {
            value: Amount::from_sat(198_000),
            script_pubkey: Script::from_bytes(P2PKH_SCRIPT.to_vec()),
        }],
    };
    let context = PackageTxContext {
        fee: 1_000,
        vsize: u32::try_from(child.vsize()).unwrap_or(u32::MAX),
        sigop_cost: 0,
        missing_inputs: false,
    };
    let prevouts = vec![(
        outpoint(6, 0),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(p2sh_true_script()),
        },
    )];
    let request = admission_request(&gateway, &child, context, prevouts);

    let result = gateway.admit_transaction(request);

    assert_eq!(
        result,
        Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
        "overlay-resolved P2SH-wrapped P2WSH sigops must trigger the standard limit despite the omission"
    );
    assert_eq!(
        gateway.read().len(),
        1,
        "only the parent must remain in the pool"
    );
    Ok(())
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "test invariants are checked with expect"
)]
fn caller_sigop_cost_is_ignored_in_stored_entry() -> Result<(), TestError> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        ValidationEngine::Native,
        None,
    ));

    let prev = outpoint(5, 0);
    let tx = tx_one_input(
        prev,
        true_redeem_script_sig(),
        Vec::new(),
        99_000,
        p2sh_script_pubkey(&[0x42; 20]),
    );
    let context = PackageTxContext {
        fee: 1_000,
        vsize: u32::try_from(tx.vsize()).unwrap_or(u32::MAX),
        sigop_cost: u32::MAX,
        missing_inputs: false,
    };
    let prevouts = vec![(
        prev,
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(p2sh_true_script()),
        },
    )];
    let request = admission_request(&gateway, &tx, context, prevouts);

    let result = gateway.admit_transaction(request)?;
    let txid = tx.txid();
    let AdmitOutcome::Committed(_) = result else {
        panic!("tx must be committed, got {result:?}");
    };

    let pool = gateway.read();
    let entry_id = pool
        .entry_id_by_txid(&txid)
        .expect("tx must be in the pool");
    let entry = pool.entry(entry_id).expect("entry must exist");
    assert_eq!(
        entry.sigop_cost, 0,
        "stored sigop cost must be the computed value, not the caller-supplied u32::MAX"
    );
    Ok(())
}

#[test]
fn v3_sibling_eviction_with_empty_direct_conflicts_admits_through_the_replacement_door()
-> Result<(), TestError> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(
        pool,
        None,
        bitcoin_rs_consensus::ValidationEngine::Native,
        None,
    ));

    let parent = Tx {
        version: 3,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: outpoint(20, 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xFFFF_FFFF),
            witness: Witness::new(),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
            TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: Script::from_bytes(p2sh_true_script()),
            },
        ],
    };
    let parent_txid = parent.txid();
    gateway.insert_entry(
        AdmissionOrigin::Rpc,
        MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 1, 0),
    )?;

    let mut sibling = tx_one_input(
        OutPoint::new(parent_txid, 0),
        Vec::new(),
        Vec::new(),
        59_000,
        P2PKH_SCRIPT.to_vec(),
    );
    sibling.version = 3;
    let sibling_txid = sibling.txid();
    gateway.insert_entry(
        AdmissionOrigin::Rpc,
        MempoolEntry::new(Arc::new(sibling), 100, 1_000, 1, 1, 0),
    )?;

    let mut candidate = tx_one_input(
        OutPoint::new(parent_txid, 1),
        true_redeem_script_sig(),
        Vec::new(),
        37_000,
        P2PKH_SCRIPT.to_vec(),
    );
    candidate.version = 3;
    let candidate_txid = candidate.txid();
    let context = PackageTxContext {
        fee: 3_000,
        vsize: u32::try_from(candidate.vsize()).unwrap_or(u32::MAX),
        sigop_cost: 0,
        missing_inputs: false,
    };
    let prevouts = vec![(
        OutPoint::new(parent_txid, 1),
        TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(p2sh_true_script()),
        },
    )];
    let request = admission_request(&gateway, &candidate, context, prevouts);

    let result = gateway.admit_transaction(request)?;
    let AdmitOutcome::Committed(changes) = result else {
        panic!("the sibling-evicting candidate must commit, got {result:?}");
    };

    let pool = gateway.read();
    assert_eq!(
        changes.removed_txids(),
        vec![sibling_txid],
        "the sibling leaves through the replacement door"
    );
    assert!(
        pool.contains_txid(&candidate_txid),
        "the candidate must be resident"
    );
    assert!(pool.contains_txid(&parent_txid), "the parent stays");
    assert!(
        !pool.contains_txid(&sibling_txid),
        "the evicted sibling must be gone"
    );
    Ok(())
}
