//! Gateway admission defects: stale-verdict retryability and prevout-aware sigop
//! counting.
//!
//! Admission expectations are governed by `docs/contracts/mempool-policy.md`,
//! especially POL-03 (fresh stamped admission context) and POL-04 (owner-
//! computed sigop limits).
//!
//! A failed pool or fixture invariant is a test failure, and panicking reports
//! it with the offending call site. `expect` is deliberate on individual tests.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;
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

fn anyone_can_spend() -> Vec<u8> {
    vec![opcode::OP_PUSHNUM_1]
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
        lock_time: LockTime::from_consensus(0),
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
        locktime_cutoff: 0,
        max_feerate_sat_per_kvb: None,
        time: 1,
        height: 1,
        origin: AdmissionOrigin::Rpc,
        expected_generation: gateway.stable_generation().expect("generation is even"),
        expected_sequence: gateway.read().sequence_number(),
    }
}

/// A stale Policy/Consensus verdict from `prepare_and_verify` is discarded when
/// the pool or generation mutates before the writer re-check, and the caller
#[test]
#[expect(
    clippy::expect_used,
    reason = "test invariants are checked with expect"
)]
fn stale_policy_verdict_becomes_retryable() -> Result<(), Box<dyn Error>> {
    // Default limits: the request must pass `prepare_and_verify` in full so
    // the parked admission reaches the writer recheck rather than failing
    // policy before the seam.
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(pool, None));

    let prev = outpoint(1, 0);
    let tx = tx_one_input(prev, Vec::new(), Vec::new(), 99_000, P2PKH_SCRIPT.to_vec());
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
            script_pubkey: Script::from_bytes(anyone_can_spend()),
        },
    )];
    let request = admission_request(&gateway, &tx, context, prevouts);

    // Arm the park so the admission thread stops between `prepare_and_verify`
    // and acquiring the pool writer.
    let (parked_tx, parked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let target = Arc::as_ptr(&gateway).expose_provenance();
    arm_admission_park(target, parked_tx, release_rx);

    let gateway_for_thread = Arc::clone(&gateway);
    let admission = thread::spawn(move || gateway_for_thread.admit_transaction(request));

    parked_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("admission must park at the gateway seam");

    // While the admission holds no lock and is parked, mutate the pool so the
    // sequence token the request carried becomes stale.
    let unrelated = tx_one_input(
        outpoint(2, 0),
        Vec::new(),
        Vec::new(),
        99_000,
        P2PKH_SCRIPT.to_vec(),
    );
    gateway.insert_entry(
        AdmissionOrigin::Rpc,
        MempoolEntry::new(Arc::new(unrelated), 100, 100_000_000, 1, 1),
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

/// A P2SH spend whose redeem script is heavy with `OP_CHECKMULTISIG` is
/// rejected before script verification because `total_sigop_cost` sees the
/// P2SH sigops once the prevout is known.
#[test]
fn p2sh_sigop_cost_exceeds_standard_limit() {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(pool, None));

    let prev = outpoint(3, 0);
    let redeem = vec![opcode::OP_CHECKMULTISIG; 200];
    let tx = tx_one_input(
        prev,
        bitcoin_rs_script::push_data(&redeem),
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
            script_pubkey: Script::from_bytes(p2sh_script_pubkey(&[0x42; 20])),
        },
    )];
    let request = admission_request(&gateway, &tx, context, prevouts);

    let result = gateway.admit_transaction(request);

    assert_eq!(
        result,
        Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
        "P2SH sigops counted from the prevout must trigger the standard limit"
    );
    assert_eq!(
        gateway.read().len(),
        0,
        "rejected tx must not enter the pool"
    );
}

/// A P2WSH spend whose witness script is heavy with `OP_CHECKMULTISIG` is
/// rejected before script verification because `total_sigop_cost` sees the
/// witness sigops once the prevout is known.
#[test]
fn p2wsh_sigop_cost_exceeds_standard_limit() {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(pool, None));

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

/// A child spending an in-pool P2SH parent counts the parent's sigops even
/// when the request omits that prevout: verification resolves the input
/// through the mempool overlay, so the sigop gate must resolve through the
/// same view instead of counting the omission as zero.
#[test]
fn overlay_resolved_parent_sigops_trigger_standard_limit() -> Result<(), Box<dyn Error>> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(pool, None));

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
        MempoolEntry::new(Arc::new(parent), 100, 100_000_000, 1, 1),
    )?;

    let redeem = vec![opcode::OP_CHECKMULTISIG; 200];
    // Two inputs: input 0 spends the in-pool P2SH parent whose prevout the
    // request omits; input 1 spends a plain resolved prevout so the request
    // is non-empty and passes the empty-prevouts refusal.
    let child = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![
            TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: Script::from_bytes(bitcoin_rs_script::push_data(&redeem)),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::new(),
            },
            TxIn {
                previous_output: outpoint(6, 0),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(u32::MAX),
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
    // The request carries only input 1's prevout; the pool resolves input 0.
    let prevouts = vec![(
        outpoint(6, 0),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: Script::from_bytes(anyone_can_spend()),
        },
    )];
    let request = admission_request(&gateway, &child, context, prevouts);

    let result = gateway.admit_transaction(request);

    assert_eq!(
        result,
        Err(AdmitError::Policy(AcceptanceRejectReason::TooManySigops)),
        "overlay-resolved P2SH sigops must trigger the standard limit despite the omission"
    );
    assert_eq!(
        gateway.read().len(),
        1,
        "only the parent must remain in the pool"
    );
    Ok(())
}

/// A caller-supplied `sigop_cost` must be ignored: the stored entry carries the
/// value computed from the resolved prevouts.
#[test]
#[expect(
    clippy::expect_used,
    reason = "test invariants are checked with expect"
)]
fn caller_sigop_cost_is_ignored_in_stored_entry() -> Result<(), Box<dyn Error>> {
    let pool = Arc::new(parking_lot::RwLock::new(Mempool::new(
        MempoolLimits::default(),
    )));
    let gateway = Arc::new(MempoolGateway::new(pool, None));

    let prev = outpoint(5, 0);
    let tx = tx_one_input(
        prev,
        Vec::new(),
        Vec::new(),
        99_000,
        p2sh_script_pubkey(&[0x42; 20]),
    );
    // Claim an absurd sigop cost; the gateway must not use it.
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
            script_pubkey: Script::from_bytes(anyone_can_spend()),
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
