#![no_main]

use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::{Hash as _, sha256};
use libfuzzer_sys::fuzz_target;
use bitcoin_rs_consensus::{
    rust_path::UtxoView, verify_transaction, verify_transaction_non_script,
};
use bitcoin_rs_mempool::{StandardnessPolicy, is_standard_tx};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    deserialize as native_deserialize,
};
use bitcoin_rs_script::VerifyFlags;

/// Applied chain context shared by every validation path below, so the
/// consensus and policy legs can never silently disagree on height or
/// lock-time cutoff.
const HEIGHT: u32 = 800_001;
const LOCKTIME_CUTOFF: u32 = 1_700_000_000;

/// Prevouts for every input in `tx`, so consensus and policy checks run
/// past missing-input rejection.
struct SpendingView<'a> {
    prevouts: &'a [(OutPoint, TxOut)],
}

impl UtxoView for SpendingView<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.prevouts
            .iter()
            .find(|(prev, _)| prev == outpoint)
            .map(|(_, output)| output.clone())
    }
}

/// Non-null, non-all-zero prevout so a witness-only seed is not treated as
/// coinbase (`OutPoint::is_null`) or rejected by mempool/node all-zero
/// outpoint policy.
fn synthetic_prevout() -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11; 32])), 0)
}

/// Standard legacy anyone-can-spend output.
fn op_true_prevout() -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000_000),
        script_pubkey: vec![0x51].into(),
    }
}

/// Fills `seed` to `len` bytes by cycling, guarding an empty seed.
fn cycled(seed: &[u8], len: usize) -> Vec<u8> {
    if seed.is_empty() {
        return vec![0; len];
    }
    (0..len).map(|index| seed[index % seed.len()]).collect()
}

/// Per-input prevout: a no-witness input spends a safe legacy OP_TRUE
/// output; a witness input spends a witness-program output shaped from the
/// stack so the standard-flags script gate exercises SegWit/Taproot paths
/// instead of rejecting the stack as unexpected.
fn witness_aware_prevout(input: &TxIn) -> TxOut {
    let stack: &[Vec<u8>] = &input.witness;
    let script_pubkey = match stack {
        [item] => [vec![0x51, 0x20], cycled(item, 32)].concat(),
        [_, second] => [vec![0x00, 0x14], cycled(second, 20)].concat(),
        // P2WSH (three or more items): the program is the sha256 of the
        // witness script (the last item), so the hash check passes and the
        // fuzzed script bytes execute under witness rules.
        [.., script] => {
            let mut program = vec![0x00, 0x20];
            program.extend_from_slice(sha256::Hash::hash(script).as_byte_array());
            program
        }
        // Empty witness: the safe legacy OP_TRUE path.
        [] => return op_true_prevout(),
    };
    TxOut {
        value: Amount::from_sat(50_000_000),
        script_pubkey: Script::from_bytes(script_pubkey),
    }
}

/// Prevouts resolved per input, in input order.
fn resolve_prevouts(tx: &Tx) -> Vec<(OutPoint, TxOut)> {
    tx.inputs
        .iter()
        .map(|input| (input.previous_output, witness_aware_prevout(input)))
        .collect()
}

fn validate_native(tx: Tx) {
    let tx = Arc::new(tx);
    let prevouts = resolve_prevouts(&tx);
    let view = SpendingView {
        prevouts: &prevouts,
    };
    // Non-script consensus leg at the applied height.
    let _ = verify_transaction_non_script(
        &tx,
        &view,
        HEIGHT,
        LOCKTIME_CUTOFF,
        VerifyFlags::STANDARD,
    );
    // Full script leg, the same gate admission runs at the spending height:
    // witness stacks now reach SegWit/Taproot verification through the
    // witness-program prevouts above.
    let _ = verify_transaction(
        &tx,
        &view,
        HEIGHT.saturating_add(1),
        LOCKTIME_CUTOFF,
        VerifyFlags::STANDARD,
    );
    // Policy leg.
    let _ = is_standard_tx(&tx, &StandardnessPolicy::default());
}

/// rust-bitcoin parses tx/witness; bitcoin-rs runs consensus and policy.
fn validate_tx(data: &[u8]) {
    if let Ok(parsed) = deserialize::<bitcoin::Transaction>(data) {
        let encoded = serialize(&parsed);
        let Ok(tx) = native_deserialize::<Tx>(&encoded) else {
            return;
        };
        validate_native(tx);
        return;
    }
    let Ok(witness) = deserialize::<bitcoin::Witness>(data) else {
        return;
    };
    let stack: Vec<Vec<u8>> = witness.iter().map(|element| element.to_vec()).collect();
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: synthetic_prevout(),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(stack),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            // Standard P2WPKH output: base size 82 (>= 65) and non-dust.
            script_pubkey: Script::from_bytes([vec![0x00, 0x14], vec![0x22; 20]].concat()),
        }],
        lock_time: LockTime::ZERO,
    };
    validate_native(tx);
}

fuzz_target!(|data: &[u8]| {
    validate_tx(data);
});
