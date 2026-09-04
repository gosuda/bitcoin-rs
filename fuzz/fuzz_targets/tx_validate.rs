#![no_main]

use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use libfuzzer_sys::fuzz_target;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_consensus::verify_transaction_non_script;
use bitcoin_rs_mempool::{
    AcceptContext, Mempool, MempoolLimits, StandardnessPolicy, check_acceptance,
};
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, deserialize as native_deserialize};

const SYNTHETIC_OUTPOINT: OutPoint = OutPoint {
    txid: Default::default(),
    vout: 0,
};

/// Prevouts for every input in `tx`, so consensus and mempool checks run
/// past missing-input rejection.
struct SpendingView<'a> {
    tx: &'a Tx,
    coin: TxOut,
}

impl UtxoView for SpendingView<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.tx
            .inputs
            .iter()
            .any(|input| input.previous_output == *outpoint)
            .then(|| self.coin.clone())
    }
}

fn accept_context() -> AcceptContext {
    AcceptContext {
        height: 800_001,
        locktime_cutoff: 1_700_000_000,
        time: 42,
        standardness: StandardnessPolicy::default(),
        require_standard: false,
        max_fee: None,
    }
}

fn validate_native(tx: Tx) {
    let tx = Arc::new(tx);
    let view = SpendingView {
        coin: TxOut {
            value: 50_000_000,
            // A v0 witness program makes non-empty witness stacks exercise
            // witness validation rather than the legacy script path.
            script_pubkey: vec![0x00, 0x20]
                .into_iter()
                .chain([0u8; 32])
                .collect(),
        },
        tx: tx.as_ref(),
    };
    let context = accept_context();
    let _ = verify_transaction_non_script(&tx, &view, context.height, context.locktime_cutoff);
    let pool = Mempool::new(MempoolLimits::default());
    let _ = check_acceptance(&pool, &tx, &view, &context);
}

/// rust-bitcoin parses tx/witness; bitcoin-rs runs consensus and mempool.
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
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: SYNTHETIC_OUTPOINT,
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: stack,
        }],
        outputs: vec![TxOut {
            value: 50_000,
            script_pubkey: Vec::new(),
        }],
        lock_time: 0,
    };
    validate_native(tx);
}

fuzz_target!(|data: &[u8]| {
    validate_tx(data);
});
