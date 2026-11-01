#![no_main]

use bitcoin::hashes::Hash;
use bitcoin_rs_primitives::{DecodeError, Tx, consensus_bytes, deserialize};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let our_res = deserialize::<Tx>(data);
    let rust_res = bitcoin::consensus::deserialize::<bitcoin::Transaction>(data);

    match (our_res, rust_res) {
        (Ok(our_tx), Ok(rust_tx)) => {
            assert_eq!(
                our_tx.txid().as_bytes(),
                rust_tx.compute_txid().as_byte_array(),
                "txid mismatch"
            );
            assert_eq!(
                our_tx.wtxid().as_bytes(),
                rust_tx.compute_wtxid().as_byte_array(),
                "wtxid mismatch"
            );
            assert_eq!(our_tx.weight(), rust_tx.weight().to_wu(), "weight mismatch");
            let our_bytes = consensus_bytes(&our_tx);
            let rust_bytes = bitcoin::consensus::serialize(&rust_tx);
            assert_eq!(our_bytes, rust_bytes, "re-encoded bytes mismatch");
        }
        (Ok(our_tx), Err(_)) if our_tx.inputs.is_empty() && zero_flag_dummy(data) => {}
        (Err(DecodeError::SuperfluousWitness), Ok(_)) => {}
        (Ok(_), Err(err)) => {
            panic!(
                "differential disagreement: our parser accepted but rust-bitcoin rejected: {err:?}"
            );
        }
        (Err(err), Ok(_)) => {
            panic!(
                "differential disagreement: rust-bitcoin accepted but our parser rejected: {err:?}"
            );
        }
        (Err(_), Err(_)) => {}
    }
});

fn zero_flag_dummy(data: &[u8]) -> bool {
    data.len() >= 6 && data[4] == 0 && data[5] == 0
}
