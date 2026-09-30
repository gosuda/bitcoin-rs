//! Transaction fixtures shared by in-crate unit tests.

use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

/// A one-input, one-output transaction distinguished by `label`: it spends
/// vout 0 of the txid filled with `label`, so distinct labels never conflict.
pub(crate) fn tx(label: u8) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51, label].into(),
        }],
    }
}
