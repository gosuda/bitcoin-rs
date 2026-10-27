//! Shared fixtures for mempool unit tests.
//!
//! Kept deliberately small: only fixtures that were byte-identical between
//! test modules live here. Integration targets under `tests/` cannot see
//! this module and keep their own copies.

use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, Wtxid,
};

use crate::MempoolGateway;

/// One-input, one-output standard spend labelled by `label`.
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

/// Multi-input fan-in spend: `outputs` bare outputs, all values derived from
/// `tag` so distinct tags produce distinct transactions.
pub(crate) fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: (0..outputs)
            .map(|vout| TxOut {
                value: Amount::from_sat(
                    10_000_u64
                        .saturating_add(u64::from(vout))
                        .saturating_add(tag.saturating_mul(1_000)),
                ),
                script_pubkey: alloc::vec![0x51].into(),
            })
            .collect(),
    }
}

/// Every (txid, wtxid) pair the gateway holds for BIP152 reconstruction.
pub(crate) fn reconstruction_identities(gateway: &MempoolGateway) -> Vec<(Txid, Wtxid)> {
    let mut seen = Vec::new();
    gateway.for_each_reconstruction_identity(|txid, wtxid| seen.push((txid, wtxid)));
    seen
}
