//! Ancestor package policy limit coverage.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolError, MempoolLimits, PolicyError};

#[test]
fn chain_of_twenty_six_unconfirmed_transactions_rejects_twenty_sixth() -> Result<(), Box<dyn Error>>
{
    let mut pool = Mempool::new(MempoolLimits::default());
    let mut previous = outpoint(1, 0);

    for height in 0_u32..25 {
        let label = u8::try_from(height + 2)?;
        let tx = chained_tx(label, previous);
        previous = OutPoint::new(tx.compute_txid(), 0);
        pool.insert_entry(MempoolEntry::new(
            Arc::new(tx),
            4_000,
            1_000,
            u64::from(height),
            1,
        ))?;
    }

    let rejected = chained_tx(40, previous);
    let err = pool
        .insert_entry(MempoolEntry::new(Arc::new(rejected), 4_000, 1_000, 26, 1))
        .err();

    assert_eq!(
        err,
        Some(MempoolError::Policy(PolicyError::TooManyAncestors))
    );
    assert_eq!(pool.len(), 25);

    Ok(())
}

fn chained_tx(label: u8, previous_output: OutPoint) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

fn outpoint(label: u8, vout: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid::from_byte_array(bytes), vout)
}
