//! Pareto-front fee priority ordering coverage.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{MempoolEntry, ParetoFront};

#[test]
fn top_n_returns_highest_rate_entries() -> Result<(), Box<dyn Error>> {
    let mut front = ParetoFront::new();
    let mut expected = Vec::with_capacity(100);

    for i in 0_u32..100 {
        let fee = u64::from(i + 1) * 1_000;
        let entry = MempoolEntry::new(Arc::new(tx(u8::try_from(i)?)), 100, fee, u64::from(i), 1);
        front.insert(i, &entry);
        expected.push((i, entry.fee_rate));
    }

    expected.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let actual: Vec<u32> = front.top_n(10).collect();
    let want: Vec<u32> = expected.into_iter().take(10).map(|(id, _)| id).collect();

    assert_eq!(actual, want);

    Ok(())
}

fn tx(label: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label, 0),
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
