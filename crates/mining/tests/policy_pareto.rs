//! Mining policy Pareto-front selection tests.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::MiningPolicy;

#[test]
fn selects_transactions_by_pareto_fee_rate_until_weight_limit() -> Result<(), Box<dyn Error>> {
    let mut mempool = Mempool::new(MempoolLimits::default());
    let mut entries = Vec::with_capacity(50);

    for index in 0_u32..50 {
        let vsize = 100 + (index % 5);
        let fee = u64::from(50_u32 - index) * 1_000;
        let entry = MempoolEntry::new(
            Arc::new(tx(u8::try_from(index)?)),
            vsize,
            fee,
            u64::from(index),
            800_000,
        );
        let id = mempool.insert_entry(entry.clone())?;
        entries.push((id, entry.fee_rate));
    }

    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let selected = MiningPolicy.select_transactions(&mempool, 4_000_000);
    let expected = entries.into_iter().map(|(id, _)| id).collect::<Vec<_>>();

    assert_eq!(selected, expected);
    Ok(())
}

fn tx(label: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
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

fn outpoint(label: u8) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid::from_byte_array(bytes), 0)
}
