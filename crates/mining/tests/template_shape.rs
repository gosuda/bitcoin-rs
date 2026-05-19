//! Block template JSON shape tests.

extern crate alloc;

use alloc::sync::Arc;
use std::error::Error;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::{BlockTemplate, BlockTemplateParams, MiningPolicy};
use bitcoin_rs_primitives::Hash256;
use serde_json::Value;

#[test]
fn block_template_serializes_core_required_fields() -> Result<(), Box<dyn Error>> {
    let mut mempool = Mempool::new(MempoolLimits::default());
    for index in 0_u32..100 {
        let entry = MempoolEntry::new(
            Arc::new(tx(u8::try_from(index)?)),
            100,
            u64::from(index + 1) * 500,
            u64::from(index),
            800_000,
        );
        mempool.insert_entry(entry)?;
    }

    let params = BlockTemplateParams {
        previous_block_hash: Hash256::from_le_bytes(&[1_u8; 32]),
        height: 800_001,
        version: 0x2000_0000,
        bits: "17034219".to_owned(),
        target: "0000000000000000000342190000000000000000000000000000000000000000".to_owned(),
        min_time: 1_700_000_000,
        current_time: 1_700_000_123,
        long_poll_id: "synthetic".to_owned(),
        max_weight: 4_000_000,
        max_sigops: 80_000,
        max_size: 4_000_000,
        witness_commitment: Hash256::from_le_bytes(&[2_u8; 32]),
    };

    let template = BlockTemplate::from_mempool(&mempool, &MiningPolicy, params)?;
    let json = serde_json::to_value(template)?;

    assert_number(&json, "version")?;
    assert_string(&json, "previousblockhash")?;
    assert_array(&json, "transactions")?;
    assert_object(&json, "coinbaseaux")?;
    assert_number(&json, "coinbasevalue")?;
    assert_string(&json, "longpollid")?;
    assert_string(&json, "target")?;
    assert_number(&json, "mintime")?;
    assert_array(&json, "mutable")?;
    assert_string(&json, "noncerange")?;
    assert_number(&json, "sigoplimit")?;
    assert_number(&json, "sizelimit")?;
    assert_number(&json, "weightlimit")?;
    assert_number(&json, "curtime")?;
    assert_string(&json, "bits")?;
    assert_number(&json, "height")?;
    assert_string(&json, "default_witness_commitment")?;

    let transactions = json
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or("transactions is not an array")?;
    assert_eq!(transactions.len(), 100);
    for tx in transactions {
        assert_string(tx, "data")?;
        assert_string(tx, "txid")?;
        assert_string(tx, "hash")?;
        assert_array(tx, "depends")?;
        assert_number(tx, "fee")?;
        assert_number(tx, "sigops")?;
        assert_number(tx, "weight")?;
    }

    Ok(())
}

fn assert_string(value: &Value, key: &str) -> Result<(), Box<dyn Error>> {
    value
        .get(key)
        .filter(|field| field.is_string())
        .map(|_| ())
        .ok_or_else(|| format!("{key} is not a string").into())
}

fn assert_number(value: &Value, key: &str) -> Result<(), Box<dyn Error>> {
    value
        .get(key)
        .filter(|field| field.is_number())
        .map(|_| ())
        .ok_or_else(|| format!("{key} is not a number").into())
}

fn assert_array(value: &Value, key: &str) -> Result<(), Box<dyn Error>> {
    value
        .get(key)
        .filter(|field| field.is_array())
        .map(|_| ())
        .ok_or_else(|| format!("{key} is not an array").into())
}

fn assert_object(value: &Value, key: &str) -> Result<(), Box<dyn Error>> {
    value
        .get(key)
        .filter(|field| field.is_object())
        .map(|_| ())
        .ok_or_else(|| format!("{key} is not an object").into())
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
