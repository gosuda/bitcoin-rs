use std::io::Cursor;

use crate::support::utxo::TestResult;
use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_storage::utxo::{UtxoSet, read_snapshot_strict_v4, write_snapshot_observed};

fn make_txid(prefix: [u8; 8], suffix_byte: u8) -> Hash256 {
    let mut bytes = [suffix_byte; 32];
    bytes[..8].copy_from_slice(&prefix);
    Hash256::from_le_bytes(&bytes)
}

fn sample_txout(value: u64, tag: u8) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: vec![0x51, tag].into(),
    }
}

// RCV-01, RCV-03
#[test]
fn recovers_from_key_prefix_collisions_in_utxo_set_and_snapshot() -> TestResult {
    use bitcoin_rs_storage::utxo::UtxoReader;
    use bitcoin_rs_storage::utxo::contract::populate_block_changes;
    use bitcoin_rs_storage::{CoinStore, MemoryKvStore};
    use std::sync::Arc;

    let store = Arc::new(MemoryKvStore::new());
    let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
    let reader = UtxoReader::from_coin_store(coin_store.clone());
    let prefix = [0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let txid_a = make_txid(prefix, 0xaa);
    let txid_b = make_txid(prefix, 0xbb);
    assert_ne!(txid_a, txid_b);

    let op_a0 = OutPoint::new(Txid::from(txid_a), 0);
    let op_a1 = OutPoint::new(Txid::from(txid_a), 1);
    let op_b0 = OutPoint::new(Txid::from(txid_b), 0);
    let op_b2 = OutPoint::new(Txid::from(txid_b), 2);

    let txout_a0 = sample_txout(1_000, 0xa0);
    let txout_a1 = sample_txout(2_000, 0xa1);
    let txout_b0 = sample_txout(3_000, 0xb0);
    let txout_b2 = sample_txout(4_000, 0xb2);

    let mut block1 = BlockChanges::default();
    block1.add(UtxoAdd::new(op_a0, txout_a0.clone(), false, 100));
    block1.add(UtxoAdd::new(op_a1, txout_a1.clone(), true, 100));
    block1.add(UtxoAdd::new(op_b0, txout_b0.clone(), false, 101));
    block1.add(UtxoAdd::new(op_b2, txout_b2.clone(), false, 101));
    populate_block_changes(&coin_store, &block1)?;

    assert!(reader.has_live_outputs_for_txid(&txid_a));
    assert!(reader.has_live_outputs_for_txid(&txid_b));
    assert_eq!(reader.get(&op_a0), Some(txout_a0));
    assert_eq!(reader.get(&op_a1), Some(txout_a1.clone()));
    assert_eq!(reader.get(&op_b0), Some(txout_b0.clone()));
    assert_eq!(reader.get(&op_b2), Some(txout_b2.clone()));

    let mut block2 = BlockChanges::<TxOut>::default();
    block2.remove(op_a0);
    populate_block_changes(&coin_store, &block2)?;

    assert!(reader.has_live_outputs_for_txid(&txid_a));
    assert!(reader.has_live_outputs_for_txid(&txid_b));
    assert_eq!(reader.get(&op_a0), None);
    assert_eq!(reader.get(&op_a1), Some(txout_a1));
    assert_eq!(reader.get(&op_b0), Some(txout_b0.clone()));
    assert_eq!(reader.get(&op_b2), Some(txout_b2.clone()));

    let mut block3 = BlockChanges::<TxOut>::default();
    block3.remove(op_a1);
    populate_block_changes(&coin_store, &block3)?;

    assert!(!reader.has_live_outputs_for_txid(&txid_a));
    assert!(reader.has_live_outputs_for_txid(&txid_b));
    assert_eq!(reader.get(&op_a1), None);
    assert_eq!(reader.get(&op_b0), Some(txout_b0.clone()));
    assert_eq!(reader.get(&op_b2), Some(txout_b2.clone()));

    let mut block4 = BlockChanges::default();
    let op_a5 = OutPoint::new(Txid::from(txid_a), 5);
    let txout_a5 = sample_txout(5_000, 0xa5);
    block4.add(UtxoAdd::new(op_a5, txout_a5.clone(), false, 104));
    populate_block_changes(&coin_store, &block4)?;

    assert!(reader.has_live_outputs_for_txid(&txid_a));
    assert!(reader.has_live_outputs_for_txid(&txid_b));
    assert_eq!(reader.get(&op_a5), Some(txout_a5.clone()));
    assert_eq!(reader.get(&op_b0), Some(txout_b0.clone()));

    let set = UtxoSet::new();
    let out_a5 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 5,
        value: 5_000,
        script_pubkey: txout_a5.script_pubkey.to_vec(),
        coinbase: false,
        height: 104,
    };
    let out_b0 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 0,
        value: 3_000,
        script_pubkey: txout_b0.script_pubkey.to_vec(),
        coinbase: false,
        height: 101,
    };
    let out_b2 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
        vout: 2,
        value: 4_000,
        script_pubkey: txout_b2.script_pubkey.to_vec(),
        coinbase: false,
        height: 101,
    };
    let rec_a =
        bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(txid_a, &[out_a5])?;
    let rec_b = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        txid_b,
        &[out_b0, out_b2],
    )?;
    set.insert_parsed_record(rec_a);
    set.insert_parsed_record(rec_b);
    assert_eq!(reader.get(&op_b2), Some(txout_b2.clone()));

    let mut snapshot_bytes = Vec::new();
    let tip = Hash256::from_le_bytes(&[5; 32]);
    write_snapshot_observed(&set, &tip, 104, &mut snapshot_bytes, ())?;
    let loaded = read_snapshot_strict_v4(&mut Cursor::new(&snapshot_bytes))?;
    assert_eq!(loaded.set.len(), 3);
    assert_eq!(loaded.set.record_count(), 2);
    assert!(loaded.set.has_live_outputs_for_txid(&txid_a));
    assert!(loaded.set.has_live_outputs_for_txid(&txid_b));

    Ok(())
}
