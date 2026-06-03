//! Snapshot trailer integration tests for coinstats.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UndoBatch, UtxoAdd, UtxoSet, aggregate_hash, write_snapshot};

#[test]
fn snapshot_trailer_uses_listener_muhash() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let mut changes = BlockChanges::default();
    for index in 0_u32..3 {
        let outpoint = OutPoint::new(txid(index), index);
        changes.add(UtxoAdd::new(outpoint, txout(index), index == 0, 7));
    }

    set.commit_block(&changes, &txid(999))?;

    let mut snapshot = Vec::new();
    let trailer = write_snapshot(&set, &txid(999), 7, &mut snapshot)?;
    let expected = listener.snapshot().muhash.finalize();

    assert_eq!(trailer, expected);
    assert_ne!(trailer, [0_u8; 384]);
    assert_eq!(&snapshot[snapshot.len() - 384..], expected);
    Ok(())
}

#[test]
fn snapshot_trailer_tracks_listener_after_removal() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let removed_outpoint = OutPoint::new(txid(1), 0);
    let kept_outpoint = OutPoint::new(txid(2), 1);
    let removed_txout = txout(1);
    let kept_txout = txout(2);

    let mut adds = BlockChanges::default();
    adds.add(UtxoAdd::new(
        removed_outpoint,
        removed_txout.clone(),
        false,
        7,
    ));
    adds.add(UtxoAdd::new(kept_outpoint, kept_txout.clone(), true, 7));
    set.commit_block(&adds, &txid(100))?;
    let before_removal = listener.snapshot();

    let mut removes = BlockChanges::default();
    removes.remove(removed_outpoint);
    set.commit_block(&removes, &txid(101))?;

    let mut expected = CoinStats::new();
    expected.insert_utxo(&removed_outpoint, &removed_txout, 7, false);
    expected.insert_utxo(&kept_outpoint, &kept_txout, 7, true);
    expected.remove_utxo(&removed_outpoint, &removed_txout, 7, false);

    let after_removal = listener.snapshot();
    assert_eq!(after_removal, expected);
    assert_ne!(
        after_removal.muhash.finalize(),
        before_removal.muhash.finalize()
    );
    assert_eq!(after_removal.utxo_count, 1);
    assert_eq!(after_removal.total_amount, kept_txout.value.to_sat());

    let mut snapshot = Vec::new();
    let trailer = write_snapshot(&set, &txid(101), 8, &mut snapshot)?;
    let expected_trailer = after_removal.muhash.finalize();

    assert_eq!(trailer, expected_trailer);
    assert_eq!(&snapshot[snapshot.len() - 384..], expected_trailer);
    Ok(())
}

#[test]
fn listener_tracks_duplicate_txid_overwrite() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let outpoint = OutPoint::new(txid(30), 0);
    let original = txout(30);
    let replacement = txout(31);

    let mut first = BlockChanges::default();
    first.add(UtxoAdd::new(outpoint, original.clone(), true, 91_722));
    set.commit_block(&first, &txid(100))?;

    let mut overwrite = BlockChanges::default();
    overwrite.add(UtxoAdd::new(outpoint, replacement.clone(), true, 91_842));
    set.commit_block(&overwrite, &txid(101))?;

    let mut expected = CoinStats::new();
    expected.insert_utxo(&outpoint, &original, 91_722, true);
    expected.remove_utxo(&outpoint, &original, 91_722, true);
    expected.insert_utxo(&outpoint, &replacement, 91_842, true);

    let after_overwrite = listener.snapshot();
    assert_eq!(set.get(&outpoint), Some(replacement.clone()));
    assert_eq!(after_overwrite, expected);
    assert_eq!(after_overwrite.utxo_count, 1);
    assert_eq!(after_overwrite.total_amount, replacement.value.to_sat());
    Ok(())
}

#[test]
fn listener_undo_restores_muhash_and_accounting() -> Result<(), Box<dyn std::error::Error>> {
    let (full, full_listener) = listener_set();
    let coinbase_outpoint = OutPoint::new(txid(40), 0);
    let coinbase_txout = txout(40);
    let kept_outpoint = OutPoint::new(txid(41), 0);
    let kept_txout = txout(41);
    let replacement_outpoint = OutPoint::new(txid(42), 0);
    let replacement_txout = txout(42);

    let first = first_undo_test_block(
        coinbase_outpoint,
        coinbase_txout.clone(),
        kept_outpoint,
        kept_txout.clone(),
    );
    full.commit_block(&first, &txid(140))?;

    let mut second = BlockChanges::default();
    second.remove(coinbase_outpoint);
    second.add(UtxoAdd::new(
        replacement_outpoint,
        replacement_txout,
        false,
        2,
    ));
    let mut undo = UndoBatch::default();
    undo.restore(UtxoAdd::new(
        coinbase_outpoint,
        coinbase_txout.clone(),
        true,
        1,
    ));
    undo.remove(replacement_outpoint);

    full.commit_block(&second, &txid(141))?;
    full.undo_block(&undo)?;

    let (first_only, first_only_listener) = listener_set();
    first_only.commit_block(&first, &txid(140))?;

    assert_eq!(full.get(&coinbase_outpoint), Some(coinbase_txout));
    assert_eq!(full.get(&kept_outpoint), Some(kept_txout));
    assert_eq!(full.get(&replacement_outpoint), None);
    assert_eq!(aggregate_hash(&full)?, aggregate_hash(&first_only)?);
    assert_eq!(full.len(), first_only.len());
    assert_observable_stats_eq(&full_listener.snapshot(), &first_only_listener.snapshot());
    Ok(())
}

fn assert_observable_stats_eq(left: &CoinStats, right: &CoinStats) {
    assert_eq!(left.height, right.height);
    assert_eq!(left.total_amount, right.total_amount);
    assert_eq!(left.bogo_size, right.bogo_size);
    assert_eq!(left.tx_count, right.tx_count);
    assert_eq!(left.utxo_count, right.utxo_count);
    assert_eq!(left.muhash.finalize(), right.muhash.finalize());
    assert_eq!(left.muhash.finalize_hash(), right.muhash.finalize_hash());
}

fn listener_set() -> (UtxoSet, CoinStatsListener) {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));
    (set, listener)
}

fn first_undo_test_block(
    coinbase_outpoint: OutPoint,
    coinbase_txout: TxOut,
    kept_outpoint: OutPoint,
    kept_txout: TxOut,
) -> BlockChanges {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(coinbase_outpoint, coinbase_txout, true, 1));
    changes.add(UtxoAdd::new(kept_outpoint, kept_txout, false, 1));
    changes
}

fn txout(index: u32) -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000 + u64::from(index)),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, index.to_le_bytes()[0]]),
    }
}

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
