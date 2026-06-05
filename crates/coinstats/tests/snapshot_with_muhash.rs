//! Snapshot trailer integration tests for coinstats.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{
    BlockChanges, UndoBatch, UtxoAdd, UtxoChangeListener, UtxoInserted, UtxoKey, UtxoRemoved,
    UtxoSet, aggregate_hash, write_snapshot,
};

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
fn listener_coalesced_parallel_path_preserves_overwrite_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::default();
    let mut seeded = Vec::new();

    for shard in 0_u8..20 {
        let index = u32::from(shard);
        let outpoint = OutPoint::new(txid_in_shard(shard, 1_100 + u64::from(shard)), index);
        let original = txout(1_100 + index);
        assert_eq!(UtxoKey::from_txid(&outpoint.txid).shard(), shard);
        expected.insert_utxo(&outpoint, &original, 110, shard % 2 == 0);
        initial.add(UtxoAdd::new(
            outpoint,
            original.clone(),
            shard % 2 == 0,
            110,
        ));
        seeded.push((outpoint, original, shard % 2 == 0));
    }
    set.commit_block(&initial, &txid(2_100))?;

    let mut overwrite = BlockChanges::default();
    let mut replacements = Vec::new();
    for (index, (outpoint, original, coinbase)) in seeded.iter().enumerate().rev() {
        let index = u32::try_from(index)?;
        let replacement = txout(1_400 + index);
        expected.remove_utxo(outpoint, original, 110, *coinbase);
        expected.insert_utxo(outpoint, &replacement, 111, false);
        overwrite.add(UtxoAdd::new(*outpoint, replacement.clone(), false, 111));
        replacements.push((*outpoint, replacement));
    }
    set.commit_block(&overwrite, &txid(2_101))?;

    assert_observable_stats_eq(&listener.snapshot(), &expected);
    for (outpoint, replacement) in replacements {
        assert_eq!(set.get(&outpoint), Some(replacement));
    }
    Ok(())
}

#[test]
fn listener_parallel_shard_delta_matches_serial_stats() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::default();
    let mut removals = Vec::new();
    let mut replacements = Vec::new();

    for shard in 0_u8..20 {
        let index = u32::from(shard);
        let outpoint = OutPoint::new(txid_in_shard(shard, 700 + u64::from(shard)), index);
        let txout = txout(700 + index);
        assert_eq!(UtxoKey::from_txid(&outpoint.txid).shard(), shard);
        expected.insert_utxo(&outpoint, &txout, 70, shard % 2 == 0);
        initial.add(UtxoAdd::new(outpoint, txout, shard % 2 == 0, 70));
        removals.push(outpoint);
    }
    set.commit_block(&initial, &txid(1_700))?;

    let mut mixed = BlockChanges::default();
    for shard in (0_u8..20).rev() {
        let index = u32::from(shard);
        let replacement = OutPoint::new(txid_in_shard(shard, 900 + u64::from(shard)), 100 + index);
        let replacement_txout = txout(900 + index);
        let removed_txout = txout(700 + index);
        expected.remove_utxo(
            &removals[usize::from(shard)],
            &removed_txout,
            70,
            shard % 2 == 0,
        );
        expected.insert_utxo(&replacement, &replacement_txout, 71, false);
        mixed.remove(removals[usize::from(shard)]);
        mixed.add(UtxoAdd::new(replacement, replacement_txout, false, 71));
        replacements.push((replacement, txout(900 + index)));
    }
    set.commit_block(&mixed, &txid(1_701))?;

    let actual = listener.snapshot();
    assert_observable_stats_eq(&actual, &expected);
    for removed in removals {
        assert_eq!(set.get(&removed), None);
    }
    for (replacement, txout) in replacements {
        assert_eq!(set.get(&replacement), Some(txout));
    }

    let mut snapshot = Vec::new();
    let trailer = write_snapshot(&set, &txid(1_701), 71, &mut snapshot)?;
    assert_eq!(trailer, expected.muhash.finalize());
    assert_eq!(
        &snapshot[snapshot.len() - 384..],
        expected.muhash.finalize()
    );
    Ok(())
}

#[test]
fn listener_chunked_two_shard_delta_matches_serial_stats() -> Result<(), Box<dyn std::error::Error>>
{
    const ENTRIES: u32 = 2_048;

    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::with_capacity(usize::try_from(ENTRIES)?, 0);
    let mut seeded = Vec::with_capacity(usize::try_from(ENTRIES)?);

    for index in 0_u32..ENTRIES {
        let shard = u8::try_from(index % 2)?;
        let outpoint = OutPoint::new(txid_in_shard(shard, 3_000 + u64::from(index)), 0);
        let txout = txout(3_000 + index);
        let coinbase = index % 2 == 0;
        assert_eq!(UtxoKey::from_txid(&outpoint.txid).shard(), shard);
        expected.insert_utxo(&outpoint, &txout, 200, coinbase);
        initial.add(UtxoAdd::new(outpoint, txout.clone(), coinbase, 200));
        seeded.push((outpoint, txout, coinbase));
    }
    set.commit_block(&initial, &txid(3_000))?;

    let mut mixed =
        BlockChanges::with_capacity(usize::try_from(ENTRIES)?, usize::try_from(ENTRIES)?);
    for (outpoint, txout, coinbase) in &seeded {
        expected.remove_utxo(outpoint, txout, 200, *coinbase);
        mixed.remove(*outpoint);
    }
    let mut replacements = Vec::with_capacity(usize::try_from(ENTRIES)?);
    for index in 0_u32..ENTRIES {
        let shard = u8::try_from(index % 2)?;
        let replacement = OutPoint::new(txid_in_shard(shard, 6_000 + u64::from(index)), 0);
        let replacement_txout = txout(6_000 + index);
        assert_eq!(UtxoKey::from_txid(&replacement.txid).shard(), shard);
        expected.insert_utxo(&replacement, &replacement_txout, 201, false);
        mixed.add(UtxoAdd::new(
            replacement,
            replacement_txout.clone(),
            false,
            201,
        ));
        replacements.push((replacement, replacement_txout));
    }
    set.commit_block(&mixed, &txid(3_001))?;

    assert_observable_stats_eq(&listener.snapshot(), &expected);
    for (outpoint, _txout, _coinbase) in seeded {
        assert_eq!(set.get(&outpoint), None);
    }
    for (replacement, txout) in replacements {
        assert_eq!(set.get(&replacement), Some(txout));
    }
    Ok(())
}

#[test]
fn listener_parallel_direct_coin_batches_match_serial_stats()
-> Result<(), Box<dyn std::error::Error>> {
    const ENTRIES: u32 = 2_048;

    let listener = CoinStatsListener::new(CoinStats::new());
    let mut expected = CoinStats::new();
    let mut outpoints = Vec::with_capacity(usize::try_from(ENTRIES)?);
    let mut txouts = Vec::with_capacity(usize::try_from(ENTRIES)?);
    let mut removals = Vec::with_capacity(usize::try_from(ENTRIES)?);

    for index in 0_u32..ENTRIES {
        let outpoint = OutPoint::new(txid(index), index);
        let txout = txout(index);
        let coinbase = index % 2 == 0;
        expected.insert_utxo(&outpoint, &txout, 300, coinbase);
        removals.push(UtxoRemoved::new(outpoint, txout.clone(), 300, coinbase));
        outpoints.push(outpoint);
        txouts.push(txout);
    }

    let insertions = outpoints
        .iter()
        .zip(&txouts)
        .enumerate()
        .map(|(index, (outpoint, txout))| UtxoInserted::new(outpoint, txout, 300, index % 2 == 0))
        .collect::<Vec<_>>();
    listener.on_insert_coins(&insertions);
    assert_observable_stats_eq(&listener.snapshot(), &expected);

    for removal in &removals {
        expected.remove_utxo(
            &removal.op,
            &removal.txout,
            removal.height,
            removal.coinbase,
        );
    }
    listener.on_remove_coins(&removals);
    assert_observable_stats_eq(&listener.snapshot(), &expected);
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

fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[0] = shard;
    bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
    bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
    bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
