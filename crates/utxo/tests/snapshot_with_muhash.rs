//! Snapshot trailer integration tests for coinstats.

#[path = "support/indexed_txid.rs"]
mod indexed_txid;
#[path = "support/shard_txid.rs"]
mod shard_txid;

use bitcoin_rs_primitives::{Amount, OutPoint, TxOut};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use bitcoin_rs_utxo::{UtxoSet, write_snapshot};

use indexed_txid::txid;
use shard_txid::txid_in_shard;

#[test]
fn snapshot_trailer_uses_listener_muhash() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.track_coin_stats(listener.clone());

    let mut changes = BlockChanges::default();
    for index in 0_u32..3 {
        let outpoint = OutPoint::new(txid(index).into(), index);
        changes.add(UtxoAdd::new(outpoint, txout(index), index == 0, 7));
    }

    bitcoin_rs_utxo::contract::commit_block_changes(&set, &changes, &txid(999))?;

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
    set.track_coin_stats(listener.clone());

    let removed_outpoint = OutPoint::new(txid(1).into(), 0);
    let kept_outpoint = OutPoint::new(txid(2).into(), 1);
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
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &adds, &txid(100))?;
    let before_removal = listener.snapshot();

    let mut removes: BlockChanges = BlockChanges::default();
    removes.remove(removed_outpoint);
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &removes, &txid(101))?;

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
    set.track_coin_stats(listener.clone());

    let outpoint = OutPoint::new(txid(30).into(), 0);
    let original = txout(30);
    let replacement = txout(31);

    let mut first = BlockChanges::default();
    first.add(UtxoAdd::new(outpoint, original.clone(), true, 91_722));
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &first, &txid(100))?;

    let mut overwrite = BlockChanges::default();
    overwrite.add(UtxoAdd::new(outpoint, replacement.clone(), true, 91_842));
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &overwrite, &txid(101))?;

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
    set.track_coin_stats(listener.clone());
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::default();
    let mut seeded = Vec::new();

    for shard in 0_u8..20 {
        let index = u32::from(shard);
        let outpoint = OutPoint::new(txid_in_shard(shard, 1_100 + u64::from(shard)).into(), index);
        let original = txout(1_100 + index);
        assert_eq!(shard_of(&outpoint), shard);
        expected.insert_utxo(&outpoint, &original, 110, shard % 2 == 0);
        initial.add(UtxoAdd::new(
            outpoint,
            original.clone(),
            shard % 2 == 0,
            110,
        ));
        seeded.push((outpoint, original, shard % 2 == 0));
    }
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &initial, &txid(2_100))?;

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
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &overwrite, &txid(2_101))?;

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
    set.track_coin_stats(listener.clone());
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::default();
    let mut removals = Vec::new();
    let mut replacements = Vec::new();

    for shard in 0_u8..20 {
        let index = u32::from(shard);
        let outpoint = OutPoint::new(txid_in_shard(shard, 700 + u64::from(shard)).into(), index);
        let txout = txout(700 + index);
        assert_eq!(shard_of(&outpoint), shard);
        expected.insert_utxo(&outpoint, &txout, 70, shard % 2 == 0);
        initial.add(UtxoAdd::new(outpoint, txout, shard % 2 == 0, 70));
        removals.push(outpoint);
    }
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &initial, &txid(1_700))?;

    let mut mixed = BlockChanges::default();
    for shard in (0_u8..20).rev() {
        let index = u32::from(shard);
        let replacement = OutPoint::new(
            txid_in_shard(shard, 900 + u64::from(shard)).into(),
            100 + index,
        );
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
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &mixed, &txid(1_701))?;

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
    set.track_coin_stats(listener.clone());
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::with_capacity(usize::try_from(ENTRIES)?, 0);
    let mut seeded = Vec::with_capacity(usize::try_from(ENTRIES)?);

    for index in 0_u32..ENTRIES {
        let shard = u8::try_from(index % 2)?;
        // Four outputs per (txid, shard) pair so each shard's runs group
        // several same-transaction entries, as the batching path expects.
        let outpoint = OutPoint::new(
            txid_in_shard(shard, 3_000 + u64::from(index / 8)).into(),
            (index % 8) / 2,
        );
        let txout = txout(3_000 + index);
        let coinbase = index % 2 == 0;
        assert_eq!(shard_of(&outpoint), shard);
        expected.insert_utxo(&outpoint, &txout, 200, coinbase);
        initial.add(UtxoAdd::new(outpoint, txout.clone(), coinbase, 200));
        seeded.push((outpoint, txout, coinbase));
    }
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &initial, &txid(3_000))?;

    let mut mixed =
        BlockChanges::with_capacity(usize::try_from(ENTRIES)?, usize::try_from(ENTRIES)?);
    for (outpoint, txout, coinbase) in &seeded {
        expected.remove_utxo(outpoint, txout, 200, *coinbase);
        mixed.remove(*outpoint);
    }
    let mut replacements = Vec::with_capacity(usize::try_from(ENTRIES)?);
    for index in 0_u32..ENTRIES {
        let shard = u8::try_from(index % 2)?;
        let replacement = OutPoint::new(
            txid_in_shard(shard, 6_000 + u64::from(index / 8)).into(),
            (index % 8) / 2,
        );
        let replacement_txout = txout(6_000 + index);
        assert_eq!(shard_of(&replacement), shard);
        expected.insert_utxo(&replacement, &replacement_txout, 201, false);
        mixed.add(UtxoAdd::new(
            replacement,
            replacement_txout.clone(),
            false,
            201,
        ));
        replacements.push((replacement, replacement_txout));
    }
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &mixed, &txid(3_001))?;

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
fn listener_single_shard_runs_match_serial_stats() -> Result<(), Box<dyn std::error::Error>> {
    const ENTRIES: u32 = 2_048;

    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.track_coin_stats(listener.clone());
    let mut expected = CoinStats::new();
    let mut initial = BlockChanges::with_capacity(usize::try_from(ENTRIES)?, 0);
    let mut seeded: Vec<(OutPoint, TxOut, bool)> = Vec::with_capacity(usize::try_from(ENTRIES)?);

    // One shard, so the commit delivers same-transaction runs through the
    // single-shard listener path at the run-grouping threshold. Eight outputs
    // per txid, so those runs have length 8 instead of 1 and the grouping
    // path is actually exercised.
    for index in 0_u32..ENTRIES {
        let outpoint = OutPoint::new(
            txid_in_shard(3, 5_000 + u64::from(index / 8)).into(),
            index % 8,
        );
        let txout = txout(5_000 + index);
        let coinbase = index % 2 == 0;
        assert_eq!(shard_of(&outpoint), 3);
        expected.insert_utxo(&outpoint, &txout, 300, coinbase);
        initial.add(UtxoAdd::new(outpoint, txout.clone(), coinbase, 300));
        seeded.push((outpoint, txout, coinbase));
    }
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &initial, &txid(8_000))?;
    assert_observable_stats_eq(&listener.snapshot(), &expected);

    let mut removals: BlockChanges = BlockChanges::with_capacity(0, usize::try_from(ENTRIES)?);
    for (outpoint, txout, coinbase) in &seeded {
        expected.remove_utxo(outpoint, txout, 300, *coinbase);
        removals.remove(*outpoint);
    }
    bitcoin_rs_utxo::contract::commit_block_changes(&set, &removals, &txid(8_001))?;
    assert_observable_stats_eq(&listener.snapshot(), &expected);
    for (outpoint, ..) in &seeded {
        assert_eq!(set.get(outpoint), None);
    }
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

fn txout(index: u32) -> TxOut {
    TxOut {
        value: Amount::from_sat(50_000 + u64::from(index)),
        script_pubkey: vec![0x51, index.to_le_bytes()[0]].into(),
    }
}

/// The shard a UTXO key selects: the first little-endian txid byte.
fn shard_of(outpoint: &OutPoint) -> u8 {
    outpoint.txid.0.to_le_bytes()[0]
}
