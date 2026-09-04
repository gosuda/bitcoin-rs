//! Public commit/get coverage for the UTXO set.

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, varint};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoError, UtxoSet, hash_serialized_3,
    set::{BorrowedBlockChanges, BorrowedUtxoAdd},
};
use sha2::{Digest, Sha256};

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xa5a5_a5a5_a5a5_a5a5).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x51, 0x20]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: 1_000 + seed,
        script_pubkey: script,
    }
}

fn txid_with_prefix(prefix: u64, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&prefix.to_le_bytes());
    bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
    bytes[16..24].copy_from_slice(&suffix.rotate_left(11).to_le_bytes());
    bytes[24..32].copy_from_slice(&suffix.wrapping_mul(17).to_le_bytes());
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

fn expected_hash_serialized_3(
    entries: &[(OutPoint, TxOut, bool, u32)],
) -> Result<Hash256, Box<dyn std::error::Error>> {
    let mut sorted: Vec<&(OutPoint, TxOut, bool, u32)> = entries.iter().collect();
    sorted.sort_unstable_by(|left, right| {
        left.0
            .txid
            .0
            .to_le_bytes()
            .cmp(&right.0.txid.0.to_le_bytes())
            .then_with(|| {
                let left_vout = left.0.vout;
                let right_vout = right.0.vout;
                left_vout.cmp(&right_vout)
            })
    });

    let mut engine = Sha256::new();
    for (outpoint, txout, coinbase, height) in sorted {
        engine.update(outpoint.txid.0.to_le_bytes());
        engine.update(outpoint.vout.to_le_bytes());
        let code = (*height << 1) | u32::from(*coinbase);
        engine.update(code.to_le_bytes());
        engine.update(txout.value.to_le_bytes());
        let script = txout.script_pubkey.as_slice();
        let script_len = u64::try_from(script.len())?;
        let encoded_len = varint::encode(script_len);
        engine.update(encoded_len.as_slice());
        engine.update(script);
    }

    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes: [u8; 32] = second.into();
    Ok(Hash256::from_le_bytes(&bytes))
}

fn borrowed_changes<'a>(
    adds: &'a [(OutPoint, TxOut, bool, u32)],
    removes: &[OutPoint],
) -> BorrowedBlockChanges<'a> {
    let mut changes = BorrowedBlockChanges::with_capacity(adds.len(), removes.len());
    for remove in removes {
        changes.remove(*remove);
    }
    for (outpoint, txout, coinbase, height) in adds {
        changes.add(BorrowedUtxoAdd::new(*outpoint, txout, *coinbase, *height));
    }
    changes
}

#[test]
fn invalid_add_does_not_apply_removes_in_same_commit() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let retained = OutPoint::new(txid(10).into(), 0);
    let retained_txout = txout(10);
    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(retained, retained_txout.clone(), false, 1));
    set.commit_block(&initial, &txid(11))?;

    let mut invalid = BlockChanges::default();
    invalid.remove(retained);
    invalid.add(UtxoAdd::new(
        OutPoint::new(txid(12).into(), 0),
        TxOut {
            value: 12,
            script_pubkey: vec![0; usize::from(u16::MAX) + 1],
        },
        false,
        2,
    ));

    let error = match set.commit_block(&invalid, &txid(13)) {
        Ok(()) => return Err("oversized script unexpectedly committed".into()),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1
        ),
        "unexpected error: {error}"
    );
    assert_eq!(set.get(&retained), Some(retained_txout));
    assert_eq!(set.get(&OutPoint::new(txid(12).into(), 0)), None);
    Ok(())
}

#[test]
fn get_entry_surfaces_coinbase_and_height() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let outpoint = OutPoint::new(txid(42).into(), 0);
    let txout = txout(42);

    changes.add(UtxoAdd::new(outpoint, txout.clone(), true, 123));
    set.commit_block(&changes, &txid(43))?;

    let entry = set
        .get_entry(&outpoint)
        .ok_or("expected committed outpoint to be live")?;
    assert_eq!(entry.txout, txout);
    assert!(entry.coinbase);
    assert_eq!(entry.height, 123);

    Ok(())
}

#[test]
fn scan_script_pubkeys_returns_matching_live_outputs() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let first = OutPoint::new(txid(52).into(), 0);
    let second = OutPoint::new(txid(53).into(), 0);
    let first_txout = txout(52);
    let second_txout = txout(53);

    changes.add(UtxoAdd::new(first, first_txout.clone(), false, 222));
    changes.add(UtxoAdd::new(second, second_txout, true, 223));
    set.commit_block(&changes, &txid(54))?;

    let scan = set.scan_script_pubkeys(std::slice::from_ref(&first_txout.script_pubkey))?;

    assert_eq!(scan.txouts, 2);
    assert_eq!(scan.unspents.len(), 1);
    assert_eq!(scan.unspents[0].outpoint, first);
    assert_eq!(scan.unspents[0].txout, first_txout);
    assert!(!scan.unspents[0].coinbase);
    assert_eq!(scan.unspents[0].height, 222);
    Ok(())
}

#[test]
fn has_live_outputs_for_txid_tracks_any_remaining_vout() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(77);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(live_txid.into(), 1),
        txout(77),
        false,
        200,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(live_txid.into(), 2),
        txout(78),
        false,
        200,
    ));
    set.commit_block(&changes, &txid(78))?;

    assert!(set.has_live_outputs_for_txid(&live_txid));
    assert!(!set.has_live_outputs_for_txid(&txid(79)));

    let mut first_spend = BlockChanges::default();
    first_spend.remove(OutPoint::new(live_txid.into(), 1));
    set.commit_block(&first_spend, &txid(80))?;

    assert!(set.has_live_outputs_for_txid(&live_txid));

    let mut final_spend = BlockChanges::default();
    final_spend.remove(OutPoint::new(live_txid.into(), 2));
    set.commit_block(&final_spend, &txid(81))?;

    assert!(!set.has_live_outputs_for_txid(&live_txid));
    Ok(())
}

#[test]
fn borrowed_commit_preserves_invalid_add_atomicity() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let retained = OutPoint::new(txid(8_010).into(), 0);
    let retained_txout = txout(8_010);
    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(retained, retained_txout.clone(), false, 1));
    set.commit_block(&initial, &txid(8_011))?;

    let invalid_outpoint = OutPoint::new(txid(8_012).into(), 0);
    let invalid_adds = vec![(
        invalid_outpoint,
        TxOut {
            value: 8_012,
            script_pubkey: vec![0; usize::from(u16::MAX) + 1],
        },
        false,
        2,
    )];
    let invalid = borrowed_changes(&invalid_adds, &[retained]);

    let error = match set.commit_borrowed_block(&invalid, &txid(8_013)) {
        Ok(()) => return Err("oversized borrowed script unexpectedly committed".into()),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1
        ),
        "unexpected error: {error}"
    );
    assert_eq!(set.get(&retained), Some(retained_txout));
    assert_eq!(set.get(&invalid_outpoint), None);
    Ok(())
}

#[test]
fn vout_64_roundtrips_through_public_utxo_api() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(88);
    let low = OutPoint::new(live_txid.into(), 63);
    let high = OutPoint::new(live_txid.into(), 64);
    let low_txout = txout(88);
    let high_txout = txout(89);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(low, low_txout.clone(), false, 300));
    changes.add(UtxoAdd::new(high, high_txout.clone(), true, 301));
    set.commit_block(&changes, &txid(90))?;

    assert_eq!(set.get(&low), Some(low_txout.clone()));
    assert_eq!(set.get(&high), Some(high_txout.clone()));
    let high_entry = set
        .get_entry(&high)
        .ok_or("expected vout 64 to remain live")?;
    assert_eq!(high_entry.txout, high_txout);
    assert!(high_entry.coinbase);
    assert_eq!(high_entry.height, 301);
    assert!(set.has_live_outputs_for_txid(&live_txid));

    let scan = set.scan_script_pubkeys(std::slice::from_ref(&high_txout.script_pubkey))?;
    assert_eq!(scan.txouts, 2);
    assert_eq!(scan.unspents.len(), 1);
    assert_eq!(scan.unspents[0].outpoint, high);

    let mut high_spend = BlockChanges::default();
    high_spend.remove(high);
    set.commit_block(&high_spend, &txid(91))?;

    assert_eq!(set.get(&high), None);
    assert_eq!(set.get(&low), Some(low_txout));
    assert!(set.has_live_outputs_for_txid(&live_txid));

    let mut low_spend = BlockChanges::default();
    low_spend.remove(low);
    set.commit_block(&low_spend, &txid(92))?;

    assert!(!set.has_live_outputs_for_txid(&live_txid));
    assert!(set.is_empty());
    Ok(())
}

#[test]
fn high_vout_full_record_delete_removes_all_outputs_in_one_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(93);
    let mut preload = BlockChanges::default();
    let mut spend = BlockChanges::default();

    for vout in 64_u32..128 {
        let outpoint = OutPoint::new(live_txid.into(), vout);
        preload.add(UtxoAdd::new(
            outpoint,
            txout(1_000 + u64::from(vout)),
            false,
            302,
        ));
        spend.remove(outpoint);
    }
    set.commit_block(&preload, &txid(94))?;
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 64);
    assert!(set.has_live_outputs_for_txid(&live_txid));

    set.commit_block(&spend, &txid(95))?;

    for vout in 64_u32..128 {
        assert_eq!(set.get(&OutPoint::new(live_txid.into(), vout)), None);
    }
    assert!(!set.has_live_outputs_for_txid(&live_txid));
    assert_eq!(set.record_count(), 0);
    assert_eq!(set.len(), 0);
    assert!(set.is_empty());
    Ok(())
}

#[test]
fn hash_serialized_3_matches_independent_core_serialization_for_unsorted_utxos()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let entries = vec![
        (OutPoint::new(txid(30).into(), 2), txout(30), false, 210),
        (OutPoint::new(txid(10).into(), 1), txout(10), true, 208),
        (OutPoint::new(txid(30).into(), 0), txout(31), false, 210),
        (OutPoint::new(txid(20).into(), 3), txout(20), true, 209),
    ];

    for (outpoint, txout, coinbase, height) in &entries {
        changes.add(UtxoAdd::new(*outpoint, txout.clone(), *coinbase, *height));
    }
    set.commit_block(&changes, &txid(99))?;

    assert_eq!(
        hash_serialized_3(&set)?,
        expected_hash_serialized_3(&entries)?
    );
    Ok(())
}

#[test]
fn same_prefix_txids_do_not_collide_in_get_or_remove_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let prefix = 0xfeed_face_cafe_beef_u64;
    let first = OutPoint::new(txid_with_prefix(prefix, 1).into(), 0);
    let second = OutPoint::new(txid_with_prefix(prefix, 2).into(), 0);
    let first_txout = txout(101);
    let second_txout = txout(202);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(first, first_txout.clone(), false, 1));
    changes.add(UtxoAdd::new(second, second_txout.clone(), false, 1));
    set.commit_block(&changes, &txid(300))?;

    assert_eq!(set.get(&first), Some(first_txout));
    assert_eq!(set.get(&second), Some(second_txout.clone()));

    let mut spend = BlockChanges::default();
    spend.remove(first);
    set.commit_block(&spend, &txid(301))?;

    assert_eq!(set.get(&first), None);
    assert_eq!(set.get(&second), Some(second_txout));
    Ok(())
}

#[test]
fn full_record_delete_uses_full_txid_and_preserves_collision_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let prefix = 0xfeed_face_cafe_beef_u64;
    let first = OutPoint::new(txid_with_prefix(prefix, 10).into(), 0);
    let second = OutPoint::new(txid_with_prefix(prefix, 11).into(), 0);
    let second_txout = txout(202);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(first, txout(101), false, 1));
    changes.add(UtxoAdd::new(second, second_txout.clone(), false, 1));
    set.commit_block(&changes, &txid(300))?;

    let mut spend = BlockChanges::default();
    spend.remove(first);
    set.commit_block(&spend, &txid(301))?;

    assert_eq!(set.get(&first), None);
    assert_eq!(set.get(&second), Some(second_txout));
    assert!(set.has_live_outputs_for_txid(&second.txid.0));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 1);
    Ok(())
}

#[test]
fn duplicate_remove_does_not_fast_delete_unspent_vout() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(700);
    let removed = OutPoint::new(live_txid.into(), 0);
    let retained = OutPoint::new(live_txid.into(), 1);
    let retained_txout = txout(701);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(removed, txout(700), false, 1));
    changes.add(UtxoAdd::new(retained, retained_txout.clone(), false, 1));
    set.commit_block(&changes, &txid(702))?;

    let mut duplicate_spend = BlockChanges::default();
    duplicate_spend.remove(removed);
    duplicate_spend.remove(removed);
    set.commit_block(&duplicate_spend, &txid(703))?;

    assert_eq!(set.get(&removed), None);
    assert_eq!(set.get(&retained), Some(retained_txout));
    assert!(set.has_live_outputs_for_txid(&live_txid));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 1);
    Ok(())
}
#[test]
fn height_u32_max_with_both_coinbase_states_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(800);
    let first = OutPoint::new(live_txid.into(), 0);
    let second = OutPoint::new(live_txid.into(), 1);
    let first_txout = txout(800);
    let second_txout = txout(801);

    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(first, first_txout.clone(), true, u32::MAX));
    changes.add(UtxoAdd::new(second, second_txout.clone(), false, u32::MAX));
    set.commit_block(&changes, &txid(802))?;

    let entry1 = set.get_entry(&first).ok_or("expected first entry")?;
    assert_eq!(entry1.txout, first_txout);
    assert!(entry1.coinbase);
    assert_eq!(entry1.height, u32::MAX);

    let entry2 = set.get_entry(&second).ok_or("expected second entry")?;
    assert_eq!(entry2.txout, second_txout);
    assert!(!entry2.coinbase);
    assert_eq!(entry2.height, u32::MAX);

    let scan = set.scan_script_pubkeys(std::slice::from_ref(&first_txout.script_pubkey))?;
    assert_eq!(scan.unspents.len(), 1);
    assert_eq!(scan.unspents[0].height, u32::MAX);
    assert!(scan.unspents[0].coinbase);
    Ok(())
}

#[test]
fn vout_u32_max_roundtrips_and_spends() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(810);
    let max_vout_op = OutPoint::new(live_txid.into(), u32::MAX);
    let txout_val = txout(810);

    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(max_vout_op, txout_val.clone(), false, 500));
    set.commit_block(&changes, &txid(811))?;

    assert_eq!(set.get(&max_vout_op), Some(txout_val.clone()));
    let entry = set
        .get_entry(&max_vout_op)
        .ok_or("expected live max vout")?;
    assert_eq!(entry.txout, txout_val);
    assert_eq!(entry.height, 500);
    assert!(set.has_live_outputs_for_txid(&live_txid));

    let mut spend = BlockChanges::default();
    spend.remove(max_vout_op);
    set.commit_block(&spend, &txid(812))?;

    assert_eq!(set.get(&max_vout_op), None);
    assert!(!set.has_live_outputs_for_txid(&live_txid));
    assert_eq!(set.record_count(), 0);
    assert_eq!(set.len(), 0);
    Ok(())
}

#[test]
fn zero_and_unequal_script_lengths_roundtrip_and_scan() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(820);

    let script_empty = Vec::new();
    let script_1b = vec![0x51];
    let script_34b = vec![0x00; 34];
    let script_520b = vec![0x51; 520];
    let script_10kb = vec![0x52; 10_000];

    let txout_empty = TxOut {
        value: 100,
        script_pubkey: script_empty.clone(),
    };
    let txout_1b = TxOut {
        value: 200,
        script_pubkey: script_1b,
    };
    let txout_34b = TxOut {
        value: 300,
        script_pubkey: script_34b,
    };
    let txout_520b = TxOut {
        value: 400,
        script_pubkey: script_520b,
    };
    let txout_10kb = TxOut {
        value: 500,
        script_pubkey: script_10kb.clone(),
    };

    let op0 = OutPoint::new(live_txid.into(), 0);
    let op1 = OutPoint::new(live_txid.into(), 1);
    let op2 = OutPoint::new(live_txid.into(), 2);
    let op3 = OutPoint::new(live_txid.into(), 3);
    let op4 = OutPoint::new(live_txid.into(), 4);

    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op0, txout_empty.clone(), false, 10));
    changes.add(UtxoAdd::new(op1, txout_1b.clone(), true, 11));
    changes.add(UtxoAdd::new(op2, txout_34b.clone(), false, 12));
    changes.add(UtxoAdd::new(op3, txout_520b.clone(), true, 13));
    changes.add(UtxoAdd::new(op4, txout_10kb.clone(), false, 14));
    set.commit_block(&changes, &txid(821))?;

    assert_eq!(set.get(&op0), Some(txout_empty.clone()));
    assert_eq!(set.get(&op1), Some(txout_1b.clone()));
    assert_eq!(set.get(&op2), Some(txout_34b.clone()));
    assert_eq!(set.get(&op3), Some(txout_520b.clone()));
    assert_eq!(set.get(&op4), Some(txout_10kb.clone()));

    let scan_empty = set.scan_script_pubkeys(&[script_empty])?;
    assert_eq!(scan_empty.unspents.len(), 1);
    assert_eq!(scan_empty.unspents[0].outpoint, op0);

    let scan_10k = set.scan_script_pubkeys(&[script_10kb])?;
    assert_eq!(scan_10k.unspents.len(), 1);
    assert_eq!(scan_10k.unspents[0].outpoint, op4);

    let entries = vec![
        (op0, txout_empty, false, 10),
        (op1, txout_1b, true, 11),
        (op2, txout_34b, false, 12),
        (op3, txout_520b, true, 13),
        (op4, txout_10kb, false, 14),
    ];
    let expected_hash = expected_hash_serialized_3(&entries)?;
    assert_eq!(hash_serialized_3(&set)?, expected_hash);
    Ok(())
}

#[test]
fn multi_shard_invalid_add_preserves_commit_rejection_atomicity()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let shard0_op = OutPoint::new(txid_in_shard(0, 100).into(), 0);
    let shard1_op = OutPoint::new(txid_in_shard(1, 100).into(), 0);
    let shard0_txout = txout(100);
    let shard1_txout = txout(101);

    let mut initial = BlockChanges::default();
    initial.add(UtxoAdd::new(shard0_op, shard0_txout.clone(), false, 10));
    initial.add(UtxoAdd::new(shard1_op, shard1_txout.clone(), false, 10));
    set.commit_block(&initial, &txid(102))?;

    let mut invalid_changes = BlockChanges::default();
    invalid_changes.remove(shard0_op);
    invalid_changes.add(UtxoAdd::new(
        OutPoint::new(txid_in_shard(0, 101).into(), 0),
        txout(102),
        false,
        11,
    ));
    invalid_changes.add(UtxoAdd::new(
        OutPoint::new(txid_in_shard(1, 101).into(), 0),
        TxOut {
            value: 103,
            script_pubkey: vec![0; usize::from(u16::MAX) + 1],
        },
        false,
        11,
    ));

    let err = match set.commit_block(&invalid_changes, &txid(103)) {
        Ok(()) => return Err("expected ScriptTooLarge error".into()),
        Err(e) => e,
    };
    assert!(matches!(err, UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1));

    // Verify rejection atomicity across shards
    assert_eq!(set.get(&shard0_op), Some(shard0_txout));
    assert_eq!(set.get(&shard1_op), Some(shard1_txout));
    assert_eq!(
        set.get(&OutPoint::new(txid_in_shard(0, 101).into(), 0)),
        None
    );
    assert_eq!(
        set.get(&OutPoint::new(txid_in_shard(1, 101).into(), 0)),
        None
    );
    assert_eq!(set.len(), 2);
    Ok(())
}

#[test]
fn hash_serialized_3_matches_independent_core_serialization_for_edge_cases()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let op1 = OutPoint::new(txid(840).into(), 0);
    let op2 = OutPoint::new(txid(841).into(), u32::MAX);
    let op3 = OutPoint::new(txid(842).into(), 64);

    let txout1 = TxOut {
        value: 0,
        script_pubkey: Vec::new(),
    };
    let txout2 = TxOut {
        value: u64::MAX,
        script_pubkey: vec![0x51; 520],
    };
    let txout3 = TxOut {
        value: 12_345,
        script_pubkey: vec![0x6a],
    };

    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op1, txout1.clone(), true, u32::MAX));
    changes.add(UtxoAdd::new(op2, txout2.clone(), false, u32::MAX));
    changes.add(UtxoAdd::new(op3, txout3.clone(), true, 0));
    set.commit_block(&changes, &txid(843))?;

    let entries = vec![
        (op1, txout1, true, u32::MAX),
        (op2, txout2, false, u32::MAX),
        (op3, txout3, true, 0),
    ];
    let expected = expected_hash_serialized_3(&entries)?;
    assert_eq!(hash_serialized_3(&set)?, expected);
    Ok(())
}
