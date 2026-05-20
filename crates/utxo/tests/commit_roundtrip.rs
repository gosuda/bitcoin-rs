//! Commit/get round-trip coverage for a synthetic UTXO set.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, varint};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet, hash_serialized_3};
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
        value: Amount::from_sat(1_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
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

fn expected_hash_serialized_3(
    entries: &[(OutPoint, TxOut, bool, u32)],
) -> Result<Hash256, Box<dyn std::error::Error>> {
    let mut sorted: Vec<&(OutPoint, TxOut, bool, u32)> = entries.iter().collect();
    sorted.sort_unstable_by(|left, right| {
        left.0
            .txid
            .to_le_bytes()
            .cmp(&right.0.txid.to_le_bytes())
            .then_with(|| {
                let left_vout = left.0.vout;
                let right_vout = right.0.vout;
                left_vout.cmp(&right_vout)
            })
    });

    let mut engine = Sha256::new();
    for (outpoint, txout, coinbase, height) in sorted {
        engine.update(outpoint.txid.to_le_bytes());
        engine.update(outpoint.vout.to_le_bytes());
        let code = (*height << 1) | u32::from(*coinbase);
        engine.update(code.to_le_bytes());
        engine.update(txout.value.to_sat().to_le_bytes());
        let script = txout.script_pubkey.as_bytes();
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

#[test]
fn commit_roundtrips_ten_thousand_outputs() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let mut expected = Vec::with_capacity(10_000);

    for i in 0_u64..10_000 {
        let outpoint = OutPoint::new(txid(i), u32::try_from(i % 4)?);
        let txout = txout(i);
        expected.push((outpoint, txout.clone()));
        changes.add(UtxoAdd::new(outpoint, txout, false, 100));
    }

    set.commit_block(&changes, &txid(10_001))?;

    for (outpoint, txout) in expected {
        assert_eq!(set.get(&outpoint), Some(txout));
    }

    Ok(())
}

#[test]
fn get_entry_surfaces_coinbase_and_height() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let outpoint = OutPoint::new(txid(42), 0);
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
fn hash_serialized_3_matches_independent_core_serialization_for_unsorted_utxos()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let entries = vec![
        (OutPoint::new(txid(30), 2), txout(30), false, 210),
        (OutPoint::new(txid(10), 1), txout(10), true, 208),
        (OutPoint::new(txid(30), 0), txout(31), false, 210),
        (OutPoint::new(txid(20), 3), txout(20), true, 209),
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
    let first = OutPoint::new(txid_with_prefix(prefix, 1), 0);
    let second = OutPoint::new(txid_with_prefix(prefix, 2), 0);
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
