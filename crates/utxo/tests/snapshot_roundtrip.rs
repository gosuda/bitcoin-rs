//! Snapshot dump/load round-trip coverage.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoError, UtxoKey, UtxoSet, hash_serialized_3, read_snapshot,
    write_snapshot,
};
use std::io::{Cursor, Read, Seek};
use tempfile::tempfile;

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txid_with_prefix(prefix: u64, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&prefix.to_le_bytes());
    bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
    bytes[16..24].copy_from_slice(&suffix.rotate_left(7).to_le_bytes());
    bytes[24..32].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(12);
    script.extend_from_slice(&[0x76, 0xa9, 0x08]);
    script.extend_from_slice(&seed.to_le_bytes());
    script.push(0x88);
    TxOut {
        value: Amount::from_sat(2_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

#[test]
fn snapshot_roundtrip_preserves_full_outpoints_hash_and_trailer()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();

    for i in 0_u64..10_000 {
        let outpoint = OutPoint::new(txid(i), u32::try_from(i % 5)?);
        changes.add(UtxoAdd::new(outpoint, txout(i), false, 200));
    }
    let collision_prefix = 0x0102_0304_0506_0708_u64;
    let first_collision = OutPoint::new(txid_with_prefix(collision_prefix, 1), 0);
    let second_collision = OutPoint::new(txid_with_prefix(collision_prefix, 2), 0);
    let first_collision_txout = txout(20_001);
    let second_collision_txout = txout(20_002);
    changes.add(UtxoAdd::new(
        first_collision,
        first_collision_txout.clone(),
        true,
        201,
    ));
    changes.add(UtxoAdd::new(
        second_collision,
        second_collision_txout.clone(),
        false,
        202,
    ));
    set.commit_block(&changes, &txid(10_000))?;

    let expected_hash = hash_serialized_3(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(99), 200, &mut file)?;
    file.rewind()?;

    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(99));
    assert_eq!(loaded.height, 200);
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);
    assert_eq!(loaded.set.len(), set.len());
    assert_eq!(
        loaded.set.get(&first_collision),
        Some(first_collision_txout)
    );
    assert_eq!(
        loaded.set.get(&second_collision),
        Some(second_collision_txout)
    );

    Ok(())
}

#[test]
fn snapshot_roundtrip_preserves_vout_64() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(42_000);
    let low = OutPoint::new(live_txid, 63);
    let high = OutPoint::new(live_txid, 64);
    let low_txout = txout(42_001);
    let high_txout = txout(42_002);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(low, low_txout.clone(), false, 400));
    changes.add(UtxoAdd::new(high, high_txout.clone(), true, 401));
    set.commit_block(&changes, &txid(42_003))?;

    let expected_hash = hash_serialized_3(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(42_004), 401, &mut file)?;
    file.rewind()?;

    let mut header = [0_u8; 8];
    file.read_exact(&mut header)?;
    let mut version = [0_u8; 4];
    version.copy_from_slice(&header[4..8]);
    assert_eq!(u32::from_le_bytes(version), 3);
    file.rewind()?;

    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(42_004));
    assert_eq!(loaded.height, 401);
    assert_eq!(loaded.set.get(&low), Some(low_txout));
    assert_eq!(loaded.set.get(&high), Some(high_txout));
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);
    Ok(())
}

#[test]
fn legacy_v2_snapshot_rejects_vout_64() -> Result<(), Box<dyn std::error::Error>> {
    let record_txid = txid(64_000);
    let tip_hash = txid(64_001);
    let key = UtxoKey::from_txid(&record_txid);
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&tip_hash.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());

    bytes.push(key.shard());
    bytes.extend_from_slice(&key.to_prefix());
    bytes.extend_from_slice(&record_txid.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.push(1);

    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&1_000_u64.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.push(0x51);

    let mut reader = Cursor::new(bytes);
    let error = match read_snapshot(&mut reader) {
        Err(error) => error,
        Ok(_) => panic!("v2 bitmap cannot encode vout 64"),
    };

    assert!(matches!(error, UtxoError::VoutOutOfRange { vout: 64 }));
    Ok(())
}
