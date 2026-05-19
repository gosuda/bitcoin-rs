//! Snapshot dump/load round-trip coverage.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoSet, aggregate_hash, read_snapshot, write_snapshot,
};
use std::io::Seek;
use tempfile::tempfile;

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
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
fn snapshot_roundtrip_preserves_sorted_aggregate_hash_and_trailer()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();

    for i in 0_u64..10_000 {
        let outpoint = OutPoint::new(txid(i), u32::try_from(i % 5)?);
        changes.add(UtxoAdd::new(outpoint, txout(i), false, 200));
    }
    set.commit_block(&changes, &txid(10_000))?;

    let expected_hash = aggregate_hash(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(99), 200, &mut file)?;
    file.rewind()?;

    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(99));
    assert_eq!(loaded.height, 200);
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);
    assert_eq!(aggregate_hash(&loaded.set)?, expected_hash);
    assert_eq!(loaded.set.len(), set.len());

    Ok(())
}
