//! Commit/get round-trip coverage for a synthetic UTXO set.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};

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
