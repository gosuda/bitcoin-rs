//! Snapshot trailer integration tests for coinstats.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_coinstats::{CoinStats, CoinStatsListener};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet, write_snapshot};

#[test]
fn snapshot_trailer_uses_listener_muhash() -> Result<(), Box<dyn std::error::Error>> {
    let listener = CoinStatsListener::new(CoinStats::new());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(listener.clone()));

    let mut changes = BlockChanges::default();
    for index in 0_u32..3 {
        let outpoint = OutPoint::new(txid(index), index);
        let txout = TxOut {
            value: Amount::from_sat(50_000 + u64::from(index)),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, index.to_le_bytes()[0]]),
        };
        changes.add(UtxoAdd::new(outpoint, txout, index == 0, 7));
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

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
