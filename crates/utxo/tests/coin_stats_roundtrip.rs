//! Coinstats listener deltas and codec round-trip tests.

use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::stats::coin_stats::COIN_STATS_ENCODED_LEN;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsDecodeError, CoinStatsListener};

#[test]
fn finish_block_applies_height_and_transaction_delta() {
    let mut stats = CoinStats::new();
    stats.finish_block(7, 3);
    stats.finish_block(8, 5);

    assert_eq!(stats.height, 8);
    assert_eq!(stats.tx_count, 8);

    let listener = CoinStatsListener::new(CoinStats::new());
    listener.finish_block(9, 2);
    listener.finish_block(10, 4);
    let snapshot = listener.snapshot();

    assert_eq!(snapshot.height, 10);
    assert_eq!(snapshot.tx_count, 6);
}

#[test]
fn coin_stats_codec_is_exact_and_preserves_muhash_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let old_op = OutPoint::new(txid(1_000).into(), 3);
    let old_txout = TxOut {
        value: Amount::from_sat(12_345),
        script_pubkey: vec![0x51, 0x21].into(),
    };
    let mut original = CoinStats::new();
    original.insert_utxo(&old_op, &old_txout, 100, true);
    original.finish_block(100, 1);

    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), COIN_STATS_ENCODED_LEN);
    let mut restored = CoinStats::from_bytes(&bytes)?;
    assert_eq!(restored, original);

    assert!(matches!(
        CoinStats::from_bytes(&bytes[..bytes.len() - 1]),
        Err(CoinStatsDecodeError::Truncated)
    ));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        CoinStats::from_bytes(&trailing),
        Err(CoinStatsDecodeError::TrailingBytes)
    ));

    let new_op = OutPoint::new(txid(1_001).into(), 4);
    let new_txout = TxOut {
        value: Amount::from_sat(54_321),
        script_pubkey: vec![0x51, 0x22].into(),
    };
    original.remove_utxo(&old_op, &old_txout, 100, true);
    restored.remove_utxo(&old_op, &old_txout, 100, true);
    original.insert_utxo(&new_op, &new_txout, 101, false);
    restored.insert_utxo(&new_op, &new_txout, 101, false);

    assert_eq!(restored, original);
    assert_eq!(restored.to_bytes(), original.to_bytes());
    Ok(())
}

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}
