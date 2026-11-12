#![no_main]

use bitcoin_rs_projection::block_log::{BlockLog, BlockRecord, cumulative_tx_count_through};
use bitcoin_rs_projection::{
    ConsumerCursor, ScriptHistoryOccurrence, ScriptLiveRow, TxPositionValue, positions_are_valid,
};
use bitcoin_rs_consensus::primitives::{BlockHash, Hash256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 5;
    let payload = &data[1..];

    match selector {
        0 => {
            if let Some(entries) = ScriptHistoryOccurrence::decode_all(payload) {
                let encoded = ScriptHistoryOccurrence::encode_all(&entries);
                assert_eq!(
                    ScriptHistoryOccurrence::decode_all(&encoded).as_ref(),
                    Some(&entries)
                );
            }
        }
        1 => {
            if let Some(positions) = TxPositionValue::decode(payload) {
                let _ = positions_are_valid(positions);
                let encoded = TxPositionValue::encode(positions);
                assert_eq!(TxPositionValue::decode(&encoded), Some(positions));
            }
        }
        2 => {
            if let Some(row) = ScriptLiveRow::from_db_row(payload) {
                let _ = row.outpoint();
                assert_eq!(ScriptLiveRow::from_db_row(row.as_bytes()), Some(row));
            }
        }
        3 => {
            if let Ok(cursor) = ConsumerCursor::from_bytes(payload) {
                let encoded = cursor.to_bytes();
                assert_eq!(ConsumerCursor::from_bytes(&encoded), Ok(cursor));
            }
        }
        _ => {
            let height = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else {
                0
            };
            let mut hash = [0_u8; 32];
            if payload.len() >= 36 {
                hash.copy_from_slice(&payload[4..36]);
            }
            let mut log = BlockLog::new();
            log.push(BlockRecord {
                hash: BlockHash::from(Hash256::from_le_bytes(&hash)),
                height,
                body_size: payload.len(),
                header: None,
                tx_count: 1,
                time: 0,
            });
            let _ = cumulative_tx_count_through(&log, height);
        }
    }
});
