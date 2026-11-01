#![no_main]

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::chainstate_journal::{decode_record, encode_record};
use bitcoin_rs_storage::{DisconnectMarker, InMemoryUndoStore, UndoStore};
use bitcoin_rs_utxo::contract::{decode_undo_record, encode_undo_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 4;
    let payload = &data[1..];

    let hash = if payload.len() >= 32 {
        let mut h = [0_u8; 32];
        h.copy_from_slice(&payload[..32]);
        Hash256::from_le_bytes(&h)
    } else {
        Hash256::default()
    };

    match selector {
        0 => {
            if let Ok(marker) = DisconnectMarker::decode(payload) {
                let encoded = marker.encode();
                let roundtripped =
                    DisconnectMarker::decode(&encoded).expect("encoded marker must decode");
                assert_eq!(marker, roundtripped);
            }
        }
        1 => {
            if let Ok(record) = decode_record(payload) {
                if let Ok(encoded) = encode_record(&record) {
                    let roundtripped =
                        decode_record(&encoded).expect("encoded journal record must decode");
                    assert_eq!(record, roundtripped);
                }
            }
        }
        2 => {
            if let Ok(batch) = decode_undo_record(payload, hash) {
                let encoded = encode_undo_record(&batch, hash);
                let roundtripped = decode_undo_record(&encoded, hash)
                    .expect("encoded undo record must decode with same block hash");
                assert_eq!(batch, roundtripped);
            }
        }
        _ => {
            let store = InMemoryUndoStore::default();
            let height = if payload.len() >= 4 {
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            } else {
                0
            };
            let _ = store.persist_undo(height, hash, payload);
            let loaded = store.load_undo(height, hash).expect("in-memory load");
            assert_eq!(loaded.as_deref(), Some(payload));
            let bound = payload.len().saturating_sub(1);
            let _ = store.load_undo_bounded(height, hash, bound);
            let _ = store.load_undo_bounded(height, hash, payload.len());
        }
    }
});
