#![no_main]

use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_storage::{DisconnectMarker, InMemoryUndoStore, UndoStore};
use bitcoin_rs_storage::utxo::contract::{decode_undo_record, encode_undo_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 3;
    let payload = &data[1..];

    let hash = payload
        .get(1..33)
        .or_else(|| payload.get(..32))
        .map_or_else(Hash256::default, |bytes| {
            let mut h = [0_u8; 32];
            h.copy_from_slice(bytes);
            Hash256::from_le_bytes(&h)
        });

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
