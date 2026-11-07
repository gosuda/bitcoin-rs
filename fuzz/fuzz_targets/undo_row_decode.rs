#![no_main]

use bitcoin_rs_consensus::primitives::Hash256;
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
            let mut frame = payload.to_vec();
            repair_journal_crc(&mut frame);
            if let Ok(record) = decode_record(&frame) {
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

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

fn repair_journal_crc(frame: &mut [u8]) {
    const HEADER: usize = 9;
    const TRAILER: usize = 4;
    if frame.len() < HEADER + TRAILER || frame[..4] != *b"JRNL" || frame[4] != 1 {
        return;
    }
    let Ok(len_bytes) = <[u8; 4]>::try_from(&frame[5..HEADER]) else {
        return;
    };
    let Some(declared) = usize::try_from(u32::from_le_bytes(len_bytes)).ok() else {
        return;
    };
    let Some(end) = HEADER.checked_add(declared) else {
        return;
    };
    if end.checked_add(TRAILER) != Some(frame.len()) {
        return;
    }
    let crc = crc32c(&frame[HEADER..end]);
    frame[end..end + TRAILER].copy_from_slice(&crc.to_le_bytes());
}
