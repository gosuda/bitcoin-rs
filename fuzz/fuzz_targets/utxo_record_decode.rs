#![no_main]

use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_utxo::contract::{decode_undo_record, encode_undo_record};
use bitcoin_rs_utxo::record::{OwnedUtxoOut, UtxoRecord};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 2;
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
            if let Ok(record) = UtxoRecord::from_encoded(payload.to_vec().into_boxed_slice()) {
                let _ = record.txid();
                let _ = record.max_vout();
                let _ = record.is_empty();
                let count = record.outputs().count();
                assert_eq!(count, record.output_count());

                for out in record.outputs() {
                    let found = record.find_output(out.vout);
                    assert!(found.is_some());
                    if let Some(f) = found {
                        assert_eq!(f.vout, out.vout);
                        assert_eq!(f.value, out.value);
                        assert_eq!(f.script_pubkey, out.script_pubkey);
                        assert_eq!(f.coinbase, out.coinbase);
                        assert_eq!(f.height, out.height);
                    }
                }

                if let Ok(roundtripped) =
                    UtxoRecord::from_encoded(record.bytes().to_vec().into_boxed_slice())
                {
                    assert_eq!(roundtripped.bytes(), record.bytes());
                } else {
                    panic!("re-encoded UTXO record failed to decode");
                }

                let owned: Vec<_> = record
                    .outputs()
                    .map(|out| {
                        OwnedUtxoOut::new(
                            out.vout,
                            out.value,
                            out.script_pubkey.to_vec(),
                            out.coinbase,
                            out.height,
                        )
                    })
                    .collect();
                let re_encoded = UtxoRecord::from_owned_outputs(record.txid(), &owned);
                match re_encoded {
                    Ok(re_encoded) => {
                        assert_eq!(record.output_count(), re_encoded.output_count());
                        for (out1, out2) in record.outputs().zip(re_encoded.outputs()) {
                            assert_eq!(out1.vout, out2.vout);
                            assert_eq!(out1.value, out2.value);
                            assert_eq!(out1.script_pubkey, out2.script_pubkey);
                            assert_eq!(out1.coinbase, out2.coinbase);
                            assert_eq!(out1.height, out2.height);
                        }
                    }
                    Err(err) => {
                        panic!("owned-outputs rebuild of decoded record failed: {err:?}");
                    }
                }
            }
        }
        _ => {
            if let Ok(batch) = decode_undo_record(payload, hash) {
                let encoded = encode_undo_record(&batch, hash);
                match decode_undo_record(&encoded, hash) {
                    Ok(roundtripped) => assert_eq!(roundtripped, batch),
                    Err(err) => panic!("re-encoded undo record failed to decode: {err:?}"),
                }
            }
        }
    }
});
