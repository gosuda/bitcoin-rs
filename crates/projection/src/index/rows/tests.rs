use std::collections::BTreeMap;

use bitcoin_rs_consensus::primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily};

use super::*;
use crate::types::{ScriptHash, ScriptLiveRow};

#[test]
fn header_and_live_bytes_are_counted_from_pending_rows() -> Result<(), IndexError> {
    let mut rows = PendingRows::default();
    rows.header_rows.push([7; crate::types::HEADER_ROW_SIZE]);
    let bytes = rows.encoded_bytes_by_family()?;
    assert_eq!(bytes.headers, crate::types::HEADER_ROW_SIZE);
    assert_eq!(bytes.script_live, 0);
    assert_eq!(rows.total(), 1);
    Ok(())
}

#[test]
fn live_coalescing_matches_first_and_last_operations_for_all_small_sequences()
-> Result<(), IndexError> {
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[0; 32])), 0);
    let keys = [
        ScriptLiveRow::new(ScriptHash::from_byte_array([0; 32]), &outpoint),
        ScriptLiveRow::new(ScriptHash::from_byte_array([1; 32]), &outpoint),
    ];
    let coin = |hash: [u8; 32]| {
        crate::types::ScriptLiveCoin::new(ScriptHash::from_byte_array(hash), 1, 1, false)
    };
    let choices = [
        LiveOp::Insert {
            row: keys[0],
            coin: coin([0; 32]),
        },
        LiveOp::Delete {
            row: keys[0],
            coin: coin([0; 32]),
        },
        LiveOp::Insert {
            row: keys[1],
            coin: coin([1; 32]),
        },
        LiveOp::Delete {
            row: keys[1],
            coin: coin([1; 32]),
        },
    ];
    for len in 0..=5_u32 {
        for mut pattern in 0..4_usize.pow(len) {
            let mut ops = Vec::new();
            for _ in 0..len {
                ops.push(choices[pattern % 4]);
                pattern /= 4;
            }
            for invert in [false, true] {
                let mut batch = BufferedWriteBatch::default();
                if invert {
                    invert_live_ops(&mut batch, &ops)?;
                } else {
                    apply_live_ops(&mut batch, &ops)?;
                }
                let mut expected = BTreeMap::new();
                for (key_index, key) in keys.iter().enumerate() {
                    let matches_key = |op: &&LiveOp| *op.row() == *key;
                    let decisive = if invert {
                        ops.iter().find(matches_key)
                    } else {
                        ops.iter().rfind(matches_key)
                    };
                    if let Some(op) = decisive {
                        let insert = matches!(op, LiveOp::Insert { .. }) != invert;
                        let byte = u8::try_from(key_index).unwrap_or(0);
                        let coin = crate::types::ScriptLiveCoin::new(
                            ScriptHash::from_byte_array([byte; 32]),
                            1,
                            1,
                            false,
                        );
                        let value = coin.encode_value()?;
                        expected.insert(key.as_bytes().to_vec(), insert.then_some(value));
                    }
                }
                let mutations: Vec<(Vec<u8>, Option<Vec<u8>>)> = batch
                    .into_ops()
                    .into_iter()
                    .map(|op| match op {
                        BatchOp::Put { cf, key, value } => {
                            assert_eq!(cf, ColumnFamily::ScriptLive);
                            (key, Some(value.into()))
                        }
                        BatchOp::Delete { cf, key } => {
                            assert_eq!(cf, ColumnFamily::ScriptLive);
                            (key, None)
                        }
                        BatchOp::DeleteRange { .. } => {
                            panic!("live ops never emit range deletes")
                        }
                    })
                    .collect();
                let actual: BTreeMap<_, _> = mutations
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
                assert_eq!(
                    actual.len(),
                    mutations.len(),
                    "each live key is emitted once"
                );
                assert_eq!(actual, expected, "invert={invert}, ops={ops:?}");
            }
        }
    }
    Ok(())
}
