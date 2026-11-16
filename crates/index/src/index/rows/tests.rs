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

#[test]
fn family_byte_histograms_recording() {
    let family = IndexRowBytes {
        tx_lookup: 42,
        script_history: 84,
        script_live: 86,
        headers: 80,
        filters: 101,
        tail_log: 7,
    };
    let recorder = RecordedHistograms::default();
    metrics::with_local_recorder(&recorder, || {
        super::super::write::record_family_byte_histograms(&family);
    });
    let recorded = recorder.samples.lock().clone();
    let expected = [
        ("tx_lookup", 42.0),
        ("script_history", 84.0),
        ("script_live", 86.0),
        ("headers", 80.0),
        ("filters", 101.0),
        ("tail_log", 7.0),
    ];
    for (label, bytes) in expected {
        assert_eq!(
            recorded.get(&format!(
                "index.family_planned_write_bytes{{family=\"{label}\"}}"
            )),
            Some(&vec![bytes]),
            "family {label} records its planned bytes once"
        );
    }
    assert_eq!(recorded.len(), expected.len());

    let partial_family = IndexRowBytes {
        tx_lookup: 100,
        ..IndexRowBytes::ZERO
    };
    let partial_recorder = RecordedHistograms::default();
    metrics::with_local_recorder(&partial_recorder, || {
        super::super::write::record_family_byte_histograms(&partial_family);
    });
    let partial_recorded = partial_recorder.samples.lock().clone();
    assert_eq!(
        partial_recorded.get("index.family_planned_write_bytes{family=\"tx_lookup\"}"),
        Some(&vec![100.0])
    );
    assert_eq!(partial_recorded.len(), 1, "a zero family records nothing");
}

#[derive(Clone, Debug, Default)]
struct RecordedHistograms {
    samples: std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<String, Vec<f64>>>>,
}

impl metrics::Recorder for RecordedHistograms {
    fn describe_counter(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }
    fn register_counter(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        metrics::Counter::noop()
    }
    fn register_gauge(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        let labels = key
            .labels()
            .map(|l| format!("{}=\"{}\"", l.key(), l.value()))
            .collect::<Vec<_>>()
            .join(",");
        let metric_name = if labels.is_empty() {
            key.name().to_owned()
        } else {
            format!("{}{{{labels}}}", key.name())
        };
        metrics::Histogram::from_arc(std::sync::Arc::new(RecordedHistogramHandle {
            samples: std::sync::Arc::clone(&self.samples),
            name: metric_name,
        }))
    }
}

struct RecordedHistogramHandle {
    samples: std::sync::Arc<parking_lot::Mutex<std::collections::HashMap<String, Vec<f64>>>>,
    name: String,
}

impl metrics::HistogramFn for RecordedHistogramHandle {
    fn record(&self, value: f64) {
        self.samples
            .lock()
            .entry(self.name.clone())
            .or_default()
            .push(value);
    }
}

fn op_cf(op: &BatchOp) -> ColumnFamily {
    match op {
        BatchOp::Put { cf, .. } | BatchOp::Delete { cf, .. } | BatchOp::DeleteRange { cf, .. } => {
            *cf
        }
    }
}

fn op_len(op: &BatchOp) -> usize {
    match op {
        BatchOp::Put { key, value, .. } => key.len() + value.len(),
        BatchOp::Delete { key, .. } => key.len(),
        BatchOp::DeleteRange { start, end, .. } => start.len() + end.len(),
    }
}

fn emitted_bytes(ops: &[BatchOp], cf: ColumnFamily) -> usize {
    ops.iter().filter(|op| op_cf(op) == cf).map(op_len).sum()
}

#[test]
fn family_bytes_accounting() -> Result<(), IndexError> {
    let outpoint1 = OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0);
    let outpoint2 = OutPoint::new(Txid(Hash256::from_le_bytes(&[2; 32])), 1);
    let live_row1 = ScriptLiveRow::new(ScriptHash::from_byte_array([10; 32]), &outpoint1);
    let live_row2 = ScriptLiveRow::new(ScriptHash::from_byte_array([20; 32]), &outpoint2);
    let live_coin1 =
        crate::types::ScriptLiveCoin::new(ScriptHash::from_byte_array([10; 32]), 100, 7, false);
    let live_coin2 =
        crate::types::ScriptLiveCoin::new(ScriptHash::from_byte_array([20; 32]), 200, 8, false);
    let rows = PendingRows {
        header_rows: vec![
            [0x42; crate::types::HEADER_ROW_SIZE],
            [0x43; crate::types::HEADER_ROW_SIZE],
        ],
        live_ops: vec![
            LiveOp::Insert {
                row: live_row1,
                coin: live_coin1,
            },
            LiveOp::Delete {
                row: live_row2,
                coin: live_coin2,
            },
        ],
    };
    let family = rows.encoded_bytes_by_family()?;
    let mut batch = BufferedWriteBatch::default();
    put_rows(&mut batch, &rows)?;
    let emitted = batch.into_ops();

    assert_eq!(
        family.headers,
        2 * crate::types::HEADER_ROW_SIZE,
        "each header row is one fixed-width key"
    );
    assert_eq!(
        family.headers,
        emitted_bytes(&emitted, ColumnFamily::BlockHeaders)
    );
    assert_eq!(
        family.script_live,
        emitted_bytes(&emitted, ColumnFamily::ScriptLive),
        "a live insert plans its key and value, a live delete its key"
    );
    assert_eq!(
        family.tx_lookup + family.script_history + family.filters + family.tail_log,
        0,
        "block rows plan only the header and live families"
    );
    assert_eq!(
        family.total()?,
        emitted.iter().map(op_len).sum::<usize>(),
        "the planned total equals the emitted key and value bytes"
    );
    Ok(())
}

fn family_mut(bytes: &mut IndexRowBytes, index: usize) -> &mut usize {
    match index {
        0 => &mut bytes.tx_lookup,
        1 => &mut bytes.script_history,
        2 => &mut bytes.script_live,
        3 => &mut bytes.headers,
        4 => &mut bytes.filters,
        _ => &mut bytes.tail_log,
    }
}

#[test]
fn family_bytes_overflow_detection() {
    let overflow_total = IndexRowBytes {
        tx_lookup: usize::MAX,
        script_history: 1,
        ..IndexRowBytes::ZERO
    };
    assert!(matches!(
        overflow_total.total(),
        Err(IndexError::MutationSizeOverflow)
    ));

    for index in 0..6 {
        let mut at_max = IndexRowBytes::ZERO;
        *family_mut(&mut at_max, index) = usize::MAX;
        let mut one = IndexRowBytes::ZERO;
        *family_mut(&mut one, index) = 1;
        assert!(
            matches!(
                at_max.checked_add(&one),
                Err(IndexError::MutationSizeOverflow)
            ),
            "family {index} overflows on checked add"
        );
    }
}

#[test]
fn family_bytes_sum_matches_every_family() -> Result<(), IndexError> {
    let addend = IndexRowBytes {
        tx_lookup: 1,
        script_history: 2,
        script_live: 3,
        headers: 4,
        filters: 5,
        tail_log: 6,
    };
    let doubled = addend.checked_add(&addend)?;
    assert_eq!(
        doubled,
        IndexRowBytes {
            tx_lookup: 2,
            script_history: 4,
            script_live: 6,
            headers: 8,
            filters: 10,
            tail_log: 12,
        }
    );
    assert_eq!(addend.total()?, 21);
    Ok(())
}

fn assert_same_ops(actual: &[BatchOp], expected: &[BatchOp]) {
    assert_eq!(actual.len(), expected.len(), "operation count");
    for op in expected {
        assert!(actual.contains(op), "missing {op:?}");
    }
}

#[test]
fn row_deletes_mirror_inserts_and_shared_headers_are_deleted_only_on_request()
-> Result<(), IndexError> {
    let outpoint1 = OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0);
    let outpoint2 = OutPoint::new(Txid(Hash256::from_le_bytes(&[2; 32])), 1);
    let rows = PendingRows {
        header_rows: vec![
            [1; crate::types::HEADER_ROW_SIZE],
            [2; crate::types::HEADER_ROW_SIZE],
        ],
        live_ops: vec![
            LiveOp::Insert {
                row: ScriptLiveRow::new(ScriptHash::from_byte_array([10; 32]), &outpoint1),
                coin: crate::types::ScriptLiveCoin::new(
                    ScriptHash::from_byte_array([10; 32]),
                    100,
                    7,
                    false,
                ),
            },
            LiveOp::Insert {
                row: ScriptLiveRow::new(ScriptHash::from_byte_array([20; 32]), &outpoint2),
                coin: crate::types::ScriptLiveCoin::new(
                    ScriptHash::from_byte_array([20; 32]),
                    200,
                    8,
                    false,
                ),
            },
        ],
    };
    let mut puts = BufferedWriteBatch::default();
    put_rows(&mut puts, &rows)?;
    let puts = puts.into_ops();
    assert!(
        puts.iter().all(|op| matches!(op, BatchOp::Put { .. })),
        "put_rows emits only puts"
    );
    let mut live_key1 = [0u8; crate::types::SCRIPT_LIVE_ROW_SIZE];
    live_key1[0..8].copy_from_slice(&[10u8; 8]);
    live_key1[8..40].copy_from_slice(&[1u8; 32]);
    let mut live_key2 = [0u8; crate::types::SCRIPT_LIVE_ROW_SIZE];
    live_key2[0..8].copy_from_slice(&[20u8; 8]);
    live_key2[8..40].copy_from_slice(&[2u8; 32]);
    live_key2[40..43].copy_from_slice(&[1u8, 0u8, 0u8]);
    let live_deletes = vec![
        BatchOp::Delete {
            cf: ColumnFamily::ScriptLive,
            key: live_key1.to_vec(),
        },
        BatchOp::Delete {
            cf: ColumnFamily::ScriptLive,
            key: live_key2.to_vec(),
        },
    ];
    let all_deletes = vec![
        BatchOp::Delete {
            cf: ColumnFamily::BlockHeaders,
            key: vec![1u8; crate::types::HEADER_ROW_SIZE],
        },
        BatchOp::Delete {
            cf: ColumnFamily::BlockHeaders,
            key: vec![2u8; crate::types::HEADER_ROW_SIZE],
        },
        BatchOp::Delete {
            cf: ColumnFamily::ScriptLive,
            key: live_key1.to_vec(),
        },
        BatchOp::Delete {
            cf: ColumnFamily::ScriptLive,
            key: live_key2.to_vec(),
        },
    ];
    assert_eq!(live_deletes.len(), 2);
    assert_eq!(all_deletes.len(), 4);

    let mut plain = BufferedWriteBatch::default();
    delete_rows(&mut plain, &rows)?;
    let plain = plain.into_ops();
    assert_same_ops(&plain, &live_deletes);

    let mut with_headers = BufferedWriteBatch::default();
    delete_rows_with_headers(&mut with_headers, &rows)?;
    let with_headers = with_headers.into_ops();
    assert_same_ops(&with_headers, &all_deletes);
    assert!(
        plain
            .iter()
            .chain(with_headers.iter())
            .all(|op| !matches!(op, BatchOp::DeleteRange { .. })),
        "row deletes never emit range deletes"
    );
    Ok(())
}
