use std::collections::BTreeMap;

use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily};

use super::*;
use crate::types::{HashPrefixRow, ScriptHash, ScriptLiveRow, TxPosition};

fn op_cf(op: &BatchOp) -> ColumnFamily {
    match op {
        BatchOp::Put { cf, .. } | BatchOp::Delete { cf, .. } | BatchOp::DeleteRange { cf, .. } => {
            *cf
        }
    }
}

fn positioned_rows() -> Vec<PositionedRow> {
    let first = HashPrefixRow::new([1; 8], 7);
    let second = HashPrefixRow::new([2; 8], 7);
    vec![
        PositionedRow {
            row: second,
            position: TxPosition::new(500, 30),
        },
        PositionedRow {
            row: first,
            position: TxPosition::new(256, 20),
        },
        PositionedRow {
            row: first,
            position: TxPosition::new(81, 10),
        },
        PositionedRow {
            row: first,
            position: TxPosition::new(81, 10),
        },
    ]
}

/// Byte contract (`docs/benchmarks/scriptindex-format.md` § Logical vs physical
/// bytes): `tx_lookup` 42 = 24 prefix + 18 pos; `script_history` 84; headers 80;
/// `script_live` 86; filters 101.
///
/// Family total equals `encoded_bytes`; physical put bytes match the family total.
#[test]
fn family_bytes_accounting() -> Result<(), IndexError> {
    let outpoint1 = OutPoint::new(Txid(Hash256::from_le_bytes(&[1; 32])), 0);
    let outpoint2 = OutPoint::new(Txid(Hash256::from_le_bytes(&[2; 32])), 1);
    let live_row1 = ScriptLiveRow::new(ScriptHash::from_byte_array([10; 32]), &outpoint1);
    let live_row2 = ScriptLiveRow::new(ScriptHash::from_byte_array([20; 32]), &outpoint2);

    let filter = super::super::filters::BasicFilter {
        filter: vec![0xaa, 0xbb, 0xcc],
        hash: [0x11; 32],
        header: [0x22; 32],
    };

    let mut rows = PendingRows {
        txid_rows: positioned_rows(),
        funding_rows: positioned_rows(),
        spending_rows: positioned_rows(),
        header_rows: vec![[0x42; crate::types::HEADER_ROW_SIZE]],
        live_ops: vec![LiveOp::Insert(live_row1), LiveOp::Delete(live_row2)],
        filter_rows: vec![([0x33; 32], filter)],
    };
    rows.sort();

    let family = rows.encoded_bytes_by_family()?;
    let total_bytes = rows.encoded_bytes()?;

    assert_eq!(family.total()?, total_bytes);

    assert_eq!(family.tx_lookup, 42);
    assert_eq!(family.script_history, 84);
    assert_eq!(family.headers, 80);
    assert_eq!(family.script_live, 86);
    assert_eq!(family.filters, 101);

    assert_eq!(total_bytes, 42 + 84 + 80 + 86 + 101);

    let mut puts = BufferedWriteBatch::default();
    put_rows(&mut puts, &rows);
    let emitted_bytes: usize = puts
        .into_ops()
        .iter()
        .map(|op| match op {
            BatchOp::Put { key, value, .. } => key.len() + value.len(),
            BatchOp::Delete { key, .. } => key.len(),
            BatchOp::DeleteRange { start, end, .. } => start.len() + end.len(),
        })
        .sum();
    assert_eq!(emitted_bytes, total_bytes);

    let mut batch =
        super::super::prepared::PreparedBatch::new(super::super::prepared::PreparedBatchLimits {
            max_rows: 100,
            max_bytes: 10_000,
        });
    let block = super::super::prepared::PreparedBlock {
        height: 1,
        hash: [1; 32],
        parent_hash: [0; 32],
        row_count: rows.total(),
        encoded_bytes: total_bytes,
        family_bytes: family,
        capabilities: super::super::capability::IndexCapabilities::ALL,
        rows,
    };
    batch
        .try_push(block)
        .map_err(|_| IndexError::MutationSizeOverflow)?;
    assert_eq!(batch.family_bytes(), family);
    assert_eq!(batch.encoded_bytes(), total_bytes);

    Ok(())
}

#[test]
fn family_bytes_overflow_detection() {
    let overflow_total = IndexRowBytes {
        tx_lookup: usize::MAX,
        script_history: 1,
        script_live: 0,
        headers: 0,
        filters: 0,
    };
    assert!(matches!(
        overflow_total.total(),
        Err(IndexError::MutationSizeOverflow)
    ));

    let base_family = IndexRowBytes {
        tx_lookup: usize::MAX - 5,
        script_history: 10,
        script_live: 10,
        headers: 10,
        filters: 10,
    };
    let add_overflow = IndexRowBytes {
        tx_lookup: 10,
        script_history: 0,
        script_live: 0,
        headers: 0,
        filters: 0,
    };
    assert!(matches!(
        base_family.checked_add(&add_overflow),
        Err(IndexError::MutationSizeOverflow)
    ));
}

#[test]
fn family_byte_histograms_recording() {
    let family = IndexRowBytes {
        tx_lookup: 42,
        script_history: 84,
        script_live: 86,
        headers: 80,
        filters: 101,
    };
    let recorder = RecordedHistograms::default();
    metrics::with_local_recorder(&recorder, || {
        super::super::write::record_family_byte_histograms(&family);
    });
    let recorded = recorder.samples.lock().clone();
    assert_eq!(
        recorded.get("index.family_planned_write_bytes{family=\"tx_lookup\"}"),
        Some(&vec![42.0])
    );
    assert_eq!(
        recorded.get("index.family_planned_write_bytes{family=\"script_history\"}"),
        Some(&vec![84.0])
    );
    assert_eq!(
        recorded.get("index.family_planned_write_bytes{family=\"headers\"}"),
        Some(&vec![80.0])
    );
    assert_eq!(
        recorded.get("index.family_planned_write_bytes{family=\"script_live\"}"),
        Some(&vec![86.0])
    );
    assert_eq!(
        recorded.get("index.family_planned_write_bytes{family=\"filters\"}"),
        Some(&vec![101.0])
    );

    let partial_family = IndexRowBytes {
        tx_lookup: 100,
        script_history: 0,
        script_live: 0,
        headers: 0,
        filters: 0,
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
    assert_eq!(partial_recorded.len(), 1);
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

#[test]
fn groups_preserve_distinct_keys_and_numeric_positions() {
    let mut rows = positioned_rows();
    rows.sort_unstable();
    rows.dedup();
    let mut grouped = Vec::new();
    for_each_row_group(&rows, |key, positions| {
        grouped.push((key, positions.to_vec()));
    });
    assert_eq!(distinct_row_count(&rows), 2);
    assert_eq!(
        grouped,
        vec![
            (
                HashPrefixRow::new([1; 8], 7),
                vec![TxPosition::new(81, 10), TxPosition::new(256, 20)]
            ),
            (
                HashPrefixRow::new([2; 8], 7),
                vec![TxPosition::new(500, 30)]
            ),
        ]
    );
    assert_eq!(distinct_row_count(&[]), 0);
    let mut empty_groups = 0;
    for_each_row_group(&[], |_, _| empty_groups += 1);
    assert_eq!(empty_groups, 0);
}

#[test]
fn row_accounting_matches_emitted_bytes_and_shared_header_deletion() -> Result<(), IndexError> {
    let mut rows = PendingRows {
        txid_rows: positioned_rows(),
        funding_rows: positioned_rows(),
        spending_rows: positioned_rows(),
        header_rows: vec![[1; crate::types::HEADER_ROW_SIZE]],
        live_ops: Vec::new(),
        filter_rows: Vec::new(),
    };
    rows.sort();
    assert_eq!(
        rows.counts(),
        IndexRowCounts {
            txids: 2,
            funding: 2,
            spending: 2,
            headers: 1,
            live: 0,
            filters: 0,
        }
    );
    let mut puts = BufferedWriteBatch::default();
    put_rows(&mut puts, &rows);
    let puts = puts.into_ops();
    assert_eq!(puts.len(), rows.total());
    let encoded_bytes: usize = puts
        .iter()
        .map(|op| match op {
            BatchOp::Put { key, value, .. } => key.len() + value.len(),
            BatchOp::Delete { key, .. } => key.len(),
            BatchOp::DeleteRange { start, end, .. } => start.len() + end.len(),
        })
        .sum();
    assert_eq!(rows.encoded_bytes()?, encoded_bytes);
    for delete_shared_identity in [false, true] {
        let mut deletes = BufferedWriteBatch::default();
        delete_rows(&mut deletes, &rows, delete_shared_identity);
        let deletes = deletes.into_ops();
        let expected: Vec<_> = puts
            .iter()
            .filter(|op| delete_shared_identity || op_cf(op) != ColumnFamily::BlockHeaders)
            .map(|op| match op {
                BatchOp::Put { cf, key, .. } => BatchOp::Delete {
                    cf: *cf,
                    key: key.clone(),
                },
                _ => unreachable!("put_rows records only puts"),
            })
            .collect();
        assert_eq!(deletes, expected);
        assert!(
            deletes
                .iter()
                .all(|op| !matches!(op, BatchOp::DeleteRange { .. }))
        );
    }
    assert!(
        puts.iter()
            .all(|op| !matches!(op, BatchOp::DeleteRange { .. }))
    );
    Ok(())
}

#[test]
fn live_coalescing_matches_first_and_last_operations_for_all_small_sequences() {
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[0; 32])), 0);
    let keys = [
        ScriptLiveRow::new(ScriptHash::from_byte_array([0; 32]), &outpoint),
        ScriptLiveRow::new(ScriptHash::from_byte_array([1; 32]), &outpoint),
    ];
    let choices = [
        LiveOp::Insert(keys[0]),
        LiveOp::Delete(keys[0]),
        LiveOp::Insert(keys[1]),
        LiveOp::Delete(keys[1]),
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
                apply_live_ops(&mut batch, &ops, invert);
                let mut expected = BTreeMap::new();
                for key in keys {
                    let matches_key = |op: &&LiveOp| match op {
                        LiveOp::Insert(row) | LiveOp::Delete(row) => *row == key,
                    };
                    let decisive = if invert {
                        ops.iter().find(matches_key)
                    } else {
                        ops.iter().rfind(matches_key)
                    };
                    if let Some(op) = decisive {
                        let insert = matches!(op, LiveOp::Insert(_)) != invert;
                        expected.insert(key.as_bytes().to_vec(), insert.then(Vec::new));
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
}
