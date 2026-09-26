use std::collections::BTreeMap;

use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};
use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily};

use super::{
    IndexError, IndexRowCounts, LiveOp, PendingRows, PositionedRow, apply_live_ops, delete_rows,
    distinct_row_count, for_each_row_group, put_rows,
};
use crate::types::{HashPrefixRow, ScriptHash, ScriptLiveRow, TxPosition};

/// Reads the target family of one recorded operation.
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

// Contract: `docs/benchmarks/scriptindex-format.md`, § Logical vs physical bytes
// (rows 163-181), together with `crates/index/src/index/rows.rs`'s
// `for_each_row_group` contract: one stored key retains all numeric positions.
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

// Contract: `docs/benchmarks/scriptindex-format.md`, § Logical vs physical
// bytes (rows 163-181), and `crates/index/src/index/rows.rs`'s
// `PendingRows::encoded_bytes`/`delete_rows` contracts: emitted logical bytes
// match row accounting, and shared block-header identity is retained unless
// explicitly requested for deletion.
#[test]
fn row_accounting_matches_emitted_bytes_and_shared_header_deletion() -> Result<(), IndexError> {
    let mut rows = PendingRows {
        txid_rows: positioned_rows(),
        funding_rows: positioned_rows(),
        spending_rows: positioned_rows(),
        header_rows: vec![[1; crate::types::HEADER_ROW_SIZE]],
        live_ops: Vec::new(),
    };
    rows.sort();
    assert_eq!(
        rows.counts(),
        IndexRowCounts {
            txids: 2,
            funding: 2,
            spending: 2,
            headers: 1,
            live: 0
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

// Contract: `crates/index/src/index/rows.rs`, `LiveOp` and
// `apply_live_ops` documentation (lines 8-18 and 153-160): forward application
// is last-operation-wins, while rollback is the exact inverse using the
// first forward operation. This is the small-sequence regression for that
// forward/rollback coalescing requirement.
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
