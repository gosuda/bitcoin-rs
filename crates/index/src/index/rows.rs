//! Canonical row accounting, grouping, and ordered live-view mutations.

use super::error::IndexError;
use crate::types::HashPrefixRow;
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily};
use zerocopy::IntoBytes;

/// One ordered live-view mutation produced by a block.
///
/// Order is semantic, unlike every other pending row family: a later block in
/// the same committed batch may delete a key an earlier block inserted, so
/// these are applied first-to-last with the last operation per key winning.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum LiveOp {
    /// The block created this currently-unspent output.
    Insert(crate::types::ScriptLiveRow),
    /// The block spent this previously-live output.
    Delete(crate::types::ScriptLiveRow),
}

/// Counts of rows written by a confirmed prepared commit.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexRowCounts {
    /// Transaction-id index rows written to [`ColumnFamily::TxConfirmed`].
    pub txids: usize,
    /// Script funding rows written to [`ColumnFamily::Funding`].
    pub funding: usize,
    /// Previous-outpoint spending rows written to [`ColumnFamily::Spending`].
    pub spending: usize,
    /// Header rows written to [`ColumnFamily::BlockHeaders`].
    pub headers: usize,
    /// Live-output mutations applied to [`ColumnFamily::ScriptLive`].
    pub live: usize,
    /// Basic-filter rows written to the optional index metadata namespace.
    pub filters: usize,
}

/// One index row together with the transaction byte range that produced it.
///
/// Ordered by key first so a sorted slice groups by row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PositionedRow {
    pub(super) row: HashPrefixRow,
    pub(super) position: crate::types::TxPosition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PositionedHistory {
    pub(super) row: HashPrefixRow,
    pub(super) occurrence: crate::types::ScriptHistoryOccurrence,
}

impl Ord for PositionedHistory {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.row
            .cmp(&other.row)
            .then_with(|| self.occurrence.position.cmp(&other.occurrence.position))
            .then_with(|| self.occurrence.txid.cmp(&other.occurrence.txid))
            .then_with(|| self.occurrence.scripthash.cmp(&other.occurrence.scripthash))
            .then_with(|| self.occurrence.flags.cmp(&other.occurrence.flags))
    }
}

impl PartialOrd for PositionedHistory {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
pub(super) struct PendingRows {
    pub(super) txid_rows: Vec<PositionedRow>,
    pub(super) funding_rows: Vec<PositionedHistory>,
    pub(super) spending_rows: Vec<PositionedRow>,
    pub(super) header_rows: Vec<[u8; crate::types::HEADER_ROW_SIZE]>,
    /// Ordered live-view mutations. Never sorted: unlike the append-only
    /// families above, this one mixes puts and deletes, and a later block's
    /// delete of an earlier block's insert must stay later.
    pub(super) live_ops: Vec<LiveOp>,
    pub(super) filter_rows: Vec<([u8; 32], super::filters::BasicFilter)>,
}

/// Counts distinct row keys in a sorted `PositionedRow` slice.
///
/// The reported count must stay "rows the store receives", not "positions
/// collected": one key can carry several positions when a block funds the same
/// script from more than one transaction, and those collapse into one row.
fn distinct_row_count(rows: &[PositionedRow]) -> usize {
    rows.chunk_by(|left, right| left.row == right.row).count()
}

fn distinct_history_row_count(rows: &[PositionedHistory]) -> usize {
    rows.chunk_by(|left, right| left.row == right.row).count()
}

/// Calls `emit` once per row key in a sorted slice, with that key's positions.
///
/// Two blocks at one height that share a key merge their positions into one
/// value. That is safe because the query engine bounds-checks every position and
/// falls back to a full-block scan when a position it reads does not resolve to
/// the requested transaction, so a merged value costs at most a scan. See
/// [`crate::types::TxPositionValue`].
fn for_each_row_group<F>(rows: &[PositionedRow], mut emit: F)
where
    F: FnMut(HashPrefixRow, &[crate::types::TxPosition]),
{
    let mut positions = Vec::new();
    for group in rows.chunk_by(|left, right| left.row == right.row) {
        positions.clear();
        positions.extend(group.iter().map(|entry| entry.position));
        emit(group[0].row, &positions);
    }
}

impl PendingRows {
    pub(super) fn sort(&mut self) {
        self.txid_rows.sort_unstable();
        self.funding_rows.sort_unstable();
        self.spending_rows.sort_unstable();
        self.header_rows.sort_unstable();
        self.txid_rows.dedup();
        // Merge funding and spending references made by the same transaction
        // for the same exact script into one ordered history occurrence.
        let mut merged: Vec<PositionedHistory> = Vec::with_capacity(self.funding_rows.len());
        for entry in self.funding_rows.drain(..) {
            if let Some(previous) = merged.last_mut()
                && previous.row == entry.row
                && previous.occurrence.position == entry.occurrence.position
                && previous.occurrence.txid == entry.occurrence.txid
                && previous.occurrence.scripthash == entry.occurrence.scripthash
            {
                previous.occurrence.flags |= entry.occurrence.flags;
            } else {
                merged.push(entry);
            }
        }
        self.funding_rows = merged;
        self.spending_rows.dedup();
        self.header_rows.dedup();
    }

    pub(super) fn counts(&self) -> IndexRowCounts {
        IndexRowCounts {
            txids: distinct_row_count(&self.txid_rows),
            funding: distinct_history_row_count(&self.funding_rows),
            spending: distinct_row_count(&self.spending_rows),
            headers: self.header_rows.len(),
            live: self.live_ops.len(),
            filters: self.filter_rows.len(),
        }
    }
    pub(super) fn append(&mut self, other: Self) {
        self.txid_rows.extend(other.txid_rows);
        self.funding_rows.extend(other.funding_rows);
        self.spending_rows.extend(other.spending_rows);
        self.header_rows.extend(other.header_rows);
        self.live_ops.extend(other.live_ops);
        self.filter_rows.extend(other.filter_rows);
    }

    pub(super) fn total(&self) -> usize {
        let counts = self.counts();
        counts.txids
            + counts.funding
            + counts.spending
            + counts.headers
            + counts.live
            + counts.filters
    }

    pub(super) fn encoded_bytes(&self) -> Result<usize, IndexError> {
        let txid_positions = self.txid_rows.len();
        let funding_positions = self.funding_rows.len();
        let distinct_prefix = distinct_row_count(&self.txid_rows)
            .checked_add(distinct_history_row_count(&self.funding_rows))
            .and_then(|s| s.checked_add(distinct_row_count(&self.spending_rows)))
            .ok_or(IndexError::MutationSizeOverflow)?;
        let prefix_bytes = distinct_prefix
            .checked_mul(crate::types::HASH_PREFIX_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let position_count = txid_positions
            .checked_add(self.spending_rows.len())
            .ok_or(IndexError::MutationSizeOverflow)?;
        let position_bytes = position_count
            .checked_mul(crate::types::TX_POSITION_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let header_bytes = self
            .header_rows
            .len()
            .checked_mul(crate::types::HEADER_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let live_bytes = self
            .live_ops
            .len()
            .checked_mul(crate::types::SCRIPT_LIVE_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let history_bytes = funding_positions
            .checked_mul(32 + 32 + crate::types::TX_POSITION_SIZE + 1)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let filter_bytes = self
            .filter_rows
            .iter()
            .try_fold(0_usize, |total, (_, row)| {
                total
                    .checked_add(34 + 64 + row.filter.len())
                    .ok_or(IndexError::MutationSizeOverflow)
            })?;
        prefix_bytes
            .checked_add(position_bytes)
            .and_then(|s| s.checked_add(history_bytes))
            .and_then(|s| s.checked_add(filter_bytes))
            .and_then(|s| s.checked_add(header_bytes))
            .and_then(|s| s.checked_add(live_bytes))
            .ok_or(IndexError::MutationSizeOverflow)
    }
}

/// Applies ordered live mutations to `batch`, last operation per key winning.
///
/// Coalescing in memory rather than relying on the backend's write-batch
/// ordering keeps the semantics backend-independent: after this, each key
/// appears in the batch at most once. `invert` swaps inserts and deletes,
/// which is exactly a block's live rollback; inverted ops are applied in
/// reverse order so the earliest forward operation determines each key's
/// undo mutation.
fn apply_live_ops(batch: &mut BufferedWriteBatch, ops: &[LiveOp], invert: bool) {
    let mut last: hashbrown::HashMap<[u8; crate::types::SCRIPT_LIVE_ROW_SIZE], bool> =
        hashbrown::HashMap::new();
    let record = |op: &LiveOp| {
        let (row, insert) = match op {
            LiveOp::Insert(row) => (row, !invert),
            LiveOp::Delete(row) => (row, invert),
        };
        last.insert(*row.as_bytes(), insert);
    };
    if invert {
        ops.iter().rev().for_each(record);
    } else {
        ops.iter().for_each(record);
    }
    for (key, insert) in last {
        if insert {
            batch.put(ColumnFamily::ScriptLive, &key, &[]);
        } else {
            batch.delete(ColumnFamily::ScriptLive, &key);
        }
    }
}

pub(super) fn put_rows(batch: &mut BufferedWriteBatch, rows: &PendingRows) {
    for (cf, positioned) in [
        (ColumnFamily::TxConfirmed, &rows.txid_rows),
        (ColumnFamily::Spending, &rows.spending_rows),
    ] {
        for_each_row_group(positioned, |row, positions| {
            batch.put(
                cf,
                row.as_bytes(),
                &crate::types::TxPositionValue::encode(positions),
            );
        });
    }
    for group in rows
        .funding_rows
        .chunk_by(|left, right| left.row == right.row)
    {
        let occurrences: Vec<_> = group.iter().map(|entry| entry.occurrence).collect();
        batch.put(
            ColumnFamily::Funding,
            group[0].row.as_bytes(),
            &crate::types::ScriptHistoryOccurrence::encode_all(&occurrences),
        );
    }
    for row in &rows.header_rows {
        batch.put(ColumnFamily::BlockHeaders, row, &[]);
    }
    for (hash, filter) in &rows.filter_rows {
        batch.put(
            ColumnFamily::UtxoMeta,
            &super::filters::key(hash),
            &filter.encode(),
        );
    }
    apply_live_ops(batch, &rows.live_ops, false);
}

pub(super) fn delete_rows(
    batch: &mut BufferedWriteBatch,
    rows: &PendingRows,
    delete_shared_identity: bool,
) {
    for (cf, positioned) in [
        (ColumnFamily::TxConfirmed, &rows.txid_rows),
        (ColumnFamily::Spending, &rows.spending_rows),
    ] {
        for group in positioned.chunk_by(|left, right| left.row == right.row) {
            batch.delete(cf, group[0].row.as_bytes());
        }
    }
    for group in rows
        .funding_rows
        .chunk_by(|left, right| left.row == right.row)
    {
        batch.delete(ColumnFamily::Funding, group[0].row.as_bytes());
    }
    // Rollback reverses the authoritative live transition, preserving op order.
    for (hash, _) in &rows.filter_rows {
        batch.delete(ColumnFamily::UtxoMeta, &super::filters::key(hash));
    }
    apply_live_ops(batch, &rows.live_ops, true);
    if delete_shared_identity {
        for row in &rows.header_rows {
            batch.delete(ColumnFamily::BlockHeaders, row);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin_rs_primitives::{Hash256, OutPoint, Txid};
    use bitcoin_rs_storage::{BatchOp, BufferedWriteBatch, ColumnFamily};

    use super::*;
    use crate::types::{HashPrefixRow, ScriptHash, ScriptLiveRow, TxPosition};

    /// Reads the target family of one recorded operation.
    fn op_cf(op: &BatchOp) -> ColumnFamily {
        match op {
            BatchOp::Put { cf, .. }
            | BatchOp::Delete { cf, .. }
            | BatchOp::DeleteRange { cf, .. } => *cf,
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

    fn positioned_histories() -> Vec<PositionedHistory> {
        let first = HashPrefixRow::new([1; 8], 7);
        let second = HashPrefixRow::new([2; 8], 7);
        let occurrence = |offset: u32, txid: u8| crate::types::ScriptHistoryOccurrence {
            scripthash: ScriptHash::from_byte_array([txid; 32]),
            txid: [txid; 32],
            position: TxPosition::new(offset, 30),
            flags: crate::types::ScriptHistoryOccurrence::FUNDING,
        };
        vec![
            PositionedHistory {
                row: second,
                occurrence: occurrence(500, 3),
            },
            PositionedHistory {
                row: first,
                occurrence: occurrence(256, 1),
            },
            PositionedHistory {
                row: first,
                occurrence: occurrence(81, 2),
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
            funding_rows: positioned_histories(),
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
}
