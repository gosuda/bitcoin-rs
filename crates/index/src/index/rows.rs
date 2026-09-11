//! Canonical row accounting, grouping, and ordered live-view mutations.

use super::error::IndexError;
use crate::types::HashPrefixRow;
use bitcoin_rs_storage::{ColumnFamily, WriteBatch};
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
}

/// One index row together with the transaction byte range that produced it.
///
/// Ordered by key first so a sorted slice groups by row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PositionedRow {
    pub(super) row: HashPrefixRow,
    pub(super) position: crate::types::TxPosition,
}

#[derive(Default)]
pub(super) struct PendingRows {
    pub(super) txid_rows: Vec<PositionedRow>,
    pub(super) funding_rows: Vec<PositionedRow>,
    pub(super) spending_rows: Vec<PositionedRow>,
    pub(super) header_rows: Vec<[u8; crate::types::HEADER_ROW_SIZE]>,
    /// Ordered live-view mutations. Never sorted: unlike the append-only
    /// families above, this one mixes puts and deletes, and a later block's
    /// delete of an earlier block's insert must stay later.
    pub(super) live_ops: Vec<LiveOp>,
}

/// Counts distinct row keys in a sorted `PositionedRow` slice.
///
/// The reported count must stay "rows the store receives", not "positions
/// collected": one key can carry several positions when a block funds the same
/// script from more than one transaction, and those collapse into one row.
fn distinct_row_count(rows: &[PositionedRow]) -> usize {
    rows.chunk_by(|left, right| left.row == right.row).count()
}

/// Calls `emit` once per row key in a sorted slice, with that key's positions.
///
/// Two blocks at one height that share a key merge their positions into one
/// value. That is safe because the reader validates every position and falls
/// back to a full scan on the first one that does not resolve, so a merged value
/// costs at most a scan — see [`crate::types::TxPositionValue`].
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
        self.funding_rows.dedup();
        self.spending_rows.dedup();
        self.header_rows.dedup();
    }

    pub(super) fn counts(&self) -> IndexRowCounts {
        IndexRowCounts {
            txids: distinct_row_count(&self.txid_rows),
            funding: distinct_row_count(&self.funding_rows),
            spending: distinct_row_count(&self.spending_rows),
            headers: self.header_rows.len(),
            live: self.live_ops.len(),
        }
    }
    pub(super) fn append(&mut self, other: Self) {
        self.txid_rows.extend(other.txid_rows);
        self.funding_rows.extend(other.funding_rows);
        self.spending_rows.extend(other.spending_rows);
        self.header_rows.extend(other.header_rows);
        self.live_ops.extend(other.live_ops);
    }

    pub(super) fn total(&self) -> usize {
        let counts = self.counts();
        counts.txids + counts.funding + counts.spending + counts.headers + counts.live
    }

    pub(super) fn encoded_bytes(&self) -> Result<usize, IndexError> {
        let txid_positions = self.txid_rows.len();
        let funding_positions = self.funding_rows.len();
        let distinct_prefix = distinct_row_count(&self.txid_rows)
            .checked_add(distinct_row_count(&self.funding_rows))
            .and_then(|s| s.checked_add(distinct_row_count(&self.spending_rows)))
            .ok_or(IndexError::MutationSizeOverflow)?;
        let prefix_bytes = distinct_prefix
            .checked_mul(crate::types::HASH_PREFIX_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let position_count = txid_positions
            .checked_add(funding_positions)
            .and_then(|s| s.checked_add(self.spending_rows.len()))
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
        prefix_bytes
            .checked_add(position_bytes)
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
fn apply_live_ops<B: WriteBatch>(batch: &mut B, ops: &[LiveOp], invert: bool) {
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

pub(super) fn put_rows<B: WriteBatch>(batch: &mut B, rows: &PendingRows) {
    for (cf, positioned) in [
        (ColumnFamily::TxConfirmed, &rows.txid_rows),
        (ColumnFamily::Funding, &rows.funding_rows),
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
    for row in &rows.header_rows {
        batch.put(ColumnFamily::BlockHeaders, row, &[]);
    }
    apply_live_ops(batch, &rows.live_ops, false);
}

pub(super) fn delete_rows<B: WriteBatch>(
    batch: &mut B,
    rows: &PendingRows,
    delete_shared_identity: bool,
) {
    for (cf, positioned) in [
        (ColumnFamily::TxConfirmed, &rows.txid_rows),
        (ColumnFamily::Funding, &rows.funding_rows),
        (ColumnFamily::Spending, &rows.spending_rows),
    ] {
        for group in positioned.chunk_by(|left, right| left.row == right.row) {
            batch.delete(cf, group[0].row.as_bytes());
        }
    }
    // Rollback reverses the authoritative live transition, preserving op order.
    apply_live_ops(batch, &rows.live_ops, true);
    if delete_shared_identity {
        for row in &rows.header_rows {
            batch.delete(ColumnFamily::BlockHeaders, row);
        }
    }
}

#[cfg(test)]
mod tests;
