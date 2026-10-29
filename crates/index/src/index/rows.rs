//! Canonical row accounting, grouping, and ordered live-view mutations.

use super::error::IndexError;
use crate::types::HashPrefixRow;
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily};
use zerocopy::IntoBytes;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum LiveOp {
    Insert(crate::types::ScriptLiveRow),
    Delete(crate::types::ScriptLiveRow),
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexRowCounts {
    pub txids: usize,
    pub funding: usize,
    pub spending: usize,
    pub headers: usize,
    pub live: usize,
    pub filters: usize,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct IndexRowBytes {
    pub(crate) tx_lookup: usize,
    pub(crate) script_history: usize,
    pub(crate) script_live: usize,
    pub(crate) headers: usize,
    pub(crate) filters: usize,
}

impl IndexRowBytes {
    pub(crate) const ZERO: Self = Self {
        tx_lookup: 0,
        script_history: 0,
        script_live: 0,
        headers: 0,
        filters: 0,
    };

    pub(crate) fn total(&self) -> Result<usize, IndexError> {
        self.tx_lookup
            .checked_add(self.script_history)
            .and_then(|s| s.checked_add(self.script_live))
            .and_then(|s| s.checked_add(self.headers))
            .and_then(|s| s.checked_add(self.filters))
            .ok_or(IndexError::MutationSizeOverflow)
    }

    pub(crate) fn checked_add(&self, other: &Self) -> Result<Self, IndexError> {
        Ok(Self {
            tx_lookup: self
                .tx_lookup
                .checked_add(other.tx_lookup)
                .ok_or(IndexError::MutationSizeOverflow)?,
            script_history: self
                .script_history
                .checked_add(other.script_history)
                .ok_or(IndexError::MutationSizeOverflow)?,
            script_live: self
                .script_live
                .checked_add(other.script_live)
                .ok_or(IndexError::MutationSizeOverflow)?,
            headers: self
                .headers
                .checked_add(other.headers)
                .ok_or(IndexError::MutationSizeOverflow)?,
            filters: self
                .filters
                .checked_add(other.filters)
                .ok_or(IndexError::MutationSizeOverflow)?,
        })
    }
}

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
    pub(super) live_ops: Vec<LiveOp>,
    pub(super) filter_rows: Vec<([u8; 32], super::filters::BasicFilter)>,
}

fn distinct_row_count(rows: &[PositionedRow]) -> usize {
    rows.chunk_by(|left, right| left.row == right.row).count()
}

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

    pub(super) fn encoded_bytes_by_family(&self) -> Result<IndexRowBytes, IndexError> {
        let tx_prefix_bytes = distinct_row_count(&self.txid_rows)
            .checked_mul(crate::types::HASH_PREFIX_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let tx_pos_bytes = self
            .txid_rows
            .len()
            .checked_mul(crate::types::TX_POSITION_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let tx_lookup = tx_prefix_bytes
            .checked_add(tx_pos_bytes)
            .ok_or(IndexError::MutationSizeOverflow)?;

        let funding_prefix_bytes = distinct_row_count(&self.funding_rows)
            .checked_mul(crate::types::HASH_PREFIX_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let spending_prefix_bytes = distinct_row_count(&self.spending_rows)
            .checked_mul(crate::types::HASH_PREFIX_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let history_prefix_bytes = funding_prefix_bytes
            .checked_add(spending_prefix_bytes)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let funding_pos_bytes = self
            .funding_rows
            .len()
            .checked_mul(crate::types::TX_POSITION_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let spending_pos_bytes = self
            .spending_rows
            .len()
            .checked_mul(crate::types::TX_POSITION_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let history_pos_bytes = funding_pos_bytes
            .checked_add(spending_pos_bytes)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let script_history = history_prefix_bytes
            .checked_add(history_pos_bytes)
            .ok_or(IndexError::MutationSizeOverflow)?;

        let headers = self
            .header_rows
            .len()
            .checked_mul(crate::types::HEADER_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;

        let script_live = self
            .live_ops
            .len()
            .checked_mul(crate::types::SCRIPT_LIVE_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;

        let filters = self
            .filter_rows
            .iter()
            .try_fold(0_usize, |total, (_, row)| {
                total
                    .checked_add(34 + 64 + row.filter.len())
                    .ok_or(IndexError::MutationSizeOverflow)
            })?;

        Ok(IndexRowBytes {
            tx_lookup,
            script_history,
            script_live,
            headers,
            filters,
        })
    }

    #[cfg(test)]
    pub(super) fn encoded_bytes(&self) -> Result<usize, IndexError> {
        self.encoded_bytes_by_family()?.total()
    }
}

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
        (ColumnFamily::Funding, &rows.funding_rows),
        (ColumnFamily::Spending, &rows.spending_rows),
    ] {
        for group in positioned.chunk_by(|left, right| left.row == right.row) {
            batch.delete(cf, group[0].row.as_bytes());
        }
    }
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
mod tests;
