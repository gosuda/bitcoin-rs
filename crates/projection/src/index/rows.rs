use super::error::IndexError;
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum LiveOp {
    Insert {
        row: crate::types::ScriptLiveRow,
        coin: crate::types::ScriptLiveCoin,
    },
    /// Carries the stored pre-image so the inverse orientation can restore
    /// the full payload (PRJ-11 rows are self-contained).
    Delete {
        row: crate::types::ScriptLiveRow,
        coin: crate::types::ScriptLiveCoin,
    },
}

impl LiveOp {
    pub(super) const fn row(&self) -> &crate::types::ScriptLiveRow {
        match self {
            LiveOp::Insert { row, .. } | LiveOp::Delete { row, .. } => row,
        }
    }

    const fn coin(&self) -> crate::types::ScriptLiveCoin {
        match self {
            LiveOp::Insert { coin, .. } | LiveOp::Delete { coin, .. } => *coin,
        }
    }
}

/// Planned bytes per family. `tx_lookup`, `script_history`, `filters`, and
/// `tail_log` are the segment-tail bytes one block appends, the undo-log row
/// included; `script_live` and `headers` are the writer's own rows.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct IndexRowBytes {
    pub(crate) tx_lookup: usize,
    pub(crate) script_history: usize,
    pub(crate) script_live: usize,
    pub(crate) headers: usize,
    pub(crate) filters: usize,
    pub(crate) tail_log: usize,
}

impl IndexRowBytes {
    pub(crate) const ZERO: Self = Self {
        tx_lookup: 0,
        script_history: 0,
        script_live: 0,
        headers: 0,
        filters: 0,
        tail_log: 0,
    };

    pub(crate) fn total(&self) -> Result<usize, IndexError> {
        self.tx_lookup
            .checked_add(self.script_history)
            .and_then(|s| s.checked_add(self.script_live))
            .and_then(|s| s.checked_add(self.headers))
            .and_then(|s| s.checked_add(self.filters))
            .and_then(|s| s.checked_add(self.tail_log))
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
            tail_log: self
                .tail_log
                .checked_add(other.tail_log)
                .ok_or(IndexError::MutationSizeOverflow)?,
        })
    }
}

/// Rows one block contributes to the writer's own families: headers and
/// ScriptLive. Transaction, script-history, and compact-filter data go to the
/// segment tail and are counted in `IndexRowBytes` by `segment::tail`.
#[derive(Default)]
pub(super) struct PendingRows {
    pub(super) header_rows: Vec<[u8; crate::types::HEADER_ROW_SIZE]>,
    pub(super) live_ops: Vec<LiveOp>,
}

impl PendingRows {
    pub(super) fn sort(&mut self) {
        self.header_rows.sort_unstable();
    }

    pub(super) fn append(&mut self, other: Self) {
        self.header_rows.extend(other.header_rows);
        self.live_ops.extend(other.live_ops);
    }

    pub(super) fn total(&self) -> usize {
        self.header_rows.len() + self.live_ops.len()
    }

    pub(super) fn encoded_bytes_by_family(&self) -> Result<IndexRowBytes, IndexError> {
        let headers = self
            .header_rows
            .len()
            .checked_mul(crate::types::HEADER_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let script_live = self.live_ops.iter().try_fold(0_usize, |total, op| {
            let size = match op {
                LiveOp::Insert { coin, .. } => coin
                    .encoded_value_len()
                    .and_then(|len| crate::types::SCRIPT_LIVE_ROW_SIZE.checked_add(len))
                    .ok_or(IndexError::MutationSizeOverflow)?,
                LiveOp::Delete { .. } => crate::types::SCRIPT_LIVE_ROW_SIZE,
            };
            total
                .checked_add(size)
                .ok_or(IndexError::MutationSizeOverflow)
        })?;
        Ok(IndexRowBytes {
            headers,
            script_live,
            ..IndexRowBytes::ZERO
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveOpsOrientation {
    Forward,
    Inverse,
}

pub(super) fn apply_live_ops(
    batch: &mut BufferedWriteBatch,
    ops: &[LiveOp],
) -> Result<(), IndexError> {
    apply_live_ops_oriented(batch, ops, LiveOpsOrientation::Forward)
}

pub(super) fn invert_live_ops(
    batch: &mut BufferedWriteBatch,
    ops: &[LiveOp],
) -> Result<(), IndexError> {
    apply_live_ops_oriented(batch, ops, LiveOpsOrientation::Inverse)
}

fn apply_live_ops_oriented(
    batch: &mut BufferedWriteBatch,
    ops: &[LiveOp],
    orientation: LiveOpsOrientation,
) -> Result<(), IndexError> {
    enum PendingWrite {
        Put(crate::types::ScriptLiveCoin),
        Remove,
    }
    let mut last: hashbrown::HashMap<[u8; crate::types::SCRIPT_LIVE_ROW_SIZE], PendingWrite> =
        hashbrown::HashMap::new();
    let invert = matches!(orientation, LiveOpsOrientation::Inverse);
    let ordered: Box<dyn Iterator<Item = &LiveOp>> = if invert {
        Box::new(ops.iter().rev())
    } else {
        Box::new(ops.iter())
    };
    for op in ordered {
        let put = matches!(op, LiveOp::Insert { .. }) != invert;
        let write = if put {
            PendingWrite::Put(op.coin())
        } else {
            PendingWrite::Remove
        };
        last.insert(*op.row().as_bytes(), write);
    }
    for (key, write) in last {
        match write {
            PendingWrite::Put(coin) => {
                let value = coin.encode_value()?;
                batch.put(ColumnFamily::ScriptLive, &key, &value);
            }
            PendingWrite::Remove => {
                batch.delete(ColumnFamily::ScriptLive, &key);
            }
        }
    }
    Ok(())
}

pub(super) fn put_rows(
    batch: &mut BufferedWriteBatch,
    rows: &PendingRows,
) -> Result<(), IndexError> {
    for row in &rows.header_rows {
        batch.put(ColumnFamily::BlockHeaders, row, &[]);
    }
    apply_live_ops(batch, &rows.live_ops)
}

pub(super) fn delete_rows(
    batch: &mut BufferedWriteBatch,
    rows: &PendingRows,
) -> Result<(), IndexError> {
    invert_live_ops(batch, &rows.live_ops)
}

pub(super) fn delete_rows_with_headers(
    batch: &mut BufferedWriteBatch,
    rows: &PendingRows,
) -> Result<(), IndexError> {
    delete_rows(batch, rows)?;
    for row in &rows.header_rows {
        batch.delete(ColumnFamily::BlockHeaders, row);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
