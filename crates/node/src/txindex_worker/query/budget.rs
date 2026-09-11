//! Fail-closed aggregate work accounting for one public query.

use super::{
    PrefixScanLimit, QUERY_BODY_READ_LIMIT, QUERY_SCAN_BYTE_LIMIT, QUERY_SCAN_COUNT_LIMIT,
    QUERY_SCAN_ROW_LIMIT, ScriptLiveScan, TxIndexScan, TxIndexScanRow, TxQueryError,
};

/// Aggregate work budget shared by every operation in one public query.
pub(super) struct QueryBudget {
    remaining_rows: usize,
    remaining_bytes: usize,
    remaining_scans: usize,
    remaining_body_reads: usize,
}

impl QueryBudget {
    pub(super) const fn new() -> Self {
        Self {
            remaining_rows: QUERY_SCAN_ROW_LIMIT,
            remaining_bytes: QUERY_SCAN_BYTE_LIMIT,
            remaining_scans: QUERY_SCAN_COUNT_LIMIT,
            remaining_body_reads: QUERY_BODY_READ_LIMIT,
        }
    }

    pub(super) fn next_scan_limit(&mut self) -> Result<PrefixScanLimit, TxQueryError> {
        if self.remaining_scans == 0 || self.remaining_rows == 0 || self.remaining_bytes == 0 {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exhausted".into(),
            ));
        }
        self.remaining_scans -= 1;
        Ok(PrefixScanLimit {
            max_rows: self.remaining_rows,
            max_bytes: self.remaining_bytes,
        })
    }

    pub(super) fn accept_scan(
        &mut self,
        scan: TxIndexScan,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex prefix scan truncated".into(),
            ));
        }
        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    pub(super) fn accept_live_scan(
        &mut self,
        scan: ScriptLiveScan,
    ) -> Result<Vec<bitcoin_rs_index::ScriptLiveRow>, TxQueryError> {
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex live prefix scan truncated".into(),
            ));
        }
        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    fn charge_scan(&mut self, rows: usize, encoded_bytes: usize) -> Result<(), TxQueryError> {
        if rows > self.remaining_rows || encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        self.remaining_rows -= rows;
        self.remaining_bytes -= encoded_bytes;
        Ok(())
    }

    pub(super) fn reserve_body_read(&mut self, max_bytes: usize) -> Result<(), TxQueryError> {
        if self.remaining_body_reads == 0 || max_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exhausted".into(),
            ));
        }
        self.remaining_body_reads -= 1;
        Ok(())
    }

    pub(super) fn charge_body_bytes(&mut self, bytes: usize) -> Result<(), TxQueryError> {
        if bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query body budget exceeded".into(),
            ));
        }
        self.remaining_bytes -= bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
