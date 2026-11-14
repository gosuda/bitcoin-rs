use super::{
    DerivedIndexQueryEngine, OccurrenceCursor, OutPoint, QueryBudget, ReadPrefix, ScriptHash,
    ScriptHistoryPage, ScriptHistoryRecord, ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan,
    SpendingRecord, Tx, TxIndexScanRow, TxIndexSnapshot, TxQueryError, TxUnavailableCause, Txid,
};
use crate::types::ScriptHistoryOccurrence;

const PAGE_SCAN_ROWS: usize = 32;

const PAGE_SCAN_BYTES: usize = 1 << 20;

fn storage_error(error: impl core::fmt::Display) -> TxQueryError {
    TxQueryError::Storage(error.to_string().into())
}

fn order_by_height_txid_vout(
    left: &ScriptIndexRecord,
    right: &ScriptIndexRecord,
) -> core::cmp::Ordering {
    left.height
        .cmp(&right.height)
        .then_with(|| left.txid.cmp(&right.txid))
        .then_with(|| left.vout.cmp(&right.vout))
}

impl DerivedIndexQueryEngine {
    fn check_script_limit(&self, entries: usize) -> Result<(), TxQueryError> {
        if entries > self.scripthash_limit {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::ScriptHashLimitExceeded {
                    limit: self.scripthash_limit,
                },
            ));
        }
        Ok(())
    }

    fn require_full_history(prefix: &ReadPrefix) -> Result<(), TxQueryError> {
        if prefix.floor > 0 {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven {
                    floor: prefix.floor,
                },
            ));
        }
        Ok(())
    }

    fn scan_funding_rows(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let mut limit = budget.next_scan_limit()?;
        limit.max_rows = limit.max_rows.min(self.scripthash_limit.saturating_add(1));
        let scan = snapshot
            .funding_rows(scripthash, limit)
            .map_err(storage_error)?;
        self.check_script_limit(scan.rows.len())?;
        budget.accept_scan(scan)
    }

    fn scan_spending_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .spending_rows(outpoint, limit)
            .map_err(storage_error)?;
        budget.accept_scan(scan)
    }

    fn scan_live_rows(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<ScriptLiveScan, TxQueryError> {
        let mut limit = budget.next_scan_limit()?;
        limit.max_rows = limit.max_rows.min(self.scripthash_limit.saturating_add(1));
        let scan: ScriptLiveScan = snapshot
            .live_rows(scripthash, limit)
            .map_err(storage_error)?;
        self.check_script_limit(scan.rows.len())?;
        budget.accept_live_scan(&scan)?;
        Ok(scan)
    }

    fn occurrences(value: &[u8]) -> Result<Vec<ScriptHistoryOccurrence>, TxQueryError> {
        ScriptHistoryOccurrence::decode_all(value)
            .ok_or_else(|| TxQueryError::Storage("malformed script-history occurrence row".into()))
    }

    fn bounded_occurrences(
        &self,
        value: &[u8],
        examined: &mut usize,
    ) -> Result<Vec<ScriptHistoryOccurrence>, TxQueryError> {
        let occurrences = Self::occurrences(value)?;
        *examined = examined.saturating_add(occurrences.len());
        self.check_script_limit(*examined)?;
        Ok(occurrences)
    }

    fn collect_funding_outputs(
        transaction: &Tx,
        height: u32,
        scripthash: ScriptHash,
        outputs: &mut Vec<(Txid, u32, u64, u32)>,
    ) -> Result<bool, TxQueryError> {
        let txid = transaction.txid();
        let before = outputs.len();
        for (vout_idx, output) in transaction.outputs.iter().enumerate() {
            if ScriptHash::new(&output.script_pubkey) != scripthash {
                continue;
            }
            let vout = u32::try_from(vout_idx)
                .map_err(|_| TxQueryError::Storage("vout overflow".into()))?;
            outputs.push((txid, vout, output.value.to_sat(), height));
        }
        Ok(outputs.len() != before)
    }

    pub(super) fn spender_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let rows = Self::scan_spending_rows(snapshot, budget, outpoint)?;
        let mut last_height = None;
        let mut below_floor = false;
        for row in rows {
            let height = row.row.height();
            if last_height == Some(height) {
                continue;
            }
            last_height = Some(height);
            if !prefix.covers(height) {
                if height < prefix.floor {
                    below_floor = true;
                }
                continue;
            }
            let hash = self.resolve_hash_at_height(height, prefix)?;
            if let Some(positions) = Self::validated_positions(&row.value)? {
                for &position in positions {
                    let Some(transaction) =
                        self.resolve_positioned_transaction(budget, height, hash, position)?
                    else {
                        break;
                    };
                    if let Some(record) = Self::spending_input(&transaction, height, outpoint)? {
                        return Ok(Some(record));
                    }
                }
            }
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                if let Some(record) = Self::spending_input(transaction, height, outpoint)? {
                    return Ok(Some(record));
                }
            }
        }
        if below_floor {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: prefix.floor,
                },
            ));
        }
        Self::scoped_absence(prefix, "script history")
    }

    fn spending_input(
        transaction: &Tx,
        height: u32,
        outpoint: &OutPoint,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let Some(vin) = transaction
            .inputs
            .iter()
            .position(|input| input.previous_output == *outpoint)
        else {
            return Ok(None);
        };
        Ok(Some(SpendingRecord {
            txid: transaction.txid(),
            height,
            vin: u32::try_from(vin).map_err(|_| TxQueryError::Storage("vin overflow".into()))?,
        }))
    }

    pub(super) fn history_snapshot_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        Self::require_full_history(prefix)?;
        let rows = self.scan_funding_rows(snapshot, budget, scripthash)?;
        let mut history = Vec::new();
        let mut reported_transactions = std::collections::BTreeSet::new();
        let mut funding_outputs = Vec::new();
        let mut examined = 0_usize;
        for row in rows {
            let height = row.row.height();
            if !prefix.covers(height) {
                continue;
            }
            let mut row_hash = None;
            for occurrence in self.bounded_occurrences(&row.value, &mut examined)? {
                if occurrence.scripthash != scripthash {
                    continue;
                }
                let txid = occurrence.txid();
                if reported_transactions.insert((txid, height)) {
                    history.push(ScriptHistoryRecord { txid, height });
                }
                if occurrence.flags & ScriptHistoryOccurrence::FUNDING == 0 {
                    continue;
                }
                let hash = if let Some(hash) = row_hash {
                    hash
                } else {
                    let resolved = self.resolve_hash_at_height(height, prefix)?;
                    row_hash = Some(resolved);
                    resolved
                };
                let transaction = if let Some(transaction) =
                    self.resolve_positioned_transaction(budget, height, hash, occurrence.position)?
                {
                    transaction
                } else {
                    let block = self.resolve_block(budget, height, hash)?;
                    block
                        .txs
                        .iter()
                        .find(|candidate| candidate.txid() == txid)
                        .cloned()
                        .ok_or(TxQueryError::Storage(
                            "script-history funding occurrence names a transaction absent from its block"
                                .into(),
                        ))?
                };
                if transaction.txid() != txid
                    || !Self::collect_funding_outputs(
                        &transaction,
                        height,
                        scripthash,
                        &mut funding_outputs,
                    )?
                {
                    return Err(TxQueryError::Storage(
                        "script-history occurrence failed exact verification".into(),
                    ));
                }
            }
        }

        let mut funding = Vec::with_capacity(funding_outputs.len());
        for (txid, vout, value, height) in funding_outputs {
            funding.push(ScriptIndexRecord {
                txid,
                height,
                value,
                vout,
            });
        }

        funding.sort_by(order_by_height_txid_vout);
        funding.dedup();

        Ok(ScriptIndexSnapshot { history, funding })
    }

    pub(super) fn confirmed_history_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        Self::require_full_history(prefix)?;
        let rows = self.scan_funding_rows(snapshot, budget, scripthash)?;
        let mut history = Vec::new();
        let mut examined = 0_usize;
        for row in rows {
            let height = row.row.height();
            if !prefix.covers(height) {
                continue;
            }
            history.extend(
                self.bounded_occurrences(&row.value, &mut examined)?
                    .into_iter()
                    .filter(|occurrence| occurrence.scripthash == scripthash)
                    .map(|occurrence| ScriptHistoryRecord {
                        txid: occurrence.txid(),
                        height,
                    }),
            );
        }

        history.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        Ok(history)
    }

    pub(super) fn history_page_for(
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        script: ScriptHash,
        last: Option<Txid>,
        view_id: u64,
        limit: usize,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        let page = Self::confirmed_history_page_for(
            snapshot, prefix, budget, script, last, view_id, limit,
        )?;
        if last.is_some() && !page.cursor_found {
            return Ok(Self::confirmed_history_page_for(
                snapshot, prefix, budget, script, None, view_id, limit,
            )?
            .records);
        }
        Ok(page.records)
    }

    pub(super) fn history_cursor_for(
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        txid: &Txid,
    ) -> Result<Option<(u32, u32)>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(storage_error)?;
        let mut heights: Vec<u32> = budget
            .accept_scan(scan)?
            .into_iter()
            .map(|row| row.row.height())
            .filter(|height| prefix.covers(*height))
            .collect();
        heights.sort_unstable_by(|left, right| right.cmp(left));
        heights.dedup();
        if heights.is_empty() {
            return Self::scoped_absence(prefix, "transaction index");
        }
        for height in heights {
            let limit = budget.next_page_scan_limit(1, PAGE_SCAN_BYTES)?;
            let scan = snapshot
                .funding_rows_from(scripthash, height, limit)
                .map_err(storage_error)?;
            let (rows, _) = budget.accept_page_scan(scan)?;
            let Some(row) = rows.first().filter(|row| row.row.height() == height) else {
                continue;
            };
            if let Some(occurrence) =
                Self::occurrences(&row.value)?
                    .into_iter()
                    .find(|occurrence| {
                        occurrence.scripthash == scripthash && occurrence.txid == *txid.as_bytes()
                    })
            {
                return Ok(Some((height, occurrence.position.offset())));
            }
        }
        Self::none_below_floor(prefix.floor, "script history")
    }

    fn lists_newest_covered_occurrence(
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        txid: &Txid,
        height: u32,
    ) -> Result<bool, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(txid, limit)
            .map_err(storage_error)?;
        let mut heights: Vec<u32> = budget
            .accept_scan(scan)?
            .into_iter()
            .map(|row| row.row.height())
            .filter(|row_height| prefix.covers(*row_height))
            .collect();
        heights.sort_unstable_by(|left, right| right.cmp(left));
        heights.dedup();
        if heights.is_empty() {
            let found: Option<Txid> = Self::scoped_absence(prefix, "transaction index")?;
            return Ok(found.is_some());
        }
        for newer in heights {
            if newer <= height {
                break;
            }
            let limit = budget.next_page_scan_limit(1, PAGE_SCAN_BYTES)?;
            let scan = snapshot
                .funding_rows_from(scripthash, newer, limit)
                .map_err(storage_error)?;
            let (rows, _) = budget.accept_page_scan(scan)?;
            let Some(row) = rows.first().filter(|row| row.row.height() == newer) else {
                continue;
            };
            if Self::occurrences(&row.value)?.iter().any(|occurrence| {
                occurrence.scripthash == scripthash && occurrence.txid == *txid.as_bytes()
            }) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn confirmed_history_page_for(
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        cursor: Option<Txid>,
        view_id: u64,
        limit: usize,
    ) -> Result<ScriptHistoryPage, TxQueryError> {
        Self::require_full_history(prefix)?;
        let limit = limit.min(crate::query_api::SCRIPT_HISTORY_PAGE_MAX);
        let resolved = match cursor {
            Some(txid) => Self::history_cursor_for(snapshot, prefix, budget, scripthash, &txid)?,
            None => None,
        };
        let cursor_found = cursor.is_none() || resolved.is_some();
        let occurrence_cursor = resolved.map(|(height, tx_pos)| OccurrenceCursor {
            view_id,
            height,
            tx_pos,
        });
        if limit == 0 {
            return Ok(ScriptHistoryPage {
                records: Vec::new(),
                cursor_found,
            });
        }

        let mut records: Vec<ScriptHistoryRecord> = Vec::with_capacity(limit);
        let mut listed = std::collections::BTreeSet::<Txid>::new();
        let mut start_height = occurrence_cursor.map_or(u32::MAX, |cursor| cursor.height);
        'scan: loop {
            let scan_limit = budget.next_page_scan_limit(PAGE_SCAN_ROWS, PAGE_SCAN_BYTES)?;
            let scan = snapshot
                .funding_rows_from(scripthash, start_height, scan_limit)
                .map_err(storage_error)?;
            let (rows, complete) = budget.accept_page_scan(scan)?;
            let Some(last_height) = rows.last().map(|row| row.row.height()) else {
                break;
            };
            for row in rows {
                let height = row.row.height();
                if !prefix.covers(height) {
                    if height < prefix.floor {
                        break 'scan;
                    }
                    continue;
                }
                let mut occurrences: Vec<_> = Self::occurrences(&row.value)?
                    .into_iter()
                    .filter(|occurrence| occurrence.scripthash == scripthash)
                    .collect();
                occurrences.sort_unstable_by(|left, right| {
                    right
                        .position
                        .offset()
                        .cmp(&left.position.offset())
                        .then_with(|| right.txid.cmp(&left.txid))
                });
                occurrences.dedup_by(|left, right| left.txid == right.txid);
                for occurrence in occurrences {
                    if let Some(cursor) = occurrence_cursor
                        && height == cursor.height
                        && occurrence.position.offset() >= cursor.tx_pos
                    {
                        continue;
                    }
                    let txid = occurrence.txid();
                    if !listed.insert(txid) {
                        continue;
                    }
                    if occurrence_cursor.is_some()
                        && !Self::lists_newest_covered_occurrence(
                            snapshot, prefix, budget, scripthash, &txid, height,
                        )?
                    {
                        continue;
                    }
                    records.push(ScriptHistoryRecord { txid, height });
                    if records.len() == limit {
                        break 'scan;
                    }
                }
            }
            if complete || last_height == 0 {
                break;
            }
            start_height = last_height.saturating_sub(1);
        }
        Ok(ScriptHistoryPage {
            records,
            cursor_found,
        })
    }

    pub(super) fn unspent_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let scan = self.scan_live_rows(snapshot, budget, scripthash)?;
        let mut records = Vec::with_capacity(scan.rows.len());
        for (row, coin) in scan.rows.iter().zip(&scan.coins) {
            if coin.scripthash != scripthash || !prefix.covers(coin.height) {
                continue;
            }
            let outpoint = row.outpoint();
            records.push(ScriptIndexRecord {
                txid: outpoint.txid,
                height: coin.height,
                value: coin.value,
                vout: outpoint.vout,
            });
        }
        records.sort_by(order_by_height_txid_vout);
        records.dedup_by(|a, b| a.txid == b.txid && a.vout == b.vout);
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashPrefixRow, ScriptHistoryOccurrence, TxPosition};
    use crate::{IndexCapability, IndexError, IndexWatermark, TxIndexScan};
    use bitcoin_rs_execution::chain::NodeId;
    use bitcoin_rs_storage::PrefixScanLimit;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct HistorySnapshot {
        script: ScriptHash,
        rows: Vec<(u32, Vec<ScriptHistoryOccurrence>)>,
        funding_scans: AtomicUsize,
        txid_scans: AtomicUsize,
        spending_unavailable: bool,
    }

    impl HistorySnapshot {
        fn new(script: ScriptHash, rows: Vec<(u32, Vec<ScriptHistoryOccurrence>)>) -> Self {
            Self {
                script,
                rows,
                funding_scans: AtomicUsize::new(0),
                txid_scans: AtomicUsize::new(0),
                spending_unavailable: false,
            }
        }

        fn scan(&self, start: u32, limit: PrefixScanLimit) -> TxIndexScan {
            self.funding_scans.fetch_add(1, Ordering::Relaxed);
            let mut rows = Vec::new();
            let mut bytes = 0_usize;
            for (height, occurrences) in &self.rows {
                if *height > start {
                    continue;
                }
                let row = HashPrefixRow::new(self.script.prefix(), *height);
                let value = ScriptHistoryOccurrence::encode_all(occurrences);
                let row_bytes = crate::HASH_PREFIX_ROW_SIZE.saturating_add(value.len());
                if rows.len() >= limit.max_rows
                    || (!rows.is_empty() && bytes.saturating_add(row_bytes) > limit.max_bytes)
                {
                    return TxIndexScan {
                        rows,
                        encoded_bytes: bytes,
                        complete: false,
                    };
                }
                bytes = bytes.saturating_add(row_bytes);
                rows.push(super::TxIndexScanRow { row, value });
            }
            TxIndexScan {
                rows,
                encoded_bytes: bytes,
                complete: true,
            }
        }
    }

    impl TxIndexSnapshot for HistorySnapshot {
        fn capability_watermark(
            &self,
            _capability: IndexCapability,
        ) -> Result<Option<IndexWatermark>, IndexError> {
            Ok(None)
        }

        fn tx_lookup_page(
            &self,
            _start_after: Option<&[u8]>,
            _limit: PrefixScanLimit,
        ) -> Result<crate::TxIndexPage, IndexError> {
            unreachable!("history pages never page the transaction family")
        }

        fn transaction_rows(
            &self,
            txid: &Txid,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            self.txid_scans.fetch_add(1, Ordering::Relaxed);
            let rows = self
                .rows
                .iter()
                .filter(|(_, occurrences)| {
                    occurrences
                        .iter()
                        .any(|entry| entry.txid == *txid.as_bytes())
                })
                .map(|(height, _)| super::TxIndexScanRow {
                    row: HashPrefixRow::new([0; 8], *height),
                    value: Vec::new(),
                })
                .collect();
            Ok(TxIndexScan {
                rows,
                encoded_bytes: 0,
                complete: true,
            })
        }

        fn funding_rows(
            &self,
            _scripthash: ScriptHash,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Ok(self.scan(u32::MAX, limit))
        }

        fn funding_rows_from(
            &self,
            _scripthash: ScriptHash,
            start_height: u32,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Ok(self.scan(start_height, limit))
        }

        fn spending_rows(
            &self,
            _outpoint: &OutPoint,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            if self.spending_unavailable {
                return Err(IndexError::Storage(
                    bitcoin_rs_storage::StorageError::Backend("spending family unavailable".into()),
                ));
            }
            Ok(TxIndexScan {
                rows: Vec::new(),
                encoded_bytes: 0,
                complete: true,
            })
        }

        fn live_rows(
            &self,
            _scripthash: ScriptHash,
            _limit: PrefixScanLimit,
        ) -> Result<ScriptLiveScan, IndexError> {
            Ok(ScriptLiveScan {
                rows: Vec::new(),
                coins: Vec::new(),
                encoded_bytes: 0,
                complete: true,
            })
        }
    }

    fn prefix() -> ReadPrefix {
        ReadPrefix {
            anchor_id: NodeId::new(0),
            height: u32::MAX,
            hash: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0; 32]),
            floor: 0,
            is_historical: true,
        }
    }

    const CURSOR_OFFSET: u32 = 10;

    fn occurrence(scripthash: ScriptHash, txid: u8, offset: u32) -> ScriptHistoryOccurrence {
        ScriptHistoryOccurrence {
            scripthash,
            txid: [txid; 32],
            position: TxPosition::new(offset, 20),
            flags: ScriptHistoryOccurrence::FUNDING,
        }
    }

    fn history_of(len: u32) -> (ScriptHash, Vec<(u32, Vec<ScriptHistoryOccurrence>)>) {
        let script = ScriptHash::from_byte_array([7; 32]);
        let rows = (1..=len)
            .rev()
            .map(|height| {
                (
                    height,
                    vec![occurrence(
                        script,
                        u8::try_from(height % 251).unwrap_or(0),
                        CURSOR_OFFSET,
                    )],
                )
            })
            .collect();
        (script, rows)
    }

    // IDX-02, IDX-12
    #[test]
    fn first_page_scan_work_is_constant_at_100_1000_and_10000_entries() {
        for len in [100_u32, 1_000, 10_000] {
            let (script, rows) = history_of(len);
            let snapshot = HistorySnapshot::new(script, rows);
            let page = DerivedIndexQueryEngine::confirmed_history_page_for(
                &snapshot,
                &prefix(),
                &mut QueryBudget::new(),
                script,
                None,
                0,
                25,
            )
            .unwrap_or_else(|error| panic!("bounded page failed: {error}"));
            assert_eq!(page.records.len(), 25, "one page holds the requested rows");
            assert_eq!(page.records[0].height, len, "the page starts at the tip");
            assert_eq!(page.records[24].height, len - 24);
            assert_eq!(
                snapshot.funding_scans.load(Ordering::Relaxed),
                1,
                "one height scan serves a 25-row first page"
            );
            assert_eq!(
                snapshot.txid_scans.load(Ordering::Relaxed),
                0,
                "a first page needs no per-item transaction lookup"
            );
        }
    }

    // IDX-02
    #[test]
    fn cursor_page_continues_without_skipping_or_repeating() {
        let (script, rows) = history_of(100);
        let snapshot = HistorySnapshot::new(script, rows);
        let budget = &mut QueryBudget::new();
        let first = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            budget,
            script,
            None,
            0,
            25,
        )
        .unwrap_or_else(|error| panic!("first page failed: {error}"));
        let cursor = Some(first.records[24].txid);
        let second = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            budget,
            script,
            cursor,
            0,
            25,
        )
        .unwrap_or_else(|error| panic!("cursor page failed: {error}"));
        assert!(second.cursor_found, "a stored occurrence names its cursor");
        let heights: Vec<u32> = second.records.iter().map(|record| record.height).collect();
        assert_eq!(heights, (51..=75).rev().collect::<Vec<_>>());
        let empty = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            budget,
            script,
            cursor,
            0,
            0,
        )
        .unwrap_or_else(|error| panic!("empty page failed: {error}"));
        assert!(empty.records.is_empty(), "a zero limit returns no records");
    }

    // IDX-02
    #[test]
    fn removed_chain_cursor_restarts_from_the_first_page() {
        let (script, rows) = history_of(50);
        let snapshot = HistorySnapshot::new(script, rows);
        let page = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            &mut QueryBudget::new(),
            script,
            Some(Txid(
                bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[200; 32]),
            )),
            0,
            25,
        )
        .unwrap_or_else(|error| panic!("cursor restart failed: {error}"));
        assert!(!page.cursor_found, "an unknown cursor is reported");
        assert_eq!(page.records[0].height, 50, "the restart is the first page");
    }

    // IDX-02
    #[test]
    fn prefix_collision_rows_serve_only_the_exact_script() {
        let mut foreign_bytes = [1_u8; 32];
        foreign_bytes[31] = 0xEE;
        let script = ScriptHash::from_byte_array([1; 32]);
        let foreign = ScriptHash::from_byte_array(foreign_bytes);
        assert_eq!(
            script.prefix(),
            foreign.prefix(),
            "the fixture must share the scan prefix"
        );
        let mut collisions = vec![occurrence(script, 1, 10), occurrence(foreign, 2, 20)];
        collisions.extend((3..40).map(|txid| occurrence(foreign, txid, 100)));
        let snapshot = HistorySnapshot::new(script, vec![(9, collisions)]);
        let page = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            &mut QueryBudget::new(),
            script,
            None,
            0,
            25,
        )
        .unwrap_or_else(|error| panic!("collision page failed: {error}"));
        assert_eq!(page.records.len(), 1, "only the exact script is served");
        assert_eq!(
            page.records[0].txid,
            Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                &[1; 32]
            ))
        );
    }

    // IDX-02
    #[test]
    fn pre_bip34_duplicate_txid_is_listed_at_its_newest_occurrence() {
        let script = ScriptHash::from_byte_array([3; 32]);
        let duplicate = occurrence(script, 9, 100);
        let snapshot =
            HistorySnapshot::new(script, vec![(20, vec![duplicate]), (5, vec![duplicate])]);
        let page = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            &mut QueryBudget::new(),
            script,
            None,
            0,
            25,
        )
        .unwrap_or_else(|error| panic!("duplicate page failed: {error}"));
        assert_eq!(page.records.len(), 1, "one duplicated txid lists once");
        assert_eq!(page.records[0].height, 20);
        assert_eq!(
            page.records[0].txid,
            Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                &[9; 32]
            ))
        );
    }

    // IDX-02
    #[test]
    fn history_cursor_resolves_the_newest_covered_occurrence() {
        let script = ScriptHash::from_byte_array([4; 32]);
        let duplicate = occurrence(script, 9, 77);
        let snapshot = HistorySnapshot::new(
            script,
            vec![(20, vec![duplicate]), (5, vec![occurrence(script, 9, 66)])],
        );
        let cursor = DerivedIndexQueryEngine::history_cursor_for(
            &snapshot,
            &prefix(),
            &mut QueryBudget::new(),
            script,
            &Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                &[9; 32],
            )),
        )
        .unwrap_or_else(|error| panic!("cursor resolution failed: {error}"));
        assert_eq!(
            cursor,
            Some((20, 77)),
            "the cursor continues below the newest occurrence of the transaction"
        );
    }

    // IDX-02
    #[test]
    fn duplicated_txid_cursor_pages_cover_the_full_history() {
        let script = ScriptHash::from_byte_array([6; 32]);
        let rows: Vec<(u32, Vec<ScriptHistoryOccurrence>)> = (1..=25)
            .rev()
            .map(|height| match height {
                20 => (height, vec![occurrence(script, 9, 100)]),
                5 => (height, vec![occurrence(script, 9, 90)]),
                other => {
                    let txid = u8::try_from(100 + other).unwrap_or(0);
                    (other, vec![occurrence(script, txid, CURSOR_OFFSET)])
                }
            })
            .collect();
        let snapshot = HistorySnapshot::new(script, rows);
        let oracle = newest_occurrence_listing(&snapshot.rows);
        let served = page_all(&snapshot, script, 6, snapshot.rows.len() + 1);
        assert_eq!(
            served, oracle,
            "the union of pages equals the newest-occurrence listing"
        );
    }

    // IDX-02, API-09
    #[test]
    fn duplicated_txid_cursor_pages_terminate_for_every_limit() {
        let script = ScriptHash::from_byte_array([6; 32]);
        let snapshot = HistorySnapshot::new(script, duplicate_rows(script, 25, 20, 6));
        let expected = newest_occurrence_listing(&snapshot.rows);
        for limit in 1..=30_usize {
            let served = page_all(&snapshot, script, limit, snapshot.rows.len() + 1);
            for record in &expected {
                let count = served.iter().filter(|entry| *entry == record).count();
                assert_eq!(
                    count, 1,
                    "limit {limit} serves {record:?} more than the documented once"
                );
            }
            assert_eq!(
                served, expected,
                "limit {limit} must cover the newest-occurrence listing in order"
            );
        }
        for limit in 1..=30_usize {
            let top = u32::try_from(2 * limit).unwrap_or(0);
            let bottom = u32::try_from(limit).unwrap_or(0);
            let snapshot = HistorySnapshot::new(script, duplicate_rows(script, top, top, bottom));
            let expected = newest_occurrence_listing(&snapshot.rows);
            let served = page_all(&snapshot, script, limit, snapshot.rows.len() + 1);
            assert_eq!(
                served, expected,
                "the duplicate gap equals limit {limit} and paging must still terminate"
            );
        }
    }

    fn duplicate_rows(
        script: ScriptHash,
        rows_top: u32,
        dup_top: u32,
        dup_bottom: u32,
    ) -> Vec<(u32, Vec<ScriptHistoryOccurrence>)> {
        (1..=rows_top)
            .rev()
            .map(|height| match height {
                h if h == dup_top => (height, vec![occurrence(script, 9, 100)]),
                h if h == dup_bottom => (height, vec![occurrence(script, 9, 90)]),
                other => (
                    other,
                    vec![occurrence(
                        script,
                        u8::try_from(100 + other).unwrap_or(0),
                        CURSOR_OFFSET,
                    )],
                ),
            })
            .collect()
    }

    fn newest_occurrence_listing(
        rows: &[(u32, Vec<ScriptHistoryOccurrence>)],
    ) -> Vec<ScriptHistoryRecord> {
        let mut listed: Vec<ScriptHistoryRecord> = Vec::new();
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for (height, occurrences) in rows {
            for occurrence in occurrences {
                if seen.contains(&occurrence.txid) {
                    continue;
                }
                seen.push(occurrence.txid);
                listed.push(ScriptHistoryRecord {
                    txid: Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                        &occurrence.txid,
                    )),
                    height: *height,
                });
            }
        }
        listed
    }

    fn page_all(
        snapshot: &HistorySnapshot,
        script: ScriptHash,
        limit: usize,
        page_bound: usize,
    ) -> Vec<ScriptHistoryRecord> {
        let budget = &mut QueryBudget::new();
        let mut served: Vec<ScriptHistoryRecord> = Vec::new();
        let mut cursor = None;
        for _ in 0..=page_bound {
            let page = DerivedIndexQueryEngine::confirmed_history_page_for(
                snapshot,
                &prefix(),
                budget,
                script,
                cursor,
                0,
                limit,
            )
            .unwrap_or_else(|error| panic!("history page failed: {error}"));
            assert!(page.cursor_found, "every fixture cursor resolves");
            served.extend(page.records.iter().copied());
            if page.records.len() < limit {
                return served;
            }
            cursor = page.records.last().map(|record| record.txid);
        }
        panic!("paging did not terminate within {page_bound} pages");
    }

    // IDX-02
    #[test]
    fn duplicate_txid_cursor_never_repeats_a_page() {
        let script = ScriptHash::from_byte_array([5; 32]);
        let duplicate = occurrence(script, 9, 100);
        let snapshot = HistorySnapshot::new(
            script,
            vec![
                (20, vec![duplicate, occurrence(script, 7, 50)]),
                (5, vec![occurrence(script, 9, 90)]),
                (3, vec![occurrence(script, 3, 30)]),
            ],
        );
        let budget = &mut QueryBudget::new();
        let mut seen: Vec<ScriptHistoryRecord> = Vec::new();
        let mut cursor = None;
        for _ in 0..8 {
            let page = DerivedIndexQueryEngine::confirmed_history_page_for(
                &snapshot,
                &prefix(),
                budget,
                script,
                cursor,
                0,
                2,
            )
            .unwrap_or_else(|error| panic!("cursor page failed: {error}"));
            assert!(page.cursor_found);
            if page.records.is_empty() {
                break;
            }
            for record in page.records {
                assert!(
                    !seen.contains(&record),
                    "a page repeated {record:?} after the cursor"
                );
                seen.push(record);
            }
            cursor = seen.last().map(|record| record.txid);
        }
        assert_eq!(
            seen.first(),
            Some(&ScriptHistoryRecord {
                txid: Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                    &[9; 32]
                )),
                height: 20,
            }),
            "the first page starts at the newest occurrence"
        );
    }

    // IDX-02
    #[test]
    fn same_transaction_multiple_occurrences_deduplicates_in_page() {
        let script = ScriptHash::from_byte_array([5; 32]);
        let occurrence1 = occurrence(script, 10, 100);
        let occurrence2 = occurrence(script, 10, 100);
        let snapshot = HistorySnapshot::new(script, vec![(15, vec![occurrence1, occurrence2])]);
        let page = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &prefix(),
            &mut QueryBudget::new(),
            script,
            None,
            0,
            25,
        )
        .unwrap_or_else(|error| panic!("dedup page failed: {error}"));
        assert_eq!(
            page.records.len(),
            1,
            "multiple occurrences in the same transaction are deduplicated"
        );
        assert_eq!(
            page.records[0].txid,
            Txid(bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                &[10; 32]
            ))
        );
    }
}
