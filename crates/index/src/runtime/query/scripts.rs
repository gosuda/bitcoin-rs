use super::{
    DerivedIndexQueryEngine, OutPoint, QueryBudget, ReadPrefix, ScriptHash, ScriptHistoryPage,
    ScriptHistoryRecord, ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan, SpendingRecord,
    TipSnapshot, Tx, TxIndexScanRow, TxIndexSnapshot, TxQueryError, TxUnavailableCause, Txid,
};
use crate::types::ScriptHistoryOccurrence;

const PAGE_SCAN_ROWS: usize = 32;

const PAGE_SCAN_BYTES: usize = 1 << 20;

fn storage_error(error: impl core::fmt::Display) -> TxQueryError {
    TxQueryError::Storage(error.to_string().into())
}

impl DerivedIndexQueryEngine {
    fn scan_funding_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .funding_rows(scripthash, limit)
            .map_err(storage_error)?;
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
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<crate::ScriptLiveRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan: ScriptLiveScan = snapshot
            .live_rows(scripthash, limit)
            .map_err(storage_error)?;
        budget.accept_live_scan(scan)
    }

    fn occurrences(value: &[u8]) -> Result<Vec<ScriptHistoryOccurrence>, TxQueryError> {
        ScriptHistoryOccurrence::decode_all(value)
            .ok_or_else(|| TxQueryError::Storage("malformed script-history occurrence row".into()))
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
        for row in rows {
            let height = row.row.height();
            if last_height == Some(height) {
                continue;
            }
            last_height = Some(height);
            if !prefix.covers(height) {
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
        if prefix.floor > 0 {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven {
                    floor: prefix.floor,
                },
            ));
        }
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut history = Vec::new();
        let mut funding_outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            if !prefix.covers(height) {
                continue;
            }
            let mut row_hash = None;
            for occurrence in Self::occurrences(&row.value)? {
                if occurrence.scripthash != scripthash {
                    continue;
                }
                let txid = Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(
                    &occurrence.txid,
                ));
                history.push(ScriptHistoryRecord { txid, height });
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

        history.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        funding.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        funding.dedup();

        Ok(ScriptIndexSnapshot { history, funding })
    }

    pub(super) fn confirmed_history_for(
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        if prefix.floor > 0 {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven {
                    floor: prefix.floor,
                },
            ));
        }
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut history = Vec::new();
        for row in rows {
            let height = row.row.height();
            if !prefix.covers(height) {
                continue;
            }
            history.extend(
                Self::occurrences(&row.value)?
                    .into_iter()
                    .filter(|occurrence| occurrence.scripthash == scripthash)
                    .map(|occurrence| ScriptHistoryRecord {
                        txid: Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(
                            &occurrence.txid,
                        )),
                        height,
                    }),
            );
        }

        history.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        Ok(history)
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

    pub(super) fn confirmed_history_page_for(
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        cursor: Option<Txid>,
        limit: usize,
    ) -> Result<ScriptHistoryPage, TxQueryError> {
        if prefix.floor > 0 {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven {
                    floor: prefix.floor,
                },
            ));
        }
        let limit = limit.min(crate::query_api::SCRIPT_HISTORY_PAGE_MAX);
        let resolved = match cursor {
            Some(txid) => Self::history_cursor_for(snapshot, prefix, budget, scripthash, &txid)?,
            None => None,
        };
        let cursor_found = cursor.is_none() || resolved.is_some();
        let cursor = resolved.filter(|_| cursor_found);
        if limit == 0 {
            return Ok(ScriptHistoryPage {
                records: Vec::new(),
                cursor_found,
            });
        }

        let mut records: Vec<ScriptHistoryRecord> = Vec::with_capacity(limit);
        let mut start_height = cursor.map_or(u32::MAX, |(height, _)| height);
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
                    if let Some((cursor_height, cursor_offset)) = cursor
                        && height == cursor_height
                        && occurrence.position.offset() >= cursor_offset
                    {
                        continue;
                    }
                    let txid = Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(
                        &occurrence.txid,
                    ));
                    if records
                        .last()
                        .is_some_and(|last| last.height == height && last.txid == txid)
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
        _tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let Some(utxo) = self.utxo.as_ref() else {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::MissingAuthority(
                    "authoritative UTXO view is unavailable for ScriptLive",
                ),
            ));
        };
        let rows = Self::scan_live_rows(snapshot, budget, scripthash)?;
        utxo.with_stable_view(|view| {
            let mut records = Vec::with_capacity(rows.len());
            for row in rows {
                let outpoint = row.outpoint();
                let Some(entry) = view.get_entry(&outpoint) else {
                    return Err(TxQueryError::Unavailable(
                        TxUnavailableCause::MissingAuthority(
                            "ScriptLive locator is absent from authoritative UTXO",
                        ),
                    ));
                };
                if ScriptHash::new(&entry.txout.script_pubkey) != scripthash {
                    continue;
                }
                records.push(ScriptIndexRecord {
                    txid: outpoint.txid,
                    height: entry.height,
                    value: entry.txout.value.to_sat(),
                    vout: outpoint.vout,
                });
            }
            records.sort_by(|a, b| {
                a.height
                    .cmp(&b.height)
                    .then_with(|| a.txid.cmp(&b.txid))
                    .then_with(|| a.vout.cmp(&b.vout))
            });
            records.dedup_by(|a, b| a.txid == b.txid && a.vout == b.vout);
            Ok(records)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HashPrefixRow, ScriptHistoryOccurrence, TxPosition};
    use crate::{IndexCapability, IndexError, IndexWatermark, TxIndexScan};
    use bitcoin_rs_chain::NodeId;
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

        fn scan_family_page(
            &self,
            _family: crate::TxIndexFamily,
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
                encoded_bytes: 0,
                complete: true,
            })
        }
    }

    fn prefix() -> ReadPrefix {
        ReadPrefix {
            anchor_id: NodeId::new(0),
            height: u32::MAX,
            hash: bitcoin_rs_primitives::Hash256::from_le_bytes(&[0; 32]),
            floor: 0,
            bound: super::super::PrefixBound::ExactTip,
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
            Some(Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(
                &[200; 32],
            ))),
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
            25,
        )
        .unwrap_or_else(|error| panic!("collision page failed: {error}"));
        assert_eq!(page.records.len(), 1, "only the exact script is served");
        assert_eq!(
            page.records[0].txid,
            Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&[1; 32]))
        );
    }

    // IDX-02
    #[test]
    fn pre_bip34_duplicate_txid_is_served_once_per_height() {
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
            25,
        )
        .unwrap_or_else(|error| panic!("duplicate page failed: {error}"));
        assert_eq!(
            page.records.len(),
            2,
            "distinct heights stay distinct records"
        );
        assert_eq!(page.records[0].height, 20);
        assert_eq!(page.records[1].height, 5);
        assert_eq!(page.records[0].txid, page.records[1].txid);
    }

    // IDX-02
    #[test]
    fn history_cursor_resolves_the_newest_occurrence() {
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
            &Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&[9; 32])),
        )
        .unwrap_or_else(|error| panic!("cursor resolution failed: {error}"));
        assert_eq!(cursor, Some((20, 77)), "the newest occurrence wins");
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
            Txid(bitcoin_rs_primitives::Hash256::from_le_bytes(&[10; 32]))
        );
    }
}
