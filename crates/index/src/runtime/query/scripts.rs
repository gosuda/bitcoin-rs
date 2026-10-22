//! Script history, spending, and live-view reads under the shared snapshot gate.

use super::{
    CapabilityFloors, DerivedIndexQueryEngine, Hash256, OutPoint, QueryBudget, ScriptHash,
    ScriptHistoryPage, ScriptHistoryRecord, ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan,
    SpendingRecord, TipSnapshot, Tx, TxIndexScanRow, TxIndexSnapshot, TxQueryError, Txid,
};
use crate::types::ScriptHistoryOccurrence;

impl DerivedIndexQueryEngine {
    fn scan_funding_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .funding_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
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
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
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
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_live_scan(scan)
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
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        outpoint: &OutPoint,
        floor: u32,
    ) -> Result<Option<SpendingRecord>, TxQueryError> {
        let rows = Self::scan_spending_rows(snapshot, budget, outpoint)?;
        let mut last_height = None;
        for row in rows {
            let height = row.row.height();
            if last_height == Some(height) {
                continue;
            }
            last_height = Some(height);
            if let Some(positions) = Self::validated_positions(&row.value) {
                for &position in positions {
                    let Some(transaction) =
                        self.resolve_positioned_transaction(tip, budget, height, position)?
                    else {
                        break;
                    };
                    if let Some(record) = Self::spending_input(&transaction, height, outpoint)? {
                        return Ok(Some(record));
                    }
                }
            }
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                if let Some(record) = Self::spending_input(transaction, height, outpoint)? {
                    return Ok(Some(record));
                }
            }
        }
        Self::none_below_floor(floor, "script history")
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
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        floor: u32,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        if floor > 0 {
            return Err(TxQueryError::Unavailable(
                format!("script history coverage starts at height {floor}; history cannot be proven complete").into(),
            ));
        }
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut history = Vec::new();
        let mut funding_outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            let occurrences = ScriptHistoryOccurrence::decode_all(&row.value).ok_or_else(|| {
                TxQueryError::Storage("malformed unified script-history row".into())
            })?;
            for occurrence in occurrences {
                if occurrence.scripthash != scripthash {
                    continue;
                }
                let txid = Txid(Hash256::from_le_bytes(&occurrence.txid));
                history.push(ScriptHistoryRecord { txid, height });
                if occurrence.flags & ScriptHistoryOccurrence::FUNDING == 0 {
                    continue;
                }
                // `block_body_range` may be absent on a source; `None` asks
                // for the whole-body read, never a hard miss (`block_body.rs`).
                let transaction = if let Some(transaction) =
                    self.resolve_positioned_transaction(tip, budget, height, occurrence.position)?
                {
                    transaction
                } else {
                    let hash = self.resolve_hash_at_height(height, tip)?;
                    let block = self.resolve_block(budget, height, hash)?;
                    let Some(transaction) = block
                        .txs
                        .into_iter()
                        .find(|candidate| candidate.txid() == txid)
                    else {
                        return Err(TxQueryError::Unavailable(
                            "script-history transaction body unavailable".into(),
                        ));
                    };
                    transaction
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
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        floor: u32,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        if floor > 0 {
            return Err(TxQueryError::Unavailable(
                format!("script history coverage starts at height {floor}; history cannot be proven complete").into(),
            ));
        }
        let _ = tip;
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut history = Vec::new();
        for row in rows {
            let height = row.row.height();
            let occurrences = ScriptHistoryOccurrence::decode_all(&row.value).ok_or_else(|| {
                TxQueryError::Storage("malformed unified script-history row".into())
            })?;
            history.extend(
                occurrences
                    .into_iter()
                    .filter(|occurrence| occurrence.scripthash == scripthash)
                    .map(|occurrence| ScriptHistoryRecord {
                        txid: Txid(Hash256::from_le_bytes(&occurrence.txid)),
                        height,
                    }),
            );
        }

        history.sort_by(|a, b| a.height.cmp(&b.height).then_with(|| a.txid.cmp(&b.txid)));
        history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        Ok(history)
    }

    fn newest_script_occurrence_height(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        txid: Txid,
        tx_lookup_floor: u32,
    ) -> Result<Option<u32>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan = snapshot
            .transaction_rows(&txid, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let mut heights: Vec<_> = budget
            .accept_scan(scan)?
            .into_iter()
            .map(|row| row.row.height())
            .collect();
        heights.sort_unstable_by(|left, right| right.cmp(left));
        heights.dedup();
        for height in heights {
            let limit = budget.next_page_scan_limit(1, 1024 * 1024)?;
            let scan = snapshot
                .funding_rows_from(scripthash, height, limit)
                .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
            let (rows, _) = budget.accept_page_scan(scan)?;
            let Some(row) = rows.first().filter(|row| row.row.height() == height) else {
                continue;
            };
            let occurrences = ScriptHistoryOccurrence::decode_all(&row.value).ok_or_else(|| {
                TxQueryError::Storage("malformed unified script-history row".into())
            })?;
            if occurrences.iter().any(|occurrence| {
                occurrence.scripthash == scripthash && occurrence.txid == *txid.as_bytes()
            }) {
                return Ok(Some(height));
            }
        }
        // A missing TxLookup occurrence below its own coverage floor does
        // not prove that the cursor is absent from retained script history.
        Self::none_below_floor(tx_lookup_floor, "transaction index")
    }

    pub(super) fn confirmed_history_page_for(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
        cursor: Option<Txid>,
        limit: usize,
        floors: CapabilityFloors,
    ) -> Result<ScriptHistoryPage, TxQueryError> {
        let floor = floors.script_history;
        if floor > 0 {
            return Err(TxQueryError::Unavailable(
                format!("script history coverage starts at height {floor}; history cannot be proven complete").into(),
            ));
        }
        let cursor_height = match cursor {
            Some(txid) => Self::newest_script_occurrence_height(
                snapshot,
                budget,
                scripthash,
                txid,
                floors.tx_lookup,
            )?,
            None => None,
        };
        let cursor_found = cursor.is_none() || cursor_height.is_some();
        if limit == 0 {
            return Ok(ScriptHistoryPage {
                records: Vec::new(),
                cursor_found,
            });
        }
        let effective_cursor = cursor.filter(|_| cursor_found);
        let mut start_height = cursor_height.unwrap_or(u32::MAX);
        let mut records = Vec::with_capacity(limit);
        let mut emitted = hashbrown::HashSet::new();

        'scan: loop {
            let scan_limit = budget.next_page_scan_limit(32, 1024 * 1024)?;
            let scan = snapshot
                .funding_rows_from(scripthash, start_height, scan_limit)
                .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
            let (rows, complete) = budget.accept_page_scan(scan)?;
            if rows.is_empty() {
                break;
            }
            let mut last_height = None;
            for row in rows {
                let height = row.row.height();
                last_height = Some(height);
                let occurrences =
                    ScriptHistoryOccurrence::decode_all(&row.value).ok_or_else(|| {
                        TxQueryError::Storage("malformed unified script-history row".into())
                    })?;
                let mut txids: Vec<_> = occurrences
                    .into_iter()
                    .filter(|entry| entry.scripthash == scripthash)
                    .map(|entry| Txid(Hash256::from_le_bytes(&entry.txid)))
                    .collect();
                txids.sort_unstable_by(|left, right| right.cmp(left));
                txids.dedup();
                for txid in txids {
                    if effective_cursor == Some(txid) && cursor_height == Some(height) {
                        continue;
                    }
                    if cursor_height == Some(height) {
                        if let Some(cursor) = effective_cursor
                            && txid > cursor
                        {
                            continue;
                        }
                    }
                    if !emitted.insert(txid) {
                        continue;
                    }
                    records.push(ScriptHistoryRecord { txid, height });
                    if records.len() == limit {
                        break 'scan;
                    }
                }
            }
            if complete || last_height == Some(0) {
                break;
            }
            let Some(last_height) = last_height else {
                break;
            };
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
                "authoritative UTXO view is unavailable for ScriptLive".into(),
            ));
        };
        let rows = Self::scan_live_rows(snapshot, budget, scripthash)?;
        utxo.with_stable_view(|view| {
            let mut records = Vec::with_capacity(rows.len());
            for row in rows {
                let outpoint = row.outpoint();
                let Some(entry) = view.get_entry(&outpoint) else {
                    // A ready live watermark naming an unresolvable locator is
                    // corruption or a failed transition. Returning an empty
                    // result would turn that into a false negative.
                    return Err(TxQueryError::Unavailable(
                        "ScriptLive locator is absent from authoritative UTXO".into(),
                    ));
                };
                if ScriptHash::new(&entry.txout.script_pubkey) != scripthash {
                    // The locator is keyed by a compact hash prefix. A
                    // prefix collision is expected to be filtered by this
                    // exact script check.
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin_rs_storage::PrefixScanLimit;

    use super::*;
    use crate::types::{HashPrefixRow, TxPositionValue};
    use crate::{IndexCapability, IndexError, IndexWatermark, ScriptLiveScan, TxIndexScan};

    struct HistorySnapshot {
        script: ScriptHash,
        rows: Vec<(u32, ScriptHistoryOccurrence)>,
        funding_scans: AtomicUsize,
        txid_scans: AtomicUsize,
        watermark: Option<IndexWatermark>,
        tx_lookup_floor: u32,
    }

    impl HistorySnapshot {
        fn new(len: u32) -> Self {
            let script = ScriptHash::from_byte_array([7; 32]);
            let rows = (1..=len)
                .map(|height| {
                    let mut bytes = [0_u8; 32];
                    bytes[..4].copy_from_slice(&height.to_le_bytes());
                    (
                        height,
                        ScriptHistoryOccurrence {
                            scripthash: script,
                            txid: bytes,
                            position: crate::types::TxPosition::new(height, 1),
                            flags: ScriptHistoryOccurrence::FUNDING,
                        },
                    )
                })
                .rev()
                .collect();
            Self {
                script,
                rows,
                funding_scans: AtomicUsize::new(0),
                txid_scans: AtomicUsize::new(0),
                watermark: None,
                tx_lookup_floor: 0,
            }
        }

        fn history_scan(&self, start: u32, limit: PrefixScanLimit) -> TxIndexScan {
            self.funding_scans.fetch_add(1, Ordering::Relaxed);
            let matching: Vec<_> = self
                .rows
                .iter()
                .filter(|(height, _)| *height <= start)
                .collect();
            let complete = matching.len() <= limit.max_rows;
            let rows = matching
                .into_iter()
                .take(limit.max_rows)
                .map(|(height, occurrence)| TxIndexScanRow {
                    row: HashPrefixRow::new(self.script.prefix(), *height),
                    value: ScriptHistoryOccurrence::encode_all(&[*occurrence]),
                })
                .collect::<Vec<_>>();
            let encoded_bytes = rows.iter().map(|row| 12 + row.value.len()).sum();
            TxIndexScan {
                rows,
                encoded_bytes,
                complete,
            }
        }
    }

    impl TxIndexSnapshot for HistorySnapshot {
        fn capability_watermark(
            &self,
            _capability: IndexCapability,
        ) -> Result<Option<IndexWatermark>, IndexError> {
            Ok(self.watermark)
        }

        fn capability_floor(&self, capability: IndexCapability) -> Result<u32, IndexError> {
            Ok(if capability == IndexCapability::TxLookup {
                self.tx_lookup_floor
            } else {
                0
            })
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
                .filter(|(height, occurrence)| {
                    *height >= self.tx_lookup_floor && occurrence.txid == *txid.as_bytes()
                })
                .map(|(height, occurrence)| TxIndexScanRow {
                    row: HashPrefixRow::new([0; 8], *height),
                    value: TxPositionValue::encode(&[occurrence.position]),
                })
                .collect::<Vec<_>>();
            let encoded_bytes = rows.iter().map(|row| 12 + row.value.len()).sum();
            Ok(TxIndexScan {
                rows,
                encoded_bytes,
                complete: true,
            })
        }

        fn funding_rows(
            &self,
            _scripthash: ScriptHash,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Ok(self.history_scan(u32::MAX, limit))
        }

        fn funding_rows_from(
            &self,
            _scripthash: ScriptHash,
            start_height: u32,
            limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
            Ok(self.history_scan(start_height, limit))
        }

        fn spending_rows(
            &self,
            _outpoint: &OutPoint,
            _limit: PrefixScanLimit,
        ) -> Result<TxIndexScan, IndexError> {
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

    impl crate::IndexReader for HistorySnapshot {
        fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
            Ok(Box::new(Self {
                script: self.script,
                rows: self.rows.clone(),
                funding_scans: AtomicUsize::new(0),
                txid_scans: AtomicUsize::new(0),
                watermark: self.watermark,
                tx_lookup_floor: self.tx_lookup_floor,
            }))
        }
    }

    #[test]
    fn first_page_scan_work_is_constant_at_100_1000_and_10000_entries() {
        for len in [100_u32, 1_000, 10_000] {
            let snapshot = HistorySnapshot::new(len);
            let page = match DerivedIndexQueryEngine::confirmed_history_page_for(
                &snapshot,
                &mut QueryBudget::new(),
                snapshot.script,
                None,
                25,
                CapabilityFloors::default(),
            ) {
                Ok(page) => page,
                Err(error) => panic!("bounded page failed: {error}"),
            };
            assert_eq!(page.records.len(), 25);
            assert_eq!(page.records[0].height, len);
            assert_eq!(page.records[24].height, len - 24);
            assert_eq!(snapshot.funding_scans.load(Ordering::Relaxed), 1);
            assert_eq!(snapshot.txid_scans.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn history_page_deduplicates_transaction_ids_within_the_page() {
        let mut snapshot = HistorySnapshot::new(50);
        let repeated_txid = snapshot.rows[0].1.txid;
        snapshot.rows[5].1.txid = repeated_txid;
        let page = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &mut QueryBudget::new(),
            snapshot.script,
            None,
            25,
            CapabilityFloors::default(),
        )
        .unwrap_or_else(|error| panic!("first page failed: {error}"));
        assert_eq!(page.records.len(), 25);
        assert_eq!(page.records.last().map(|record| record.height), Some(25));
        assert_eq!(
            page.records
                .iter()
                .filter(|record| record.txid.as_bytes() == &repeated_txid)
                .count(),
            1,
        );
        assert_eq!(snapshot.txid_scans.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cursor_pages_seek_without_per_item_transaction_lookups() {
        let snapshot = HistorySnapshot::new(100);
        let cursor = Txid(Hash256::from_le_bytes(&snapshot.rows[24].1.txid));
        let page = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &mut QueryBudget::new(),
            snapshot.script,
            Some(cursor),
            25,
            CapabilityFloors::default(),
        )
        .unwrap_or_else(|error| panic!("cursor page failed: {error}"));
        assert!(page.cursor_found);
        assert_eq!(
            page.records
                .iter()
                .map(|record| record.height)
                .collect::<Vec<_>>(),
            (51..=75).rev().collect::<Vec<_>>(),
        );
        assert_eq!(snapshot.funding_scans.load(Ordering::Relaxed), 2);
        assert_eq!(snapshot.txid_scans.load(Ordering::Relaxed), 1);
        let empty = DerivedIndexQueryEngine::confirmed_history_page_for(
            &snapshot,
            &mut QueryBudget::new(),
            snapshot.script,
            Some(cursor),
            0,
            CapabilityFloors::default(),
        )
        .unwrap_or_else(|error| panic!("empty cursor page failed: {error}"));
        assert!(empty.cursor_found);
        assert_eq!(empty.records, []);
    }

    /// IDX-04 preserves sibling history when only `TxLookup` is rebuilt from
    /// a pruned frontier. API-09 must not call a retained cursor unknown.
    #[test]
    fn history_pages_respect_independent_transaction_lookup_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::query_api::ScriptIndexQuery as _;
        use std::sync::Arc;

        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let mut tree = bitcoin_rs_chain::BlockTree::new();
        tree.insert_header(genesis.header, bitcoin_rs_chain::NodeStatus::HeaderValid)?;
        let mut previous = genesis.block_hash();
        for height in 1..=100 {
            let block = bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at_time(
                previous,
                bitcoin_rs_chain::regtest_fixture::genesis_time() + height,
                height,
            )?;
            tree.insert_header(block.header, bitcoin_rs_chain::NodeStatus::HeaderValid)?;
            previous = block.block_hash();
        }
        let tip = tree.tip().ok_or("header tip missing")?;
        // Existing synthetic index rows test query semantics; the real header
        // identities exercise only the public watermark and tip gate.
        let mut snapshot = HistorySnapshot::new(tip.height);
        let script = snapshot.script;
        let txid_at = |height: u32| {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&height.to_le_bytes());
            Txid(Hash256::from_le_bytes(&bytes))
        };
        snapshot.tx_lookup_floor = 42;
        snapshot.watermark = Some(IndexWatermark {
            height: tip.height,
            hash: *tip.hash.as_byte_array(),
        });
        let (wake_tx, _wake_rx) = crossbeam_channel::bounded(4);
        let block_log: crate::block_log::BlockLog = std::iter::empty().collect();
        let engine = DerivedIndexQueryEngine::new(
            Arc::new(crate::runtime::DerivedIndexRuntime::new(wake_tx)),
            Arc::new(snapshot),
            super::super::IndexBlockSource::new(Arc::new(parking_lot::RwLock::new(block_log))),
            bitcoin_rs_chain::BlockTreeReader::new(Arc::new(parking_lot::RwLock::new(tree))),
            bitcoin_rs_chain::TipReader::new(Arc::new(arc_swap::ArcSwapOption::new(Some(tip)))),
            None,
            super::super::QueryEngineLive {
                utxo: None,
                chain_transition: None,
                enabled: crate::IndexCapabilities::HISTORICAL,
            },
        );

        // Both ready watermarks pass the public query gate. A positive floor
        // must not block pages whose complete occurrence evidence remains.
        for (cursor, expected) in [
            (None, (76..=100).rev().collect::<Vec<_>>()),
            (Some(txid_at(75)), (50..=74).rev().collect()),
            // Page records themselves need only retained ScriptHistory.
            // Transaction/body hydration has its separate TxLookup owner.
            (Some(txid_at(55)), (30..=54).rev().collect()),
        ] {
            let page = engine.confirmed_history_page(script, cursor, 25)?;
            assert!(page.cursor_found);
            assert_eq!(
                page.records
                    .iter()
                    .map(|record| record.height)
                    .collect::<Vec<_>>(),
                expected,
            );
        }
        // Height20 is known to ScriptHistory but below TxLookup coverage.
        // A completely unknown cursor is also unproven below that floor.
        for cursor in [txid_at(20), txid_at(101)] {
            assert!(matches!(
                engine.confirmed_history_page(script, Some(cursor), 25),
                Err(TxQueryError::Unavailable(_)),
            ));
        }
        Ok(())
    }
}
