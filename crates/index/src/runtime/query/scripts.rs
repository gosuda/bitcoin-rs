//! Script history, spending, and live-view reads under the shared snapshot gate.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    DerivedIndexQueryEngine, OutPoint, QueryBudget, ReadPrefix, ScriptHash, ScriptHistoryRecord,
    ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan, SpendingRecord, TipSnapshot, Tx,
    TxIndexScanRow, TxIndexSnapshot, TxQueryError, TxUnavailableCause, Txid,
};

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
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
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
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        budget.accept_scan(scan)
    }

    fn scan_live_rows(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<crate::ScriptLiveRow>, TxQueryError> {
        let mut limit = budget.next_scan_limit()?;
        limit.max_rows = limit.max_rows.min(self.scripthash_limit.saturating_add(1));
        let scan: ScriptLiveScan = snapshot
            .live_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        self.check_script_limit(scan.rows.len())?;
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

    fn funding_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, TxQueryError> {
        let rows = self.scan_funding_rows(snapshot, budget, scripthash)?;
        // Reject oversized positioned histories before any body I/O. Prefix
        // collisions count toward work, even though exact matching filters them.
        let positions =
            rows.iter()
                .filter(|row| prefix.covers(row.row.height()))
                .try_fold(0_usize, |count, row| {
                    Ok::<_, TxQueryError>(count.saturating_add(
                        Self::validated_positions(&row.value)?.map_or(1, <[_]>::len),
                    ))
                })?;
        self.check_script_limit(positions)?;
        let mut outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            if !prefix.covers(height) {
                continue;
            }
            let hash = self.resolve_hash_at_height(height, prefix)?;
            let Some(positions) = Self::validated_positions(&row.value)? else {
                let block = self.resolve_block(budget, height, hash)?;
                for transaction in &block.txs {
                    Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
                    self.check_script_limit(outputs.len())?;
                }
                continue;
            };

            let row_start = outputs.len();
            let mut complete = true;
            for &position in positions {
                let Some(transaction) =
                    self.resolve_positioned_transaction(budget, height, hash, position)?
                else {
                    complete = false;
                    break;
                };
                if !Self::collect_funding_outputs(&transaction, height, scripthash, &mut outputs)? {
                    complete = false;
                    break;
                }
                self.check_script_limit(outputs.len())?;
            }
            if complete {
                continue;
            }

            outputs.truncate(row_start);
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
                self.check_script_limit(outputs.len())?;
            }
        }
        Ok(outputs)
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
        let funding_outputs = self.funding_outputs_for(snapshot, prefix, budget, scripthash)?;

        let history =
            self.history_from_funding(snapshot, prefix, budget, &funding_outputs, None)?;
        let mut funding = Vec::with_capacity(funding_outputs.len());
        for (txid, vout, value, height) in funding_outputs {
            funding.push(ScriptIndexRecord {
                txid,
                height,
                value,
                vout,
            });
        }

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
        &self,
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
        let funding_outputs = self.funding_outputs_for(snapshot, prefix, budget, scripthash)?;

        self.history_from_funding(snapshot, prefix, budget, &funding_outputs, None)
    }

    pub(super) fn history_page_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        script: ScriptHash,
        last: Option<Txid>,
        limit: usize,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        if prefix.floor > 0 {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::HistoryUnproven {
                    floor: prefix.floor,
                },
            ));
        }
        let funding = self.funding_outputs_for(snapshot, prefix, budget, script)?;
        self.history_from_funding(snapshot, prefix, budget, &funding, Some((last, limit)))
    }

    /// Funding locators do not index spends by script. Inspect every funding
    /// outpoint, including old ones, before choosing the newest history page.
    /// Only spender bodies below the proven page boundary can be skipped.
    fn history_from_funding(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        prefix: &ReadPrefix,
        budget: &mut QueryBudget,
        funding: &[(Txid, u32, u64, u32)],
        page: Option<(Option<Txid>, usize)>,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        let mut history: BTreeSet<(u32, Txid)> = funding
            .iter()
            .map(|&(txid, _, _, height)| (height, txid))
            .collect();
        let outpoints: BTreeSet<_> = funding
            .iter()
            .map(|&(txid, vout, _, _)| (txid, vout))
            .collect();
        let mut candidates = BTreeMap::<u32, Vec<(OutPoint, Vec<u8>)>>::new();
        for (txid, vout) in outpoints {
            let outpoint = OutPoint { txid, vout };
            let mut rows = Self::scan_spending_rows(snapshot, budget, &outpoint)?;
            rows.retain(|row| prefix.covers(row.row.height()));
            if rows.len() > 1 {
                // Preserve earliest-spender and compact-prefix collision semantics.
                if let Some(spender) = self.spender_for(snapshot, prefix, budget, &outpoint)? {
                    history.insert((spender.height, spender.txid));
                }
            } else if let Some(row) = rows.pop() {
                candidates
                    .entry(row.row.height())
                    .or_default()
                    .push((outpoint, row.value));
            }
        }
        for (height, rows) in candidates.into_iter().rev() {
            if Self::page_complete(&history, page, height) {
                break;
            }
            let hash = self.resolve_hash_at_height(height, prefix)?;
            let mut positions = BTreeMap::new();
            let mut fallback = false;
            for (_, value) in &rows {
                match Self::validated_positions(value)? {
                    Some(values) => {
                        for &position in values {
                            positions.insert(position, None);
                        }
                    }
                    None => fallback = true,
                }
            }
            if !fallback {
                for (position, transaction) in &mut positions {
                    *transaction = self
                        .resolve_positioned_transaction(budget, height, hash, *position)?
                        .map(|tx| Self::spending_txids(&tx));
                    if transaction.is_none() {
                        fallback = true;
                        break;
                    }
                }
            }
            if !fallback {
                for (outpoint, value) in &rows {
                    let mut matched = false;
                    for position in Self::validated_positions(value)?.unwrap_or_default() {
                        if let Some(inputs) = positions.get(position).and_then(Option::as_ref) {
                            if let Some(txid) = inputs.get(&(outpoint.txid, outpoint.vout)) {
                                history.insert((height, *txid));
                                matched = true;
                                break;
                            }
                        }
                    }
                    fallback |= !matched;
                }
            }
            if fallback {
                let block = self.resolve_block(budget, height, hash)?;
                let mut inputs = BTreeMap::new();
                for tx in &block.txs {
                    for (outpoint, txid) in Self::spending_txids(tx) {
                        inputs.entry(outpoint).or_insert(txid);
                    }
                }
                for (outpoint, _) in &rows {
                    if let Some(txid) = inputs.get(&(outpoint.txid, outpoint.vout)) {
                        history.insert((height, *txid));
                    }
                }
            }
        }
        if let Some((last, limit)) = page {
            let ordered: Vec<_> = history.into_iter().rev().collect();
            let start = last
                .and_then(|txid| ordered.iter().position(|&(_, id)| id == txid))
                .map_or(0, |i| i + 1);
            return Ok(ordered
                .into_iter()
                .skip(start)
                .take(limit)
                .map(|(height, txid)| ScriptHistoryRecord { txid, height })
                .collect());
        }
        Ok(history
            .into_iter()
            .map(|(height, txid)| ScriptHistoryRecord { txid, height })
            .collect())
    }

    fn spending_txids(tx: &Tx) -> BTreeMap<(Txid, u32), Txid> {
        let txid = tx.txid();
        tx.inputs
            .iter()
            .map(|input| {
                let outpoint = input.previous_output;
                ((outpoint.txid, outpoint.vout), txid)
            })
            .collect()
    }

    fn page_complete(
        history: &BTreeSet<(u32, Txid)>,
        page: Option<(Option<Txid>, usize)>,
        next_height: u32,
    ) -> bool {
        let Some((last, limit)) = page else {
            return false;
        };
        // A cursor not encountered yet may be a spender in an older row.
        let cursor = match last {
            Some(txid) => match history.iter().rev().find(|&&(_, id)| id == txid) {
                Some(&cursor) => Some(cursor),
                None => return false,
            },
            None => None,
        };
        if limit == 0 {
            return true;
        }
        let boundary = match cursor {
            Some(cursor) => history.range(..cursor).rev().nth(limit - 1),
            None => history.iter().rev().nth(limit - 1),
        };
        boundary.is_some_and(|&(height, _)| height > next_height)
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
        let rows = self.scan_live_rows(snapshot, budget, scripthash)?;
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
