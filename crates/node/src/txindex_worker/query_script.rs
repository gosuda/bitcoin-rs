//! Budgeted script history, spending, and authoritative live-output composition.

use super::QueryBudget;
use super::TxIndexQueryEngine;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_index::ScriptLiveScan;
use bitcoin_rs_index::TxIndexScanRow;
use bitcoin_rs_index::TxIndexSnapshot;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::ScriptHistoryRecord;
use bitcoin_rs_rpc::context::ScriptIndexRecord;
use bitcoin_rs_rpc::context::ScriptIndexSnapshot;
use bitcoin_rs_rpc::context::SpendingRecord;
use bitcoin_rs_rpc::context::TxQueryError;

impl TxIndexQueryEngine {
    pub(super) fn scan_funding_rows(
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

    pub(super) fn scan_spending_rows(
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

    pub(super) fn scan_live_rows(
        snapshot: &dyn TxIndexSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<bitcoin_rs_index::ScriptLiveRow>, TxQueryError> {
        let limit = budget.next_scan_limit()?;
        let scan: ScriptLiveScan = snapshot
            .live_rows(scripthash, limit)
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        if !scan.complete {
            return Err(TxQueryError::Unavailable(
                "txindex live prefix scan truncated".into(),
            ));
        }
        if scan.rows.len() > budget.remaining_rows || scan.encoded_bytes > budget.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        budget.remaining_rows -= scan.rows.len();
        budget.remaining_bytes -= scan.encoded_bytes;
        Ok(scan.rows)
    }

    pub(super) fn collect_funding_outputs(
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

    pub(super) fn funding_outputs_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
        budget: &mut QueryBudget,
        scripthash: ScriptHash,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, TxQueryError> {
        let rows = Self::scan_funding_rows(snapshot, budget, scripthash)?;
        let mut outputs = Vec::new();
        for row in rows {
            let height = row.row.height();
            let Some(positions) = Self::validated_positions(&row.value) else {
                let hash = self.resolve_hash_at_height(height, tip)?;
                let block = self.resolve_block(budget, height, hash)?;
                for transaction in &block.txs {
                    Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
                }
                continue;
            };

            let row_start = outputs.len();
            let mut complete = true;
            for &position in positions {
                let Some(transaction) =
                    self.resolve_positioned_transaction(tip, budget, height, position)?
                else {
                    complete = false;
                    break;
                };
                if !Self::collect_funding_outputs(&transaction, height, scripthash, &mut outputs)? {
                    complete = false;
                    break;
                }
            }
            if complete {
                continue;
            }

            outputs.truncate(row_start);
            let hash = self.resolve_hash_at_height(height, tip)?;
            let block = self.resolve_block(budget, height, hash)?;
            for transaction in &block.txs {
                Self::collect_funding_outputs(transaction, height, scripthash, &mut outputs)?;
            }
        }
        Ok(outputs)
    }

    pub(super) fn spender_for(
        &self,
        snapshot: &dyn TxIndexSnapshot,
        tip: &TipSnapshot,
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
        Ok(None)
    }

    pub(super) fn spending_input(
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
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let funding_outputs = self.funding_outputs_for(snapshot, tip, budget, scripthash)?;

        let mut history = Vec::with_capacity(funding_outputs.len());
        let mut funding = Vec::with_capacity(funding_outputs.len());
        for (txid, vout, value, height) in funding_outputs {
            history.push(ScriptHistoryRecord { txid, height });
            funding.push(ScriptIndexRecord {
                txid,
                height,
                value,
                vout,
            });
            let outpoint = OutPoint { txid, vout };
            if let Some(spender) = self.spender_for(snapshot, tip, budget, &outpoint)? {
                history.push(ScriptHistoryRecord {
                    txid: spender.txid,
                    height: spender.height,
                });
            }
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
