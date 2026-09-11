//! Snapshot-gated queries and their shared bounded work budget.

mod scripts;
mod transactions;

use super::{lifecycle::TxIndexLifecycle, runtime::TxIndexRuntime, source::IndexBlockSource};
use arc_swap::ArcSwap;
use bitcoin_rs_chain::{BlockBodySource, BlockTree, TipSnapshot};
use bitcoin_rs_index::{
    IndexCapabilities, IndexCapability, IndexReader, IndexWatermark, ScriptHash, TxIndexScan,
    TxIndexScanRow, TxIndexSnapshot,
};
use bitcoin_rs_primitives::{OutPoint, Tx, Txid};
use bitcoin_rs_rpc::{
    context::ScriptIndexQuery, context::ScriptIndexRecord, context::ScriptIndexSnapshot,
    context::SpendingRecord, context::TxIndexInfo, context::TxIndexQuery, context::TxQueryError,
};
use bitcoin_rs_storage::PrefixScanLimit;
use parking_lot::{Mutex, RwLock};
use std::{sync::Arc, sync::atomic::Ordering};

/// Stable outer query adapter constructed before backend open and before RPC
/// context construction. Each method loads exactly one `ArcSwap` snapshot,
/// holds that `Arc` for the complete request, and delegates to the captured
/// query engine if a payload exists. It never reads lifecycle state and query
/// payload from separate loads.
#[derive(Clone)]
pub(crate) struct TxIndexQueryAdapter {
    lifecycle: Arc<ArcSwap<TxIndexLifecycle>>,
}

impl TxIndexQueryAdapter {
    pub(crate) fn new(lifecycle: Arc<ArcSwap<TxIndexLifecycle>>) -> Self {
        Self { lifecycle }
    }

    pub(super) fn load_engine(&self) -> Result<Arc<TxIndexQueryEngine>, TxQueryError> {
        let snapshot = self.lifecycle.load_full();
        match snapshot.query_payload() {
            Some(engine) => Ok(Arc::clone(engine)),
            None => Err(TxQueryError::Unavailable(
                snapshot.unavailable_reason().into(),
            )),
        }
    }
}

/// Bounded scan limits used by the query engine.
///
/// These are query-side safety limits, not the writer batch limits.
const QUERY_SCAN_ROW_LIMIT: usize = 1_000_000;

const QUERY_SCAN_BYTE_LIMIT: usize = 64 << 20;

pub(super) const QUERY_SCAN_COUNT_LIMIT: usize = 4_096;

const QUERY_BODY_READ_LIMIT: usize = 4_096;

const MAX_SERIALIZED_BLOCK_BYTES: usize = 4_000_000;

/// Aggregate work budget shared by every operation in one public query.
pub(super) struct QueryBudget {
    pub(super) remaining_rows: usize,
    pub(super) remaining_bytes: usize,
    pub(super) remaining_scans: usize,
    pub(super) remaining_body_reads: usize,
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
        if scan.rows.len() > self.remaining_rows || scan.encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                "txindex query work budget exceeded".into(),
            ));
        }
        self.remaining_rows -= scan.rows.len();
        self.remaining_bytes -= scan.encoded_bytes;
        Ok(scan.rows)
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

/// Authoritative Live query sources: capability selection, the UTXO set, and
/// the chain-transition lock Live composition requires.
pub(crate) struct QueryEngineLive {
    pub(crate) utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    pub(crate) chain_transition: Option<Arc<Mutex<()>>>,
    pub(crate) enabled: IndexCapabilities,
}

/// Node-owned, snapshot-gated transaction-index query engine.
///
/// Implements `bitcoin_rs_rpc::context::TxIndexQuery` and [`ScriptIndexQuery`] as the
/// only public read paths for the transaction index. Every query runs against
/// one typed point-in-time snapshot, captures
/// health/shutdown/revision/tip before and after work, and returns typed
/// `Retry`/`Unavailable` when the answer cannot be proven.
#[derive(Clone)]
pub(crate) struct TxIndexQueryEngine {
    pub(super) runtime: Arc<TxIndexRuntime>,
    pub(super) reader: Arc<dyn IndexReader>,
    pub(super) block_source: IndexBlockSource,
    pub(super) block_tree: Arc<RwLock<BlockTree>>,
    pub(super) applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    pub(super) body_source: Option<Arc<dyn BlockBodySource>>,
    pub(super) utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    pub(super) chain_transition: Option<Arc<Mutex<()>>>,
    pub(super) enabled: IndexCapabilities,
}

impl core::fmt::Debug for TxIndexQueryEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxIndexQueryEngine").finish_non_exhaustive()
    }
}

impl TxIndexQueryEngine {
    /// Builds a query engine over the shared reader and authoritative block source.
    #[must_use]
    pub(crate) fn new(
        runtime: Arc<TxIndexRuntime>,
        reader: Arc<dyn IndexReader>,
        block_source: IndexBlockSource,
        block_tree: Arc<RwLock<BlockTree>>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        body_source: Option<Arc<dyn BlockBodySource>>,
        live: QueryEngineLive,
    ) -> Self {
        Self {
            runtime,
            reader,
            block_source,
            block_tree,
            applied_tip,
            body_source,
            utxo: live.utxo,
            chain_transition: live.chain_transition,
            enabled: live.enabled,
        }
    }

    pub(super) fn query_health(&self) -> Result<(), TxQueryError> {
        if self.runtime.failed.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable(
                self.runtime
                    .failure_message()
                    .unwrap_or_else(|| "txindex worker failed".into()),
            ));
        }
        if self.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable("txindex worker stopped".into()));
        }
        Ok(())
    }

    pub(super) fn require_enabled(&self, required: IndexCapabilities) -> Result<(), TxQueryError> {
        if required.tx_lookup && !self.enabled.tx_lookup {
            return Err(TxQueryError::Unavailable("txindex is disabled".into()));
        }
        if required.script_history && !self.enabled.script_history {
            return Err(TxQueryError::Unavailable(
                "script history is disabled".into(),
            ));
        }
        if required.script_live && !self.enabled.script_live {
            return Err(TxQueryError::Unavailable("script live is disabled".into()));
        }
        Ok(())
    }

    pub(super) fn with_snapshot<F, T>(
        &self,
        required: IndexCapabilities,
        f: F,
    ) -> Result<T, TxQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &TipSnapshot,
            &mut QueryBudget,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health()?;
        self.require_enabled(required)?;

        // Live answers compose the index snapshot, the authoritative UTXO set,
        // and the applied tip. Apply mutates UTXO before publishing that tip,
        // so a before/after tip comparison cannot exclude that window. Hold
        // chain-transition across watermark check, locator scan, and UTXO
        // resolution. History and tx lookup never take it.
        let _chain_transition = if required.script_live {
            Some(
                self.chain_transition
                    .as_ref()
                    .ok_or_else(|| {
                        TxQueryError::Unavailable(
                            "chain transition authority missing for ScriptLive".into(),
                        )
                    })?
                    .lock(),
            )
        } else {
            None
        };

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        for capability in [
            IndexCapability::TxLookup,
            IndexCapability::ScriptHistory,
            IndexCapability::ScriptLive,
        ] {
            if !required.contains(capability) {
                continue;
            }
            let watermark = snapshot
                .capability_watermark(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            let Some(watermark) = watermark else {
                return Err(TxQueryError::Retry);
            };
            if watermark.height != tip_before.height
                || watermark.hash != *tip_before.hash.as_byte_array()
            {
                return Err(TxQueryError::Retry);
            }
        }

        let mut budget = QueryBudget::new();
        let result = f(snapshot.as_ref(), &tip_before, &mut budget);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();
        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        result
    }

    /// Watermark progress of `required` capabilities against one applied
    /// tip: `synced` when every one names that tip, `processed_height` the
    /// lowest of their heights, `target_height` the tip they were measured
    /// against. `Retry` when the tip or revision moved during the read.
    pub(crate) fn index_progress_for(
        &self,
        required: IndexCapabilities,
    ) -> Result<IndexProgress, TxQueryError> {
        self.query_health()?;

        let tip_before = self
            .applied_tip
            .load()
            .as_ref()
            .cloned()
            .ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        let tx = required
            .tx_lookup
            .then(|| snapshot.capability_watermark(IndexCapability::TxLookup))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let script_index = required
            .script_history
            .then(|| snapshot.capability_watermark(IndexCapability::ScriptHistory))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let script_live = required
            .script_live
            .then(|| snapshot.capability_watermark(IndexCapability::ScriptLive))
            .transpose()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?
            .flatten();
        let at_tip = |watermark: Option<IndexWatermark>| {
            watermark.is_some_and(|watermark| {
                watermark.height == tip_before.height
                    && watermark.hash == *tip_before.hash.as_byte_array()
            })
        };
        let synced = (!required.tx_lookup || at_tip(tx))
            && (!required.script_history || at_tip(script_index))
            && (!required.script_live || at_tip(script_live));
        let watermark_height =
            |watermark: Option<IndexWatermark>| watermark.map_or(0, |watermark| watermark.height);
        let best_block_height = [
            required.tx_lookup.then(|| watermark_height(tx)),
            required
                .script_history
                .then(|| watermark_height(script_index)),
            required.script_live.then(|| watermark_height(script_live)),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(0);

        self.query_health()?;
        let tip_after = self.applied_tip.load();
        let revision_after = self.runtime.revision();

        if revision_before != revision_after
            || tip_after
                .as_ref()
                .is_none_or(|tip| tip.height != tip_before.height || tip.hash != tip_before.hash)
        {
            return Err(TxQueryError::Retry);
        }

        Ok(IndexProgress {
            synced,
            processed_height: best_block_height,
            target_height: tip_before.height,
        })
    }
}

/// One coherent read of index progress against a single applied tip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexProgress {
    pub synced: bool,
    pub processed_height: u32,
    pub target_height: u32,
}

impl TxIndexQuery for TxIndexQueryEngine {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            self.transaction_for(snapshot, tip, budget, txid)
        })
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            self.outpoint_value_for(snapshot, tip, budget, outpoint)
        })
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {
            Ok(self
                .locate_transaction_for(snapshot, tip, budget, txid)?
                .map(|(height, _)| height))
        })
    }

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        let progress = self.index_progress_for(IndexCapabilities::TX_LOOKUP)?;
        Ok(TxIndexInfo {
            synced: progress.synced,
            best_block_height: progress.processed_height,
        })
    }
}

impl ScriptIndexQuery for TxIndexQueryEngine {
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.history_snapshot_for(snapshot, tip, budget, scripthash),
        )
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::SCRIPT_LIVE, |snapshot, tip, budget| {
            self.unspent_outputs_for(snapshot, tip, budget, scripthash)
        })
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget| self.spender_for(snapshot, tip, budget, &outpoint),
        )
    }
}

impl TxIndexQuery for TxIndexQueryAdapter {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction(txid)
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.outpoint_value(outpoint)
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.transaction_height(txid)
    }

    fn index_info(&self) -> Result<TxIndexInfo, TxQueryError> {
        let engine = self.load_engine()?;
        engine.index_info()
    }
}

impl ScriptIndexQuery for TxIndexQueryAdapter {
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let engine = self.load_engine()?;
        engine.history_snapshot(scripthash)
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.unspent_outputs(scripthash)
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        let engine = self.load_engine()?;
        engine.spender(outpoint)
    }
}
