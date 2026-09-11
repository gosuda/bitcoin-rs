//! One snapshot gate for transaction, history, and live-view queries.
//! Resolution and script traversal stay in private child modules; all public
//! entrypoints retain health, revision, watermark, and chain-transition checks.

use super::{
    Arc, Block, BlockBodySource, BlockHash, BlockLog, BlockSource, BlockTree, Hash256,
    IndexCapabilities, IndexCapability, IndexReader, IndexWatermark, MAX_SERIALIZED_BLOCK_BYTES,
    Mutex, Ordering, OutPoint, PrefixScanLimit, QUERY_BODY_READ_LIMIT, QUERY_SCAN_BYTE_LIMIT,
    QUERY_SCAN_COUNT_LIMIT, QUERY_SCAN_ROW_LIMIT, RwLock, ScriptHash, ScriptHistoryRecord,
    ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan, SpendingRecord,
    TipSnapshot, Tx, TxIndexInfo, TxIndexQuery, TxIndexRuntime, TxIndexScan, TxIndexScanRow,
    TxIndexSnapshot, TxPosition, TxPositionValue, TxQueryError, Txid, deserialize,
    record_at_height,
};

mod block_source;
mod budget;
mod scripts;
mod transactions;

pub(crate) use block_source::IndexBlockSource;
use budget::QueryBudget;

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
    runtime: Arc<TxIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_source: IndexBlockSource,
    block_tree: Arc<RwLock<BlockTree>>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    body_source: Option<Arc<dyn BlockBodySource>>,
    utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    chain_transition: Option<Arc<Mutex<()>>>,
    enabled: IndexCapabilities,
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

    fn query_health(&self) -> Result<(), TxQueryError> {
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

    fn require_enabled(&self, required: IndexCapabilities) -> Result<(), TxQueryError> {
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

    fn with_snapshot<F, T>(&self, required: IndexCapabilities, f: F) -> Result<T, TxQueryError>
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
