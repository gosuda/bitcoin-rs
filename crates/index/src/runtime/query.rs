//! One snapshot gate for transaction, history, and live-view queries.
//! Resolution and script traversal stay in private child modules; all public
//! entrypoints retain health, revision, watermark, and chain-transition checks.

use super::{
    Arc, Block, BlockBodySource, BlockHash, BlockLog, BlockSource, BlockTree, DerivedIndexInfo,
    DerivedIndexQuery, DerivedIndexRuntime, Hash256, IndexCapabilities, IndexCapability,
    IndexReader, IndexWatermark, MAX_SERIALIZED_BLOCK_BYTES, Mutex, Ordering, OutPoint,
    PrefixScanLimit, QUERY_BODY_READ_LIMIT, QUERY_SCAN_BYTE_LIMIT, QUERY_SCAN_COUNT_LIMIT,
    QUERY_SCAN_ROW_LIMIT, RwLock, ScriptHash, ScriptHistoryRecord, ScriptIndexQuery,
    ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan, SpendingRecord, TipSnapshot, Tx,
    TxIndexScan, TxIndexScanRow, TxIndexSnapshot, TxPosition, TxPositionValue, TxQueryError, Txid,
    deserialize, record_at_height,
};

mod scripts;
mod transactions;

/// Private index-side `BlockSource`: active-chain identity from the tree,
/// bodies from the chain body store. Not a node-owned concept.
#[derive(Clone)]
pub struct IndexBlockSource {
    blocks: Arc<RwLock<BlockLog>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    block_tree: Option<Arc<RwLock<BlockTree>>>,
}

impl IndexBlockSource {
    /// A source backed only by the log of connected block records.
    #[must_use]
    pub const fn new(blocks: Arc<RwLock<BlockLog>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
            block_tree: None,
        }
    }

    /// Adds the chain body store used to fetch raw block bodies.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    /// Adds the authoritative block tree used for active-chain identity.
    #[must_use]
    pub fn with_block_tree(mut self, tree: Arc<RwLock<BlockTree>>) -> Self {
        self.block_tree = Some(tree);
        self
    }

    /// Returns the stored body bytes for the block identified by height and
    /// hash, or `None` when no body store is attached or the body is absent.
    pub fn block_body_bytes_for(&self, height: u32, hash: BlockHash) -> Option<Vec<u8>> {
        self.block_body_source.as_ref()?.block_body(height, hash)
    }

    pub(super) fn resolve_block_by_hash(&self, height: u32, active_hash: Hash256) -> Option<Block> {
        let bytes = self.block_body_bytes_for(height, BlockHash::from(active_hash))?;
        let block = deserialize::<Block>(&bytes).ok()?;
        (block.block_hash() == BlockHash::from(active_hash)).then_some(block)
    }
}

impl core::fmt::Debug for IndexBlockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndexBlockSource").finish_non_exhaustive()
    }
}

impl BlockSource for IndexBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let active_hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            Hash256::from(record_at_height(&guard, height)?.hash)
        };
        self.resolve_block_by_hash(height, active_hash)
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let source = self.block_body_source.as_ref()?;
        let hash = if let Some(tree) = &self.block_tree {
            BlockHash::from(tree.read().active_node_at_height(height)?.hash)
        } else {
            let guard = self.blocks.read();
            record_at_height(&guard, height)?.hash
        };
        source.block_body_range(height, hash, offset, len)
    }
}

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
    ) -> Result<Vec<crate::ScriptLiveRow>, TxQueryError> {
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

/// Authoritative Live query sources: capability selection, the UTXO set, and
/// the chain-transition lock Live composition requires.
pub struct QueryEngineLive {
    /// Authoritative UTXO set for the compact live view.
    pub utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    /// Serializes live-view work against a chain transition.
    pub chain_transition: Option<Arc<Mutex<()>>>,
    /// Capability set this engine serves.
    pub enabled: IndexCapabilities,
}

/// Node-owned, snapshot-gated transaction-index query engine.
///
/// Implements `crate::query_api::DerivedIndexQuery` and [`ScriptIndexQuery`] as the
/// only public read paths for the transaction index. Every query runs against
/// one typed point-in-time snapshot, captures
/// health/shutdown/revision/tip before and after work, and returns typed
/// `Retry`/`Unavailable` when the answer cannot be proven.
#[derive(Clone)]
pub struct DerivedIndexQueryEngine {
    runtime: Arc<DerivedIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_source: IndexBlockSource,
    block_tree: Arc<RwLock<BlockTree>>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    body_source: Option<Arc<dyn BlockBodySource>>,
    utxo: Option<Arc<bitcoin_rs_utxo::UtxoSet>>,
    chain_transition: Option<Arc<Mutex<()>>>,
    enabled: IndexCapabilities,
}

impl core::fmt::Debug for DerivedIndexQueryEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedIndexQueryEngine")
            .finish_non_exhaustive()
    }
}

impl DerivedIndexQueryEngine {
    /// Builds a query engine over the shared reader and authoritative block source.
    #[must_use]
    pub fn new(
        runtime: Arc<DerivedIndexRuntime>,
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

impl DerivedIndexQuery for DerivedIndexQueryEngine {
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

    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        let progress = self.index_progress_for(IndexCapabilities::TX_LOOKUP)?;
        Ok(DerivedIndexInfo {
            synced: progress.synced,
            best_block_height: progress.processed_height,
        })
    }
}

impl ScriptIndexQuery for DerivedIndexQueryEngine {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_and_live_scans_share_the_byte_budget() -> Result<(), TxQueryError> {
        let mut budget = QueryBudget::new();
        budget.remaining_bytes = 5;
        budget.accept_scan(TxIndexScan {
            rows: Vec::new(),
            encoded_bytes: 2,
            complete: true,
        })?;
        budget.accept_live_scan(ScriptLiveScan {
            rows: Vec::new(),
            encoded_bytes: 3,
            complete: true,
        })?;
        assert_eq!(budget.remaining_bytes, 0);
        assert!(matches!(
            budget.next_scan_limit(),
            Err(TxQueryError::Unavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn truncated_scan_families_fail_without_charging_rows_or_bytes() {
        let mut budget = QueryBudget::new();
        let before = (budget.remaining_rows, budget.remaining_bytes);
        let historical = budget.accept_scan(TxIndexScan {
            rows: Vec::new(),
            encoded_bytes: 2,
            complete: false,
        });
        assert!(
            matches!(historical, Err(TxQueryError::Unavailable(reason)) if reason == "txindex prefix scan truncated")
        );
        let live = budget.accept_live_scan(ScriptLiveScan {
            rows: Vec::new(),
            encoded_bytes: 3,
            complete: false,
        });
        assert!(
            matches!(live, Err(TxQueryError::Unavailable(reason)) if reason == "txindex live prefix scan truncated")
        );
        assert_eq!((budget.remaining_rows, budget.remaining_bytes), before);
    }

    #[test]
    fn rejected_scan_charge_does_not_partially_consume_budget() -> Result<(), TxQueryError> {
        let mut budget = QueryBudget::new();
        budget.remaining_rows = 2;
        budget.remaining_bytes = 5;
        for (rows, bytes) in [(3, 1), (1, 6), (usize::MAX, usize::MAX)] {
            assert!(matches!(
                budget.charge_scan(rows, bytes),
                Err(TxQueryError::Unavailable(_))
            ));
            assert_eq!((budget.remaining_rows, budget.remaining_bytes), (2, 5));
        }
        budget.charge_scan(2, 5)?;
        assert_eq!((budget.remaining_rows, budget.remaining_bytes), (0, 0));
        Ok(())
    }

    #[test]
    fn scan_count_rows_and_bytes_each_stop_admission() {
        for (rows, bytes, scans) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
            let mut budget = QueryBudget {
                remaining_rows: rows,
                remaining_bytes: bytes,
                remaining_scans: scans,
                remaining_body_reads: 1,
            };
            assert!(matches!(
                budget.next_scan_limit(),
                Err(TxQueryError::Unavailable(_))
            ));
            assert_eq!(budget.remaining_scans, scans);
        }
    }

    #[test]
    fn scan_limit_is_remaining_work_and_reserves_one_scan() -> Result<(), TxQueryError> {
        let mut budget = QueryBudget::new();
        budget.remaining_rows = 7;
        budget.remaining_bytes = 11;
        budget.remaining_scans = 1;
        let limit = budget.next_scan_limit()?;
        assert_eq!((limit.max_rows, limit.max_bytes), (7, 11));
        assert!(matches!(
            budget.next_scan_limit(),
            Err(TxQueryError::Unavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn bodies_and_scans_share_bytes_but_reserve_body_reads_separately() -> Result<(), TxQueryError>
    {
        let mut budget = QueryBudget::new();
        budget.remaining_bytes = 5;
        budget.remaining_body_reads = 1;
        assert!(matches!(
            budget.reserve_body_read(6),
            Err(TxQueryError::Unavailable(_))
        ));
        assert_eq!(budget.remaining_body_reads, 1);
        budget.reserve_body_read(5)?;
        assert_eq!(budget.remaining_bytes, 5);
        assert!(matches!(
            budget.reserve_body_read(1),
            Err(TxQueryError::Unavailable(_))
        ));
        budget.charge_body_bytes(3)?;
        assert!(matches!(
            budget.charge_body_bytes(3),
            Err(TxQueryError::Unavailable(_))
        ));
        assert_eq!(budget.remaining_bytes, 2);
        budget.accept_live_scan(ScriptLiveScan {
            rows: Vec::new(),
            encoded_bytes: 2,
            complete: true,
        })?;
        assert_eq!(budget.remaining_bytes, 0);
        Ok(())
    }
}
