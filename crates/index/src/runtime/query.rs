//! One snapshot gate for transaction, history, and live-view queries.
//! Resolution and script traversal stay in private child modules; all public
//! entrypoints retain health, revision, watermark, and chain-transition checks.

use super::{
    Arc, AtPrefix, Block, BlockBodySource, BlockTree, DerivedIndexInfo, DerivedIndexQuery,
    DerivedIndexRuntime, Hash256, HistoricalQueryError, HistoricalUnavailableCause,
    IndexCapabilities, IndexCapability, IndexReader, IndexWatermark, MAX_SERIALIZED_BLOCK_BYTES,
    Ordering, OutPoint, PrefixScanLimit, QUERY_BODY_READ_LIMIT, QUERY_SCAN_BYTE_LIMIT,
    QUERY_SCAN_COUNT_LIMIT, QUERY_SCAN_ROW_LIMIT, ScriptHash, ScriptHistoryRecord,
    ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, ScriptLiveScan, SpendingRecord,
    TipSnapshot, Tx, TxIndexScan, TxIndexScanRow, TxIndexSnapshot, TxPosition, TxPositionValue,
    TxQueryError, TxUnavailableCause, Txid, deserialize,
};
use crate::query_api::CoveredPrefix;
use bitcoin_rs_chain::{AncestryBudgetExceeded, NodeId};

mod filters;
mod scripts;
mod transactions;

/// Aggregate work budget shared by every operation in one public query.
///
/// Also pins at most one query-scoped decoded block: consecutive full-block
/// reads at the same `(height, hash)` identity reuse the retained block, while
/// a read at any other identity evicts it before fetching and decoding the new
/// block, so an evicted identity is re-read and re-charged on its next use.
/// Positioned range reads do not use the memo. The memo lives and dies
/// with the budget, so separate public queries never share entries. Every
/// pinned body was first charged to `remaining_bytes`, so the pinned block's
/// serialized body bytes never exceed `QUERY_SCAN_BYTE_LIMIT`; its decoded
/// heap size is larger.
pub(super) struct QueryBudget {
    remaining_rows: usize,
    remaining_bytes: usize,
    remaining_scans: usize,
    remaining_body_reads: usize,
    block_memo: Option<(u32, Hash256, Arc<Block>)>,
}

impl QueryBudget {
    pub(super) fn new() -> Self {
        Self {
            remaining_rows: QUERY_SCAN_ROW_LIMIT,
            remaining_bytes: QUERY_SCAN_BYTE_LIMIT,
            remaining_scans: QUERY_SCAN_COUNT_LIMIT,
            remaining_body_reads: QUERY_BODY_READ_LIMIT,
            block_memo: None,
        }
    }

    pub(super) fn next_scan_limit(&mut self) -> Result<PrefixScanLimit, TxQueryError> {
        if self.remaining_scans == 0 || self.remaining_rows == 0 || self.remaining_bytes == 0 {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::RowBudgetExhausted,
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
                TxUnavailableCause::PrefixScanTruncated,
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
                TxUnavailableCause::LivePrefixScanTruncated,
            ));
        }
        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok(scan.rows)
    }

    fn charge_scan(&mut self, rows: usize, encoded_bytes: usize) -> Result<(), TxQueryError> {
        if rows > self.remaining_rows || encoded_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::RowBudgetExceeded,
            ));
        }
        self.remaining_rows -= rows;
        self.remaining_bytes -= encoded_bytes;
        Ok(())
    }

    pub(super) fn reserve_body_read(&mut self, max_bytes: usize) -> Result<(), TxQueryError> {
        if self.remaining_body_reads == 0 || max_bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::BodyReadBudgetExhausted,
            ));
        }
        self.remaining_body_reads -= 1;
        Ok(())
    }

    pub(super) fn charge_body_bytes(&mut self, bytes: usize) -> Result<(), TxQueryError> {
        if bytes > self.remaining_bytes {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::BodyBudgetExceeded,
            ));
        }
        self.remaining_bytes -= bytes;
        Ok(())
    }

    /// Returns the decoded block retained for `(height, hash)`. A hit costs no
    /// body budget: the reserve and the byte charge happened on the miss that
    /// cached it. A miss evicts the previously retained block, if any, before
    /// the caller fetches and decodes a new one, so a failed fetch or decode
    /// leaves the memo empty instead of pinning a stale identity.
    pub(super) fn memoized_block(&mut self, height: u32, hash: Hash256) -> Option<Arc<Block>> {
        if let Some((memo_height, memo_hash, block)) = &self.block_memo {
            if *memo_height == height && *memo_hash == hash {
                return Some(Arc::clone(block));
            }
        }
        self.block_memo = None;
        None
    }

    /// Pins a successfully verified block as the single retained entry,
    /// replacing whatever the memo held, and returns the shared handle. Only
    /// call this after verification: failures must leave the memo as the miss
    /// left it (empty).
    pub(super) fn memoize_block(
        &mut self,
        height: u32,
        hash: Hash256,
        block: Arc<Block>,
    ) -> Arc<Block> {
        self.block_memo = Some((height, hash, Arc::clone(&block)));
        block
    }
}

/// Authoritative Live query sources: capability selection, the UTXO set, and
/// the chain-transition lock Live composition requires.
pub(crate) struct QueryEngineLive {
    /// Authoritative UTXO set for the compact live view.
    pub(crate) utxo: Option<bitcoin_rs_utxo::UtxoReader>,
    /// Serializes live-view work against a chain transition.
    pub(crate) chain_transition: Option<bitcoin_rs_chain::StableRead>,
    /// Capability set this engine serves.
    pub(crate) enabled: IndexCapabilities,
}

/// First covered height per history-derived capability, loaded from the
/// snapshot's durable floor records. `0` means coverage from genesis; a
/// positive value means the prefix below it was pruned, so a row's absence
/// there is unproven and queries answer `Unavailable` instead of `None`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CapabilityFloors {
    /// `TxLookup` first covered height.
    pub(crate) tx_lookup: u32,
    /// `ScriptHistory` first covered height.
    pub(crate) script_history: u32,
}

impl CapabilityFloors {
    /// Assigns `floor` to `capability`'s slot. `ScriptLive` has no coverage
    /// floor — it reseeds from the UTXO view — so it stores nothing.
    pub(crate) fn set(&mut self, capability: IndexCapability, floor: u32) {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup = floor,
            IndexCapability::ScriptHistory => self.script_history = floor,
            IndexCapability::ScriptLive | IndexCapability::CompactFilters => {}
        }
    }
}

/// Shared hop budget for one historical query's ancestry walks.
///
/// The budget is shared across every watermark join in one call, so a fleet
/// of deep stale branches cannot each spend a full budget. Trusted
/// active-prefix joins are free via the height index; only side-branch
/// parent hops consume the budget. `256` covers organic reorgs (tens of
/// blocks) with wide margin while still failing closed on deep stale
/// branches instead of walking unbounded history.
pub(super) const HISTORICAL_ANCESTRY_BUDGET: usize = 256;

/// Which row-filtering and absence rule a [`ReadPrefix`] carries.
///
/// `ExactTip` preserves the strict exact-tip contract byte for byte: no
/// above-anchor/below-floor skip, pruned-prefix refusals on positive floors.
/// `AtMost` serves historical `[floor, anchor]` coverage on `chain(anchor)`:
/// rows outside the range are skipped before body reads and scoped absence
/// is `Ok(None)` (full history stays `HistoryUnproven` via the shared
/// helper, never silent partial completeness).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrefixBound {
    /// Strict exact-tip read: anchor equals the published tip.
    ExactTip,
    /// Historical covered-prefix read: rows prove `[floor, anchor]`.
    AtMost,
}

/// One stack-owned historical read descriptor.
///
/// Built on the stack per query from one immutable snapshot plus one bounded
/// ancestry walk; it carries no heap, no cache, and no persistent state.
/// `anchor_id` names the common covered ancestor in the live tree,
/// `height`/`hash` its chain identity, `floor` the maximum consumed floor,
/// and `bound` the filtering/absence rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadPrefix {
    /// Tree identity of the common covered ancestor.
    pub(super) anchor_id: NodeId,
    /// Anchor height on `chain(anchor)`.
    pub(super) height: u32,
    /// Full chain hash at the anchor height.
    pub(super) hash: Hash256,
    /// Maximum consumed floor for the call.
    pub(super) floor: u32,
    /// Filtering and absence rule.
    pub(super) bound: PrefixBound,
}

impl ReadPrefix {
    /// Returns whether `height` is provable under this prefix.
    pub(super) fn covers(&self, height: u32) -> bool {
        match self.bound {
            PrefixBound::ExactTip => true,
            PrefixBound::AtMost => height >= self.floor && height <= self.height,
        }
    }
}

pub(super) fn map_historical_error(error: TxQueryError) -> HistoricalQueryError {
    match error {
        TxQueryError::Retry => HistoricalQueryError::Retry,
        TxQueryError::Storage(message) => HistoricalQueryError::Storage(message),
        TxQueryError::Unavailable(cause) => {
            HistoricalQueryError::Unavailable(HistoricalUnavailableCause::Shared(cause))
        }
    }
}

/// Node-owned, snapshot-gated transaction-index query engine.
///
/// Each query reads one typed point-in-time snapshot and checks worker health.
/// Strict queries require an unchanged revision and applied tip. Historical
/// queries retain a covered ancestor and require that ancestor to remain active.
/// Both paths return typed `Retry` or `Unavailable` when the answer is unproven.
#[derive(Clone)]
pub struct DerivedIndexQueryEngine {
    runtime: Arc<DerivedIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_tree: bitcoin_rs_chain::BlockTreeReader,
    applied_tip: bitcoin_rs_chain::TipReader,
    body_source: Option<Arc<dyn BlockBodySource>>,
    utxo: Option<bitcoin_rs_utxo::UtxoReader>,
    chain_transition: Option<bitcoin_rs_chain::StableRead>,
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
    pub(crate) fn new(
        runtime: Arc<DerivedIndexRuntime>,
        reader: Arc<dyn IndexReader>,
        block_tree: bitcoin_rs_chain::BlockTreeReader,
        applied_tip: bitcoin_rs_chain::TipReader,
        body_source: Option<Arc<dyn BlockBodySource>>,
        live: QueryEngineLive,
    ) -> Self {
        Self {
            runtime,
            reader,
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
            return Err(TxQueryError::Unavailable(TxUnavailableCause::WorkerFailed(
                self.runtime
                    .failure_message()
                    .unwrap_or_else(|| "txindex worker failed".into()),
            )));
        }
        if self.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable(TxUnavailableCause::WorkerStopped));
        }
        Ok(())
    }

    fn require_enabled(&self, required: IndexCapabilities) -> Result<(), TxQueryError> {
        // INVARIANT: the refusal text is the first unmet capability's own,
        // scanned in IndexCapability::ALL order.
        for capability in required.iter() {
            if !self.enabled.contains(capability) {
                return Err(TxQueryError::Unavailable(
                    TxUnavailableCause::CapabilityDisabled(capability),
                ));
            }
        }
        Ok(())
    }

    fn with_snapshot<F, T>(&self, required: IndexCapabilities, f: F) -> Result<T, TxQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &TipSnapshot,
            &mut QueryBudget,
            CapabilityFloors,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health()?;
        self.require_enabled(required)?;
        if required.contains(IndexCapability::CompactFilters)
            && let Some(reason) = self.runtime.compact_filter_failure.read().clone()
        {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::CompactFilterFailed(reason),
            ));
        }

        // Live answers compose the index snapshot, the authoritative UTXO set,
        // and the applied tip. Apply mutates UTXO before publishing that tip,
        // so a before/after tip comparison cannot exclude that window. Hold
        // chain-transition across watermark check, locator scan, and UTXO
        // resolution. History and tx lookup never take it.
        let _chain_transition = if required.contains(IndexCapability::ScriptLive) {
            Some(
                self.chain_transition
                    .as_ref()
                    .ok_or_else(|| {
                        TxQueryError::Unavailable(TxUnavailableCause::MissingAuthority(
                            "chain transition authority missing for ScriptLive",
                        ))
                    })?
                    .lock(),
            )
        } else {
            None
        };

        let tip_before = self.applied_tip.load_full().ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        let mut floors = CapabilityFloors::default();
        for capability in [IndexCapability::TxLookup, IndexCapability::ScriptHistory] {
            if !required.contains(capability) {
                continue;
            }
            let floor = snapshot
                .capability_floor(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            floors.set(capability, floor);
        }

        for capability in IndexCapability::ALL {
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
        let result = f(snapshot.as_ref(), &tip_before, &mut budget, floors);

        self.query_health()?;
        if required.contains(IndexCapability::CompactFilters)
            && let Some(reason) = self.runtime.compact_filter_failure.read().clone()
        {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::CompactFilterFailed(reason),
            ));
        }
        let tip_after = self.applied_tip.load_full();
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

    fn bounded_common_ancestor(
        tree: &BlockTree,
        a: NodeId,
        b: NodeId,
        remaining: &mut usize,
    ) -> Result<Option<NodeId>, AncestryBudgetExceeded> {
        let a_node = tree.node(a).map_err(|_| AncestryBudgetExceeded)?;
        let b_node = tree.node(b).map_err(|_| AncestryBudgetExceeded)?;
        let (mut cursor_a, mut cursor_b) = (a, b);
        let (mut height_a, mut height_b) = (a_node.height, b_node.height);
        if height_a > height_b {
            let aligned = tree.node_at_height_from_bounded(cursor_a, height_b, remaining)?;
            let Some(aligned) = aligned else {
                return Ok(None);
            };
            cursor_a = aligned;
            height_a = height_b;
        } else if height_b > height_a {
            let aligned = tree.node_at_height_from_bounded(cursor_b, height_a, remaining)?;
            let Some(aligned) = aligned else {
                return Ok(None);
            };
            cursor_b = aligned;
            height_b = height_a;
        }
        debug_assert_eq!(height_a, height_b);
        if cursor_a == cursor_b {
            return Ok(Some(cursor_a));
        }
        loop {
            let node_a = tree.node(cursor_a).map_err(|_| AncestryBudgetExceeded)?;
            let node_b = tree.node(cursor_b).map_err(|_| AncestryBudgetExceeded)?;
            let (Some(parent_a), Some(parent_b)) = (node_a.parent, node_b.parent) else {
                return Ok(None);
            };
            *remaining = remaining.checked_sub(1).ok_or(AncestryBudgetExceeded)?;
            if parent_a == parent_b {
                return Ok(Some(parent_a));
            }
            cursor_a = parent_a;
            cursor_b = parent_b;
        }
    }

    fn covered_anchor(
        &self,
        tip_id: NodeId,
        watermarks: &[(IndexCapability, IndexWatermark)],
        remaining: &mut usize,
    ) -> Result<(NodeId, u32, Hash256), HistoricalQueryError> {
        let tree = self.block_tree.read();
        tree.node(tip_id).map_err(|_| HistoricalQueryError::Retry)?;
        let mut anchor_id = tip_id;
        for (capability, watermark) in watermarks {
            let hash = Hash256::from_le_bytes(&watermark.hash);
            let Some(watermark_id) = tree.lookup(hash) else {
                return Err(HistoricalQueryError::Retry);
            };
            match Self::bounded_common_ancestor(&tree, anchor_id, watermark_id, remaining) {
                Ok(Some(joined)) => anchor_id = joined,
                Ok(None) => return Err(HistoricalQueryError::Retry),
                Err(_) => {
                    return Err(HistoricalQueryError::Unavailable(
                        HistoricalUnavailableCause::AncestryBudgetExhausted {
                            capability: *capability,
                            watermark_height: watermark.height,
                        },
                    ));
                }
            }
        }
        let anchor = tree
            .node(anchor_id)
            .map_err(|_| HistoricalQueryError::Retry)?;
        Ok((anchor_id, anchor.height, anchor.hash))
    }

    fn require_anchor_still_covers(&self, anchor: &ReadPrefix) -> Result<(), HistoricalQueryError> {
        let tip_after = self
            .applied_tip
            .load_full()
            .ok_or(HistoricalQueryError::Retry)?;
        let tree = self.block_tree.read();
        let mut remaining = HISTORICAL_ANCESTRY_BUDGET;
        let found = tree
            .node_at_height_from_bounded(tip_after.tip_id, anchor.height, &mut remaining)
            .map_err(|_| HistoricalQueryError::Retry)?;
        match found {
            Some(id) if id == anchor.anchor_id => Ok(()),
            _ => Err(HistoricalQueryError::Retry),
        }
    }

    fn with_prefix<F, T>(
        &self,
        required: IndexCapabilities,
        f: F,
    ) -> Result<AtPrefix<T>, HistoricalQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &ReadPrefix,
            &mut QueryBudget,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health().map_err(map_historical_error)?;
        self.require_enabled(required)
            .map_err(map_historical_error)?;
        if required.contains(IndexCapability::CompactFilters)
            && let Some(reason) = self.runtime.compact_filter_failure.read().clone()
        {
            return Err(HistoricalQueryError::Unavailable(
                HistoricalUnavailableCause::Shared(TxUnavailableCause::CompactFilterFailed(reason)),
            ));
        }
        let tip_before = self
            .applied_tip
            .load_full()
            .ok_or(HistoricalQueryError::Retry)?;
        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| HistoricalQueryError::Storage(e.to_string().into()))?;
        let mut floor: u32 = 0;
        let mut watermarks = Vec::new();
        for capability in required.iter() {
            let capability_floor = snapshot
                .capability_floor(capability)
                .map_err(|e| HistoricalQueryError::Storage(e.to_string().into()))?;
            floor = floor.max(capability_floor);
            let watermark = snapshot
                .capability_watermark(capability)
                .map_err(|e| HistoricalQueryError::Storage(e.to_string().into()))?;
            let Some(watermark) = watermark else {
                return Err(HistoricalQueryError::Unavailable(
                    HistoricalUnavailableCause::NoCoveredPrefix { capability },
                ));
            };
            watermarks.push((capability, watermark));
        }
        let mut remaining = HISTORICAL_ANCESTRY_BUDGET;
        let (anchor_id, anchor_height, anchor_hash) =
            self.covered_anchor(tip_before.tip_id, &watermarks, &mut remaining)?;
        if anchor_height < floor {
            return Err(HistoricalQueryError::Unavailable(
                HistoricalUnavailableCause::PrefixBelowFloor { floor },
            ));
        }
        let prefix = ReadPrefix {
            anchor_id,
            height: anchor_height,
            hash: anchor_hash,
            floor,
            bound: PrefixBound::AtMost,
        };
        let mut budget = QueryBudget::new();
        let answer = f(snapshot.as_ref(), &prefix, &mut budget).map_err(map_historical_error)?;
        self.query_health().map_err(map_historical_error)?;
        if required.contains(IndexCapability::CompactFilters)
            && let Some(reason) = self.runtime.compact_filter_failure.read().clone()
        {
            return Err(HistoricalQueryError::Unavailable(
                HistoricalUnavailableCause::Shared(TxUnavailableCause::CompactFilterFailed(reason)),
            ));
        }
        self.require_anchor_still_covers(&prefix)?;
        self.query_health().map_err(map_historical_error)?;
        Ok(AtPrefix {
            prefix: CoveredPrefix {
                floor: prefix.floor,
                height: prefix.height,
                hash: prefix.hash,
            },
            answer,
        })
    }

    pub(crate) fn transaction_at_prefix(
        &self,
        txid: &Txid,
    ) -> Result<AtPrefix<Option<(u32, Tx)>>, HistoricalQueryError> {
        self.with_prefix(IndexCapabilities::TX_LOOKUP, |snapshot, prefix, budget| {
            self.locate_transaction_for(snapshot, prefix, budget, txid)
        })
    }

    pub(crate) fn script_history_at_prefix(
        &self,
        script: ScriptHash,
    ) -> Result<AtPrefix<ScriptIndexSnapshot>, HistoricalQueryError> {
        self.with_prefix(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, prefix, budget| self.history_snapshot_for(snapshot, prefix, budget, script),
        )
    }

    pub(crate) fn spender_at_prefix(
        &self,
        outpoint: OutPoint,
    ) -> Result<AtPrefix<Option<SpendingRecord>>, HistoricalQueryError> {
        self.with_prefix(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, prefix, budget| self.spender_for(snapshot, prefix, budget, &outpoint),
        )
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

        let tip_before = self.applied_tip.load_full().ok_or(TxQueryError::Retry)?;
        let revision_before = self.runtime.revision();

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        let mut marks = [None; 4];
        for capability in IndexCapability::ALL {
            if !required.contains(capability) {
                continue;
            }
            marks[capability.index()] = snapshot
                .capability_watermark(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
        }
        let at_tip = |watermark: Option<IndexWatermark>| {
            watermark.is_some_and(|watermark| {
                watermark.height == tip_before.height
                    && watermark.hash == *tip_before.hash.as_byte_array()
            })
        };
        let synced = required
            .iter()
            .all(|capability| at_tip(marks[capability.index()]));
        let best_block_height = required
            .iter()
            .map(|capability| marks[capability.index()].map_or(0, |watermark| watermark.height))
            .min()
            .unwrap_or(0);

        self.query_health()?;
        let tip_after = self.applied_tip.load_full();
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
        self.with_snapshot(
            IndexCapabilities::TX_LOOKUP,
            |snapshot, tip, budget, floors| {
                let prefix = ReadPrefix {
                    anchor_id: tip.tip_id,
                    height: tip.height,
                    hash: tip.hash,
                    floor: floors.tx_lookup,
                    bound: PrefixBound::ExactTip,
                };
                self.transaction_for(snapshot, &prefix, budget, txid)
            },
        )
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::TX_LOOKUP,
            |snapshot, tip, budget, floors| {
                let prefix = ReadPrefix {
                    anchor_id: tip.tip_id,
                    height: tip.height,
                    hash: tip.hash,
                    floor: floors.tx_lookup,
                    bound: PrefixBound::ExactTip,
                };
                self.outpoint_value_for(snapshot, &prefix, budget, outpoint)
            },
        )
    }

    fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::TX_LOOKUP,
            |snapshot, tip, budget, floors| {
                let prefix = ReadPrefix {
                    anchor_id: tip.tip_id,
                    height: tip.height,
                    hash: tip.hash,
                    floor: floors.tx_lookup,
                    bound: PrefixBound::ExactTip,
                };
                Ok(self
                    .locate_transaction_for(snapshot, &prefix, budget, txid)?
                    .map(|(height, _)| height))
            },
        )
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
            |snapshot, tip, budget, floors| {
                let prefix = ReadPrefix {
                    anchor_id: tip.tip_id,
                    height: tip.height,
                    hash: tip.hash,
                    floor: floors.script_history,
                    bound: PrefixBound::ExactTip,
                };
                self.history_snapshot_for(snapshot, &prefix, budget, scripthash)
            },
        )
    }

    fn confirmed_history(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget, floors| {
                let prefix = ReadPrefix {
                    anchor_id: tip.tip_id,
                    height: tip.height,
                    hash: tip.hash,
                    floor: floors.script_history,
                    bound: PrefixBound::ExactTip,
                };
                self.confirmed_history_for(snapshot, &prefix, budget, scripthash)
            },
        )
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_LIVE,
            |snapshot, tip, budget, _floors| {
                self.unspent_outputs_for(snapshot, tip, budget, scripthash)
            },
        )
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        self.with_snapshot(
            IndexCapabilities::SCRIPT_HISTORY,
            |snapshot, tip, budget, floors| {
                let prefix = ReadPrefix {
                    anchor_id: tip.tip_id,
                    height: tip.height,
                    hash: tip.hash,
                    floor: floors.script_history,
                    bound: PrefixBound::ExactTip,
                };
                self.spender_for(snapshot, &prefix, budget, &outpoint)
            },
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
        assert!(matches!(
            historical,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrefixScanTruncated
            ))
        ));
        let live = budget.accept_live_scan(ScriptLiveScan {
            rows: Vec::new(),
            encoded_bytes: 3,
            complete: false,
        });
        assert!(matches!(
            live,
            Err(TxQueryError::Unavailable(
                TxUnavailableCause::LivePrefixScanTruncated
            ))
        ));
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
                block_memo: None,
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

    #[test]
    fn block_memo_retains_only_the_latest_identity() {
        use std::sync::Weak;

        let mut budget = QueryBudget::new();
        let hash_a = Hash256::from_le_bytes(&[0x11; 32]);
        let hash_b = Hash256::from_le_bytes(&[0x22; 32]);

        let block_a = Arc::new(Block::default());
        let weak_a: Weak<Block> = Arc::downgrade(&block_a);
        let pinned_a = budget.memoize_block(1, hash_a, block_a);
        assert!(weak_a.upgrade().is_some());
        drop(pinned_a);

        assert!(budget.memoized_block(2, hash_b).is_none());
        assert!(
            weak_a.upgrade().is_none(),
            "a miss must release the previously retained block before fetching its replacement"
        );

        let block_b = Arc::new(Block::default());
        let weak_b: Weak<Block> = Arc::downgrade(&block_b);
        let pinned_b = budget.memoize_block(2, hash_b, block_b);
        drop(pinned_b);
        assert!(budget.memoized_block(2, hash_b).is_some());
        assert!(weak_b.upgrade().is_some());
        drop(budget);
        assert!(weak_b.upgrade().is_none());
    }
}
