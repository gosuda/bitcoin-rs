use super::{
    Arc, Block, BlockBodySource, BlockTree, DerivedIndexInfo, DerivedIndexQuery,
    DerivedIndexRuntime, Generation, Hash256, IndexCapabilities, IndexCapability, IndexReader,
    IndexWatermark, MAX_SERIALIZED_BLOCK_BYTES, Ordering, OutPoint, PrefixScanLimit,
    QUERY_BODY_READ_LIMIT, QUERY_SCAN_BYTE_LIMIT, QUERY_SCAN_COUNT_LIMIT, QUERY_SCAN_ROW_LIMIT,
    ScriptHash, ScriptHistoryRecord, ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot,
    ScriptLiveScan, SpendingRecord, Tx, TxIndexScan, TxIndexScanRow, TxIndexSnapshot, TxPosition,
    TxPositionValue, TxQueryError, TxUnavailableCause, Txid, deserialize,
};
use crate::query_api::{
    Answer, AppliedEpoch, CapabilityCoverage, CoveredPrefix, QueryMiss, RetryReason,
    ScriptHistoryPage, TransactionBlock, VerificationState,
};
use bitcoin_rs_execution::chain::{NodeId, TipReader};

use std::time::{Duration, Instant};

mod filters;
#[cfg(any(test, verification, kani))]
pub(crate) mod proofs;
mod scripts;
mod transactions;

pub const DEFAULT_SCRIPTHASH_LIMIT: usize = 25_000;

pub(crate) struct QueryBudget {
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

    pub(super) fn next_page_scan_limit(
        &mut self,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<PrefixScanLimit, TxQueryError> {
        let limit = self.next_scan_limit()?;
        Ok(PrefixScanLimit {
            max_rows: limit.max_rows.min(max_rows),
            max_bytes: limit.max_bytes.min(max_bytes),
        })
    }

    pub(super) fn accept_page_scan(
        &mut self,
        scan: TxIndexScan,
    ) -> Result<(Vec<TxIndexScanRow>, bool), TxQueryError> {
        self.charge_scan(scan.rows.len(), scan.encoded_bytes)?;
        Ok((scan.rows, scan.complete))
    }

    pub(super) fn accept_scan(
        &mut self,
        scan: TxIndexScan,
    ) -> Result<Vec<TxIndexScanRow>, TxQueryError> {
        self.accept_completed_scan(
            scan.complete,
            TxUnavailableCause::PrefixScanTruncated,
            scan.rows.len(),
            scan.encoded_bytes,
        )?;
        Ok(scan.rows)
    }

    pub(super) fn accept_live_scan(&mut self, scan: &ScriptLiveScan) -> Result<(), TxQueryError> {
        self.accept_completed_scan(
            scan.complete,
            TxUnavailableCause::LivePrefixScanTruncated,
            scan.rows.len(),
            scan.encoded_bytes,
        )
    }

    fn accept_completed_scan(
        &mut self,
        complete: bool,
        truncated: TxUnavailableCause,
        rows: usize,
        encoded_bytes: usize,
    ) -> Result<(), TxQueryError> {
        if !complete {
            return Err(TxQueryError::Unavailable(truncated));
        }
        self.charge_scan(rows, encoded_bytes)
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

    pub(super) fn memoized_block(&mut self, height: u32, hash: Hash256) -> Option<Arc<Block>> {
        if let Some((memo_height, memo_hash, block)) = &self.block_memo {
            if *memo_height == height && *memo_hash == hash {
                return Some(Arc::clone(block));
            }
        }
        self.block_memo = None;
        None
    }

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

/// View lifetime bound (`QRY-07`): a captured view stops serving after this
/// deadline so a long reader cannot pin a stale generation indefinitely.
pub(crate) const VIEW_DEADLINE: Duration = Duration::from_secs(60);

pub type HistoricalVerifiedReader =
    Arc<dyn Fn() -> Result<Option<(u32, Hash256)>, TxQueryError> + Send + Sync>;

pub(crate) struct QueryEngineLive {
    pub(crate) enabled: IndexCapabilities,
    pub(crate) generation: Arc<Generation>,
    pub(crate) historical_verified: Option<HistoricalVerifiedReader>,
    #[cfg(any(test, feature = "test-seam"))]
    pub(crate) chain_transition: Option<bitcoin_rs_execution::chain::StableRead>,
}

/// View-qualified pagination position (`QRY-06`): the generation that issued
/// the cursor plus the funding-row position it resolved to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OccurrenceCursor {
    pub(crate) view_id: u64,
    pub(crate) height: u32,
    pub(crate) tx_pos: u32,
}

impl DerivedIndexQueryEngine {
    fn require_cursor_tx_lookup_coverage_on_view(
        view: &ServingView,
        cursor: Option<Txid>,
    ) -> Result<(), TxQueryError> {
        let Some(_) = cursor else {
            return Ok(());
        };
        let Some(tx_lookup) = view.coverage_for(IndexCapability::TxLookup) else {
            return Ok(());
        };
        let Some(script_history) = view.coverage_for(IndexCapability::ScriptHistory) else {
            return Ok(());
        };
        if tx_lookup.floor > script_history.floor {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::PrunedPrefixUnproven {
                    family: "transaction index",
                    floor: tx_lookup.floor,
                },
            ));
        }
        Ok(())
    }
    // QRY-03
    fn require_tip_coverage_on_view(
        view: &ServingView,
        required: IndexCapabilities,
    ) -> Result<(), TxQueryError> {
        for capability in required.iter() {
            let covers_tip = view.coverage_for(capability).is_some_and(|coverage| {
                coverage.last_height == view.epoch.height && coverage.last_hash == view.epoch.hash
            });
            if !covers_tip {
                return Err(TxQueryError::Retry(RetryReason::TipMoved {
                    expected_commit: view.epoch.commit_id,
                    current_commit: view.epoch.commit_id,
                }));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadPrefix {
    pub(super) anchor_id: NodeId,
    pub(super) height: u32,
    pub(super) hash: Hash256,
    pub(super) floor: u32,
    pub(super) is_historical: bool,
}

impl ReadPrefix {
    /// A row serves the view only inside the declared coverage window:
    /// rows written after the view was captured are not part of it.
    pub(super) fn covers(&self, height: u32) -> bool {
        height >= self.floor && height <= self.height
    }
}

#[derive(Clone)]
pub struct DerivedIndexQueryEngine {
    scripthash_limit: usize,
    runtime: Arc<DerivedIndexRuntime>,
    reader: Arc<dyn IndexReader>,
    block_tree: bitcoin_rs_execution::chain::BlockTreeReader,
    applied_tip: TipReader,
    body_source: Option<Arc<dyn BlockBodySource>>,
    enabled: IndexCapabilities,
    generation: Arc<Generation>,
    historical_verified: Option<HistoricalVerifiedReader>,
    query_charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    #[cfg(any(test, feature = "test-seam"))]
    #[expect(dead_code, reason = "test seam field")]
    pub(crate) chain_transition: Option<bitcoin_rs_execution::chain::StableRead>,
}

/// One immutable serving view (`QRY-01`, `QRY-07`): the captured epoch,
/// generation pin, coverage window, and verification provenance of a read.
/// One owner, one bounded lifetime; methods return `ExpiredView` after the
/// deadline or once the generation is retired.
pub(crate) struct ServingView {
    pub epoch: AppliedEpoch,
    pub generation_id: u64,
    pub coverage: [Option<CapabilityCoverage>; 4],
    pub historical_verified: Option<(u32, Hash256)>,
    pub(super) tip_id: NodeId,
    deadline: Instant,
    #[cfg(test)]
    expired_for_test: std::sync::atomic::AtomicBool,
    _view_charge: Option<ViewCharge>,
}

impl ServingView {
    fn expired(&self) -> bool {
        #[cfg(test)]
        if self.expired_for_test.load(Ordering::SeqCst) {
            return true;
        }
        Instant::now() >= self.deadline
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&self) {
        self.expired_for_test.store(true, Ordering::SeqCst);
    }

    fn coverage_for(&self, capability: IndexCapability) -> Option<CapabilityCoverage> {
        self.coverage[capability.index()]
    }

    fn prefix_for(
        &self,
        capability: IndexCapability,
        is_historical: bool,
    ) -> Result<ReadPrefix, TxQueryError> {
        let coverage = self.coverage_for(capability).ok_or_else(|| {
            TxQueryError::Retry(RetryReason::TipMoved {
                expected_commit: self.epoch.commit_id,
                current_commit: self.epoch.commit_id,
            })
        })?;
        if coverage.floor > self.epoch.height {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: coverage.floor,
                },
            ));
        }
        let height = coverage.last_height.min(self.epoch.height);
        Ok(ReadPrefix {
            anchor_id: self.tip_id,
            height,
            hash: coverage.last_hash,
            floor: coverage.floor,
            is_historical,
        })
    }
}

struct ViewCharge {
    handle: bitcoin_rs_storage::budget::ChargeHandle,
    bytes: u64,
}

impl Drop for ViewCharge {
    fn drop(&mut self) {
        self.handle.release(self.bytes);
    }
}
impl core::fmt::Debug for DerivedIndexQueryEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedIndexQueryEngine")
            .finish_non_exhaustive()
    }
}

impl DerivedIndexQueryEngine {
    #[must_use]
    pub(crate) fn new(
        runtime: Arc<DerivedIndexRuntime>,
        reader: Arc<dyn IndexReader>,
        block_tree: bitcoin_rs_execution::chain::BlockTreeReader,
        applied_tip: TipReader,
        body_source: Option<Arc<dyn BlockBodySource>>,
        live: QueryEngineLive,
    ) -> Self {
        Self {
            scripthash_limit: DEFAULT_SCRIPTHASH_LIMIT,
            runtime,
            reader,
            block_tree,
            applied_tip,
            body_source,
            enabled: live.enabled,
            generation: live.generation,
            historical_verified: live.historical_verified,
            query_charge: None,
            #[cfg(any(test, feature = "test-seam"))]
            chain_transition: live.chain_transition,
        }
    }

    pub(crate) fn with_scripthash_limit(mut self, limit: usize) -> Self {
        self.scripthash_limit = limit;
        self
    }

    pub(crate) fn with_query_charge(
        mut self,
        charge: Option<bitcoin_rs_storage::budget::ChargeHandle>,
    ) -> Self {
        self.query_charge = charge;
        self
    }

    #[cfg(test)]
    pub(crate) fn set_generation_for_test(&mut self, generation: Arc<Generation>) {
        self.generation = generation;
    }

    fn script_budget(&self, budget: &mut QueryBudget) {
        budget.remaining_body_reads = self.scripthash_limit.saturating_mul(4).saturating_add(1);
        budget.remaining_scans = self.scripthash_limit.saturating_mul(2).saturating_add(2);
    }

    fn script_page_requirements(&self, cursor: Option<Txid>) -> IndexCapabilities {
        if cursor.is_some() && self.enabled.contains(IndexCapability::TxLookup) {
            IndexCapabilities::SCRIPT_HISTORY.insert(IndexCapability::TxLookup)
        } else {
            IndexCapabilities::SCRIPT_HISTORY
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
        for capability in required.iter() {
            if !self.enabled.contains(capability) {
                return Err(TxQueryError::Unavailable(
                    TxUnavailableCause::CapabilityDisabled(capability),
                ));
            }
        }
        Ok(())
    }

    /// Reads the applied epoch, generation, and coverage once and pins the
    /// generation and the capture-time snapshot for the view's bounded
    /// lifetime (`QRY-01`, `QRY-07`).
    pub(crate) fn capture_view(
        &self,
        required: IndexCapabilities,
    ) -> Result<(ServingView, Box<dyn TxIndexSnapshot + '_>), TxQueryError> {
        self.query_health()?;
        self.require_enabled(required)?;
        self.check_capability_failures(required)?;
        if self.generation.is_revoked() {
            return Err(TxQueryError::ExpiredView);
        }
        let revision = self.runtime.revision();
        let tip = self.applied_tip.load_full().ok_or_else(|| {
            TxQueryError::Retry(RetryReason::TipMoved {
                expected_commit: revision,
                current_commit: revision,
            })
        })?;

        let reader: &dyn IndexReader = self.reader.as_ref();
        let snapshot = reader
            .snapshot()
            .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;

        for capability in required.iter() {
            let published = snapshot
                .capability_published(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            if !published {
                return Err(TxQueryError::Unavailable(
                    TxUnavailableCause::CapabilityUnpublished(capability),
                ));
            }
        }

        let mut coverage = [None; 4];
        for capability in required.iter() {
            let watermark = snapshot
                .capability_watermark(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            let Some(watermark) = watermark else {
                return Err(TxQueryError::Retry(RetryReason::TipMoved {
                    expected_commit: revision,
                    current_commit: revision,
                }));
            };
            let floor = snapshot
                .capability_floor(capability)
                .map_err(|e| TxQueryError::Storage(e.to_string().into()))?;
            coverage[capability.index()] = Some(CapabilityCoverage {
                floor,
                last_height: watermark.height,
                last_hash: Hash256::from_le_bytes(&watermark.hash),
            });
        }
        {
            let tree = self.block_tree.read();
            for capability in required.iter() {
                let Some(entry) = coverage[capability.index()] else {
                    continue;
                };
                if Self::hash_at_height(&tree, tip.tip_id, entry.last_height)
                    != Some(entry.last_hash)
                {
                    return Err(TxQueryError::Retry(RetryReason::TipMoved {
                        expected_commit: revision,
                        current_commit: revision,
                    }));
                }
            }
        }

        let historical_verified = match &self.historical_verified {
            Some(read) => read()?,
            None => None,
        };
        let view_charge = self.charge_view()?;
        Ok((
            ServingView {
                epoch: AppliedEpoch {
                    hash: tip.hash,
                    height: tip.height,
                    commit_id: self.runtime.revision(),
                },
                generation_id: self.generation.id(),
                coverage,
                historical_verified,
                tip_id: tip.tip_id,
                deadline: Instant::now() + VIEW_DEADLINE,
                #[cfg(test)]
                expired_for_test: std::sync::atomic::AtomicBool::new(false),
                _view_charge: view_charge,
            },
            snapshot,
        ))
    }

    fn charge_view(&self) -> Result<Option<ViewCharge>, TxQueryError> {
        let Some(handle) = self.query_charge.as_ref() else {
            return Ok(None);
        };
        let bytes = u64::try_from(std::mem::size_of::<ServingView>()).unwrap_or(u64::MAX);
        handle
            .charge(bytes)
            .map_err(|_| TxQueryError::Unavailable(TxUnavailableCause::NodeBudgetExhausted))?;
        Ok(Some(ViewCharge {
            handle: handle.clone(),
            bytes,
        }))
    }

    fn check_view(&self, view: &ServingView) -> Result<(), TxQueryError> {
        if view.generation_id != self.generation.id() || self.generation.is_revoked() {
            return Err(TxQueryError::ExpiredView);
        }
        if view.expired() {
            return Err(TxQueryError::ExpiredView);
        }
        Ok(())
    }

    pub(crate) fn with_view<F, T>(
        &self,
        required: IndexCapabilities,
        view: &ServingView,
        snapshot: &dyn TxIndexSnapshot,
        f: F,
    ) -> Result<T, TxQueryError>
    where
        F: for<'s> FnOnce(
            &'s dyn TxIndexSnapshot,
            &ServingView,
            &mut QueryBudget,
        ) -> Result<T, TxQueryError>,
    {
        self.query_health()?;
        self.require_enabled(required)?;
        self.check_capability_failures(required)?;
        self.check_view(view)?;

        let mut budget = QueryBudget::new();
        let result = f(snapshot, view, &mut budget);

        self.query_health()?;
        self.check_capability_failures(required)?;
        self.check_view(view)?;
        result
    }

    fn answer<T>(&self, view: &ServingView, capability: IndexCapability, value: T) -> Answer<T> {
        let coverage = view.coverage_for(capability);
        let (floor, height, hash) = coverage.map_or((0, view.epoch.height, view.epoch.hash), |c| {
            (c.floor, c.last_height, c.last_hash)
        });
        let verification_state = match view.historical_verified {
            Some((verified_height, verified_hash)) if verified_height < view.epoch.height => {
                VerificationState::AssumedHistory {
                    verified_height,
                    verified_hash,
                }
            }
            _ => VerificationState::ChainVerified,
        };
        Answer {
            value,
            block_hash: view.epoch.hash,
            height: view.epoch.height,
            coverage: CoveredPrefix {
                floor,
                height,
                hash,
            },
            verification_state,
        }
    }

    /// Absence inside complete declared coverage is scoped absence (`QRY-05`);
    /// absence above the coverage tip means the answer would mislead.
    fn scoped_or_outside<T>(
        &self,
        view: &ServingView,
        capability: IndexCapability,
        value: Option<T>,
    ) -> Result<Option<T>, TxQueryError> {
        if value.is_some() {
            return Ok(value);
        }
        let in_coverage = view
            .coverage_for(capability)
            .is_some_and(|coverage| coverage.last_height >= view.epoch.height);
        if in_coverage {
            QueryMiss::Absent.into_scoped()
        } else {
            let declared_floor_or_tip = view
                .coverage_for(capability)
                .map_or(0, |coverage| coverage.last_height);
            QueryMiss::Unavailable {
                capability,
                declared_floor_or_tip,
            }
            .into_scoped()
        }
    }

    /// Historical queries stay answerable under ordinary chain extension
    /// (`QRY-03`): the view pins its epoch, so extension cannot invalidate it.
    pub(crate) fn transaction_at_answer(
        &self,
        txid: &Txid,
    ) -> Result<Answer<Option<(u32, Tx)>>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::TX_LOOKUP)?;
        let value = self.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                let prefix = Self::require_prefix(view, IndexCapability::TxLookup)?;
                let located = self.locate_transaction_for(snapshot, &prefix, budget, txid)?;
                self.scoped_or_outside(view, IndexCapability::TxLookup, located)
            },
        )?;
        Ok(self.answer(&view, IndexCapability::TxLookup, value))
    }

    pub(crate) fn script_history_at_answer(
        &self,
        script: ScriptHash,
    ) -> Result<Answer<ScriptIndexSnapshot>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::SCRIPT_HISTORY)?;
        let value = self.with_view(
            IndexCapabilities::SCRIPT_HISTORY,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                self.script_budget(budget);
                let prefix = Self::require_prefix(view, IndexCapability::ScriptHistory)?;
                self.history_snapshot_for(snapshot, &prefix, budget, script)
            },
        )?;
        Ok(self.answer(&view, IndexCapability::ScriptHistory, value))
    }

    pub(crate) fn spender_at_answer(
        &self,
        outpoint: OutPoint,
    ) -> Result<Answer<Option<SpendingRecord>>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::SCRIPT_HISTORY)?;
        let value = self.with_view(
            IndexCapabilities::SCRIPT_HISTORY,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                let prefix = Self::require_prefix(view, IndexCapability::ScriptHistory)?;
                let spent = self.spender_for(snapshot, &prefix, budget, &outpoint)?;
                self.scoped_or_outside(view, IndexCapability::ScriptHistory, spent)
            },
        )?;
        Ok(self.answer(&view, IndexCapability::ScriptHistory, value))
    }
    fn require_prefix(
        view: &ServingView,
        capability: IndexCapability,
    ) -> Result<ReadPrefix, TxQueryError> {
        view.prefix_for(capability, true)
    }

    fn require_tip_prefix(
        view: &ServingView,
        capability: IndexCapability,
    ) -> Result<ReadPrefix, TxQueryError> {
        view.prefix_for(capability, false)
    }

    #[cfg(test)]
    pub(crate) fn transaction_at_prefix(
        &self,
        txid: &Txid,
    ) -> Result<Answer<Option<(u32, Tx)>>, TxQueryError> {
        self.transaction_at_answer(txid)
    }

    #[cfg(test)]
    pub(crate) fn script_history_at_prefix(
        &self,
        script: ScriptHash,
    ) -> Result<Answer<ScriptIndexSnapshot>, TxQueryError> {
        self.script_history_at_answer(script)
    }

    #[cfg(test)]
    pub(crate) fn spender_at_prefix(
        &self,
        outpoint: OutPoint,
    ) -> Result<Answer<Option<SpendingRecord>>, TxQueryError> {
        self.spender_at_answer(outpoint)
    }

    pub(crate) fn index_progress_for(
        &self,
        required: IndexCapabilities,
    ) -> Result<IndexProgress, TxQueryError> {
        self.query_health()?;

        let revision_before = self.runtime.revision();
        let tip_before = self.applied_tip.load_full().ok_or_else(|| {
            TxQueryError::Retry(RetryReason::TipMoved {
                expected_commit: revision_before,
                current_commit: revision_before,
            })
        })?;

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
            return Err(TxQueryError::Retry(RetryReason::TipMoved {
                expected_commit: revision_before,
                current_commit: revision_after,
            }));
        }

        Ok(IndexProgress {
            synced,
            processed_height: best_block_height,
            target_height: tip_before.height,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexProgress {
    pub synced: bool,
    pub processed_height: u32,
    pub target_height: u32,
}

impl DerivedIndexQuery for DerivedIndexQueryEngine {
    fn transaction(&self, txid: &Txid) -> Result<Option<Tx>, TxQueryError> {
        Ok(self
            .transaction_block(txid)?
            .map(|(transaction, _)| transaction))
    }

    fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::TX_LOOKUP)?;
        self.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, IndexCapabilities::TX_LOOKUP)?;
                let prefix = Self::require_tip_prefix(view, IndexCapability::TxLookup)?;
                let value = self.outpoint_value_for(snapshot, &prefix, budget, outpoint)?;
                self.scoped_or_outside(view, IndexCapability::TxLookup, value)
            },
        )
    }

    fn transaction_block(
        &self,
        txid: &Txid,
    ) -> Result<Option<(Tx, TransactionBlock)>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::TX_LOOKUP)?;
        self.with_view(
            IndexCapabilities::TX_LOOKUP,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, IndexCapabilities::TX_LOOKUP)?;
                let prefix = Self::require_tip_prefix(view, IndexCapability::TxLookup)?;
                let found = self
                    .locate_transaction_for(snapshot, &prefix, budget, txid)?
                    .map(|(height, transaction)| {
                        let hash = self.resolve_hash_at_height(height, &prefix)?;
                        Ok::<_, TxQueryError>((transaction, TransactionBlock { height, hash }))
                    })
                    .transpose()?;
                self.scoped_or_outside(view, IndexCapability::TxLookup, found)
            },
        )
    }

    fn index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        let progress = self.index_progress_for(IndexCapabilities::TX_LOOKUP)?;
        let applied_height = self
            .applied_tip
            .load_full()
            .as_ref()
            .map_or(0, |tip| tip.height);
        let coverage_height = progress.processed_height;
        let verified_height = progress.processed_height.min(applied_height);
        Ok(DerivedIndexInfo {
            synced: progress.synced,
            best_block_height: progress.processed_height,
            applied_height,
            verified_height,
            historical_height: progress.processed_height,
            coverage_height,
        })
    }
}

impl ScriptIndexQuery for DerivedIndexQueryEngine {
    fn history_page(
        &self,
        script: ScriptHash,
        last: Option<Txid>,
        limit: usize,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        let required = self.script_page_requirements(last);
        let (view, snapshot) = self.capture_view(required)?;
        self.with_view(
            required,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, required)?;
                self.script_budget(budget);
                Self::require_cursor_tx_lookup_coverage_on_view(view, last)?;
                let prefix = Self::require_prefix(view, IndexCapability::ScriptHistory)?;
                Self::history_page_for(
                    snapshot,
                    &prefix,
                    budget,
                    script,
                    last,
                    view.generation_id,
                    limit,
                )
            },
        )
    }
    fn history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ScriptIndexSnapshot, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::SCRIPT_HISTORY)?;
        self.with_view(
            IndexCapabilities::SCRIPT_HISTORY,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, IndexCapabilities::SCRIPT_HISTORY)?;
                self.script_budget(budget);
                let prefix = Self::require_prefix(view, IndexCapability::ScriptHistory)?;
                self.history_snapshot_for(snapshot, &prefix, budget, scripthash)
            },
        )
    }

    fn confirmed_history(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptHistoryRecord>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::SCRIPT_HISTORY)?;
        self.with_view(
            IndexCapabilities::SCRIPT_HISTORY,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, IndexCapabilities::SCRIPT_HISTORY)?;
                self.script_budget(budget);
                let prefix = Self::require_prefix(view, IndexCapability::ScriptHistory)?;
                self.confirmed_history_for(snapshot, &prefix, budget, scripthash)
            },
        )
    }

    fn confirmed_history_page(
        &self,
        scripthash: ScriptHash,
        cursor: Option<Txid>,
        limit: usize,
    ) -> Result<ScriptHistoryPage, TxQueryError> {
        let required = self.script_page_requirements(cursor);
        let (view, snapshot) = self.capture_view(required)?;
        self.with_view(
            required,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, required)?;
                Self::require_cursor_tx_lookup_coverage_on_view(view, cursor)?;
                let prefix = Self::require_prefix(view, IndexCapability::ScriptHistory)?;
                Self::confirmed_history_page_for(
                    snapshot,
                    &prefix,
                    budget,
                    scripthash,
                    cursor,
                    view.generation_id,
                    limit,
                )
            },
        )
    }

    fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<ScriptIndexRecord>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::SCRIPT_LIVE)?;
        self.with_view(
            IndexCapabilities::SCRIPT_LIVE,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, IndexCapabilities::SCRIPT_LIVE)?;
                let prefix = Self::require_prefix(view, IndexCapability::ScriptLive)?;
                self.unspent_outputs_for(snapshot, &prefix, budget, scripthash)
            },
        )
    }

    fn spender(&self, outpoint: OutPoint) -> Result<Option<SpendingRecord>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::SCRIPT_HISTORY)?;
        self.with_view(
            IndexCapabilities::SCRIPT_HISTORY,
            &view,
            snapshot.as_ref(),
            |snapshot, view, budget| {
                Self::require_tip_coverage_on_view(view, IndexCapabilities::SCRIPT_HISTORY)?;
                let prefix = Self::require_tip_prefix(view, IndexCapability::ScriptHistory)?;
                let spent = self.spender_for(snapshot, &prefix, budget, &outpoint)?;
                self.scoped_or_outside(view, IndexCapability::ScriptHistory, spent)
            },
        )
    }
}

impl DerivedIndexQueryEngine {
    fn check_capability_failures(&self, required: IndexCapabilities) -> Result<(), TxQueryError> {
        if required.contains(IndexCapability::TxLookup)
            && let Some(reason) = self.runtime.tx_lookup_failure.read().clone()
        {
            return Err(TxQueryError::Unavailable(TxUnavailableCause::Other(reason)));
        }
        if required.contains(IndexCapability::CompactFilters)
            && let Some(reason) = self.runtime.compact_filter_failure.read().clone()
        {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::CompactFilterFailed(reason),
            ));
        }
        if required.contains(IndexCapability::ScriptLive)
            && let Some(outage) = self.runtime.script_live_failure.read().clone()
        {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::ScriptLiveUnavailable(outage.reason()),
            ));
        }
        if required.contains(IndexCapability::ScriptHistory)
            && let Some(reason) = self.runtime.script_history_failure.read().clone()
        {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::ScriptHistoryUnavailable(reason),
            ));
        }
        Ok(())
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
        budget.accept_live_scan(&ScriptLiveScan {
            rows: Vec::new(),
            coins: Vec::new(),
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
        let live = budget.accept_live_scan(&ScriptLiveScan {
            rows: Vec::new(),
            coins: Vec::new(),
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
        budget.accept_live_scan(&ScriptLiveScan {
            rows: Vec::new(),
            coins: Vec::new(),
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

    // IDX-03
    #[test]
    fn same_height_fork_watermark_fails_tip_coverage() {
        let tip_hash = Hash256::from_le_bytes(&[0xaa; 32]);
        let watermark_hash = Hash256::from_le_bytes(&[0xbb; 32]);
        let forked = ServingView {
            epoch: AppliedEpoch {
                hash: tip_hash,
                height: 9,
                commit_id: 1,
            },
            generation_id: 0,
            coverage: [
                Some(CapabilityCoverage {
                    floor: 0,
                    last_height: 9,
                    last_hash: watermark_hash,
                }),
                None,
                None,
                None,
            ],
            historical_verified: None,
            tip_id: NodeId::new(0),
            deadline: Instant::now() + VIEW_DEADLINE,
            expired_for_test: std::sync::atomic::AtomicBool::new(false),
            _view_charge: None,
        };
        let refused = DerivedIndexQueryEngine::require_tip_coverage_on_view(
            &forked,
            IndexCapabilities::TX_LOOKUP,
        );
        assert!(
            matches!(
                refused,
                Err(TxQueryError::Retry(RetryReason::TipMoved { .. }))
            ),
            "a watermark on another chain at the same height must refuse tip reads"
        );
        let aligned = ServingView {
            coverage: [
                Some(CapabilityCoverage {
                    floor: 0,
                    last_height: 9,
                    last_hash: tip_hash,
                }),
                None,
                None,
                None,
            ],
            ..forked
        };
        assert!(
            DerivedIndexQueryEngine::require_tip_coverage_on_view(
                &aligned,
                IndexCapabilities::TX_LOOKUP
            )
            .is_ok()
        );
    }
}
