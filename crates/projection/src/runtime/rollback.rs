use super::DerivedIndexWorkerError;
use super::UndoScripts;
use super::Worker;
use crate::ConsumerCursorUpdate;
use crate::IndexCapabilities;
use crate::IndexCapability;
use crate::IndexWatermark;
use crate::IndexWatermarks;
use crate::IndexWriteFence;
use crate::NoSpentScripts;
use crate::reconcile::ReconcileLeg;
use crate::snapshot_seed::ScriptLiveSeedPhase;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_execution::chain::TipSnapshot;
use bitcoin_rs_storage::pruning::HistoryLease;
use bitcoin_rs_storage::pruning::HistoryUnavailable;
use std::sync::Arc;

pub(super) fn index_ahead_capability_label(capabilities: IndexCapabilities) -> Option<String> {
    let names: Vec<&str> = capabilities.iter().map(IndexCapability::name).collect();
    (!names.is_empty()).then(|| names.join(","))
}

pub(super) enum SeedPass {
    Idle,
    Stall,
    Published,
    Discarded,
}

pub(super) enum SeedBatch {
    Rows(Vec<Vec<u8>>),
    Empty,
    Disconnected,
}

const SEED_DRAIN_BATCH_ROWS: usize = 4_096;

impl Worker {
    fn clear_interrupted_seed_for_replay(&self) -> Result<(), DerivedIndexWorkerError> {
        if !self.enabled.contains(IndexCapability::ScriptLive) {
            return Ok(());
        }
        let Some(_idle) = self.runtime.script_live_seed().lock_idle() else {
            return Ok(());
        };
        if self
            .writer
            .reset_interrupted_script_live_seed()
            .map_err(DerivedIndexWorkerError::Index)?
        {
            tracing::warn!("cleared ScriptLive rows left by an interrupted seed before replay");
        }
        Ok(())
    }

    pub(super) fn take_seed_lease(&self) -> Option<HistoryLease> {
        self.seed_history_lease.lock().take()
    }

    pub(super) fn park_seed_lease(&self, lease: Option<HistoryLease>) {
        let Some(lease) = lease else {
            return;
        };
        let mut guard = self.seed_history_lease.lock();
        if guard.is_none() {
            *guard = Some(lease);
        }
    }

    pub(super) fn release_seed_lease_if_superseded(&self, watermark: Option<IndexWatermark>) {
        let mut guard = self.seed_history_lease.lock();
        let release = self.runtime.should_stop()
            || guard.as_ref().is_none_or(|lease| {
                lease
                    .floor()
                    .is_none_or(|floor| watermark.is_some_and(|watermark| watermark.height > floor))
            });
        if release {
            guard.take();
        }
    }

    pub(super) fn dispatch_script_live_seed_pass(
        &self,
        fence: &mut IndexWriteFence,
        watermarks: &mut IndexWatermarks,
    ) -> Result<SeedPass, DerivedIndexWorkerError> {
        if !self.enabled.contains(IndexCapability::ScriptLive) {
            return Ok(SeedPass::Idle);
        }
        if self.runtime.script_live_failure.read().is_some()
            && self.runtime.undo_gap().is_none()
            && watermarks.script_live.is_some()
        {
            self.writer
                .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                .map_err(DerivedIndexWorkerError::Index)?;
            let (next_fence, next_watermarks) = self
                .writer
                .fenced_watermarks()
                .map_err(DerivedIndexWorkerError::Index)?;
            *fence = next_fence;
            *watermarks = next_watermarks;
        }
        let seed = self.runtime.script_live_seed();
        match seed.phase() {
            ScriptLiveSeedPhase::Seeding => self.seed_pass_stage_rows(),
            ScriptLiveSeedPhase::PublishPending { tip } => {
                self.seed_pass_publish(seed, tip, fence, watermarks)
            }
            ScriptLiveSeedPhase::AbortPending => self.seed_pass_discard(seed),
            ScriptLiveSeedPhase::Idle => {
                self.clear_interrupted_seed_for_replay()?;
                self.release_seed_lease_if_superseded(watermarks.script_live);
                Ok(SeedPass::Idle)
            }
        }
    }

    fn seed_pass_stage_rows(&self) -> Result<SeedPass, DerivedIndexWorkerError> {
        self.prepare_seed_rows()?;
        if self.published_live_seed()?.is_some() {
            return Ok(SeedPass::Stall);
        }
        loop {
            match self.collect_seed_batch()? {
                SeedBatch::Rows(rows) => self.stage_seed_rows(rows)?,
                SeedBatch::Empty => return Ok(SeedPass::Stall),
                SeedBatch::Disconnected => return Ok(SeedPass::Stall),
            }
        }
    }

    fn prepare_seed_rows(&self) -> Result<(), DerivedIndexWorkerError> {
        if !self.runtime.script_live_seed().claim_row_reset() {
            return Ok(());
        }
        self.clear_interrupted_seed_rows()
    }

    fn clear_interrupted_seed_rows(&self) -> Result<(), DerivedIndexWorkerError> {
        if !self.enabled.contains(IndexCapability::ScriptLive) {
            return Ok(());
        }
        if self
            .writer
            .reset_interrupted_script_live_seed()
            .map_err(DerivedIndexWorkerError::Index)?
        {
            tracing::warn!("cleared ScriptLive rows left by an interrupted seed before staging");
        }
        Ok(())
    }

    fn seed_pass_publish(
        &self,
        seed: &Arc<crate::snapshot_seed::ScriptLiveSeedState>,
        tip: IndexWatermark,
        fence: &mut IndexWriteFence,
        watermarks: &mut IndexWatermarks,
    ) -> Result<SeedPass, DerivedIndexWorkerError> {
        self.prepare_seed_rows()?;
        let published = self.published_live_seed()?;
        let covered = published.is_some_and(|watermark| tip.height <= watermark.height);
        if covered && !seed.is_closed() {
            return Ok(SeedPass::Stall);
        }
        if published.is_some() && !covered {
            self.writer
                .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                .map_err(DerivedIndexWorkerError::Index)?;
            tracing::warn!("replaced the published ScriptLive base for the snapshot seed");
        }
        if !covered {
            loop {
                match self.collect_seed_batch()? {
                    SeedBatch::Rows(rows) => self.stage_seed_rows(rows)?,
                    SeedBatch::Empty => return Ok(SeedPass::Stall),
                    SeedBatch::Disconnected => break,
                }
            }
            self.writer
                .publish_script_live_seed(tip)
                .map_err(DerivedIndexWorkerError::Index)?;
        }
        self.runtime.clear_script_live();
        seed.complete_publish();
        let (next_fence, next_watermarks) = self
            .writer
            .fenced_watermarks()
            .map_err(DerivedIndexWorkerError::Index)?;
        *fence = next_fence;
        *watermarks = next_watermarks;
        Ok(SeedPass::Published)
    }

    fn seed_pass_discard(
        &self,
        seed: &Arc<crate::snapshot_seed::ScriptLiveSeedState>,
    ) -> Result<SeedPass, DerivedIndexWorkerError> {
        loop {
            match self.collect_seed_batch()? {
                SeedBatch::Rows(_) => {}
                SeedBatch::Empty => return Ok(SeedPass::Stall),
                SeedBatch::Disconnected => break,
            }
        }
        if self
            .writer
            .reset_interrupted_script_live_seed()
            .map_err(DerivedIndexWorkerError::Index)?
        {
            tracing::warn!("cleared ScriptLive rows left by an aborted seed");
        }
        seed.complete_abort();
        Ok(SeedPass::Discarded)
    }

    fn stage_seed_rows(&self, rows: Vec<Vec<u8>>) -> Result<(), DerivedIndexWorkerError> {
        self.writer
            .stage_script_live_rows(&mut rows.into_iter())
            .map_err(DerivedIndexWorkerError::Index)?;
        Ok(())
    }

    /// SNP-07: a published ScriptLive watermark means the live base already
    /// covers committed history; a seed replaces it only at publish time,
    /// when the seed tip is known to be higher.
    fn published_live_seed(&self) -> Result<Option<IndexWatermark>, DerivedIndexWorkerError> {
        if !self.enabled.contains(IndexCapability::ScriptLive) {
            return Ok(None);
        }
        Ok(self
            .writer
            .fenced_watermarks()
            .map_err(DerivedIndexWorkerError::Index)?
            .1
            .script_live)
    }

    fn collect_seed_batch(&self) -> Result<SeedBatch, DerivedIndexWorkerError> {
        let seed = self.runtime.script_live_seed();
        let rows = seed
            .take_backlog(SEED_DRAIN_BATCH_ROWS)
            .map_err(DerivedIndexWorkerError::Index)?;
        if rows.is_empty() {
            return Ok(if seed.is_closed() {
                SeedBatch::Disconnected
            } else {
                SeedBatch::Empty
            });
        }
        Ok(SeedBatch::Rows(rows))
    }

    pub(super) fn reset_for_rebuild(
        &self,
        capabilities: IndexCapabilities,
    ) -> Result<(IndexWriteFence, IndexWatermarks), DerivedIndexWorkerError> {
        self.writer
            .reset_capabilities(capabilities)
            .map_err(DerivedIndexWorkerError::Index)?;
        self.runtime
            .publish_leg(capabilities, ReconcileLeg::Rebuilding);
        self.writer
            .fenced_watermarks()
            .map_err(DerivedIndexWorkerError::Index)
    }

    pub(super) fn report_index_ahead(
        &self,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
        target: &TipSnapshot,
    ) -> Result<(), DerivedIndexWorkerError> {
        let Some(capability) = index_ahead_capability_label(capabilities) else {
            return Ok(());
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.reporter
            .report_index_ahead(
                &capability,
                watermark.height,
                target.height,
                &target.hash.to_string_be(),
                &Hash256::from_le_bytes(&watermark.hash).to_string_be(),
                watermark.height.saturating_sub(target.height),
                now,
            )
            .map_err(DerivedIndexWorkerError::RollbackEvidence)
    }

    pub(super) fn rollback_one(
        &self,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        capabilities: IndexCapabilities,
        watermark: IndexWatermark,
    ) -> Result<Option<IndexWatermark>, DerivedIndexWorkerError> {
        let capabilities = crate::index::tail_rollback_group(watermarks, capabilities);
        let watermark_hash = Hash256::from_le_bytes(&watermark.hash);
        let lease = match self.history.request_history(watermark.height) {
            Ok(lease) => lease,
            Err(error @ HistoryUnavailable::Pruned { .. }) => {
                if capabilities.contains(IndexCapability::CompactFilters) {
                    return Err(DerivedIndexWorkerError::HistoryUnavailable(error));
                }
                return Err(DerivedIndexWorkerError::MissingBody {
                    height: watermark.height,
                    hash: watermark_hash,
                });
            }
            Err(error) => return Err(DerivedIndexWorkerError::HistoryUnavailable(error)),
        };
        let body = self.load_body(watermark.height, watermark_hash, &lease)?;
        let anchor = capabilities
            .contains(IndexCapability::ScriptLive)
            .then(|| self.live_anchor(watermark.height, watermark.hash))
            .transpose()?;
        lease.release();

        let spent: &dyn crate::SpentCoins =
            anchor.as_ref().map_or(&NoSpentScripts, |anchor| anchor);

        let prev = if watermark.height == 0 {
            None
        } else {
            let prepared = self
                .writer
                .prepare_block_with_spent_scripts(
                    crate::index::rollback_prepare_capabilities(capabilities),
                    watermark.height,
                    watermark.hash,
                    &body,
                    spent,
                )
                .map_err(DerivedIndexWorkerError::Index)?;
            Some(IndexWatermark {
                height: watermark.height.saturating_sub(1),
                hash: prepared.parent_hash,
            })
        };

        if self.runtime.should_stop() {
            return Err(DerivedIndexWorkerError::Stopped);
        }
        let cursor = self.cursor_for_result(capabilities, prev, watermarks);
        let cursor = cursor
            .as_ref()
            .map_or(ConsumerCursorUpdate::Clear, |bytes| {
                ConsumerCursorUpdate::Set(bytes.as_slice())
            });
        self.writer
            .commit_rollback_one_for_with_cursor_with_spent_scripts(
                fence,
                capabilities,
                prev,
                &body,
                cursor,
                spent,
            )
            .map_err(DerivedIndexWorkerError::Index)?;
        Ok(prev)
    }

    pub(super) fn load_body(
        &self,
        height: u32,
        hash: Hash256,
        lease: &HistoryLease,
    ) -> Result<Vec<u8>, DerivedIndexWorkerError> {
        let _ = lease;
        let Some(store) = self.body_store.as_ref() else {
            return Err(DerivedIndexWorkerError::NoBodyStore);
        };
        let body = store.load_block_body(height, hash)?;
        body.ok_or(DerivedIndexWorkerError::HistoryUnavailable(
            HistoryUnavailable::Missing,
        ))
    }

    pub(super) fn live_anchor(
        &self,
        height: u32,
        hash_bytes: [u8; 32],
    ) -> Result<UndoScripts, DerivedIndexWorkerError> {
        if height == 0 {
            return Ok(UndoScripts {
                coins: hashbrown::HashMap::new(),
            });
        }
        let hash = Hash256::from_le_bytes(&hash_bytes);
        let Some(store) = self.body_store.as_ref() else {
            return Err(DerivedIndexWorkerError::NoBodyStore);
        };
        let bytes = store
            .undo_record(height, hash)
            .map_err(DerivedIndexWorkerError::Storage)?
            .ok_or(DerivedIndexWorkerError::UndoUnavailable { height, hash })?;
        UndoScripts::from_undo_bytes(&bytes, hash)
            .map_err(|_| DerivedIndexWorkerError::UndoUnavailable { height, hash })
    }
}
