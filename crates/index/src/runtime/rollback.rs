//! Capability rollback, selective rebuilding, live seeding, and recovery evidence.

use super::DerivedIndexWorkerError;
use super::PendingForward;
use super::ReconcileAction;
use super::SeedBundle;
use super::UndoScripts;
use super::Worker;
use crate::ConsumerCursorUpdate;
use crate::IndexCapabilities;
use crate::IndexCapability;
use crate::IndexError;
use crate::IndexWatermark;
use crate::IndexWatermarks;
use crate::IndexWriteFence;
use crate::NoSpentScripts;
use crate::ScriptHash;
use crate::reconcile::ReconcileLeg;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::pruning::{HistoryLease, HistoryUnavailable};
use bitcoin_rs_utxo::snapshot::RawSeedError;
use std::cell::Cell;

pub(super) fn index_ahead_capability_label(capabilities: IndexCapabilities) -> Option<String> {
    let names: Vec<&str> = capabilities.iter().map(IndexCapability::name).collect();
    (!names.is_empty()).then(|| names.join(","))
}

pub(super) enum SeedFlow {
    Return(ReconcileAction),
    Seeded,
    FallThrough { want_on_stall: bool },
}

impl Worker {
    fn clear_interrupted_seed_for_replay(&self) -> Result<(), DerivedIndexWorkerError> {
        if !self.enabled.contains(IndexCapability::ScriptLive) {
            return Ok(());
        }
        if self
            .writer
            .reset_interrupted_script_live_seed()
            .map_err(DerivedIndexWorkerError::Index)?
        {
            tracing::warn!("cleared ScriptLive rows left by an interrupted seed before replay");
        }
        Ok(())
    }

    pub(super) fn seed_dispatch(
        &self,
        pending: Option<&PendingForward>,
    ) -> Result<SeedFlow, DerivedIndexWorkerError> {
        let has_artifact = self
            .seed_bundle
            .lock()
            .as_ref()
            .is_some_and(|bundle| bundle.artifact.is_some());
        if has_artifact {
            return self.seed_from_bundle();
        }
        let has_bundle = self.seed_bundle.lock().is_some();
        if has_bundle {
            let Some(slot) = self.seed_slot.as_ref() else {
                return Ok(SeedFlow::FallThrough {
                    want_on_stall: false,
                });
            };
            let Some(artifact) = slot.take() else {
                return Ok(SeedFlow::FallThrough {
                    want_on_stall: false,
                });
            };
            self.runtime.clear_script_live();
            let mut bundle = self.seed_bundle.lock().take().unwrap_or(SeedBundle {
                artifact: None,
                lease: None,
            });
            bundle.artifact = Some(artifact);
            *self.seed_bundle.lock() = Some(bundle);
            return self.seed_from_bundle();
        }
        if pending.is_some_and(|state| state.capabilities.contains(IndexCapability::ScriptLive)) {
            return Ok(SeedFlow::FallThrough {
                want_on_stall: false,
            });
        }
        let Some(slot) = self.seed_slot.as_ref() else {
            self.clear_interrupted_seed_for_replay()?;
            return Ok(SeedFlow::FallThrough {
                want_on_stall: false,
            });
        };
        if let Some(artifact) = slot.take() {
            self.runtime.clear_script_live();
            *self.seed_bundle.lock() = Some(SeedBundle {
                artifact: Some(artifact),
                lease: None,
            });
            self.seed_from_bundle()
        } else {
            self.clear_interrupted_seed_for_replay()?;
            Ok(SeedFlow::FallThrough {
                want_on_stall: true,
            })
        }
    }

    #[expect(clippy::too_many_lines, reason = "Seed outcomes share one owner")]
    fn seed_from_bundle(&self) -> Result<SeedFlow, DerivedIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(SeedFlow::Return(ReconcileAction::Stalled));
        }
        let mut bundle = self.seed_bundle.lock().take().unwrap_or(SeedBundle {
            artifact: None,
            lease: None,
        });
        let Some(mut artifact) = bundle.artifact.take() else {
            return Ok(SeedFlow::FallThrough {
                want_on_stall: false,
            });
        };
        let (height, tip_hash) = artifact.tip();
        let lease_covers = bundle
            .lease
            .as_ref()
            .is_some_and(|lease| lease.floor().is_some_and(|floor| floor <= height));
        if !lease_covers {
            bundle.lease = None;
            match self.history.request_history(height) {
                Ok(lease) => bundle.lease = Some(lease),
                Err(HistoryUnavailable::Pruned { .. }) => {
                    drop(artifact);
                    return Ok(SeedFlow::FallThrough {
                        want_on_stall: true,
                    });
                }
                Err(_) => {
                    *self.seed_bundle.lock() = Some(SeedBundle {
                        artifact: Some(artifact),
                        lease: None,
                    });
                    return Ok(SeedFlow::Return(ReconcileAction::Stalled));
                }
            }
        }
        let tip = IndexWatermark {
            height,
            hash: tip_hash.to_le_bytes(),
        };
        let poisoned: Cell<bool> = Cell::new(false);
        let cancelled = || self.runtime.should_stop();
        let result = self.writer.seed_script_live_stream(
            &mut |emit| match artifact.for_each_coin_raw::<IndexError, _>(
                &mut |outpoint, script| emit(*outpoint, ScriptHash::from_script_bytes(script)),
                &cancelled,
            ) {
                Ok(()) => Ok(()),
                Err(RawSeedError::Integrity) => {
                    poisoned.set(true);
                    Err(IndexError::InvalidWatermark)
                }
                Err(RawSeedError::Io(error)) => Err(IndexError::Storage(StorageError::Io(error))),
                Err(RawSeedError::Emit(error)) => Err(error),
                Err(RawSeedError::Cancelled) => Err(IndexError::Cancelled),
            },
            tip,
            &cancelled,
        );
        match result {
            Ok(written) => {
                drop(artifact);
                self.runtime.clear_script_live();
                tracing::info!(
                    height,
                    rows = written,
                    "seeded ScriptLive from snapshot artifact"
                );
                *self.seed_bundle.lock() = Some(SeedBundle {
                    artifact: None,
                    lease: bundle.lease,
                });
                Ok(SeedFlow::Seeded)
            }
            Err(IndexError::Cancelled) => {
                *self.seed_bundle.lock() = Some(SeedBundle {
                    artifact: Some(artifact),
                    lease: bundle.lease,
                });
                Ok(SeedFlow::Return(ReconcileAction::Stalled))
            }
            Err(_) if poisoned.take() => {
                drop(artifact);
                drop(bundle.lease);
                if let Err(error) = self
                    .writer
                    .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                {
                    tracing::debug!(%error, "seed poison cleanup reset deferred");
                    return Ok(SeedFlow::Return(ReconcileAction::Stalled));
                }
                Ok(SeedFlow::Seeded)
            }
            Err(IndexError::LiveAlreadySeeded) => {
                drop(artifact);
                *self.seed_bundle.lock() = Some(SeedBundle {
                    artifact: None,
                    lease: bundle.lease,
                });
                Ok(SeedFlow::Seeded)
            }
            Err(
                IndexError::StaleIndexState | IndexError::ResetInProgress | IndexError::Storage(_),
            ) => {
                *self.seed_bundle.lock() = Some(SeedBundle {
                    artifact: Some(artifact),
                    lease: bundle.lease,
                });
                Ok(SeedFlow::Return(ReconcileAction::Stalled))
            }
            Err(error) => {
                drop(artifact);
                drop(bundle.lease);
                Err(DerivedIndexWorkerError::Index(error))
            }
        }
    }

    pub(super) fn rest_seed_cell(&self) {
        if let Some(slot) = self.seed_slot.as_ref() {
            slot.rest();
        }
    }

    pub(super) fn release_seed_lease_if_superseded(&self, watermark: Option<IndexWatermark>) {
        let mut guard = self.seed_bundle.lock();
        let Some(bundle) = guard.as_mut() else {
            return;
        };
        if watermark.is_some() {
            bundle.artifact = None;
        }
        let release = self.runtime.should_stop()
            || bundle.lease.as_ref().is_none_or(|lease| {
                lease
                    .floor()
                    .is_none_or(|floor| watermark.is_some_and(|watermark| watermark.height > floor))
            });
        if release {
            bundle.lease = None;
        }
        if bundle.artifact.is_none() && bundle.lease.is_none() {
            guard.take();
        }
    }

    pub(super) fn take_seed_lease(&self) -> Option<HistoryLease> {
        let mut guard = self.seed_bundle.lock();
        let lease = if guard
            .as_ref()
            .is_some_and(|bundle| bundle.artifact.is_none())
        {
            guard.as_mut().and_then(|bundle| bundle.lease.take())
        } else {
            None
        };
        if guard
            .as_ref()
            .is_some_and(|bundle| bundle.artifact.is_none() && bundle.lease.is_none())
        {
            guard.take();
        }
        lease
    }

    pub(super) fn park_seed_lease(&self, lease: Option<HistoryLease>) {
        let Some(lease) = lease else {
            return;
        };
        let mut guard = self.seed_bundle.lock();
        match guard.as_mut() {
            Some(bundle) if bundle.lease.is_none() => bundle.lease = Some(lease),
            Some(_) => {}
            None => {
                *guard = Some(SeedBundle {
                    artifact: None,
                    lease: Some(lease),
                });
            }
        }
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

    /// Publishes the index-ahead rollback evidence for a watermark above the
    /// applied tip. The marker is part of the rollback transition: a data dir
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
        let anchor = (capabilities.contains(IndexCapability::ScriptLive)
            || capabilities.contains(IndexCapability::CompactFilters))
        .then(|| self.live_anchor(watermark.height, watermark.hash))
        .transpose()?;
        lease.release();

        let spent: &dyn crate::SpentCoinScripts =
            anchor.as_ref().map_or(&NoSpentScripts, |anchor| anchor);

        let prev = if watermark.height == 0 {
            None
        } else {
            let prepared = self
                .writer
                .prepare_block_with_spent_scripts(
                    capabilities,
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

    /// INVARIANT: permanence comes from the grant. The worker never compares a
    /// height against a copied prune frontier to decide it.
    pub(super) fn load_body(
        &self,
        height: u32,
        hash: Hash256,
        lease: &bitcoin_rs_storage::pruning::HistoryLease,
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
                scripts: hashbrown::HashMap::new(),
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
