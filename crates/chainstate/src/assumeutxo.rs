use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::{AssumeUtxoData, Block, BlockPayload, Hash256, Network};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::core_snapshot::{StateVerifyError, VerifiedSnapshotState};
use parking_lot::{Mutex, MutexGuard, RwLock};

use crate::error::{ApplyError, DisconnectError};
use crate::{Chainstate, ConnectOutcome};

mod serde_hash256 {
    use bitcoin_rs_primitives::Hash256;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S>(hash: &Hash256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hash.to_string())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Hash256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<Hash256>().map_err(serde::de::Error::custom)
    }
}

mod serde_opt_hash256 {
    use bitcoin_rs_primitives::Hash256;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[expect(clippy::ref_option)]
    pub(super) fn serialize<S>(hash: &Option<Hash256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hash.as_ref().map(ToString::to_string).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Hash256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|s| s.parse::<Hash256>())
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChainstateRole {
    Ordinary,
    /// Serves normal node consumers, but rejects reorgs at or below `base_height`.
    AssumedActive {
        base_height: u32,
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
    },
    Historical {
        base_height: u32,
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
    },
}

impl ChainstateRole {
    #[must_use]
    pub const fn is_assumed_active(&self) -> bool {
        matches!(self, Self::AssumedActive { .. })
    }

    #[must_use]
    pub const fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary)
    }

    #[must_use]
    pub const fn base_height(&self) -> Option<u32> {
        match self {
            Self::AssumedActive { base_height, .. } | Self::Historical { base_height, .. } => {
                Some(*base_height)
            }
            Self::Ordinary => None,
        }
    }
}

pub use bitcoin_rs_storage::assumeutxo::{AssumeUtxoDiskStatus, HistoricalCheckpointRef};

const DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL: u32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalAdvance {
    Complete,
    ReplayPending,
    MissingBody { height: u32, hash: Hash256 },
}

#[derive(Debug, thiserror::Error)]
pub enum AssumeUtxoError {
    /// The snapshot base must have strictly more accumulated work than the applied tip.
    #[error("snapshot base does not have more accumulated work than the applied tip")]
    ActivationBehindTip,
    #[error(
        "snapshot activation requires matching tip (hash, height, transaction count; transaction count 0 means unknown): durable {}, applied {}",
        durable_tip.map_or_else(|| "<none>".to_owned(), |(hash, height, count)| format!("({hash}, {height}, {count})")),
        applied_tip.map_or_else(|| "<none>".to_owned(), |(hash, height, count)| format!("({hash}, {height}, {count})"))
    )]
    SnapshotTipNotSettled {
        durable_tip: Option<(Hash256, u32, u64)>,
        applied_tip: Option<(Hash256, u32, u64)>,
    },
    #[error("missing durable snapshot anchor")]
    MissingDurableAnchor,
    #[error("historical validation produced no undo record")]
    MissingHistoricalUndo,
    #[error("snapshot storage: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error("snapshot archive: {0}")]
    Archive(#[from] anyhow::Error),
    #[error("snapshot base header {0} is not present")]
    SnapshotHeaderMissing(Hash256),
    #[error("snapshot base header height {found} does not match pinned height {expected}")]
    SnapshotHeaderHeightMismatch { expected: u32, found: u32 },
    #[error(
        "snapshot base {base_hash} at height {base_height} is not on the best-work header chain ending at {best_header:?}"
    )]
    SnapshotBaseNotOnBestHeaderChain {
        base_hash: Hash256,
        base_height: u32,
        best_header: Option<Hash256>,
    },
    #[error("historical transaction count {found} does not match pinned count {expected}")]
    HistoricalTransactionCountMismatch { expected: u64, found: u64 },
    #[error("snapshot height {0} is not pinned in AssumeUtxoData for this network")]
    UntrustedSnapshotHeight(u32),
    #[error("snapshot block hash {found} does not match pinned hash {expected}")]
    SnapshotBlockHashMismatch { expected: Hash256, found: Hash256 },
    #[error("snapshot commitment {found} does not match pinned hash {expected}")]
    SnapshotCommitmentMismatch { expected: Hash256, found: Hash256 },
    #[error(
        "node previously failed assumeutxo validation at base height {base_height}: expected {expected_hash_serialized}, found {actual_hash_serialized}; failing closed"
    )]
    PreviouslyFailed {
        base_height: u32,
        expected_hash_serialized: Hash256,
        actual_hash_serialized: Hash256,
    },
    #[error("cannot activate assumeutxo snapshot: assumeutxo validation is already in progress")]
    AlreadyActive,
    #[error("snapshot activation requires completion of full revalidation")]
    FullRevalidationRequired,
    #[error(
        "assumeutxo commitment mismatch at base height {base_height}: expected {expected}, actual {actual}"
    )]
    CommitmentMismatch {
        base_height: u32,
        expected: Hash256,
        actual: Hash256,
    },
    #[error("no historical chainstate present")]
    NoHistoricalChainstate,
    #[error(
        "historical validation reached unexpected block hash {found} at target height {base_height}, expected {expected}"
    )]
    HistoricalTargetHashMismatch {
        base_height: u32,
        expected: Hash256,
        found: Hash256,
    },
    #[error("apply error: {0}")]
    Apply(#[from] ApplyError),
    #[error("disconnect error: {0}")]
    Disconnect(#[from] DisconnectError),
    #[error("utxo error: {0}")]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
}

impl From<StateVerifyError> for AssumeUtxoError {
    fn from(error: StateVerifyError) -> Self {
        match error {
            StateVerifyError::Utxo(error) => Self::Utxo(error),
            StateVerifyError::CommitmentMismatch { expected, actual } => {
                Self::SnapshotCommitmentMismatch {
                    expected,
                    found: actual,
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainstatesSummary {
    pub active_chainstate: ActiveChainstateSummary,
    pub historical_chainstate: Option<HistoricalChainstateSummary>,
    pub status: AssumeUtxoDiskStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainstatesReport {
    pub lifecycle: ChainstatesSummary,
    pub headers: u32,
    pub active_verification_progress: Option<f64>,
    pub historical_verification_progress: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveChainstateSummary {
    pub role: ChainstateRole,
    pub height: Option<u32>,
    #[serde(with = "serde_opt_hash256")]
    pub hash: Option<Hash256>,
    pub validated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalChainstateSummary {
    pub base_height: u32,
    #[serde(with = "serde_hash256")]
    pub base_hash: Hash256,
    pub current_height: u32,
    #[serde(with = "serde_hash256")]
    pub current_hash: Hash256,
    #[serde(with = "serde_hash256")]
    pub expected_hash_serialized: Hash256,
    pub validated_utxo_count: u64,
}

pub struct AssumeUtxoManager {
    lifecycle: Mutex<()>,
    network: Network,
    active_chainstate: Arc<Chainstate>,
    historical_chainstate: RwLock<Option<Arc<Chainstate>>>,
    historical_undo: Arc<bitcoin_rs_storage::InMemoryUndoStore>,
    data_dir: PathBuf,
    historical_checkpoint_interval: u32,
    pending_activation_mint: Mutex<Option<bitcoin_rs_utxo::V4Witness>>,
}

impl std::fmt::Debug for AssumeUtxoManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssumeUtxoManager")
            .field("network", &self.network)
            .field("status", &self.status())
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

impl AssumeUtxoManager {
    pub fn open(
        network: Network,
        active_chainstate: Arc<Chainstate>,
        data_dir: PathBuf,
    ) -> Result<Self, AssumeUtxoError> {
        Self::open_with_historical_checkpoint_interval(
            network,
            active_chainstate,
            data_dir,
            DEFAULT_HISTORICAL_CHECKPOINT_INTERVAL,
        )
    }

    fn open_with_historical_checkpoint_interval(
        network: Network,
        active_chainstate: Arc<Chainstate>,
        data_dir: PathBuf,
        historical_checkpoint_interval: u32,
    ) -> Result<Self, AssumeUtxoError> {
        let loaded_status = active_chainstate
            .durable_head
            .load()?
            .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo);

        let mut historical = None;
        let historical_undo = Arc::new(bitcoin_rs_storage::InMemoryUndoStore::default());
        match loaded_status {
            AssumeUtxoDiskStatus::Failed {
                base_height,
                expected_hash_serialized,
                actual_hash_serialized,
                ..
            } => {
                active_chainstate.fail_closed_for_recovery();
                return Err(AssumeUtxoError::PreviouslyFailed {
                    base_height,
                    expected_hash_serialized,
                    actual_hash_serialized,
                });
            }
            AssumeUtxoDiskStatus::Validating {
                base_height,
                base_hash,
                historical_height,
                historical_hash,
                checkpoint,
                ..
            } => {
                active_chainstate.set_role(ChainstateRole::AssumedActive {
                    base_height,
                    base_hash,
                });
                historical = Some(Self::open_historical_chainstate(
                    &active_chainstate,
                    network,
                    &data_dir,
                    base_height,
                    base_hash,
                    historical_height,
                    historical_hash,
                    checkpoint,
                    Arc::clone(&historical_undo),
                )?);
            }
            AssumeUtxoDiskStatus::Finalized { .. } | AssumeUtxoDiskStatus::Uninitialized => {
                active_chainstate.set_role(ChainstateRole::Ordinary);
            }
        }

        let manager = Self {
            lifecycle: Mutex::new(()),
            network,
            active_chainstate,
            historical_chainstate: RwLock::new(historical),
            historical_undo,
            data_dir,
            historical_checkpoint_interval: historical_checkpoint_interval.max(1),
            pending_activation_mint: Mutex::new(None),
        };
        manager.recover_pending().inspect_err(|_| {
            manager.active_chainstate.fail_closed_for_recovery();
        })?;
        if let Err(error) =
            crate::assumeutxo_snapshot::cleanup_reservations(&manager.data_dir, network)
        {
            tracing::warn!(%error, "snapshot reservation cleanup deferred");
        }
        match manager.status()? {
            AssumeUtxoDiskStatus::Validating {
                checkpoint: Some(checkpoint),
                ..
            } => manager.cleanup_historical_checkpoints(Some(checkpoint.checkpoint)),
            AssumeUtxoDiskStatus::Finalized { .. } => manager.cleanup_historical_checkpoints(None),
            _ => {}
        }
        Ok(manager)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the durable historical recovery inputs together"
    )]
    fn open_historical_chainstate(
        active: &Arc<Chainstate>,
        network: Network,
        data_dir: &Path,
        base_height: u32,
        base_hash: Hash256,
        historical_height: u32,
        historical_hash: Hash256,
        checkpoint: Option<HistoricalCheckpointRef>,
        undo: Arc<bitcoin_rs_storage::InMemoryUndoStore>,
    ) -> Result<Arc<Chainstate>, AssumeUtxoError> {
        let Some(checkpoint) = checkpoint else {
            return active.create_historical_counterpart(base_height, base_hash, undo, None);
        };
        if checkpoint.height > historical_height || checkpoint.height > base_height {
            return Err(anyhow::anyhow!(
                "historical checkpoint is ahead of certified validation progress"
            )
            .into());
        }
        let data =
            bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir).map_err(|error| {
                anyhow::anyhow!("open historical checkpoint data directory: {error}")
            })?;
        let config = crate::checkpoint::headers::HeaderCheckpointConfig {
            network,
            genesis: network.genesis_block_hash(),
        };
        let loaded = crate::checkpoint::load_checkpoint_generation_from_dir(
            &data,
            config,
            bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
            checkpoint.checkpoint,
        )
        .map_err(|error| anyhow::anyhow!("historical checkpoint load failed: {error}"))?;
        let crate::checkpoint::CheckpointLoad::Complete(restored) = loaded else {
            return Err(anyhow::anyhow!(
                "durable head names a historical checkpoint that is not published"
            )
            .into());
        };
        if restored.generation != checkpoint.checkpoint.generation
            || restored.applied_tip.height != checkpoint.height
            || restored.applied_tip.hash != checkpoint.hash
        {
            return Err(anyhow::anyhow!(
                "historical checkpoint does not match its durable-head reference"
            )
            .into());
        }
        if restored.applied_tip.chain_tx_count.get().is_none() {
            return Err(anyhow::anyhow!(
                "historical checkpoint has no certified transaction count"
            )
            .into());
        }

        let mut tree = active.block_tree.write();
        let base_id = tree
            .lookup(base_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(base_hash))?;
        let checkpoint_id = tree
            .node_at_height_from(base_id, checkpoint.height)
            .ok_or_else(|| {
                anyhow::anyhow!("historical checkpoint is not on the pinned ancestry")
            })?;
        let checkpoint_node = tree.node(checkpoint_id).map_err(ApplyError::from)?;
        if checkpoint_node.hash != checkpoint.hash || checkpoint_node.height != checkpoint.height {
            return Err(anyhow::anyhow!(
                "historical checkpoint hash is not on the pinned ancestry"
            )
            .into());
        }
        let checkpoint_height = checkpoint_node.height;
        let checkpoint_hash = checkpoint_node.hash;
        let checkpoint_chainwork = checkpoint_node.chainwork;
        let progress_id = tree
            .node_at_height_from(base_id, historical_height)
            .ok_or_else(|| {
                anyhow::anyhow!("certified historical progress is not on the pinned ancestry")
            })?;
        let progress_node = tree.node(progress_id).map_err(ApplyError::from)?;
        if progress_node.hash != historical_hash {
            return Err(anyhow::anyhow!(
                "durable historical progress is not on the pinned ancestry"
            )
            .into());
        }
        tree.restore_chain_tx_count(checkpoint_id, restored.applied_tip.chain_tx_count)
            .map_err(ApplyError::from)?;
        let applied_tip = TipSnapshot {
            tip_id: checkpoint_id,
            height: checkpoint_height,
            chainwork: checkpoint_chainwork,
            hash: checkpoint_hash,
            chain_tx_count: restored.applied_tip.chain_tx_count,
        };
        drop(tree);
        active.create_historical_counterpart(
            base_height,
            base_hash,
            undo,
            Some((restored.utxo, restored.coin_stats, applied_tip)),
        )
    }

    pub fn activate_snapshot_state(
        &self,
        set: UtxoSet,
        base_hash: Hash256,
        height: u32,
    ) -> Result<(), AssumeUtxoError> {
        let pinned = self
            .network
            .assume_utxo_for_height(height)
            .ok_or(AssumeUtxoError::UntrustedSnapshotHeight(height))?;

        self.activate_pinned_snapshot(set, base_hash, pinned)
    }

    pub fn activate_verified_snapshot(
        &self,
        state: VerifiedSnapshotState,
    ) -> Result<(), AssumeUtxoError> {
        let _lifecycle = self.lifecycle.lock();
        let pinned = self
            .network
            .assume_utxo_for_height(state.height())
            .ok_or(AssumeUtxoError::UntrustedSnapshotHeight(state.height()))?;
        self.require_unactivated()?;
        self.install_verified(state, pinned)
    }

    fn require_unactivated(&self) -> Result<(), AssumeUtxoError> {
        if !matches!(self.status()?, AssumeUtxoDiskStatus::Uninitialized) {
            return Err(AssumeUtxoError::AlreadyActive);
        }
        if crate::recovery::requires_full_revalidation(&self.data_dir) {
            return Err(AssumeUtxoError::FullRevalidationRequired);
        }
        Ok(())
    }

    fn activate_pinned_snapshot(
        &self,
        set: UtxoSet,
        base_hash: Hash256,
        pinned: &AssumeUtxoData,
    ) -> Result<(), AssumeUtxoError> {
        let _lifecycle = self.lifecycle.lock();
        self.require_unactivated()?;
        if pinned.block_hash != base_hash {
            return Err(AssumeUtxoError::SnapshotBlockHashMismatch {
                expected: pinned.block_hash,
                found: base_hash,
            });
        }
        let state = VerifiedSnapshotState::verify(set, pinned)?;
        self.install_verified(state, pinned)
    }

    fn install_verified(
        &self,
        state: VerifiedSnapshotState,
        pinned: &AssumeUtxoData,
    ) -> Result<(), AssumeUtxoError> {
        if state.height() != pinned.height {
            return Err(AssumeUtxoError::UntrustedSnapshotHeight(state.height()));
        }
        if state.base_hash() != pinned.block_hash {
            return Err(AssumeUtxoError::SnapshotBlockHashMismatch {
                expected: pinned.block_hash,
                found: state.base_hash(),
            });
        }
        if state.hash_serialized() != pinned.hash_serialized {
            return Err(AssumeUtxoError::SnapshotCommitmentMismatch {
                expected: pinned.hash_serialized,
                found: state.hash_serialized(),
            });
        }
        let genesis_hash = self.network.genesis_block_hash();
        let new_status = AssumeUtxoDiskStatus::Validating {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
            expected_hash_serialized: pinned.hash_serialized,
            chain_tx_count: pinned.chain_tx_count,
            historical_height: 0,
            historical_hash: genesis_hash,
            pending: None,
            checkpoint: None,
        };

        let (set, stats, staging_witness) =
            crate::assumeutxo_snapshot::write_coins_sealed(&self.data_dir, state, pinned)?;
        self.active_chainstate
            .install_snapshot(set, stats, pinned, |tree, tip, prior| {
                if crate::recovery::requires_full_revalidation(&self.data_dir) {
                    return Err(AssumeUtxoError::FullRevalidationRequired);
                }
                crate::assumeutxo_snapshot::write_headers(&self.data_dir, tree, tip)?;
                let next = bitcoin_rs_storage::DurableHead {
                    assumeutxo: new_status,
                    commit_id: prior.map_or(1, |head| head.commit_id + 1),
                    height: pinned.height,
                    tip: pinned.block_hash,
                    chain_tx_count: pinned.chain_tx_count,
                    body_extent: prior.and_then(|head| head.body_extent),
                    undo_extent: prior.and_then(|head| head.undo_extent),
                };
                self.active_chainstate.durable_head.commit(
                    prior,
                    &next,
                    &bitcoin_rs_storage::CommitRecords::default(),
                )?;
                Ok(())
            })?;
        *self.pending_activation_mint.lock() = staging_witness;

        let historical = self.active_chainstate.create_historical_counterpart(
            pinned.height,
            pinned.block_hash,
            Arc::clone(&self.historical_undo),
            None,
        )?;

        *self.historical_chainstate.write() = Some(historical);

        Ok(())
    }

    /// - On mismatch: fails closed immediately, sets both chainstates to closed,
    ///   persists [`AssumeUtxoDiskStatus::Failed`], and returns an error.
    pub fn take_pending_activation_witness(&self) -> Option<bitcoin_rs_utxo::V4Witness> {
        self.pending_activation_mint.lock().take()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep the serialized lifecycle transition and its failure ordering together"
    )]
    pub fn step_historical(
        &self,
        payload: &BlockPayload,
    ) -> Result<ConnectOutcome, AssumeUtxoError> {
        let _lifecycle = self.lifecycle.lock();
        let historical = self
            .historical_chainstate
            .read()
            .clone()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;

        let expected_prev = historical
            .applied_tip_snapshot()
            .map_or_else(Hash256::default, |tip| tip.hash);
        if payload.block().header.prev_blockhash.0 != expected_prev {
            return Err(ApplyError::PrevHashMismatch {
                tip: expected_prev,
                prev: payload.block().header.prev_blockhash.0,
            }
            .into());
        }
        let archived = self
            .begin_historical(payload.block(), &historical)
            .inspect_err(|_| {
                self.active_chainstate.fail_closed_for_recovery();
                historical.fail_closed_for_recovery();
            })?;

        let result = {
            let transition = historical.lock_transition()?.into_transition();
            transition.connect(payload)
        };
        let outcome = match result {
            Err(ApplyError::HistoricalTargetHashMismatch {
                base_height,
                expected,
                found,
            }) => {
                self.fail_historical(&historical)?;
                return Err(AssumeUtxoError::HistoricalTargetHashMismatch {
                    base_height,
                    expected,
                    found,
                });
            }
            Err(error) => {
                if matches!(
                    crate::classify_apply_error(&error),
                    crate::WindowApplyDisposition::Permanent | crate::WindowApplyDisposition::Fatal
                ) {
                    self.fail_historical(&historical)?;
                }
                return Err(error.into());
            }
            Ok(outcome) => outcome,
        };

        if archived {
            self.historical_undo
                .remove_archived(outcome.height, outcome.hash);
            return Ok(outcome);
        }

        let current_status = self.status().inspect_err(|_| {
            self.active_chainstate.fail_closed_for_recovery();
            historical.fail_closed_for_recovery();
        })?;
        if let AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            chain_tx_count,
            checkpoint,
            ..
        } = current_status
        {
            if outcome.height < base_height {
                let updated = AssumeUtxoDiskStatus::Validating {
                    base_height,
                    base_hash,
                    expected_hash_serialized,
                    chain_tx_count,
                    historical_height: outcome.height,
                    historical_hash: outcome.hash,
                    pending: None,
                    checkpoint,
                };
                self.persist_status(updated, Some((payload, &historical)))
                    .inspect_err(|_| {
                        self.active_chainstate.fail_closed_for_recovery();
                        historical.fail_closed_for_recovery();
                    })?;
            } else if outcome.height == base_height {
                if outcome.hash != base_hash {
                    self.fail_historical(&historical)?;
                    return Err(AssumeUtxoError::HistoricalTargetHashMismatch {
                        base_height,
                        expected: base_hash,
                        found: outcome.hash,
                    });
                }

                let actual_hash_serialized = historical
                    .utxo
                    .lock_stable_view()
                    .hash_serialized_3()
                    .inspect_err(|_| {
                        self.active_chainstate.fail_closed_for_recovery();
                        historical.fail_closed_for_recovery();
                    })?;
                let actual_count = historical
                    .applied_tip_snapshot()
                    .map_or(0, |tip| tip.chain_tx_count.to_wire());
                if actual_count != chain_tx_count {
                    self.fail_historical(&historical)?;
                    return Err(AssumeUtxoError::HistoricalTransactionCountMismatch {
                        expected: chain_tx_count,
                        found: actual_count,
                    });
                }
                if actual_hash_serialized == expected_hash_serialized {
                    let finalized = AssumeUtxoDiskStatus::Finalized {
                        base_height,
                        base_hash,
                        validated_hash_serialized: actual_hash_serialized,
                    };
                    self.persist_status(finalized, Some((payload, &historical)))
                        .inspect_err(|_| {
                            self.active_chainstate.fail_closed_for_recovery();
                            historical.fail_closed_for_recovery();
                        })?;
                    self.active_chainstate.set_role(ChainstateRole::Ordinary);
                    *self.historical_chainstate.write() = None;
                } else {
                    self.fail_historical(&historical)?;
                    return Err(AssumeUtxoError::CommitmentMismatch {
                        base_height,
                        expected: expected_hash_serialized,
                        actual: actual_hash_serialized,
                    });
                }
            }
        }

        self.historical_undo
            .remove_archived(outcome.height, outcome.hash);
        Ok(outcome)
    }

    pub fn next_historical_block(&self) -> Result<Option<(u32, Hash256)>, AssumeUtxoError> {
        let historical = self.historical_chainstate.read().clone();
        let Some(historical) = historical else {
            return Ok(None);
        };
        if self.active_chainstate.is_closed_for_recovery() || historical.is_closed_for_recovery() {
            return Err(ApplyError::Shutdown.into());
        }
        let ChainstateRole::Historical {
            base_height,
            base_hash,
        } = historical.role()
        else {
            return Err(AssumeUtxoError::NoHistoricalChainstate);
        };
        let height = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height + 1);
        if height > base_height {
            return Ok(None);
        }
        let tree = self.active_chainstate.block_tree.read();
        let base = tree
            .lookup(base_hash)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(base_hash))?;
        let id = tree
            .node_at_height_from(base, height)
            .ok_or(AssumeUtxoError::SnapshotHeaderMissing(base_hash))?;
        Ok(Some((
            height,
            tree.node(id).map_err(ApplyError::from)?.hash,
        )))
    }

    pub fn advance_historical(&self) -> Result<HistoricalAdvance, AssumeUtxoError> {
        for _ in 0..8 {
            let Some((height, hash)) = self.next_historical_block()? else {
                return Ok(HistoricalAdvance::Complete);
            };
            if height == 0 {
                let genesis_payload = BlockPayload::from_local(self.network.genesis_block());
                self.step_historical(&genesis_payload)?;
                continue;
            }
            let bytes = match &self.active_chainstate.block_body_store {
                Some(store) => store.load_block_body(height, hash)?,
                None => None,
            };
            let Some(bytes) = bytes else {
                return Ok(HistoricalAdvance::MissingBody { height, hash });
            };
            let payload =
                BlockPayload::from_raw(bytes::Bytes::from(bytes)).map_err(anyhow::Error::from)?;
            if payload.block().block_hash().0 != hash {
                return Err(anyhow::anyhow!("historical archive body identity mismatch").into());
            }
            self.step_historical(&payload)?;
        }
        if self.next_historical_block()?.is_some() {
            Ok(HistoricalAdvance::ReplayPending)
        } else {
            Ok(HistoricalAdvance::Complete)
        }
    }

    pub fn chainstates_summary(&self) -> Result<ChainstatesSummary, AssumeUtxoError> {
        let lifecycle = self.lifecycle.lock();
        self.capture_chainstates_report(&lifecycle)
            .map(|report| report.lifecycle)
    }

    pub fn try_chainstates_report(&self) -> Result<Option<ChainstatesReport>, AssumeUtxoError> {
        let Some(lifecycle) = self.lifecycle.try_lock() else {
            return Ok(None);
        };
        self.capture_chainstates_report(&lifecycle).map(Some)
    }

    fn capture_chainstates_report(
        &self,
        _lifecycle: &MutexGuard<'_, ()>,
    ) -> Result<ChainstatesReport, AssumeUtxoError> {
        let _transition = self.active_chainstate.chain_transition.lock();
        let active_role = self.active_chainstate.role();
        let active_applied = self.active_chainstate.applied_tip_snapshot();
        let now = bitcoin_rs_primitives::unix_time_secs();
        let reader = self.active_chainstate.chain_progress_reader();
        let active_progress = reader.progress_at(active_applied.as_deref(), self.network, now);
        let active_summary = ActiveChainstateSummary {
            role: active_role,
            height: active_applied.as_ref().map(|tip| tip.height),
            hash: active_applied.as_ref().map(|tip| tip.hash),
            validated: active_role.is_ordinary(),
        };
        let status = self.status()?;
        let (historical_summary, historical_verification_progress) =
            match (status, self.historical_chainstate.read().as_ref()) {
                (
                    AssumeUtxoDiskStatus::Validating {
                        base_height,
                        base_hash,
                        expected_hash_serialized,
                        ..
                    },
                    Some(historical),
                ) => {
                    let applied = historical.applied_tip_snapshot();
                    let progress = reader.progress_at(applied.as_deref(), self.network, now);
                    (
                        Some(HistoricalChainstateSummary {
                            base_height,
                            base_hash,
                            current_height: applied.as_ref().map_or(0, |tip| tip.height),
                            current_hash: applied
                                .as_ref()
                                .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash),
                            expected_hash_serialized,
                            validated_utxo_count: historical.coin_stats.snapshot().utxo_count,
                        }),
                        known_progress(applied.as_deref(), progress.verification_progress),
                    )
                }
                _ => (None, None),
            };
        Ok(ChainstatesReport {
            headers: active_progress.headers,
            active_verification_progress: known_progress(
                active_applied.as_deref(),
                active_progress.verification_progress,
            ),
            historical_verification_progress,
            lifecycle: ChainstatesSummary {
                active_chainstate: active_summary,
                historical_chainstate: historical_summary,
                status,
            },
        })
    }

    #[must_use]
    pub fn active_chainstate(&self) -> Arc<Chainstate> {
        Arc::clone(&self.active_chainstate)
    }

    #[must_use]
    #[cfg(test)]
    fn historical_chainstate(&self) -> Option<Arc<Chainstate>> {
        self.historical_chainstate.read().clone()
    }

    pub fn status(&self) -> Result<AssumeUtxoDiskStatus, AssumeUtxoError> {
        Ok(self
            .active_chainstate
            .durable_head
            .load()?
            .map_or(AssumeUtxoDiskStatus::Uninitialized, |head| head.assumeutxo))
    }

    fn fail_historical(&self, historical: &Chainstate) -> Result<(), AssumeUtxoError> {
        self.active_chainstate.fail_closed_for_recovery();
        historical.fail_closed_for_recovery();
        if let AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            ..
        } = self.status()?
        {
            let actual_hash_serialized = historical.utxo.lock_stable_view().hash_serialized_3()?;
            let failed = AssumeUtxoDiskStatus::Failed {
                base_height,
                base_hash,
                expected_hash_serialized,
                actual_hash_serialized,
            };
            self.persist_status(failed, None)?;
        }
        Ok(())
    }

    fn begin_historical(
        &self,
        block: &Block,
        historical: &Chainstate,
    ) -> Result<bool, AssumeUtxoError> {
        let active = &self.active_chainstate;
        let _transition = active.lock_transition()?;
        let mut status = self.status()?;
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            historical_height,
            pending,
            ..
        } = &mut status
        else {
            return Err(AssumeUtxoError::NoHistoricalChainstate);
        };
        let height = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height + 1);
        let hash = block.block_hash().0;
        if height < *base_height
            && height <= *historical_height
            && self.next_historical_block()? == Some((height, hash))
            && active.undo_store.load_undo(height, hash)?.is_some()
        {
            return Ok(true);
        }
        if pending.is_some_and(|record| record.height == height && record.hash == hash) {
            return Ok(false);
        }
        let prior = active
            .durable_head
            .load()?
            .ok_or(AssumeUtxoError::MissingDurableAnchor)?;
        let position = match &active.block_body_store {
            Some(store) => {
                let position = store.stage_block_body(
                    height,
                    hash,
                    &bitcoin_rs_primitives::consensus_bytes(block),
                )?;
                store.sync()?;
                position
            }
            None => None,
        };
        *pending = Some(bitcoin_rs_storage::assumeutxo::PendingHistoricalBlock {
            height,
            hash,
            position,
        });
        let next = bitcoin_rs_storage::DurableHead {
            commit_id: prior.commit_id + 1,
            assumeutxo: status,
            body_extent: active
                .block_body_store
                .as_ref()
                .and_then(|store| store.append_cursor())
                .or(prior.body_extent),
            ..prior
        };
        active.durable_head.commit(
            Some(&prior),
            &next,
            &bitcoin_rs_storage::CommitRecords::default(),
        )?;
        Ok(false)
    }

    fn recover_pending(&self) -> Result<(), AssumeUtxoError> {
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            pending: Some(pending),
            ..
        } = self.status()?
        else {
            return Ok(());
        };
        if pending.height > base_height {
            return Err(
                anyhow::anyhow!("historical validation intent exceeds snapshot base").into(),
            );
        }
        let historical = self
            .historical_chainstate
            .read()
            .clone()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
        let replay_start = historical
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height.saturating_add(1));
        if replay_start > pending.height {
            return Err(anyhow::anyhow!(
                "historical checkpoint is ahead of pending validation intent"
            )
            .into());
        }
        for height in replay_start..pending.height {
            let (_, hash) = self
                .next_historical_block()?
                .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
            let payload = if height == 0 {
                BlockPayload::from_local(self.network.genesis_block())
            } else {
                let bytes = self
                    .active_chainstate
                    .block_body_store
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing historical body store"))?
                    .load_block_body(height, hash)?
                    .ok_or_else(|| anyhow::anyhow!("missing historical validation dependency"))?;
                BlockPayload::from_raw(bytes::Bytes::from(bytes)).map_err(anyhow::Error::from)?
            };
            if payload.block().block_hash().0 != hash {
                return Err(
                    anyhow::anyhow!("historical validation dependency identity mismatch").into(),
                );
            }
            historical
                .lock_transition()?
                .into_transition()
                .connect(&payload)?;
            self.historical_undo.remove_archived(height, hash);
        }
        let payload = if pending.height == 0 && pending.hash == self.network.genesis_block_hash() {
            BlockPayload::from_local(self.network.genesis_block())
        } else {
            let bytes = self
                .active_chainstate
                .block_body_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing pending validation body store"))?
                .load_staged_body(pending.height, pending.hash, pending.position)?
                .ok_or_else(|| anyhow::anyhow!("missing pending validation body"))?;
            BlockPayload::from_raw(bytes::Bytes::from(bytes)).map_err(anyhow::Error::from)?
        };
        if payload.block().block_hash().0 != pending.hash {
            return Err(anyhow::anyhow!("pending validation body identity mismatch").into());
        }
        self.step_historical(&payload)?;
        Ok(())
    }

    fn persist_status(
        &self,
        mut status: AssumeUtxoDiskStatus,
        historical_block: Option<(&BlockPayload, &Chainstate)>,
    ) -> Result<(), AssumeUtxoError> {
        let active = &self.active_chainstate;
        let _transition = active.chain_transition.lock();
        let prior = active
            .durable_head
            .load()?
            .ok_or(AssumeUtxoError::MissingDurableAnchor)?;
        self.maybe_publish_historical_checkpoint(&mut status, historical_block.map(|(_, cs)| cs))?;
        let mut records = bitcoin_rs_storage::CommitRecords::default();
        let undo;
        if let Some((block, historical)) = historical_block {
            let tip = historical
                .applied_tip_snapshot()
                .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
            undo = historical
                .undo_store
                .load_undo(tip.height, tip.hash)?
                .ok_or(AssumeUtxoError::MissingHistoricalUndo)?;
            records.undo_rows.push((tip.height, tip.hash, &undo));
            if let Some(store) = &active.block_body_store {
                let staged = match prior.assumeutxo {
                    AssumeUtxoDiskStatus::Validating {
                        pending: Some(pending),
                        ..
                    } if pending.height == tip.height && pending.hash == tip.hash => {
                        pending.position
                    }
                    _ => None,
                };
                let position = match staged {
                    Some(position) => Some(position),
                    None => store.stage_block_body(tip.height, tip.hash, block.bytes())?,
                };
                store.sync()?;
                if let Some(position) = position {
                    records.body_rows.push((tip.height, tip.hash, position));
                }
            }
        }
        let next = bitcoin_rs_storage::DurableHead {
            commit_id: prior.commit_id + 1,
            assumeutxo: status,
            undo_extent: records
                .undo_rows
                .last()
                .map(|(height, hash, _)| (*height, *hash))
                .filter(|(height, _)| prior.undo_extent.is_none_or(|(old, _)| *height > old))
                .or(prior.undo_extent),
            body_extent: active
                .block_body_store
                .as_ref()
                .and_then(|store| store.append_cursor())
                .or(prior.body_extent),
            ..prior
        };
        active.durable_head.commit(Some(&prior), &next, &records)?;
        if let AssumeUtxoDiskStatus::Validating {
            checkpoint: Some(checkpoint),
            ..
        } = status
        {
            let previous = match prior.assumeutxo {
                AssumeUtxoDiskStatus::Validating { checkpoint, .. } => checkpoint,
                _ => None,
            };
            if previous != Some(checkpoint) {
                self.cleanup_historical_checkpoints(Some(checkpoint.checkpoint));
            }
        } else if matches!(status, AssumeUtxoDiskStatus::Finalized { .. }) {
            self.cleanup_historical_checkpoints(None);
        }
        Ok(())
    }

    fn cleanup_historical_checkpoints(
        &self,
        retained: Option<bitcoin_rs_storage::checkpoint::CheckpointReference>,
    ) {
        let cleanup = bitcoin_rs_storage::checkpoint::fs::open_data_dir(&self.data_dir)
            .map_err(bitcoin_rs_storage::checkpoint::CheckpointError::from)
            .and_then(|data| match retained {
                Some(reference) => {
                    bitcoin_rs_storage::checkpoint::retire_checkpoint_generations_at(
                        &data,
                        bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
                        reference.generation,
                    )
                }
                None => bitcoin_rs_storage::checkpoint::clear_checkpoint_generations_at(
                    &data,
                    bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
                ),
            });
        if let Err(error) = cleanup {
            tracing::warn!(%error, "historical checkpoint cleanup deferred");
        }
    }

    fn maybe_publish_historical_checkpoint(
        &self,
        status: &mut AssumeUtxoDiskStatus,
        historical: Option<&Chainstate>,
    ) -> Result<(), AssumeUtxoError> {
        let AssumeUtxoDiskStatus::Validating {
            base_height,
            historical_height,
            checkpoint,
            ..
        } = status
        else {
            return Ok(());
        };
        let interval = self.historical_checkpoint_interval.max(1);
        let due = *historical_height
            >= (*checkpoint).map_or(interval, |ref_| ref_.height.saturating_add(interval));
        if !due {
            return Ok(());
        }
        let Some(historical) = historical else {
            return Err(anyhow::anyhow!(
                "historical checkpoint is due without a historical chainstate"
            )
            .into());
        };
        let tip = historical
            .applied_tip_snapshot()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;
        if tip.height != *historical_height || tip.height > *base_height {
            return Err(anyhow::anyhow!(
                "historical checkpoint tip does not match certified progress"
            )
            .into());
        }
        let data =
            bitcoin_rs_storage::checkpoint::fs::open_data_dir(&self.data_dir).map_err(|error| {
                anyhow::anyhow!("open historical checkpoint data directory: {error}")
            })?;
        let config = crate::checkpoint::headers::HeaderCheckpointConfig {
            network: self.network,
            genesis: self.network.genesis_block_hash(),
        };
        let (write, _historical_witness) = crate::checkpoint::write_checkpoint_from_dir_at(
            &data,
            config,
            &historical.block_tree,
            &historical.utxo,
            &historical.coin_stats,
            Some(&tip),
            bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT,
            bitcoin_rs_storage::checkpoint::CheckpointRetention::UntilReferenced,
        )
        .map_err(|error| anyhow::anyhow!("publish historical checkpoint: {error}"))?;
        let reference = match write {
            crate::checkpoint::CheckpointWrite::Published { reference } => reference,
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                return Err(AssumeUtxoError::NoHistoricalChainstate);
            }
        };
        *checkpoint = Some(HistoricalCheckpointRef {
            checkpoint: reference,
            height: tip.height,
            hash: tip.hash,
        });
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/unit/assumeutxo_tests.rs"]
mod tests;

fn known_progress(tip: Option<&TipSnapshot>, progress: f64) -> Option<f64> {
    match tip {
        None => None,
        Some(tip) => tip.chain_tx_count.get().map(|_| progress),
    }
}
