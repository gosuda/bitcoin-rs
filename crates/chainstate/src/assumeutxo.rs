//! Explicit `AssumeUTXO` chainstate role management and background historical validation.
//!
//! Under `AssumeUTXO`, a node can bootstrap instantly from a pinned UTXO snapshot.
//! To protect consensus safety, the node manages two explicit chainstate roles
//! behind a single coordination boundary ([`AssumeUtxoManager`]):
//!
//! 1. **Active assumed chainstate** ([`ChainstateRole::AssumedActive`]):
//!    Initialized at the snapshot base (`base_height`, `base_hash`). This is the
//!    single active authority driving P2P block sync, mempool, mining, RPC, ZMQ,
//!    and derived indexers. Reorgs below `base_height` are strictly prohibited.
//!
//! 2. **Historical validated chainstate** ([`ChainstateRole::Historical`]):
//!    Validates from genesis up to `base_height` through the normal consensus
//!    path ([`Chainstate::connect`]). It does not publish external events,
//!    mempool changes, or indexer updates, and stops connecting blocks past
//!    `base_height`.
//!
//! 3. **Finalization & Single Authority**:
//!    When the historical chainstate connects `base_height`, its reconstructed
//!    UTXO commitment (`hash_serialized_3`) is compared against the pinned commitment.
//!    - On match: the active chainstate transitions to [`ChainstateRole::Ordinary`],
//!      the historical chainstate is retired, and the node converges to a single
//!      ordinary chainstate.
//!    - On mismatch: the node fails closed immediately, permanently closing
//!      mutation admission and recording the failure on disk so future restarts
//!      also fail closed.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use bitcoin_rs_primitives::{Block, Hash256, Network};
use bitcoin_rs_utxo::snapshot::SnapshotLoad;
use parking_lot::{Mutex, RwLock};

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
    use serde::{Deserialize, Deserializer, Serializer};

    #[expect(clippy::ref_option)]
    pub(super) fn serialize<S>(hash: &Option<Hash256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match hash {
            Some(h) => serializer.serialize_some(&h.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Hash256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => s
                .parse::<Hash256>()
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// The operational role of a chainstate instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChainstateRole {
    /// Fully validated single active chainstate.
    Ordinary,
    /// Active assumed chainstate loaded from an `AssumeUTXO` snapshot at `base_height` / `base_hash`.
    /// Serves normal node consumers, but rejects reorgs at or below `base_height`.
    AssumedActive {
        /// Block height of the snapshot base.
        base_height: u32,
        /// Block hash of the snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
    },
    /// Background historical chainstate validating from genesis up to `base_height`.
    /// Does not emit external side effects, and stops connecting blocks past `base_height`.
    Historical {
        /// Target block height (the snapshot base).
        base_height: u32,
        /// Target block hash.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
    },
}

impl ChainstateRole {
    /// Returns `true` if this role is `AssumedActive`.
    #[must_use]
    pub const fn is_assumed_active(&self) -> bool {
        matches!(self, Self::AssumedActive { .. })
    }

    /// Returns `true` if this role is `Historical`.
    #[must_use]
    pub const fn is_historical(&self) -> bool {
        matches!(self, Self::Historical { .. })
    }

    /// Returns `true` if this role is `Ordinary`.
    #[must_use]
    pub const fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary)
    }

    /// Returns the snapshot base height if this role is `AssumedActive` or `Historical`.
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

/// The persistent lifecycle status of `AssumeUTXO` coordination.
/// The on-disk `*_muhash` field spellings are retained; the commitment is
/// Bitcoin Core's serialized-set hash, as named by the Rust fields below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AssumeUtxoDiskStatus {
    /// No `AssumeUTXO` snapshot has been activated.
    Uninitialized,
    /// Snapshot is active; background historical validation is progressing towards `base_height`.
    Validating {
        /// Block height of the snapshot base.
        base_height: u32,
        /// Block hash of the snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
        /// Pinned expected UTXO commitment (`hash_serialized_3`) at `base_height`.
        #[serde(with = "serde_hash256", rename = "expected_muhash")]
        expected_hash_serialized: Hash256,
        /// Cumulative transaction count through `base_height`.
        chain_tx_count: u64,
        /// Historical chainstate validated tip height.
        historical_height: u32,
        /// Historical chainstate validated tip hash.
        #[serde(with = "serde_hash256")]
        historical_hash: Hash256,
    },
    /// Background historical validation succeeded and matched the pinned commitment.
    /// Chainstate roles have converged to `Ordinary`.
    Finalized {
        /// Block height of the validated snapshot base.
        base_height: u32,
        /// Block hash of the validated snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
        /// Verified UTXO commitment (`hash_serialized_3`) at `base_height`.
        #[serde(with = "serde_hash256", rename = "validated_muhash")]
        validated_hash_serialized: Hash256,
    },
    /// Background validation failed (e.g. commitment mismatch). The node must fail closed.
    Failed {
        /// Block height of the snapshot base.
        base_height: u32,
        /// Block hash of the snapshot base.
        #[serde(with = "serde_hash256")]
        base_hash: Hash256,
        /// Expected UTXO commitment (`hash_serialized_3`).
        #[serde(with = "serde_hash256", rename = "expected_muhash")]
        expected_hash_serialized: Hash256,
        /// Reconstructed actual UTXO commitment (`hash_serialized_3`).
        #[serde(with = "serde_hash256", rename = "actual_muhash")]
        actual_hash_serialized: Hash256,
    },
}

/// Errors produced by `AssumeUTXO` management and validation.
#[derive(Debug, thiserror::Error)]
pub enum AssumeUtxoError {
    /// The snapshot base must resolve to an admitted header before installation.
    #[error("snapshot base header {0} is not present")]
    SnapshotHeaderMissing(Hash256),
    /// A known base header must have the pinned height.
    #[error("snapshot base header height {found} does not match pinned height {expected}")]
    SnapshotHeaderHeightMismatch {
        /// Pinned height.
        expected: u32,
        /// Header height.
        found: u32,
    },
    /// Historical validation must reproduce the pinned cumulative transaction count.
    #[error("historical transaction count {found} does not match pinned count {expected}")]
    HistoricalTransactionCountMismatch {
        /// Pinned count.
        expected: u64,
        /// Reconstructed count.
        found: u64,
    },
    /// Snapshot height is not pinned in the network parameters.
    #[error("snapshot height {0} is not pinned in AssumeUtxoData for this network")]
    UntrustedSnapshotHeight(u32),
    /// Snapshot tip hash does not match the pinned block hash.
    #[error("snapshot block hash {found} does not match pinned hash {expected}")]
    SnapshotBlockHashMismatch {
        /// Pinned block hash.
        expected: Hash256,
        /// Hash declared by the snapshot.
        found: Hash256,
    },
    /// Snapshot commitment (`hash_serialized_3`) does not match the pinned commitment.
    #[error("snapshot commitment {found} does not match pinned hash {expected}")]
    SnapshotCommitmentMismatch {
        /// Pinned commitment.
        expected: Hash256,
        /// Computed commitment.
        found: Hash256,
    },
    /// Node was previously marked as failed; refuses to start to protect operator data.
    #[error(
        "node previously failed assumeutxo validation at base height {base_height}: expected {expected_hash_serialized}, found {actual_hash_serialized}; failing closed"
    )]
    PreviouslyFailed {
        /// Base height of failed validation.
        base_height: u32,
        /// Expected commitment.
        expected_hash_serialized: Hash256,
        /// Actual commitment encountered.
        actual_hash_serialized: Hash256,
    },
    /// Snapshot activation attempted while another `AssumeUTXO` operation is active.
    #[error("cannot activate assumeutxo snapshot: assumeutxo validation is already in progress")]
    AlreadyActive,
    /// Background validation reached base height but the reconstructed commitment did not match.
    #[error(
        "assumeutxo commitment mismatch at base height {base_height}: expected {expected}, actual {actual}"
    )]
    CommitmentMismatch {
        /// Base height where mismatch was detected.
        base_height: u32,
        /// Expected commitment.
        expected: Hash256,
        /// Actual commitment computed from genesis.
        actual: Hash256,
    },
    /// No historical chainstate is present to perform historical operations.
    #[error("no historical chainstate present")]
    NoHistoricalChainstate,
    /// Historical validation reached target height but the block hash diverged.
    #[error(
        "historical validation reached unexpected block hash {found} at target height {base_height}, expected {expected}"
    )]
    HistoricalTargetHashMismatch {
        /// Target base height.
        base_height: u32,
        /// Expected block hash.
        expected: Hash256,
        /// Observed block hash.
        found: Hash256,
    },
    /// Chainstate mutation failed.
    #[error("apply error: {0}")]
    Apply(#[from] ApplyError),
    /// Chainstate rollback failed.
    #[error("disconnect error: {0}")]
    Disconnect(#[from] DisconnectError),
    /// UTXO error.
    #[error("utxo error: {0}")]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    /// I/O error while reading/writing disk status.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization error while decoding/encoding disk status.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Summary of active and background chainstates for operator reporting (e.g. `getchainstates`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainstatesSummary {
    /// Active chainstate status.
    pub active_chainstate: ActiveChainstateSummary,
    /// Historical background chainstate status, if present.
    pub historical_chainstate: Option<HistoricalChainstateSummary>,
    /// Persistent lifecycle status.
    pub status: AssumeUtxoDiskStatus,
}

/// Active chainstate status.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveChainstateSummary {
    /// Role of the active chainstate.
    pub role: ChainstateRole,
    /// Current applied tip height.
    pub height: Option<u32>,
    /// Current applied tip block hash.
    #[serde(with = "serde_opt_hash256")]
    pub hash: Option<Hash256>,
    /// Whether this chainstate is fully validated (`Ordinary`).
    pub validated: bool,
}

/// Historical background chainstate status.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalChainstateSummary {
    /// Target base height of background validation.
    pub base_height: u32,
    /// Target base block hash of background validation.
    #[serde(with = "serde_hash256")]
    pub base_hash: Hash256,
    /// Current validated tip height.
    pub current_height: u32,
    /// Current validated tip block hash.
    #[serde(with = "serde_hash256")]
    pub current_hash: Hash256,
    /// Expected UTXO commitment (`hash_serialized_3`) at `base_height`.
    #[serde(with = "serde_hash256")]
    pub expected_hash_serialized: Hash256,
    /// Validated UTXO record count in the historical chainstate.
    pub validated_utxo_count: u64,
}

const STATUS_FILENAME: &str = "assumeutxo.json";
const STATUS_TMP_FILENAME: &str = "assumeutxo.json.tmp";

/// Single authority managing `AssumeUTXO` roles and lifecycle progression.
pub struct AssumeUtxoManager {
    /// Serializes activation, historical progress, and finalization.
    lifecycle: Mutex<()>,
    network: Network,
    active_chainstate: Arc<Chainstate>,
    historical_chainstate: Arc<RwLock<Option<Arc<Chainstate>>>>,
    status: Arc<RwLock<AssumeUtxoDiskStatus>>,
    data_dir: Option<PathBuf>,
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
    /// Initializes the `AssumeUTXO` manager, inspecting persistent state if available.
    ///
    /// # Errors
    ///
    /// Returns [`AssumeUtxoError::PreviouslyFailed`] and closes active chainstate
    /// admission if a prior validation failure is recorded on disk.
    pub fn open(
        network: Network,
        active_chainstate: Arc<Chainstate>,
        data_dir: Option<PathBuf>,
    ) -> Result<Self, AssumeUtxoError> {
        let mut loaded_status = if let Some(dir) = &data_dir {
            let path = dir.join(STATUS_FILENAME);
            if path.exists() {
                let content = fs::read_to_string(&path)?;
                serde_json::from_str::<AssumeUtxoDiskStatus>(&content)?
            } else {
                AssumeUtxoDiskStatus::Uninitialized
            }
        } else {
            AssumeUtxoDiskStatus::Uninitialized
        };

        let mut historical = None;
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
                expected_hash_serialized,
                chain_tx_count,
                ..
            } => {
                active_chainstate.set_role(ChainstateRole::AssumedActive {
                    base_height,
                    base_hash,
                });
                let hist_cs =
                    active_chainstate.create_historical_counterpart(base_height, base_hash);
                // The historical store is deliberately transient. A progress
                // marker is not a coin set: restart validation from genesis,
                // never attach an advanced tip to empty coins and statistics.
                loaded_status = AssumeUtxoDiskStatus::Validating {
                    base_height,
                    base_hash,
                    expected_hash_serialized,
                    chain_tx_count,
                    historical_height: 0,
                    historical_hash: network.genesis_block_hash(),
                };
                historical = Some(hist_cs);
            }
            AssumeUtxoDiskStatus::Finalized { .. } | AssumeUtxoDiskStatus::Uninitialized => {
                active_chainstate.set_role(ChainstateRole::Ordinary);
            }
        }

        Ok(Self {
            lifecycle: Mutex::new(()),
            network,
            active_chainstate,
            historical_chainstate: Arc::new(RwLock::new(historical)),
            status: Arc::new(RwLock::new(loaded_status)),
            data_dir,
        })
    }

    /// Activates a verified `AssumeUTXO` snapshot, installing snapshot UTXO and tip onto the
    /// active chainstate, and configuring the isolated background historical validator.
    ///
    /// # Errors
    ///
    /// Rejects untrusted heights, mismatched block hashes, or mismatched serialized UTXO commitments.
    pub fn activate_snapshot(&self, snapshot_load: SnapshotLoad) -> Result<(), AssumeUtxoError> {
        let pinned = self
            .network
            .assume_utxo_for_height(snapshot_load.height)
            .ok_or(AssumeUtxoError::UntrustedSnapshotHeight(
                snapshot_load.height,
            ))?;

        self.activate_pinned_snapshot(snapshot_load, pinned)
    }

    // Only network-pinned metadata reaches this boundary in production. Tests
    // use a small consensus-valid chain to exercise lifecycle transitions.
    fn activate_pinned_snapshot(
        &self,
        snapshot_load: SnapshotLoad,
        pinned: &bitcoin_rs_primitives::AssumeUtxoData,
    ) -> Result<(), AssumeUtxoError> {
        let _lifecycle = self.lifecycle.lock();
        if !matches!(*self.status.read(), AssumeUtxoDiskStatus::Uninitialized) {
            return Err(AssumeUtxoError::AlreadyActive);
        }
        if pinned.block_hash != snapshot_load.tip_hash {
            return Err(AssumeUtxoError::SnapshotBlockHashMismatch {
                expected: pinned.block_hash,
                found: snapshot_load.tip_hash,
            });
        }

        // Core's AssumeutxoHash is HASH_SERIALIZED, not MuHash. Derive it
        // from the owned imported coins; neither a caller nor a trailer can
        // assert the commitment on behalf of the verifier.
        let (commitment, stats) = snapshot_load.set.with_stable_view(|view| {
            Ok::<_, bitcoin_rs_utxo::UtxoError>((
                view.hash_serialized_3()?,
                bitcoin_rs_utxo::stats::scan_coin_stats(view, pinned.height, true)?,
            ))
        })?;
        if commitment != pinned.hash_serialized {
            return Err(AssumeUtxoError::SnapshotCommitmentMismatch {
                expected: pinned.hash_serialized,
                found: commitment,
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
        };

        // Header validation and lifecycle persistence run under the same
        // transition as installation, before exposing any snapshot state.
        self.active_chainstate
            .install_snapshot(snapshot_load.set, stats, pinned, || {
                self.persist_status(new_status)
            })?;

        // 3. Create isolated historical chainstate with detached events
        let historical = self
            .active_chainstate
            .create_historical_counterpart(pinned.height, pinned.block_hash);

        *self.historical_chainstate.write() = Some(historical);
        *self.status.write() = new_status;

        Ok(())
    }

    /// Connects one block to the historical chainstate in the background.
    ///
    /// When the connected block reaches `base_height`:
    /// - Reconstructs the UTXO commitment and compares with `expected_hash_serialized`.
    /// - On match: transitions active chainstate to [`ChainstateRole::Ordinary`],
    ///   retires historical chainstate, and persists [`AssumeUtxoDiskStatus::Finalized`].
    /// - On mismatch: fails closed immediately, sets both chainstates to closed,
    ///   persists [`AssumeUtxoDiskStatus::Failed`], and returns an error.
    pub fn step_historical(
        &self,
        block: &Block,
        serialized: Option<bytes::Bytes>,
    ) -> Result<ConnectOutcome, AssumeUtxoError> {
        let _lifecycle = self.lifecycle.lock();
        let historical = self
            .historical_chainstate
            .read()
            .clone()
            .ok_or(AssumeUtxoError::NoHistoricalChainstate)?;

        let result = {
            let transition = historical.lock_transition()?.into_transition();
            transition.connect(block, serialized)
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
            result => result?,
        };

        let current_status = *self.status.read();
        if let AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            chain_tx_count,
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
                };
                self.persist_status(updated).inspect_err(|_| {
                    self.active_chainstate.fail_closed_for_recovery();
                    historical.fail_closed_for_recovery();
                })?;
                *self.status.write() = updated;
            } else if outcome.height == base_height {
                if outcome.hash != base_hash {
                    self.fail_historical(&historical)?;
                    return Err(AssumeUtxoError::HistoricalTargetHashMismatch {
                        base_height,
                        expected: base_hash,
                        found: outcome.hash,
                    });
                }

                let actual_hash_serialized =
                    historical.utxo.lock_stable_view().hash_serialized_3()?;
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
                    self.persist_status(finalized).inspect_err(|_| {
                        self.active_chainstate.fail_closed_for_recovery();
                        historical.fail_closed_for_recovery();
                    })?;
                    self.active_chainstate.set_role(ChainstateRole::Ordinary);
                    *self.historical_chainstate.write() = None;
                    *self.status.write() = finalized;
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

        Ok(outcome)
    }

    /// Produces a summary of active and historical chainstates for operator reporting.
    #[must_use]
    pub fn chainstates_summary(&self) -> ChainstatesSummary {
        let active_role = self.active_chainstate.role();
        let active_applied = self.active_chainstate.applied_tip_snapshot();
        let active_summary = ActiveChainstateSummary {
            role: active_role,
            height: active_applied.as_ref().map(|t| t.height),
            hash: active_applied.as_ref().map(|t| t.hash),
            validated: active_role.is_ordinary(),
        };

        let status = *self.status.read();
        let historical_summary = match (status, self.historical_chainstate.read().as_ref()) {
            (
                AssumeUtxoDiskStatus::Validating {
                    base_height,
                    base_hash,
                    expected_hash_serialized,
                    ..
                },
                Some(historical),
            ) => {
                let hist_applied = historical.applied_tip_snapshot();
                Some(HistoricalChainstateSummary {
                    base_height,
                    base_hash,
                    current_height: hist_applied.as_ref().map_or(0, |t| t.height),
                    current_hash: hist_applied
                        .as_ref()
                        .map_or_else(|| self.network.genesis_block_hash(), |t| t.hash),
                    expected_hash_serialized,
                    validated_utxo_count: u64::try_from(historical.utxo.record_count())
                        .unwrap_or(u64::MAX),
                })
            }
            _ => None,
        };

        ChainstatesSummary {
            active_chainstate: active_summary,
            historical_chainstate: historical_summary,
            status,
        }
    }

    /// Returns the active chainstate handle.
    #[must_use]
    pub fn active_chainstate(&self) -> Arc<Chainstate> {
        Arc::clone(&self.active_chainstate)
    }

    /// Returns the historical chainstate handle, if currently validating.
    #[must_use]
    pub fn historical_chainstate(&self) -> Option<Arc<Chainstate>> {
        self.historical_chainstate.read().clone()
    }

    /// Returns the current `AssumeUTXO` lifecycle status.
    #[must_use]
    pub fn status(&self) -> AssumeUtxoDiskStatus {
        *self.status.read()
    }

    fn fail_historical(&self, historical: &Chainstate) -> Result<(), AssumeUtxoError> {
        // Close admission even when the diagnostic record cannot be written.
        self.active_chainstate.fail_closed_for_recovery();
        historical.fail_closed_for_recovery();
        if let AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            ..
        } = self.status()
        {
            let actual_hash_serialized = historical.utxo.lock_stable_view().hash_serialized_3()?;
            let failed = AssumeUtxoDiskStatus::Failed {
                base_height,
                base_hash,
                expected_hash_serialized,
                actual_hash_serialized,
            };
            *self.status.write() = failed;
            self.persist_status(failed)?;
        }
        Ok(())
    }

    fn persist_status(&self, status: AssumeUtxoDiskStatus) -> Result<(), AssumeUtxoError> {
        if let Some(dir) = &self.data_dir {
            let tmp_path = dir.join(STATUS_TMP_FILENAME);
            let target_path = dir.join(STATUS_FILENAME);
            let serialized = serde_json::to_string_pretty(&status)?;
            {
                use std::io::Write;
                let mut file = fs::File::create(&tmp_path)?;
                file.write_all(serialized.as_bytes())?;
                file.sync_all()?;
            }
            fs::rename(&tmp_path, &target_path)?;
            let directory = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir)?;
            bitcoin_rs_storage::checkpoint::fs::sync_dir(&directory)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/unit/assumeutxo_tests.rs"]
mod tests;
