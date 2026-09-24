//! Full-checkpoint publication: the chainstate maintenance export.
//!
//! `CheckpointPublisher` owns the full-checkpoint write path shared by the
//! clean-shutdown publication, retention-pressure compaction
//! ([`crate::maintenance`]), and manual export. A checkpoint is a
//! maintenance artifact, not a recovery authority (`RCV-10` in
//! `docs/contracts/recovery.md`): the durable root and the ordered commit
//! protocol make every committed tip recoverable, boot replays the journal
//! suffix from the last checkpoint, and a node killed mid-sync restarts
//! from that base with no periodic publisher running.
//!
//! ## Cost when it fires
//!
//! `publish` closes apply admission for the duration (pausing block
//! application), syncs the block-body store, then writes the full checkpoint
//! snapshot (staging dir → per-artifact fsync → generation rename → `CURRENT`
//! atomic swap). Snapshot size scales with tip (22.8 MB at height 130k;
//! plausibly several GB near modern tips). The pause is
//! seconds-to-tens-of-seconds and lands on compaction pressure or shutdown,
//! off the apply path's steady-state cadence.

use arc_swap::ArcSwapOption;

use bitcoin_rs_chain::{BlockTree, TipSnapshot};

use bitcoin_rs_primitives::Hash256;

use bitcoin_rs_storage::block_body::BlockBodyStore;

use bitcoin_rs_utxo::{UtxoSet, stats::CoinStatsListener};

use bitcoin_rs_storage::recovery_evidence::{AppliedTipWitness, write_witness};

use crate::{
    ApplyAdmission, UndoStore,
    checkpoint::{self, CheckpointError, CheckpointWrite},
    events::ChainEventPublisher,
};

use parking_lot::RwLock;

use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};

fn retire_full_revalidation_marker(data_dir: &std::path::Path) -> Result<(), CheckpointError> {
    bitcoin_rs_storage::chainstate_journal::clear_full_revalidation_marker_at(data_dir).map_err(
        |error| match error {
            bitcoin_rs_storage::chainstate_journal::JournalWriterError::Io(io) => {
                CheckpointError::FullRevalidationMarker(io)
            }
            other => CheckpointError::Store(
                bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(other.to_string()),
            ),
        },
    )
}

/// All the shared handles needed to publish a checkpoint from a background
/// thread without retaining the full [`crate::Chainstate`].
///
/// Created once from chainstate's shared handles and moved into the worker
/// thread. The `checkpoint_data_dir` is reopened from the data-dir path
/// (a cheap `openat`) so the worker does not borrow the service.
pub(crate) struct CheckpointPublisher {
    pub(crate) admission: Arc<ApplyAdmission>,
    pub(crate) undo_store: Arc<dyn UndoStore>,
    pub(crate) durable_head: Arc<dyn bitcoin_rs_storage::DurableHeadStore>,
    pub(crate) block_body_store: Arc<dyn BlockBodyStore>,
    pub(crate) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) checkpoint_data_dir: cap_std::fs::Dir,
    pub(crate) network: bitcoin_rs_primitives::Network,
    pub(crate) genesis_hash: Hash256,
    pub(crate) block_tree: Arc<RwLock<BlockTree>>,
    pub(crate) utxo: Arc<UtxoSet>,
    pub(crate) coin_stats: Arc<CoinStatsListener>,
    pub(crate) journal: Option<bitcoin_rs_storage::chainstate_journal::SharedJournalWriter>,

    pub(crate) data_dir: PathBuf,
    pub(crate) chain_events: Arc<ChainEventPublisher>,
    pub(crate) durable_tip_height: Arc<std::sync::atomic::AtomicU32>,
}

impl CheckpointPublisher {
    /// Publishes the same durable checkpoint exposed by
    /// [`crate::Chainstate::publish_checkpoint`].
    ///
    /// Both clean and periodic callers use this exact freeze → publish →
    /// compact → resume sequence.
    pub(crate) fn publish(&self) -> core::result::Result<CheckpointWrite, CheckpointError> {
        let _exclusive_apply = self.admission.pause();
        let mut journal = self.journal.as_ref().map(|journal| journal.lock());
        if let Some(writer) = journal.as_mut() {
            writer.freeze().map_err(|error| {
                CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                    error.to_string(),
                ))
            })?;
        }
        // One applied-tip load supplies the tip and the count it certifies,
        // so the checkpoint and the journal compaction share one value.
        let applied_tip = self.applied_tip.load_full();
        let chain_tx_count = applied_tip
            .as_ref()
            .map_or(0, |tip| tip.chain_tx_count.to_wire());
        let mut result = self.publish_frozen(applied_tip.as_deref());

        if let (Ok(CheckpointWrite::Published { generation }), Some(tip), Some(writer)) =
            (&result, applied_tip.as_ref(), journal.as_mut())
        {
            let compact_result = self.tip_prev_hash(tip).and_then(|tip_prev_hash| {
                writer
                    .compact_to_checkpoint(
                        *generation,
                        tip.height,
                        tip.hash.to_le_bytes(),
                        tip_prev_hash.to_le_bytes(),
                        chain_tx_count,
                    )
                    .map_err(|error| {
                        CheckpointError::Store(
                            bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                                error.to_string(),
                            ),
                        )
                    })
            });
            if let Err(error) = compact_result {
                result = Err(error);
            }
        }
        if let Some(writer) = journal.as_mut()
            && let Err(error) = writer.resume()
        {
            let resume_error = CheckpointError::Store(
                bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(error.to_string()),
            );
            if result.is_ok() {
                result = Err(resume_error);
            } else {
                tracing::error!(%error, "failed to resume chainstate journal after publication error");
            }
        }
        result
    }

    /// Publishes a checkpoint when a `RolledBack` disconnect marker is present.
    ///
    /// Returns `Ok(false)` when there is no marker, or when the marker is
    /// `InFlight` (a torn rollback must not be made durable). `Ok(true)` means
    /// a checkpoint was published and the marker was disarmed.
    pub(crate) fn settle_disconnect_debt(&self) -> core::result::Result<bool, CheckpointError> {
        let Some(marker) = self.undo_store.load_disconnect_marker()? else {
            return Ok(false);
        };
        if marker.phase == crate::DisconnectPhase::InFlight {
            return Ok(false);
        }
        self.publish()?;
        Ok(true)
    }

    fn tip_prev_hash(&self, tip: &TipSnapshot) -> core::result::Result<Hash256, CheckpointError> {
        let tree = self.block_tree.read();
        let node = tree.node(tip.tip_id).map_err(|error| {
            CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                format!("checkpoint tip is absent from block tree: {error}"),
            ))
        })?;
        let Some(parent_id) = node.parent else {
            return Ok(Hash256::default());
        };
        tree.node(parent_id)
            .map(|parent| parent.hash)
            .map_err(|error| {
                CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                    format!("checkpoint tip parent is absent: {error}"),
                ))
            })
    }

    fn publish_frozen(
        &self,
        applied_tip: Option<&TipSnapshot>,
    ) -> core::result::Result<CheckpointWrite, CheckpointError> {
        if let Some(marker) = self.undo_store.load_disconnect_marker()?
            && marker.phase == crate::DisconnectPhase::InFlight
        {
            return Err(CheckpointError::DisconnectInFlight {
                hash: marker.hash,
                height: marker.height,
            });
        }
        // The durable head is the chain's commit point and publication
        // follows it, so a checkpoint — which freezes the published state —
        // can never legitimately name a tip the head has not certified. The
        // two authorities must not disagree about the durable tip.
        // No applied tip is the legitimate pre-genesis state (`SkippedNoAppliedTip`
        // below); the guard has nothing to compare there.
        if let (Some(head), Some(tip)) = (
            self.durable_head.load().map_err(|error| {
                CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                    format!("durable head unreadable: {error}"),
                ))
            })?,
            applied_tip,
        ) {
            // A tip below the head is the committed-but-unpublished gap a
            // crash can leave; checkpointing the older state is harmless. A
            // tip at or above the head that the head does not certify is
            // genuine divergence between the two authorities.
            // `head.tip` and `tip.hash` name the same fact — the 32-byte
            // block hash of the certified/applied tip — under two field
            // names.
            let same_tip = head.tip == tip.hash;
            let diverged = head.height < tip.height || (head.height == tip.height && !same_tip);
            if diverged {
                return Err(CheckpointError::AheadOfDurableHead {
                    tip: tip.hash,
                    tip_height: tip.height,
                    head: head.tip,
                    head_height: head.height,
                });
            }
        }
        // A checkpoint may name this tip only after body files then index rows sync.
        self.block_body_store.sync()?;
        let written = checkpoint::write_checkpoint_from_dir(
            &self.checkpoint_data_dir,
            checkpoint::headers::HeaderCheckpointConfig {
                network: self.network,
                genesis: self.genesis_hash,
            },
            &self.block_tree,
            &self.utxo,
            &self.coin_stats,
            applied_tip,
        )?;
        // A2: Only after `CheckpointWrite::Published` and root fsync, write
        // the applied-tip witness for the same captured tip.
        if let CheckpointWrite::Published { .. } = written
            && let Some(tip) = applied_tip
        {
            let genesis_hex = self.genesis_hash.to_string_be();
            let witness = AppliedTipWitness::new(
                genesis_hex,
                self.chain_events.epoch(),
                tip.height,
                tip.hash.to_string_be(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            );
            write_witness(&self.data_dir, &witness).map_err(|e| {
                CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                    e.to_string(),
                ))
            })?;
        }
        // Remove the disconnect marker only after this checkpoint publishes the
        // matching UTXO set and applied tip.
        self.undo_store
            .disarm_disconnect()
            .map_err(CheckpointError::from)?;
        // Marker retirement is a second durability step after `CURRENT`.
        // Propagate failure so the worker retries next tick; the published
        // checkpoint stays, and the marker stays until unlink+dirsync commits.
        if matches!(written, CheckpointWrite::Published { .. }) {
            retire_full_revalidation_marker(&self.data_dir)?;
        }
        // Everything up to this tip is now recoverable, so undo records below
        // it may be pruned.
        self.durable_tip_height
            .store(applied_tip.map_or(0, |tip| tip.height), Ordering::Release);
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::retire_full_revalidation_marker;
    use crate::checkpoint::CheckpointError;
    use bitcoin_rs_storage::chainstate_journal::JOURNAL_DIR_NAME;

    #[test]
    fn full_revalidation_marker_clears_after_checkpoint_publication() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let journal_dir = dir.path().join(JOURNAL_DIR_NAME);
        let marker =
            journal_dir.join(bitcoin_rs_storage::chainstate_journal::FULL_REVALIDATION_MARKER);
        std::fs::create_dir_all(&journal_dir)?;
        std::fs::write(&marker, b"force full validation\n")?;

        retire_full_revalidation_marker(dir.path())?;

        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn missing_full_revalidation_marker_is_success() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        retire_full_revalidation_marker(dir.path())?;
        Ok(())
    }

    #[test]
    fn marker_clear_io_is_classified_as_retryable_marker_error() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(JOURNAL_DIR_NAME), b"not a directory")?;

        let error = match retire_full_revalidation_marker(dir.path()) {
            Err(error) => error,
            Ok(()) => anyhow::bail!("opening a file as the journal directory must fail"),
        };
        assert!(matches!(error, CheckpointError::FullRevalidationMarker(_)));
        Ok(())
    }
}
