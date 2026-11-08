use arc_swap::ArcSwapOption;

use crate::chain::{BlockTree, TipSnapshot};

use bitcoin_rs_consensus::primitives::Hash256;

use bitcoin_rs_storage::DisconnectPhase;
use bitcoin_rs_storage::block_body::BlockBodyStore;

use bitcoin_rs_storage::utxo::snapshot::{SeedOfferCell, V4Witness};
use bitcoin_rs_storage::utxo::{UtxoSet, stats::CoinStatsListener};

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
    bitcoin_rs_storage::recovery_evidence::clear_full_revalidation_marker_at(data_dir).map_err(
        |error| match error {
            bitcoin_rs_storage::recovery_evidence::EvidenceError::Io(io) => {
                CheckpointError::FullRevalidationMarker(io)
            }
            other => CheckpointError::Store(
                bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(other.to_string()),
            ),
        },
    )
}

#[derive(Clone, Copy)]
enum DisconnectRetirement {
    Ordinary,
    Recovered,
    /// Boot replay is still below the durable head. Publish a compaction base
    /// without retiring either recovery marker; a crash must resume recovery,
    /// not treat this progress checkpoint as a completed repair.
    #[expect(dead_code)]
    RecoveryProgress,
}

pub(crate) struct CheckpointPublisher {
    pub(crate) admission: Arc<ApplyAdmission>,
    pub(crate) undo_store: Arc<dyn UndoStore>,
    pub(crate) durable_head: Arc<dyn bitcoin_rs_storage::DurableHeadStore>,
    pub(crate) block_body_store: Arc<dyn BlockBodyStore>,
    pub(crate) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) checkpoint_data_dir: cap_std::fs::Dir,
    pub(crate) network: bitcoin_rs_consensus::primitives::Network,
    pub(crate) genesis_hash: Hash256,
    pub(crate) block_tree: Arc<RwLock<BlockTree>>,
    pub(crate) utxo: Arc<UtxoSet>,
    pub(crate) coin_stats: Arc<CoinStatsListener>,

    pub(crate) seed_offer: Option<SeedOfferCell>,
    pub(crate) data_dir: PathBuf,
    pub(crate) chain_events: Arc<ChainEventPublisher>,
    pub(crate) durable_tip_height: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) store: Option<Arc<dyn bitcoin_rs_storage::KvStore>>,
}

impl CheckpointPublisher {
    pub(crate) fn publish(&self) -> core::result::Result<CheckpointWrite, CheckpointError> {
        self.publish_transaction(DisconnectRetirement::Ordinary)
    }

    pub(crate) fn publish_recovered(
        &self,
    ) -> core::result::Result<CheckpointWrite, CheckpointError> {
        self.publish_transaction(DisconnectRetirement::Recovered)
    }

    #[expect(dead_code)]
    pub(crate) fn publish_recovery_progress(
        &self,
    ) -> core::result::Result<CheckpointWrite, CheckpointError> {
        self.publish_transaction(DisconnectRetirement::RecoveryProgress)
    }

    fn publish_transaction(
        &self,
        retirement: DisconnectRetirement,
    ) -> core::result::Result<CheckpointWrite, CheckpointError> {
        let _exclusive_apply = self.admission.pause();
        let _publication = self.admission.publication.lock();
        if self.admission.is_closed() {
            return Err(CheckpointError::ClosedForRecovery);
        }
        let applied_tip = self.applied_tip.load_full();
        self.publish_frozen(applied_tip.as_deref(), retirement)
    }

    pub(crate) fn settle_disconnect_debt(&self) -> core::result::Result<bool, CheckpointError> {
        let Some(marker) = self.undo_store.load_disconnect_marker()? else {
            return Ok(false);
        };
        if marker.phase == DisconnectPhase::InFlight {
            return Ok(false);
        }
        self.publish()?;
        Ok(true)
    }

    #[expect(dead_code)]
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

    /// The disconnect marker is the recovery latch: it retires only once the
    /// checkpoint publication succeeded.
    ///
    /// The durable head is the chain's commit point and publication follows it, so a
    /// checkpoint — which freezes the published state — can never legitimately name a
    /// tip the head has not certified. The two authorities must not disagree about the
    /// durable tip.
    fn publish_frozen(
        &self,
        applied_tip: Option<&TipSnapshot>,
        retirement: DisconnectRetirement,
    ) -> core::result::Result<CheckpointWrite, CheckpointError> {
        if let Some(marker) = self.undo_store.load_disconnect_marker()?
            && marker.phase == DisconnectPhase::InFlight
            && matches!(retirement, DisconnectRetirement::Ordinary)
        {
            return Err(CheckpointError::DisconnectInFlight {
                hash: marker.hash,
                height: marker.height,
            });
        }
        if let (Some(head), Some(tip)) = (
            self.durable_head.load().map_err(|error| {
                CheckpointError::Store(bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(
                    format!("durable head unreadable: {error}"),
                ))
            })?,
            applied_tip,
        ) {
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
        self.block_body_store.sync()?;
        self.block_body_store.flush_index()?;
        let header_config = checkpoint::headers::HeaderCheckpointConfig {
            network: self.network,
            genesis: self.genesis_hash,
        };
        let (written, stage_witness) = if let Some(store) = self.store.as_deref() {
            checkpoint::write_checkpoint_with_store(
                &self.checkpoint_data_dir,
                header_config,
                &self.block_tree,
                &self.coin_stats,
                applied_tip,
                checkpoint::CheckpointStoreTarget {
                    store,
                    host_data_dir: &self.data_dir,
                },
            )?
        } else {
            checkpoint::write_checkpoint_from_dir(
                &self.checkpoint_data_dir,
                header_config,
                &self.block_tree,
                &self.utxo,
                &self.coin_stats,
                applied_tip,
            )?
        };
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
        if matches!(written, CheckpointWrite::Published { .. })
            && !matches!(retirement, DisconnectRetirement::RecoveryProgress)
        {
            retire_full_revalidation_marker(&self.data_dir)?;
            if let Err(error) = match retirement {
                DisconnectRetirement::Ordinary => self.undo_store.disarm_disconnect(),
                DisconnectRetirement::Recovered => self.undo_store.retire_disconnect_marker(),
                DisconnectRetirement::RecoveryProgress => Ok(()),
            } {
                return Err(CheckpointError::Store(
                    bitcoin_rs_storage::checkpoint::CheckpointError::Invalid(error.to_string()),
                ));
            }
        }
        if let (CheckpointWrite::Published { reference }, Some(witness)) = (&written, stage_witness)
            && let Some(cell) = &self.seed_offer
            && cell.is_wanted()
        {
            Self::offer_committed_seed(&self.checkpoint_data_dir, cell, *reference, witness);
        }
        self.durable_tip_height
            .store(applied_tip.map_or(0, |tip| tip.height), Ordering::Release);
        Ok(written)
    }

    fn offer_committed_seed(
        _checkpoint_data_dir: &cap_std::fs::Dir,
        _cell: &SeedOfferCell,
        _reference: bitcoin_rs_storage::checkpoint::CheckpointReference,
        _witness: V4Witness,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::retire_full_revalidation_marker;
    use crate::checkpoint::CheckpointError;
    use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;

    use crate::test_fixtures::{TestError, TestResult};

    #[test]
    fn full_revalidation_marker_clears_after_checkpoint_publication() -> TestResult {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join(FULL_REVALIDATION_MARKER);
        std::fs::write(&marker, b"force full validation\n")?;

        retire_full_revalidation_marker(dir.path())?;

        assert!(!marker.exists());
        Ok(())
    }

    #[test]
    fn marker_clear_io_is_classified_as_retryable_marker_error() -> TestResult {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir(dir.path().join(FULL_REVALIDATION_MARKER))?;

        let error = match retire_full_revalidation_marker(dir.path()) {
            Err(error) => error,
            Ok(()) => {
                return Err(TestError::UnexpectedSuccess(
                    "removing a directory at the marker path must fail",
                ));
            }
        };
        assert!(matches!(error, CheckpointError::FullRevalidationMarker(_)));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn committed_fifo_does_not_block_or_seal() -> TestResult {
        use std::os::unix::fs::FileTypeExt as _;

        let set = bitcoin_rs_storage::utxo::UtxoSet::new();
        let tip = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[0_u8; 32]);
        let mut encoded = Vec::new();
        let (_, (), witness) = bitcoin_rs_storage::utxo::snapshot::write_snapshot_witnessed(
            &set,
            &tip,
            0,
            &mut encoded,
            (),
        )?;
        let Some(witness) = witness else {
            return Err(TestError::UnexpectedSuccess(
                "empty snapshot must mint a witness",
            ));
        };
        let reference = bitcoin_rs_storage::checkpoint::CheckpointReference {
            generation: 0,
            manifest_sha256: [0_u8; 32],
        };

        let dir = tempfile::tempdir()?;
        let generation_path = dir
            .path()
            .join(bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT)
            .join("gen-00000000000000000000");
        std::fs::create_dir_all(&generation_path)?;
        let fifo_path = generation_path.join("seed.fifo");
        let created = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()?;
        assert!(created.success(), "create isolated Unix FIFO");

        let cap_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(dir.path())?;
        let worker_dir = cap_dir.try_clone()?;
        let cell: bitcoin_rs_storage::utxo::snapshot::SeedOfferCell =
            std::sync::Arc::new(bitcoin_rs_storage::utxo::snapshot::SeedSlot::new());
        cell.want();
        let worker_cell = cell.clone();

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            super::CheckpointPublisher::offer_committed_seed(
                &worker_dir,
                &worker_cell,
                reference,
                witness,
            );
            let _receiver_gone = sender.send(());
        });
        let observed = receiver.recv_timeout(std::time::Duration::from_secs(5));
        let rescue: Option<std::io::Result<cap_std::fs::File>> = if observed.is_err() {
            use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
            let mut options = cap_std::fs::OpenOptions::new();
            options
                .read(true)
                .write(true)
                .follow(FollowSymlinks::No)
                .nonblock(true);
            Some(cap_dir.open_with(
                format!(
                    "{}/gen-00000000000000000000/seed.fifo",
                    bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT
                ),
                &options,
            ))
        } else {
            None
        };
        let join_result = worker.join();
        let rescue = match rescue {
            Some(Ok(file)) => Some(file),
            Some(Err(error)) => return Err(error.into()),
            None => None,
        };
        join_result.map_err(|_| TestError::WorkerPanicked("checkpoint seed worker panicked"))?;
        drop(rescue);
        observed.map_err(|_| TestError::Blocked("committed FIFO open must not block"))?;
        assert!(cell.take().is_none(), "committed FIFO must not seal");
        assert!(
            std::fs::symlink_metadata(&fifo_path)?.file_type().is_fifo(),
            "substituted FIFO is preserved, not consumed"
        );
        Ok(())
    }
}
