use arc_swap::ArcSwapOption;

use crate::chain::{BlockTree, TipSnapshot};

use bitcoin_rs_consensus::primitives::Hash256;

use bitcoin_rs_storage::DisconnectPhase;
use bitcoin_rs_storage::block_body::BlockBodyStore;

use bitcoin_rs_storage::utxo::stats::CoinStatsListener;

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
    pub(crate) coin_stats: Arc<CoinStatsListener>,

    pub(crate) data_dir: PathBuf,
    pub(crate) chain_events: Arc<ChainEventPublisher>,
    pub(crate) durable_tip_height: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) store: Arc<dyn bitcoin_rs_storage::KvStore>,
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
        let written = checkpoint::write_checkpoint_with_store(
            &self.checkpoint_data_dir,
            header_config,
            &self.block_tree,
            &self.coin_stats,
            applied_tip,
            checkpoint::CheckpointStoreTarget {
                store: self.store.as_ref(),
                host_data_dir: &self.data_dir,
            },
        )?;
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
        self.durable_tip_height
            .store(applied_tip.map_or(0, |tip| tip.height), Ordering::Release);
        Ok(written)
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
}
