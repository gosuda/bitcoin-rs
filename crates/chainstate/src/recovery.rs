use crate::{ChainstateJournalConfig, JournalBootstrap};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_storage::ScriptAttestation;
use bitcoin_rs_storage::chainstate_journal::JournalWriterError;
use bitcoin_rs_storage::checkpoint::CheckpointLoadError;
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::snapshot::VerifiedSnapshotArtifact;
use std::path::{Path, PathBuf};

use crate::assumeutxo_snapshot::SnapshotArchiveError;

pub const STALE_RESTORE_ERROR_THRESHOLD: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeSource {
    Snapshot,
    Cold,
    Checkpoint,
    Journal,
}

pub const CHAINSTATE_JOURNAL_DIR: &str = bitcoin_rs_storage::chainstate_journal::JOURNAL_DIR_NAME;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointLoadError),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotArchiveError),
    #[error("read the script attestation of the durable head")]
    AttestationRead {
        #[source]
        source: bitcoin_rs_storage::StorageError,
    },
    #[error("mark the datadir for full revalidation")]
    MarkFullRevalidation {
        #[source]
        source: JournalWriterError,
    },
    #[error("remove {path}")]
    RemoveJournalDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("create {path}")]
    CreateJournalDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("open {path}")]
    OpenJournalDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("open data_dir {path}")]
    OpenDataDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("validate CURRENT_SCHEMA for datadir {path}")]
    ValidateSchema {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("snapshot-base checkpoint does not match the pinned commitment/count")]
    PinnedCheckpointMismatch,
    #[error("checkpoint disappeared while recovering from journal fallback")]
    CheckpointDisappeared,
    #[error(
        "full validation requires an unpruned datadir; restart with --validation-mode assume-valid or resync"
    )]
    PrunedDatadirNeedsFullValidation,
}

pub fn requires_full_revalidation(data_dir: &Path) -> bool {
    data_dir
        .join(CHAINSTATE_JOURNAL_DIR)
        .join(bitcoin_rs_storage::chainstate_journal::FULL_REVALIDATION_MARKER)
        .is_file()
}

pub fn require_full_script_attestation(
    data_dir: &Path,
    mode: crate::ValidationMode,
    head: Option<&bitcoin_rs_storage::DurableHead>,
    store: &dyn bitcoin_rs_storage::DurableHeadStore,
    pruned: bool,
) -> Result<(), RecoveryError> {
    let (crate::ValidationMode::Full, Some(head)) = (mode, head) else {
        return Ok(());
    };
    let attested = store
        .load_attestation(head)
        .map_err(|source| RecoveryError::AttestationRead { source })?;
    if attested >= ScriptAttestation::Full {
        return Ok(());
    }
    if pruned {
        return Err(RecoveryError::PrunedDatadirNeedsFullValidation);
    }
    tracing::warn!(
        attested = ?attested,
        "the stored chain was not fully script-validated; rebuilding it with full validation"
    );
    bitcoin_rs_storage::chainstate_journal::mark_full_revalidation_at(data_dir)
        .map_err(|source| RecoveryError::MarkFullRevalidation { source })?;
    Ok(())
}

pub struct InitialChainstate {
    pub utxo: UtxoSet,
    pub coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    pub tree: bitcoin_rs_chain::BlockTree,
    pub applied_tip: Option<TipSnapshot>,
    pub resume_source: ResumeSource,
    pub journal_bootstrap: Option<JournalBootstrap>,
    pub script_live_seed: Option<VerifiedSnapshotArtifact>,
}

fn reset_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir, RecoveryError> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(RecoveryError::RemoveJournalDir { path, source });
        }
    }
    open_journal_dir(data_dir)
}

pub fn open_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir, RecoveryError> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    std::fs::create_dir_all(&path).map_err(|source| RecoveryError::CreateJournalDir {
        path: path.clone(),
        source,
    })?;
    bitcoin_rs_storage::checkpoint::fs::open_data_dir(&path)
        .map_err(|source| RecoveryError::OpenJournalDir { path, source })
}

fn restored_initial(
    restored: crate::checkpoint::RestoredChainstate,
    config: ChainstateJournalConfig,
) -> Result<InitialChainstate, RecoveryError> {
    let journal_bootstrap = if config.enabled {
        let node = restored.tree.node(restored.applied_tip.tip_id)?;
        let prev_hash = match node.parent {
            Some(parent) => restored.tree.node(parent)?.hash.to_le_bytes(),
            None => [0_u8; 32],
        };
        Some(JournalBootstrap {
            open_existing: false,
            base_generation: restored.generation,
            height: restored.applied_tip.height,
            block_hash: restored.applied_tip.hash.to_le_bytes(),
            prev_hash,
            chain_tx_count: restored.applied_tip.chain_tx_count.to_wire(),
            config,
        })
    } else {
        None
    };
    Ok(InitialChainstate {
        utxo: restored.utxo,
        coin_stats: restored.coin_stats,
        tree: restored.tree,
        applied_tip: Some(restored.applied_tip),
        resume_source: ResumeSource::Checkpoint,
        journal_bootstrap,
        script_live_seed: restored.seed,
    })
}

pub(crate) fn restore_snapshot(
    data_dir: &Path,
    network: bitcoin_rs_primitives::Network,
    pinned: &bitcoin_rs_primitives::AssumeUtxoData,
) -> Result<InitialChainstate, RecoveryError> {
    let config = crate::checkpoint::headers::HeaderCheckpointConfig {
        network,
        genesis: network.genesis_block_hash(),
    };
    let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir)?;
    if let crate::checkpoint::CheckpointLoad::Complete(restored) =
        crate::checkpoint::load_checkpoint_from_dir(&data, config)?
    {
        let compatible = restored
            .tree
            .node_at_height_from(restored.applied_tip.tip_id, pinned.height)
            .and_then(|id| restored.tree.node(id).ok())
            .is_some_and(|node| node.hash == pinned.block_hash);
        if compatible {
            if restored.applied_tip.height == pinned.height
                && (restored
                    .utxo
                    .lock_stable_view()
                    .hash_serialized_3_at_height(pinned.height)?
                    != pinned.hash_serialized
                    || restored.applied_tip.chain_tx_count.to_wire() != pinned.chain_tx_count)
            {
                return Err(RecoveryError::PinnedCheckpointMismatch);
            }
            return restored_initial(
                *restored,
                ChainstateJournalConfig {
                    enabled: false,
                    ..ChainstateJournalConfig::default()
                },
            );
        }
    }
    crate::assumeutxo_snapshot::load_verified(data_dir, network, pinned)
        .map_err(RecoveryError::from)
}

fn cold_initial_chainstate(
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
) -> InitialChainstate {
    InitialChainstate {
        utxo: UtxoSet::new(),
        coin_stats: bitcoin_rs_utxo::stats::CoinStats::default(),
        tree: bitcoin_rs_chain::BlockTree::new(),
        applied_tip: None,
        resume_source: ResumeSource::Cold,
        script_live_seed: None,
        journal_bootstrap: journal_config.enabled.then_some(JournalBootstrap {
            open_existing: false,
            base_generation: 0,
            height: 0,
            block_hash: network.genesis_block_hash().to_le_bytes(),
            prev_hash: [0_u8; 32],
            chain_tx_count: 1,
            config: journal_config,
        }),
    }
}

fn discard_journal_and_start_cold(
    data_dir: &Path,
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
) -> Result<InitialChainstate, RecoveryError> {
    if journal_config.enabled {
        drop(reset_journal_dir(data_dir)?);
    }
    Ok(cold_initial_chainstate(network, journal_config))
}

fn open_checkpoint_data_dir(data_dir: &Path) -> Result<cap_std::fs::Dir, RecoveryError> {
    let checkpoint_data_dir =
        bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir).map_err(|source| {
            RecoveryError::OpenDataDir {
                path: data_dir.to_path_buf(),
                source,
            }
        })?;
    bitcoin_rs_storage::checkpoint::fs::ensure_current_schema(&checkpoint_data_dir).map_err(
        |source| RecoveryError::ValidateSchema {
            path: data_dir.to_path_buf(),
            source,
        },
    )?;
    Ok(checkpoint_data_dir)
}

fn header_checkpoint_config(
    network: bitcoin_rs_primitives::Network,
) -> crate::checkpoint::headers::HeaderCheckpointConfig {
    crate::checkpoint::headers::HeaderCheckpointConfig {
        network,
        genesis: network.genesis_block_hash(),
    }
}

fn full_revalidation_cold_start(
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
) -> InitialChainstate {
    metrics::counter!(
        "node.chainstate_journal.fallback_total",
        "reason" => "full_revalidation_marker"
    )
    .increment(1);
    tracing::warn!(
        restore_source = "cold",
        reason = "fork_below_checkpoint_base",
        "chainstate restore requires full validation"
    );
    cold_initial_chainstate(network, journal_config)
}

fn no_checkpoint_cold_start(
    data_dir: &Path,
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
) -> Result<InitialChainstate, RecoveryError> {
    if journal_config.enabled {
        metrics::counter!(
            "node.chainstate_journal.fallback_total",
            "reason" => "no_checkpoint"
        )
        .increment(1);
    }
    tracing::info!(
        restore_source = "cold",
        reason = "no_complete_checkpoint",
        "chainstate restore selected"
    );
    discard_journal_and_start_cold(data_dir, network, journal_config)
}

fn checkpoint_without_journal(
    restored: crate::checkpoint::RestoredChainstate,
    journal_config: ChainstateJournalConfig,
) -> Result<InitialChainstate, RecoveryError> {
    tracing::info!(
        restore_source = "checkpoint",
        height = restored.applied_tip.height,
        hash = %restored.applied_tip.hash,
        chain_tx_count = restored.applied_tip.chain_tx_count.to_wire(),
        reason = "journal_disabled",
        "chainstate restore selected"
    );
    restored_initial(restored, journal_config)
}

fn recover_checkpoint(
    data_dir: &Path,
    checkpoint_data_dir: &cap_std::fs::Dir,
    checkpoint_config: crate::checkpoint::headers::HeaderCheckpointConfig,
    journal_config: ChainstateJournalConfig,
) -> Result<InitialChainstate, RecoveryError> {
    drop(reset_journal_dir(data_dir)?);
    let reloaded =
        crate::checkpoint::load_checkpoint_from_dir(checkpoint_data_dir, checkpoint_config)?;
    let crate::checkpoint::CheckpointLoad::Complete(reloaded) = reloaded else {
        return Err(RecoveryError::CheckpointDisappeared);
    };
    restored_initial(*reloaded, journal_config)
}

fn replay_checkpoint_journal(
    data_dir: &Path,
    checkpoint_data_dir: &cap_std::fs::Dir,
    checkpoint_config: crate::checkpoint::headers::HeaderCheckpointConfig,
    journal_config: ChainstateJournalConfig,
    restored: crate::checkpoint::RestoredChainstate,
) -> Result<InitialChainstate, RecoveryError> {
    let crate::checkpoint::RestoredChainstate {
        generation: base_generation,
        tree,
        utxo,
        coin_stats,
        applied_tip,
        seed,
    } = restored;
    let base_height = applied_tip.height;
    let journal_dir = open_journal_dir(data_dir)?;
    let replay_started = std::time::Instant::now();
    let replay = crate::journal::replay_from_journal(
        &journal_dir,
        base_generation,
        tree,
        utxo,
        coin_stats,
        applied_tip,
    );
    let replay_seconds = replay_started.elapsed().as_secs_f64();
    drop(journal_dir);
    let replayed = match replay {
        Ok(replayed) => replayed,
        Err(error) => {
            let reason = error.reason();
            metrics::counter!(
                "node.chainstate_journal.fallback_total",
                "reason" => reason
            )
            .increment(1);
            if error.is_checksum_failure() {
                metrics::counter!("node.chainstate_journal.checksum_failures_total").increment(1);
            }
            tracing::warn!(
                restore_source = "checkpoint",
                checkpoint_generation = base_generation,
                checkpoint_height = base_height,
                reason,
                %error,
                replay_seconds,
                "chainstate journal rejected; checkpoint recovery selected"
            );
            return recover_checkpoint(
                data_dir,
                checkpoint_data_dir,
                checkpoint_config,
                journal_config,
            );
        }
    };
    Ok(replayed_initial(
        *replayed,
        base_generation,
        base_height,
        replay_seconds,
        journal_config,
        seed,
    ))
}

fn replayed_initial(
    replayed: crate::journal::ReplayedState,
    base_generation: u64,
    base_height: u32,
    replay_seconds: f64,
    journal_config: ChainstateJournalConfig,
    seed: Option<VerifiedSnapshotArtifact>,
) -> InitialChainstate {
    let replayed_records = replayed.applied_tip.height.saturating_sub(base_height);
    let (restore_source, resume_source) = if replayed_records == 0 {
        ("checkpoint", ResumeSource::Checkpoint)
    } else {
        ("journal", ResumeSource::Journal)
    };
    tracing::info!(
        restore_source,
        checkpoint_generation = base_generation,
        checkpoint_height = base_height,
        height = replayed.applied_tip.height,
        hash = %replayed.applied_tip.hash,
        replayed_records,
        chain_tx_count = replayed.applied_tip.chain_tx_count.to_wire(),
        replay_seconds,
        "chainstate restore selected"
    );
    let bootstrap = JournalBootstrap {
        open_existing: true,
        base_generation,
        height: replayed.applied_tip.height,
        block_hash: replayed.applied_tip.hash.to_le_bytes(),
        prev_hash: [0_u8; 32],
        chain_tx_count: replayed.applied_tip.chain_tx_count.to_wire(),
        config: journal_config,
    };
    InitialChainstate {
        utxo: replayed.utxo,
        coin_stats: replayed.coin_stats,
        tree: replayed.tree,
        applied_tip: Some(replayed.applied_tip),
        resume_source,
        journal_bootstrap: Some(bootstrap),
        script_live_seed: seed,
    }
}

pub fn prepare_initial_chainstate(
    data_dir: &Path,
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
    durable_head: Option<&bitcoin_rs_storage::DurableHead>,
) -> Result<InitialChainstate, RecoveryError> {
    let checkpoint_data_dir = open_checkpoint_data_dir(data_dir)?;
    let anchor = durable_head
        .map(|head| crate::assumeutxo_snapshot::trusted_anchor(network, &head.assumeutxo))
        .transpose()?
        .flatten();
    let checkpoint_config = header_checkpoint_config(network);
    if requires_full_revalidation(data_dir) {
        return Ok(full_revalidation_cold_start(network, journal_config));
    }
    if let Some(pinned) = anchor {
        return restore_snapshot(data_dir, network, pinned);
    }
    let checkpoint_load =
        crate::checkpoint::load_checkpoint_from_dir(&checkpoint_data_dir, checkpoint_config)?;
    let crate::checkpoint::CheckpointLoad::Complete(restored) = checkpoint_load else {
        return no_checkpoint_cold_start(data_dir, network, journal_config);
    };
    let restored = *restored;
    if !journal_config.enabled {
        return checkpoint_without_journal(restored, journal_config);
    }
    replay_checkpoint_journal(
        data_dir,
        &checkpoint_data_dir,
        checkpoint_config,
        journal_config,
        restored,
    )
}
