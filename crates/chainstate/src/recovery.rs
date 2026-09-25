//! Checkpoint selection, journal replay, and fail-closed startup recovery.

use crate::{ChainstateJournalConfig, JournalBootstrap};
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_utxo::UtxoSet;
use std::path::Path;

/// Threshold for classifying a restored checkpoint as catastrophically stale.
///
/// A checkpoint restore more than this many blocks behind the durable
/// applied-tip witness is a catastrophic rollback, not a routine resume.
/// The restore is still accepted — the chainstate is valid — but the node
/// logs at ERROR and the warning snapshot carries the gap so operators
/// and RPC consumers can see the node is starting far behind where it was.
pub const STALE_RESTORE_ERROR_THRESHOLD: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Source selected for the initial authoritative chainstate.
pub enum ResumeSource {
    /// No recoverable checkpoint existed.
    Cold,
    /// State came directly from a full checkpoint.
    Checkpoint,
    /// State came from checkpoint plus committed journal replay.
    Journal,
}

/// Directory name containing the chainstate journal.
pub const CHAINSTATE_JOURNAL_DIR: &str = bitcoin_rs_storage::chainstate_journal::JOURNAL_DIR_NAME;

/// Returns whether startup must ignore incremental recovery and fully revalidate.
pub fn requires_full_revalidation(data_dir: &Path) -> bool {
    data_dir
        .join(CHAINSTATE_JOURNAL_DIR)
        .join(bitcoin_rs_storage::chainstate_journal::FULL_REVALIDATION_MARKER)
        .is_file()
}

/// Fully recovered state ready for runtime composition.
pub struct InitialChainstate {
    /// Recovered UTXO set.
    pub utxo: UtxoSet,
    /// Recovered coin statistics.
    pub coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    /// Recovered block tree.
    pub tree: bitcoin_rs_chain::BlockTree,
    /// Recovered applied tip, absent on a cold start.
    pub applied_tip: Option<TipSnapshot>,
    /// Recovery source selected at startup.
    pub resume_source: ResumeSource,
    /// Journal writer bootstrap, when journaling is enabled.
    pub journal_bootstrap: Option<JournalBootstrap>,
}

fn reset_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove {}", path.display())),
    }
    std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    bitcoin_rs_storage::checkpoint::fs::open_data_dir(&path)
        .with_context(|| format!("open {}", path.display()))
}

/// Opens or creates the chainstate journal directory.
pub fn open_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    bitcoin_rs_storage::checkpoint::fs::open_data_dir(&path)
        .with_context(|| format!("open {}", path.display()))
}

fn restored_initial(
    restored: crate::checkpoint::RestoredChainstate,
    config: ChainstateJournalConfig,
    open_existing: bool,
    resume_source: ResumeSource,
) -> Result<InitialChainstate> {
    let journal_bootstrap = if config.enabled {
        let node = restored.tree.node(restored.applied_tip.tip_id)?;
        let prev_hash = match node.parent {
            Some(parent) => restored.tree.node(parent)?.hash.to_le_bytes(),
            None => [0_u8; 32],
        };
        Some(JournalBootstrap {
            open_existing,
            base_generation: restored.generation,
            height: restored.applied_tip.height,
            block_hash: restored.applied_tip.hash.to_le_bytes(),
            prev_hash,
            chain_tx_count: restored.chain_tx_count,
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
        resume_source,
        journal_bootstrap,
    })
}

fn cold_initial_chainstate(
    data_dir: &Path,
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
    reset_journal: bool,
) -> Result<InitialChainstate> {
    if journal_config.enabled && reset_journal {
        drop(reset_journal_dir(data_dir)?);
    }
    Ok(InitialChainstate {
        utxo: UtxoSet::new(),
        coin_stats: bitcoin_rs_utxo::stats::CoinStats::default(),
        tree: bitcoin_rs_chain::BlockTree::new(),
        applied_tip: None,
        resume_source: ResumeSource::Cold,
        journal_bootstrap: journal_config.enabled.then_some(JournalBootstrap {
            open_existing: false,
            base_generation: 0,
            height: 0,
            block_hash: network.genesis_block_hash().to_le_bytes(),
            prev_hash: [0_u8; 32],
            chain_tx_count: 1,
            config: journal_config,
        }),
    })
}

#[allow(clippy::too_many_lines)]
/// Recovers the initial authoritative state from checkpoint and journal evidence.
pub fn prepare_initial_chainstate(
    data_dir: &Path,
    network: bitcoin_rs_primitives::Network,
    journal_config: ChainstateJournalConfig,
) -> Result<InitialChainstate> {
    let checkpoint_data_dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir)
        .with_context(|| format!("open data_dir {}", data_dir.display()))?;
    bitcoin_rs_storage::checkpoint::fs::ensure_current_schema(&checkpoint_data_dir)
        .with_context(|| format!("validate CURRENT_SCHEMA for datadir {}", data_dir.display()))?;
    let checkpoint_config = crate::checkpoint::headers::HeaderCheckpointConfig {
        network,
        genesis: network.genesis_block_hash(),
    };
    let checkpoint_load =
        crate::checkpoint::load_checkpoint_from_dir(&checkpoint_data_dir, checkpoint_config)?;
    if requires_full_revalidation(data_dir) {
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
        return cold_initial_chainstate(data_dir, network, journal_config, false);
    }
    let crate::checkpoint::CheckpointLoad::Complete(restored) = checkpoint_load else {
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
        return cold_initial_chainstate(data_dir, network, journal_config, true);
    };
    let restored = *restored;
    if !journal_config.enabled {
        tracing::info!(
            restore_source = "checkpoint",
            height = restored.applied_tip.height,
            hash = %restored.applied_tip.hash,
            chain_tx_count = restored.chain_tx_count,
            reason = "journal_disabled",
            "chainstate restore selected"
        );
        return restored_initial(restored, journal_config, false, ResumeSource::Checkpoint);
    }

    let base_generation = restored.generation;
    let base_height = restored.applied_tip.height;
    let journal_dir = open_journal_dir(data_dir)?;
    let replay_started = std::time::Instant::now();
    let replay = crate::journal::replay_from_journal(
        &journal_dir,
        base_generation,
        restored.tree,
        restored.utxo,
        restored.coin_stats,
        restored.applied_tip,
        restored.chain_tx_count,
    );
    let replay_seconds = replay_started.elapsed().as_secs_f64();
    metrics::histogram!("node.chainstate_journal.replay_seconds").record(replay_seconds);
    drop(journal_dir);
    match replay {
        Ok(replayed) => {
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
                chain_tx_count = replayed.chain_tx_count,
                replay_seconds,
                "chainstate restore selected"
            );
            let bootstrap = JournalBootstrap {
                open_existing: true,
                base_generation,
                height: replayed.applied_tip.height,
                block_hash: replayed.applied_tip.hash.to_le_bytes(),
                prev_hash: [0_u8; 32],
                chain_tx_count: replayed.chain_tx_count,
                config: journal_config,
            };
            Ok(InitialChainstate {
                utxo: replayed.utxo,
                coin_stats: replayed.coin_stats,
                tree: replayed.tree,
                applied_tip: Some(replayed.applied_tip),
                resume_source,
                journal_bootstrap: Some(bootstrap),
            })
        }
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
            drop(reset_journal_dir(data_dir)?);
            let reloaded = crate::checkpoint::load_checkpoint_from_dir(
                &checkpoint_data_dir,
                checkpoint_config,
            )?;
            let crate::checkpoint::CheckpointLoad::Complete(reloaded) = reloaded else {
                bail!("checkpoint disappeared while recovering from journal fallback");
            };
            restored_initial(*reloaded, journal_config, false, ResumeSource::Checkpoint)
        }
    }
}
