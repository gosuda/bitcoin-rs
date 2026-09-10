//! Checkpoint selection, journal replay, and fail-closed startup recovery.

use super::storage::JournalBootstrap;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_utxo::UtxoSet;
use std::path::Path;

/// A checkpoint restore more than this many blocks behind the durable
/// applied-tip witness is a catastrophic rollback, not a routine resume.
/// The restore is still accepted — the chainstate is valid — but the node
/// logs at ERROR and the warning snapshot carries the gap so operators
/// and RPC consumers can see the node is starting far behind where it was.
pub(super) const STALE_RESTORE_ERROR_THRESHOLD: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeSource {
    Cold,
    Checkpoint,
    Journal,
}

pub(crate) const CHAINSTATE_JOURNAL_DIR: &str = crate::chainstate_journal::JOURNAL_DIR_NAME;

pub(super) fn requires_full_revalidation(data_dir: &Path) -> bool {
    data_dir
        .join(CHAINSTATE_JOURNAL_DIR)
        .join(crate::chainstate_journal::FULL_REVALIDATION_MARKER)
        .is_file()
}

pub(super) struct InitialChainstate {
    pub(super) utxo: UtxoSet,
    pub(super) coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    pub(super) tree: bitcoin_rs_chain::BlockTree,
    pub(super) applied_tip: Option<TipSnapshot>,
    pub(super) chain_tx_count: u64,
    pub(super) resume_source: ResumeSource,
    pub(super) journal_bootstrap: Option<JournalBootstrap>,
}

fn reset_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove {}", path.display())),
    }
    std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    crate::checkpoint_fs::open_data_dir(&path).with_context(|| format!("open {}", path.display()))
}

pub(super) fn open_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    crate::checkpoint_fs::open_data_dir(&path).with_context(|| format!("open {}", path.display()))
}

fn checkpoint_bootstrap(
    restored: &crate::checkpoint::RestoredChainstate,
    config: crate::config::ChainstateJournalConfig,
    open_existing: bool,
) -> Result<JournalBootstrap> {
    let node = restored.tree.node(restored.applied_tip.tip_id)?;
    let prev_hash = match node.parent {
        Some(parent) => restored.tree.node(parent)?.hash.to_le_bytes(),
        None => [0_u8; 32],
    };
    Ok(JournalBootstrap {
        open_existing,
        base_generation: restored.generation,
        height: restored.applied_tip.height,
        block_hash: restored.applied_tip.hash.to_le_bytes(),
        prev_hash,
        chain_tx_count: restored.chain_tx_count,
        config,
    })
}

fn restored_initial(
    restored: crate::checkpoint::RestoredChainstate,
    config: crate::config::ChainstateJournalConfig,
    open_existing: bool,
    resume_source: ResumeSource,
) -> Result<InitialChainstate> {
    let journal_bootstrap = config
        .enabled
        .then(|| checkpoint_bootstrap(&restored, config, open_existing))
        .transpose()?;
    Ok(InitialChainstate {
        utxo: restored.utxo,
        coin_stats: restored.coin_stats,
        tree: restored.tree,
        applied_tip: Some(restored.applied_tip),
        chain_tx_count: restored.chain_tx_count,
        resume_source,
        journal_bootstrap,
    })
}

fn cold_initial_chainstate(
    config: &NodeConfig,
    journal_config: crate::config::ChainstateJournalConfig,
    reset_journal: bool,
) -> Result<InitialChainstate> {
    if journal_config.enabled && reset_journal {
        drop(reset_journal_dir(&config.data_dir)?);
    }
    Ok(InitialChainstate {
        utxo: UtxoSet::new(),
        coin_stats: bitcoin_rs_utxo::stats::CoinStats::default(),
        tree: bitcoin_rs_chain::BlockTree::new(),
        applied_tip: None,
        chain_tx_count: 0,
        resume_source: ResumeSource::Cold,
        journal_bootstrap: journal_config.enabled.then_some(JournalBootstrap {
            open_existing: false,
            base_generation: 0,
            height: 0,
            block_hash: config.network.genesis_block_hash().to_le_bytes(),
            prev_hash: [0_u8; 32],
            chain_tx_count: 1,
            config: journal_config,
        }),
    })
}

pub(super) fn prepare_initial_chainstate(
    checkpoint_load: crate::checkpoint::CheckpointLoad,
    checkpoint_data_dir: &cap_std::fs::Dir,
    checkpoint_config: crate::checkpoint::headers::HeaderCheckpointConfig,
    config: &NodeConfig,
) -> Result<InitialChainstate> {
    let journal_config = config.chainstate_journal;
    if requires_full_revalidation(&config.data_dir) {
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
        return cold_initial_chainstate(config, journal_config, false);
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
        return cold_initial_chainstate(config, journal_config, true);
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

    replay_checkpoint_journal(
        restored,
        checkpoint_data_dir,
        checkpoint_config,
        config,
        journal_config,
    )
}

fn replay_checkpoint_journal(
    restored: crate::checkpoint::RestoredChainstate,
    checkpoint_data_dir: &cap_std::fs::Dir,
    checkpoint_config: crate::checkpoint::headers::HeaderCheckpointConfig,
    config: &NodeConfig,
    journal_config: crate::config::ChainstateJournalConfig,
) -> Result<InitialChainstate> {
    let base_generation = restored.generation;
    let base_height = restored.applied_tip.height;
    let journal_dir = open_journal_dir(&config.data_dir)?;
    let replay_started = std::time::Instant::now();
    let replay = crate::chainstate_journal::replay_from_journal(
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
        crate::chainstate_journal::ReplayOutcome::Replayed(replayed) => {
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
                chain_tx_count: replayed.chain_tx_count,
                resume_source,
                journal_bootstrap: Some(bootstrap),
            })
        }
        crate::chainstate_journal::ReplayOutcome::Fallback(error) => {
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
            drop(reset_journal_dir(&config.data_dir)?);
            let reloaded = crate::checkpoint::load_checkpoint_from_dir(
                checkpoint_data_dir,
                checkpoint_config,
            )?;
            let crate::checkpoint::CheckpointLoad::Complete(reloaded) = reloaded else {
                bail!("checkpoint disappeared while recovering from journal fallback");
            };
            restored_initial(*reloaded, journal_config, false, ResumeSource::Checkpoint)
        }
    }
}
