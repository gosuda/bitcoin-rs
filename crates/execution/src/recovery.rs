use crate::chain::TipSnapshot;
use bitcoin_rs_storage::ScriptAttestation;
use bitcoin_rs_storage::checkpoint::CheckpointLoadError;
use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::snapshot::VerifiedSnapshotArtifact;
use std::path::{Path, PathBuf};

use crate::assumeutxo_snapshot::SnapshotArchiveError;

pub const STALE_RESTORE_ERROR_THRESHOLD: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeSource {
    Snapshot,
    Cold,
    Checkpoint,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointLoadError),
    #[error(transparent)]
    Chain(#[from] crate::chain::ChainError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotArchiveError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error("read the script attestation of the durable head")]
    AttestationRead {
        #[source]
        source: bitcoin_rs_storage::StorageError,
    },
    #[error("mark the datadir for full revalidation")]
    MarkFullRevalidation {
        #[source]
        source: bitcoin_rs_storage::recovery_evidence::EvidenceError,
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
    #[error(
        "full validation requires an unpruned datadir; restart with --validation-mode assume-valid or resync"
    )]
    PrunedDatadirNeedsFullValidation,
    #[error(
        "full validation cannot revalidate an assumeutxo datadir that is still validating its historical suffix; restart with --validation-mode assume-valid or resync"
    )]
    AssumeUtxoValidatingNeedsFullValidation,
}

pub fn requires_full_revalidation(data_dir: &Path) -> bool {
    data_dir.join(FULL_REVALIDATION_MARKER).is_file()
}

pub fn require_full_script_attestation(
    data_dir: &Path,
    mode: crate::ValidationMode,
    head: Option<&bitcoin_rs_storage::DurableHead>,
    store: &dyn bitcoin_rs_storage::DurableHeadStore,
    pruned: bool,
) -> Result<(), RecoveryError> {
    let Some(head) = head else {
        return Ok(());
    };
    if mode != crate::ValidationMode::Full {
        if let Ok(attested) = store.load_attestation(head)
            && attested < ScriptAttestation::Full
        {
            tracing::warn!(
                attested = ?attested,
                height = head.height,
                "the stored assume-valid chain is not fully script-validated; blocks the fast path skipped stay unverified"
            );
        }
        return Ok(());
    }
    let attested = store
        .load_attestation(head)
        .map_err(|source| RecoveryError::AttestationRead { source })?;
    if attested >= ScriptAttestation::Full {
        return Ok(());
    }
    if matches!(
        head.assumeutxo,
        bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Validating { .. }
    ) {
        return Err(RecoveryError::AssumeUtxoValidatingNeedsFullValidation);
    }
    if pruned {
        return Err(RecoveryError::PrunedDatadirNeedsFullValidation);
    }
    tracing::warn!(
        attested = ?attested,
        "the stored chain was not fully script-validated; rebuilding it with full validation"
    );
    bitcoin_rs_storage::recovery_evidence::mark_full_revalidation_at(data_dir)
        .map_err(|source| RecoveryError::MarkFullRevalidation { source })?;
    Ok(())
}

pub struct InitialChainstate {
    pub utxo: UtxoSet,
    pub coin_stats: bitcoin_rs_storage::utxo::stats::CoinStats,
    pub tree: crate::chain::BlockTree,
    pub applied_tip: Option<TipSnapshot>,
    pub resume_source: ResumeSource,
    pub script_live_seed: Option<VerifiedSnapshotArtifact>,
}

/// Restore source plus the checkpoint generation's engine snapshot.
///
/// `engine` carries the coin, undo and body-index rows the checkpointed engine
/// held at its head; `None` means cold (no engine image) and the restore wipes
/// the derived coin namespace so replay from genesis refills it.
pub struct RestoredState {
    pub initial: InitialChainstate,
    pub engine: Option<std::sync::Arc<dyn bitcoin_rs_storage::KvStore>>,
}

/// Installs a restored state into `chain` before any replayed block runs.
///
/// Warm: copies the checkpoint engine snapshot's rows into the chain engine
/// (every column family except `UtxoMeta`; the live durable head and its
/// attestation stay authoritative and are re-certified by replay). Cold: wipes
/// the derived coin namespace and leaves head, undo and body-index rows in
/// place. The resident UtxoSet is replaced but never seeds the engine.
pub fn install_restored_state(
    chain: &mut crate::Chainstate,
    restored: RestoredState,
    mode: crate::ValidationMode,
) -> Result<(), RecoveryError> {
    install_engine_checkpoint(chain, restored.engine.as_ref())?;
    chain.validation_mode = mode;
    chain.coin_stats = std::sync::Arc::new(
        bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(restored.initial.coin_stats),
    );
    let mut utxo = restored.initial.utxo;
    utxo.track_coin_stats((*chain.coin_stats).clone());
    chain.utxo = std::sync::Arc::new(utxo);
    *chain.block_tree.write() = restored.initial.tree;
    let tip_arc = restored.initial.applied_tip.map(std::sync::Arc::new);
    chain.applied_tip.store(tip_arc.clone());
    chain.chain_tip.store(tip_arc);
    chain.chain_events = std::sync::Arc::new(crate::events::ChainEventPublisher::detached(1));
    Ok(())
}

/// Installs a checkpoint's engine image into the chain engine before boot replay.
///
/// `Some(image)` copies the commit-batch families (`UndoData`, `BlockBodies`)
/// and the coin namespace (through `CoinStore`, so the resident cache stays
/// coherent) out of the image; `None` wipes the derived coin namespace so a
/// genesis replay refills it. The live durable head row is never touched.
pub fn install_engine_checkpoint(
    chain: &crate::Chainstate,
    engine: Option<&std::sync::Arc<dyn bitcoin_rs_storage::KvStore>>,
) -> Result<(), bitcoin_rs_storage::StorageError> {
    use bitcoin_rs_storage::ColumnFamily::{BlockBodies, Coins, UndoData};

    const KEY_SPACE_END: &[u8] = bitcoin_rs_storage::coins::COIN_KEYSPACE_END;
    /// Column families `CommitAuthority::commit_prefix` writes; nothing else
    /// in the engine belongs to the restored chain state.
    const COMMIT_BATCH_FAMILIES: [bitcoin_rs_storage::ColumnFamily; 2] = [UndoData, BlockBodies];
    let target = chain.commit_authority.store();
    let Some(snapshot) = engine else {
        target.delete_range(Coins, &[], KEY_SPACE_END)?;
        return chain.coins.ingest_sorted(std::iter::empty());
    };
    const HEIGHT_BYTES_START: usize = 1;
    let prune_line = bitcoin_rs_storage::pruning::load_pruneheight(&**target)?
        .or(
            bitcoin_rs_storage::pruning::load_executed_frontier(&**target)?
                .map(|frontier| frontier.height()),
        )
        .unwrap_or(0);
    let below_prune_line = |key: &[u8]| -> bool {
        let prefix = key.first().copied();
        prefix.is_some_and(|prefix| prefix == b'b' || prefix == b'u')
            && height_bytes(key, HEIGHT_BYTES_START).is_some_and(|height| height < prune_line)
    };
    let snap = snapshot.snapshot()?;
    for cf in COMMIT_BATCH_FAMILIES {
        let mut batch = target.new_batch();
        for pair in snap.iter_prefix(cf, &[])? {
            let (key, value) = pair?;
            if target.get(cf, &key)?.is_none() && !below_prune_line(&key) {
                batch.put(cf, &key, &value);
            }
        }
        target.write_durable(batch)?;
    }
    let rows = snap
        .iter_prefix(Coins, &[])?
        .map(|row| {
            let (key, value) = row?;
            Ok((
                bitcoin_rs_storage::CoinKey::from_slice(&key)?,
                bytes::Bytes::from(value),
            ))
        })
        .collect::<Result<Vec<_>, bitcoin_rs_storage::StorageError>>()?;
    let absent_rows: Vec<(bitcoin_rs_storage::CoinKey, bytes::Bytes)> = rows
        .into_iter()
        .filter_map(|(key, value)| match target.get(Coins, key.as_bytes()) {
            Ok(None) => Some(Ok((key, value))),
            Ok(Some(_)) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>, bitcoin_rs_storage::StorageError>>()?;
    chain.coins.ingest_sorted(absent_rows.into_iter())
}

fn height_bytes(key: &[u8], start: usize) -> Option<u32> {
    let end = start + 4;
    if key.len() < end {
        return None;
    }
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&key[start..end]);
    Some(u32::from_be_bytes(bytes))
}

fn restored_initial(
    restored: crate::checkpoint::RestoredChainstate,
) -> Result<InitialChainstate, RecoveryError> {
    Ok(InitialChainstate {
        utxo: restored.utxo,
        coin_stats: restored.coin_stats,
        tree: restored.tree,
        applied_tip: Some(restored.applied_tip),
        resume_source: ResumeSource::Checkpoint,
        script_live_seed: None,
    })
}

#[cfg_attr(not(test), expect(dead_code))]
pub(crate) fn restore_snapshot(
    data_dir: &Path,
    network: bitcoin_rs_consensus::primitives::Network,
    pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
) -> Result<InitialChainstate, RecoveryError> {
    Ok(restore_snapshot_with_engine(data_dir, network, pinned)?.initial)
}

fn restore_snapshot_with_engine(
    data_dir: &Path,
    network: bitcoin_rs_consensus::primitives::Network,
    pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
) -> Result<RestoredState, RecoveryError> {
    let config = header_checkpoint_config(network);
    let data = bitcoin_rs_storage::checkpoint::fs::open_data_dir(data_dir)?;
    if let crate::checkpoint::CheckpointLoad::Complete(restored) =
        crate::checkpoint::load_checkpoint_from_dir_with_path(
            &data,
            Some(data_dir),
            config,
            bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
        )?
    {
        let compatible = restored
            .tree
            .node_at_height_from(restored.applied_tip.tip_id, pinned.height)
            .and_then(|id| restored.tree.node(id).ok())
            .is_some_and(|node| node.hash == pinned.block_hash);
        if compatible {
            if restored.applied_tip.height == pinned.height {
                let coins_match = match restored.engine.as_ref() {
                    Some(image) => {
                        let snap = image.snapshot().map_err(RecoveryError::Storage)?;
                        let coins = bitcoin_rs_storage::utxo::UtxoSet::new();
                        for row in snap.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
                            let (_key, value) = row?;
                            coins.insert_parsed_record(
                                bitcoin_rs_storage::utxo::UtxoRecord::from_encoded(
                                    value.into_boxed_slice(),
                                )
                                .map_err(RecoveryError::Utxo)?,
                            );
                        }
                        coins
                            .lock_stable_view()
                            .hash_serialized_3_at_height(pinned.height)?
                            == pinned.hash_serialized
                    }
                    None => {
                        restored
                            .utxo
                            .lock_stable_view()
                            .hash_serialized_3_at_height(pinned.height)?
                            == pinned.hash_serialized
                    }
                };
                if !coins_match
                    || restored.applied_tip.chain_tx_count.to_wire() != pinned.chain_tx_count
                {
                    return Err(RecoveryError::PinnedCheckpointMismatch);
                }
            }
            let engine = restored.engine.clone();
            return Ok(RestoredState {
                initial: restored_initial(*restored)?,
                engine,
            });
        }
    }
    let initial = crate::assumeutxo_snapshot::load_verified(data_dir, network, pinned)
        .map_err(RecoveryError::from)?;
    Ok(RestoredState {
        initial,
        engine: None,
    })
}

fn cold_initial_chainstate(
    _network: bitcoin_rs_consensus::primitives::Network,
) -> InitialChainstate {
    InitialChainstate {
        utxo: UtxoSet::new(),
        coin_stats: bitcoin_rs_storage::utxo::stats::CoinStats::default(),
        tree: crate::chain::BlockTree::new(),
        applied_tip: None,
        resume_source: ResumeSource::Cold,
        script_live_seed: None,
    }
}

fn no_checkpoint_cold_start(
    _data_dir: &Path,
    network: bitcoin_rs_consensus::primitives::Network,
) -> Result<InitialChainstate, RecoveryError> {
    tracing::info!(
        restore_source = "cold",
        reason = "no_complete_checkpoint",
        "chainstate restore selected"
    );
    Ok(cold_initial_chainstate(network))
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
    network: bitcoin_rs_consensus::primitives::Network,
) -> crate::checkpoint::headers::HeaderCheckpointConfig {
    crate::checkpoint::headers::HeaderCheckpointConfig {
        network,
        genesis: network.genesis_block_hash(),
    }
}

fn full_revalidation_cold_start(
    network: bitcoin_rs_consensus::primitives::Network,
) -> InitialChainstate {
    tracing::warn!(
        restore_source = "cold",
        reason = "fork_below_checkpoint_base",
        "chainstate restore requires full validation"
    );
    cold_initial_chainstate(network)
}

pub fn prepare_initial_chainstate(
    data_dir: &Path,
    network: bitcoin_rs_consensus::primitives::Network,
    durable_head: Option<&bitcoin_rs_storage::DurableHead>,
) -> Result<InitialChainstate, RecoveryError> {
    Ok(prepare_initial_state_with_engine(data_dir, network, durable_head)?.initial)
}

pub fn prepare_initial_state_with_engine(
    data_dir: &Path,
    network: bitcoin_rs_consensus::primitives::Network,
    durable_head: Option<&bitcoin_rs_storage::DurableHead>,
) -> Result<RestoredState, RecoveryError> {
    let checkpoint_data_dir = open_checkpoint_data_dir(data_dir)?;
    let anchor = durable_head
        .map(|head| crate::assumeutxo_snapshot::trusted_anchor(network, &head.assumeutxo))
        .transpose()?
        .flatten();
    let checkpoint_config = header_checkpoint_config(network);
    if requires_full_revalidation(data_dir) {
        return Ok(RestoredState {
            initial: full_revalidation_cold_start(network),
            engine: None,
        });
    }
    if let Some(pinned) = anchor {
        return restore_snapshot_with_engine(data_dir, network, pinned);
    }
    let checkpoint_load = crate::checkpoint::load_checkpoint_from_dir_with_path(
        &checkpoint_data_dir,
        Some(data_dir),
        checkpoint_config,
        bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
    )?;
    let crate::checkpoint::CheckpointLoad::Complete(restored) = checkpoint_load else {
        return Ok(RestoredState {
            initial: no_checkpoint_cold_start(data_dir, network)?,
            engine: None,
        });
    };
    let engine = restored.engine.clone();
    Ok(RestoredState {
        initial: restored_initial(*restored)?,
        engine,
    })
}

pub struct ConvertedCheckpoint<'a> {
    pub headers: &'a [crate::chain::BlockHeader],
    pub tip_height: u32,
    pub tip_hash: bitcoin_rs_consensus::primitives::Hash256,
    pub chain_tx_count: u64,
    pub stats: bitcoin_rs_storage::utxo::stats::CoinStats,
}

#[derive(Debug, thiserror::Error)]
pub enum ConvertedCheckpointError {
    #[error("source checkpoint does not load")]
    Source(#[source] CheckpointLoadError),
    #[error("source datadir has no complete checkpoint to extend")]
    SourceNotComplete,
    #[error("suffix headers do not extend the source checkpoint tree")]
    Headers(#[source] crate::chain::ChainError),
    #[error("durable head {hash} at height {height} is missing from the header tree")]
    TipNotInTree { hash: String, height: u32 },
    #[error("header tree node height {tree} does not match the durable head height {head}")]
    HeightMismatch { tree: u32, head: u32 },
    #[error("checkpoint publication failed")]
    Publish(#[source] crate::CheckpointError),
    #[error("checkpoint publication skipped: no applied tip")]
    Skipped,
}

pub fn publish_converted_checkpoint(
    source_data_dir: &cap_std::fs::Dir,
    target_data_dir: &cap_std::fs::Dir,
    target_host_dir: &Path,
    network: bitcoin_rs_consensus::primitives::Network,
    checkpoint: ConvertedCheckpoint<'_>,
    engine: &dyn bitcoin_rs_storage::KvStore,
) -> Result<(), ConvertedCheckpointError> {
    let config = header_checkpoint_config(network);
    let source = match crate::checkpoint::load_conversion_source_from_dir(
        source_data_dir,
        config,
        bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT,
    )
    .map_err(ConvertedCheckpointError::Source)?
    {
        crate::checkpoint::CheckpointLoad::Complete(restored) => restored,
        crate::checkpoint::CheckpointLoad::Cold => {
            return Err(ConvertedCheckpointError::SourceNotComplete);
        }
    };
    let mut tree = source.tree;
    crate::chain::accept_headers(
        &mut tree,
        checkpoint.headers,
        network,
        0,
        crate::chain::HeaderValidationMode::HistoricalReplay,
    )
    .map_err(ConvertedCheckpointError::Headers)?;
    let tip_id =
        tree.lookup(checkpoint.tip_hash)
            .ok_or_else(|| ConvertedCheckpointError::TipNotInTree {
                hash: checkpoint.tip_hash.to_string_be(),
                height: checkpoint.tip_height,
            })?;
    let node = tree
        .node(tip_id)
        .map_err(ConvertedCheckpointError::Headers)?;
    if node.height != checkpoint.tip_height {
        return Err(ConvertedCheckpointError::HeightMismatch {
            tree: node.height,
            head: checkpoint.tip_height,
        });
    }
    let chainwork = node.chainwork;
    let hash = node.hash;
    let chain_tx_count = crate::chain::ChainTxCount::from_wire(checkpoint.chain_tx_count);
    tree.restore_chain_tx_count(tip_id, chain_tx_count)
        .map_err(ConvertedCheckpointError::Headers)?;
    let applied = TipSnapshot {
        tip_id,
        height: checkpoint.tip_height,
        chainwork,
        hash,
        chain_tx_count,
    };
    let listener = bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(checkpoint.stats);
    let block_tree = parking_lot::RwLock::new(tree);
    let written = crate::checkpoint::write_checkpoint_with_store(
        target_data_dir,
        config,
        &block_tree,
        &listener,
        Some(&applied),
        crate::checkpoint::CheckpointStoreTarget {
            store: engine,
            host_data_dir: target_host_dir,
        },
    )
    .map_err(ConvertedCheckpointError::Publish)?;
    match written {
        crate::checkpoint::CheckpointWrite::Published { .. } => Ok(()),
        crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
            Err(ConvertedCheckpointError::Skipped)
        }
    }
}
