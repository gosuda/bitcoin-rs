//! Immutable snapshot input selected only by the authoritative durable head.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_chain::{BlockTree, ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::{AssumeUtxoData, Network, consensus_bytes, deserialize};
use bitcoin_rs_storage::checkpoint::fs::{open_data_dir, sync_dir};
use bitcoin_rs_utxo::{SnapshotLoad, UtxoSet};

use crate::AssumeUtxoDiskStatus;
use crate::recovery::{InitialChainstate, ResumeSource};

const DIRECTORY: &str = "assumeutxo";

/// Stage durable coins before the root can name them. Uncommitted files never
/// establish an anchor. One activation is admitted per datadir.
pub(super) fn write_coins(data_dir: &Path, set: &UtxoSet, pinned: &AssumeUtxoData) -> Result<()> {
    let path = data_dir.join(DIRECTORY).join(pinned.block_hash.to_string());
    fs::create_dir_all(&path)?;
    sync_dir(&open_data_dir(data_dir)?)?;
    sync_dir(&open_data_dir(&data_dir.join(DIRECTORY))?)?;
    let mut writer = BufWriter::new(File::create(path.join("coins.tmp"))?);
    bitcoin_rs_utxo::snapshot::write_snapshot_observed(
        set,
        &pinned.block_hash,
        pinned.height,
        &mut writer,
        bitcoin_rs_utxo::stats::CoinStatsAccumulator::with_parallel_muhash(pinned.height),
    )?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    fs::rename(path.join("coins.tmp"), path.join("coins.dat"))?;
    sync_dir(&open_data_dir(&path)?)?;
    Ok(())
}

pub(super) fn write_headers(data_dir: &Path, tree: &BlockTree, base: &TipSnapshot) -> Result<()> {
    let path = data_dir.join(DIRECTORY).join(base.hash.to_string());
    let mut writer = BufWriter::new(File::create(path.join("headers.tmp"))?);
    let mut ancestry = tree.ancestor_chain(base.tip_id)?;
    ancestry.reverse();
    for id in ancestry {
        writer.write_all(&consensus_bytes(&tree.node(id)?.header))?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    fs::rename(path.join("headers.tmp"), path.join("headers.dat"))?;
    sync_dir(&open_data_dir(&path)?)?;
    Ok(())
}

pub(crate) fn trusted_anchor(
    network: Network,
    status: &AssumeUtxoDiskStatus,
) -> Result<Option<&'static AssumeUtxoData>> {
    let (height, hash, commitment) = match status {
        AssumeUtxoDiskStatus::Uninitialized => return Ok(None),
        AssumeUtxoDiskStatus::Failed { .. } => bail!(
            "AssumeUTXO validation previously failed; preserve this datadir and resync into a separate directory"
        ),
        AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            expected_hash_serialized,
            ..
        } => (base_height, base_hash, expected_hash_serialized),
        AssumeUtxoDiskStatus::Finalized {
            base_height,
            base_hash,
            validated_hash_serialized,
        } => (base_height, base_hash, validated_hash_serialized),
    };
    let pinned = network
        .assume_utxo_for_height(*height)
        .context("unrecognized durable snapshot base")?;
    if pinned.block_hash != *hash || pinned.hash_serialized != *commitment {
        bail!("durable snapshot identity differs from the network trust anchor");
    }
    if let AssumeUtxoDiskStatus::Validating { chain_tx_count, .. } = status
        && *chain_tx_count != pinned.chain_tx_count
    {
        bail!("durable snapshot transaction count differs from the network trust anchor");
    }
    Ok(Some(pinned))
}

pub(super) fn load_verified(
    data_dir: &Path,
    network: Network,
    pinned: &AssumeUtxoData,
) -> Result<InitialChainstate> {
    let path = data_dir.join(DIRECTORY).join(pinned.block_hash.to_string());
    let mut headers = BufReader::new(File::open(path.join("headers.dat"))?);
    if headers.get_ref().metadata()?.len() != (u64::from(pinned.height) + 1) * 80 {
        bail!("snapshot header archive length does not match the pinned height");
    }
    let mut tree = BlockTree::new();
    for _ in 0..=pinned.height {
        let mut bytes = [0; 80];
        headers.read_exact(&mut bytes)?;
        let header = deserialize(&bytes)?;
        bitcoin_rs_chain::accept_headers(
            &mut tree,
            &[header],
            network,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::HistoricalReplay,
        )?;
    }
    let id = tree
        .lookup(pinned.block_hash)
        .context("snapshot header archive does not end at the pinned block")?;
    let node = tree.node(id)?;
    if node.height != pinned.height {
        bail!("snapshot header height mismatch");
    }
    let tip = TipSnapshot {
        tip_id: id,
        height: pinned.height,
        hash: pinned.block_hash,
        chainwork: node.chainwork,
        chain_tx_count: ChainTxCount::established(pinned.chain_tx_count),
    };
    tree.restore_chain_tx_count(id, tip.chain_tx_count)?;
    let mut coins = BufReader::new(File::open(path.join("coins.dat"))?);
    let SnapshotLoad {
        set,
        height,
        tip_hash,
        ..
    } = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut coins)?;
    if height != pinned.height || tip_hash != pinned.block_hash {
        bail!("snapshot coin archive identity mismatch");
    }
    let mut stats = set.with_stable_view(|view| {
        if view.hash_serialized_3_at_height(pinned.height)? != pinned.hash_serialized {
            return Err(bitcoin_rs_utxo::UtxoError::CorruptRecord);
        }
        bitcoin_rs_utxo::stats::scan_coin_stats(view, pinned.height, true)
    })?;
    stats.tx_count = pinned.chain_tx_count;
    Ok(InitialChainstate {
        utxo: set,
        coin_stats: stats,
        tree,
        applied_tip: Some(tip),
        resume_source: ResumeSource::Snapshot,
        journal_bootstrap: None,
    })
}
