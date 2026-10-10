//! Immutable snapshot input selected only by the authoritative durable head.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::DirExt as _;
use cap_std::fs::Dir;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_chain::{BlockTree, ChainTxCount, TipSnapshot};
use bitcoin_rs_primitives::{AssumeUtxoData, Network, consensus_bytes, deserialize};
use bitcoin_rs_storage::checkpoint::fs::{create_file, open_data_dir, sync_dir};
use bitcoin_rs_utxo::{SnapshotLoad, UtxoSet};

use crate::AssumeUtxoDiskStatus;
use crate::recovery::{InitialChainstate, ResumeSource};

const DIRECTORY: &str = "assumeutxo";

// Temporary names are only reservation candidates: exclusive creation owns
// the inode, and collisions never authorize truncating an existing artifact.
static NEXT_ARCHIVE: AtomicU64 = AtomicU64::new(0);

fn archive_directory(data_dir: &Path, base: bitcoin_rs_primitives::Hash256) -> Result<Dir> {
    fn child(parent: &Dir, name: &str) -> std::io::Result<Dir> {
        if let Err(error) = parent.create_dir(name)
            && error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(error);
        }
        let directory = parent.open_dir_nofollow(name)?;
        // Retry also certifies an entry left by an earlier failed directory
        // sync; existence alone is not evidence that its parent is durable.
        sync_dir(parent)?;
        Ok(directory)
    }
    let data = open_data_dir(data_dir)?;
    let root = child(&data, DIRECTORY)?;
    Ok(child(&root, &base.to_string())?)
}

fn write_archive(
    directory: &Dir,
    name: &str,
    write: impl FnOnce(&mut BufWriter<cap_std::fs::File>) -> Result<()>,
) -> Result<()> {
    let mut reserved = None;
    for _ in 0..32 {
        let sequence = NEXT_ARCHIVE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{name}.{}.{sequence}.tmp", std::process::id());
        match create_file(directory, &temporary) {
            Ok(file) => {
                reserved = Some((temporary, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary, file) = reserved.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "snapshot temporary reservation exhausted",
        )
    })?;
    let result = (|| {
        let mut writer = BufWriter::new(file);
        write(&mut writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);
        directory.rename(&temporary, directory, name)?;
        sync_dir(directory)?;
        Ok(())
    })();
    if result.is_err() {
        // Only the exclusively reserved temporary can be removed. If rename
        // succeeded, this is already absent and the published archive remains.
        let _ = directory.remove_file(&temporary);
    }
    result
}

/// Stage durable coins before the root can name them. Uncommitted files never
/// establish an anchor. One activation is admitted per datadir.
pub(super) fn write_coins(data_dir: &Path, set: &UtxoSet, pinned: &AssumeUtxoData) -> Result<()> {
    let directory = archive_directory(data_dir, pinned.block_hash)?;
    write_archive(&directory, "coins.dat", |writer| {
        bitcoin_rs_utxo::snapshot::write_snapshot_observed(
            set,
            &pinned.block_hash,
            pinned.height,
            writer,
            bitcoin_rs_utxo::stats::CoinStatsAccumulator::with_parallel_muhash(pinned.height),
        )?;
        Ok(())
    })
}

pub(super) fn write_headers(data_dir: &Path, tree: &BlockTree, base: &TipSnapshot) -> Result<()> {
    let directory = archive_directory(data_dir, base.hash)?;
    write_archive(&directory, "headers.dat", |writer| {
        let mut ancestry = tree.ancestor_chain(base.tip_id)?;
        ancestry.reverse();
        for id in ancestry {
            writer.write_all(&consensus_bytes(&tree.node(id)?.header))?;
        }
        Ok(())
    })
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
