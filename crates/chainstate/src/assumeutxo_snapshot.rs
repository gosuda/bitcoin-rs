//! Immutable snapshot input selected only by the authoritative durable head.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
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
    write: impl FnOnce(&mut BufWriter<File>) -> Result<()>,
) -> Result<()> {
    let mut reserved = None;
    for _ in 0..32 {
        let sequence = NEXT_ARCHIVE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{name}.{}.{sequence}.tmp", std::process::id());
        match create_file(directory, &temporary) {
            Ok(file) => {
                let file = file.into_std();
                // Recovery only reclaims a recognized reservation after taking
                // this same exclusive lock. Acquire it before writing any bytes.
                if let Err(error) = file.lock() {
                    drop(file);
                    let _ = directory.remove_file(&temporary);
                    return Err(error.into());
                }
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
        // Keep the reservation locked until it no longer has a temporary
        // name; a concurrent recovery pass must not reclaim a live writer.
        directory.rename(&temporary, directory, name)?;
        sync_dir(directory)?;
        drop(writer);
        Ok(())
    })();
    if result.is_err() {
        // Only the exclusively reserved temporary can be removed. If rename
        // succeeded, this is already absent and the published archive remains.
        let _ = directory.remove_file(&temporary);
    }
    result
}

#[derive(Clone, Copy)]
enum ReservationKind {
    Coins,
    Headers,
}

// Match only the exact, canonical names emitted by write_archive. Unknown
// files, older operator-visible names such as coins.tmp, and final archives
// are outside this owner's reclamation surface.
fn reservation_kind(name: &str) -> Option<ReservationKind> {
    let (kind, suffix) = name
        .strip_prefix(".coins.dat.")
        .map(|suffix| (ReservationKind::Coins, suffix))
        .or_else(|| {
            name.strip_prefix(".headers.dat.")
                .map(|suffix| (ReservationKind::Headers, suffix))
        })?;
    let mut parts = suffix.split('.');
    let pid_text = parts.next()?;
    let sequence_text = parts.next()?;
    let pid = pid_text.parse::<u32>().ok()?;
    let sequence = sequence_text.parse::<u64>().ok()?;
    if pid == 0
        || pid.to_string() != pid_text
        || sequence.to_string() != sequence_text
        || parts.next()? != "tmp"
        || parts.next().is_some()
    {
        return None;
    }
    Some(kind)
}

fn recognized_reservation(
    file: &mut File,
    kind: ReservationKind,
    network: Network,
    pinned: &AssumeUtxoData,
) -> std::io::Result<bool> {
    match kind {
        ReservationKind::Coins => {
            match bitcoin_rs_utxo::snapshot::read_snapshot_metadata_v4(file) {
                Ok(metadata) => {
                    Ok((metadata.tip_hash, metadata.height) == (pinned.block_hash, pinned.height))
                }
                Err(bitcoin_rs_utxo::UtxoError::Io(error))
                    if error.kind() != std::io::ErrorKind::UnexpectedEof =>
                {
                    Err(error)
                }
                // Unknown formats and unidentifiable fragments are preserved.
                Err(_) => Ok(false),
            }
        }
        ReservationKind::Headers => {
            let mut header = [0_u8; 80];
            match file.read_exact(&mut header) {
                Ok(()) => Ok(header.as_slice()
                    == consensus_bytes(&network.genesis_block().header).as_slice()),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
                Err(error) => Err(error),
            }
        }
    }
}

/// Reclaims identifiable, uncommitted archive reservations after a crash.
/// Called before the manager is published; per-file exclusive lock probes
/// additionally prove that no other live archive writer owns each inode.
/// Only known network/base directories and native archive prefixes qualify.
pub(super) fn cleanup_reservations(data_dir: &Path, network: Network) -> Result<()> {
    let data = open_data_dir(data_dir)?;
    let root = match data.open_dir_nofollow(DIRECTORY) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for pinned in network.assume_utxo_data() {
        let directory = match root.open_dir_nofollow(pinned.block_hash.to_string()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut changed = false;
        for entry in directory.entries()? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some((name, kind)) = name
                .to_str()
                .and_then(|name| reservation_kind(name).map(|kind| (name, kind)))
            else {
                continue;
            };
            changed |= reclaim_reservation(&directory, name, kind, network, pinned)?;
        }
        if changed {
            sync_dir(&directory)?;
        }
    }
    Ok(())
}

/// Reclaims one already-selected reservation, retaining its lock through unlink.
fn reclaim_reservation(
    directory: &Dir,
    name: &str,
    kind: ReservationKind,
    network: Network,
    pinned: &AssumeUtxoData,
) -> std::io::Result<bool> {
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    let mut file = directory.open_with(name, &options)?.into_std();
    // Directory-entry type is only a precheck. Validate the opened inode
    // before locking or reading; a substituted FIFO must never wait for data.
    if !file.metadata()?.is_file() {
        return Ok(false);
    }
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    if !recognized_reservation(&mut file, kind, network, pinned)? {
        return Ok(false);
    }
    directory.remove_file(name)?;
    Ok(true)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn native_fixture() -> Result<(Vec<u8>, &'static AssumeUtxoData)> {
        let core = include_bytes!("../../utxo/tests/fixtures/core-v2/core200.dat");
        let loaded = bitcoin_rs_utxo::core_snapshot::read_and_verify(
            &mut core.as_slice(),
            Network::Regtest,
            bitcoin_rs_utxo::core_snapshot::SnapshotLimits::default(),
        )?;
        let mut native = Vec::new();
        bitcoin_rs_utxo::write_snapshot_observed(
            &loaded.set,
            &loaded.anchor.block_hash,
            loaded.anchor.height,
            &mut native,
            (),
        )?;
        Ok((native, loaded.anchor))
    }

    #[cfg(unix)]
    #[test]
    fn fifo_replacement_after_entry_check_is_preserved_without_blocking() -> Result<()> {
        use std::os::unix::fs::FileTypeExt as _;

        let dir = tempfile::tempdir()?;
        let (_, pinned) = native_fixture()?;
        let archive = archive_directory(dir.path(), pinned.block_hash)?;
        let name = ".headers.dat.1234.5.tmp";
        archive.write(
            name,
            consensus_bytes(&Network::Regtest.genesis_block().header),
        )?;
        let entry = archive.entries()?.next().context("reservation entry")??;
        assert!(entry.file_type()?.is_file());
        // Deterministically occupy the actual enumeration/open race boundary.
        archive.remove_file(name)?;
        let path = dir
            .path()
            .join(DIRECTORY)
            .join(pinned.block_hash.to_string())
            .join(name);
        let created = std::process::Command::new("mkfifo").arg(&path).status()?;
        assert!(created.success(), "create isolated Unix FIFO");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker_directory = archive.try_clone()?;
        let worker = std::thread::spawn(move || {
            let result = reclaim_reservation(
                &worker_directory,
                name,
                ReservationKind::Headers,
                Network::Regtest,
                pinned,
            );
            let _ = sender.send(result);
        });
        let observed = receiver.recv_timeout(std::time::Duration::from_secs(5));
        let rescue = if observed.is_err() {
            // Unblock a regressed reader before reporting failure. O_RDWR plus
            // NONBLOCK prevents this rescue from introducing another FIFO wait.
            let mut options = cap_std::fs::OpenOptions::new();
            options.read(true).write(true).follow(FollowSymlinks::No);
            cap_fs_ext::OpenOptionsSyncExt::nonblock(&mut options, true);
            let mut file = archive.open_with(name, &options)?;
            file.write_all(&[0_u8; 80])?;
            Some(file)
        } else {
            None
        };
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("cleanup worker panicked"))?;
        // Keep queued rescue bytes alive even if the worker started late.
        drop(rescue);
        assert!(!observed.context("cleanup blocked on substituted FIFO")??);
        assert!(std::fs::symlink_metadata(&path)?.file_type().is_fifo());
        Ok(())
    }

    #[test]
    fn live_archive_reservation_is_not_reclaimed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (native, pinned) = native_fixture()?;
        let archive = archive_directory(dir.path(), pinned.block_hash)?;
        write_archive(&archive, "coins.dat", |writer| {
            writer.write_all(&native)?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            let before = archive.entries()?.count();
            cleanup_reservations(dir.path(), Network::Regtest)?;
            assert_eq!(
                archive.entries()?.count(),
                before,
                "live reservation retained"
            );
            Ok(())
        })?;
        assert_eq!(archive.read("coins.dat")?, native);
        Ok(())
    }

    #[test]
    fn abandoned_native_reservations_are_reclaimed_without_touching_unknowns() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (native, pinned) = native_fixture()?;
        let archive = archive_directory(dir.path(), pinned.block_hash)?;
        let orphan = ".coins.dat.1234.0.tmp";
        archive.write(orphan, &native)?;
        let header_orphan = ".headers.dat.1234.1.tmp";
        archive.write(
            header_orphan,
            consensus_bytes(&Network::Regtest.genesis_block().header),
        )?;
        let core = include_bytes!("../../utxo/tests/fixtures/core-v2/core200.dat");
        for (name, bytes) in [
            ("coins.dat", native.as_slice()),
            ("coins.tmp", core.as_slice()),
            (".coins.dat.1234.2.tmp", core.as_slice()),
            (".coins.dat.1234.3.tmp", &[0_u8][..]),
            (".coins.dat.operator.tmp", native.as_slice()),
            (".coins.dat.01234.4.tmp", native.as_slice()),
        ] {
            archive.write(name, bytes)?;
        }
        cleanup_reservations(dir.path(), Network::Regtest)?;
        assert!(!archive.try_exists(orphan)?);
        assert!(!archive.try_exists(header_orphan)?);
        for (name, bytes) in [
            ("coins.dat", native.as_slice()),
            ("coins.tmp", core.as_slice()),
            (".coins.dat.1234.2.tmp", core.as_slice()),
            (".coins.dat.1234.3.tmp", &[0_u8][..]),
            (".coins.dat.operator.tmp", native.as_slice()),
            (".coins.dat.01234.4.tmp", native.as_slice()),
        ] {
            assert_eq!(archive.read(name)?, bytes, "preserve {name}");
        }
        Ok(())
    }
}
