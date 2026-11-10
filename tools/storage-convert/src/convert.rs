use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, Write};
use std::path::Path;

use bitcoin_rs_storage::recovery_evidence::FULL_REVALIDATION_MARKER;

use crate::cli::CliArgs;
use crate::error::ConvertError;
use crate::fs_util::{
    copy_dir_recursive, create_file_no_follow, open_file_read_no_follow, publish_current_schema,
    sync_dir, validate_and_open_roots,
};
use crate::report::{
    CoinStatsReport, ConversionReport, CopiedFileReport, FamilyReport, NamespaceReport,
    NormalizedUndoRowReport,
};
use crate::source::{SourceNamespace, detect_engine};
use crate::target::{
    BatchWriter, FamilyDigest, compute_destination_digest, open_destination_store,
};
use bitcoin_rs_consensus::bip30::{BIP30_DUPLICATE_TXID_EXCEPTIONS, is_bip30_exception};
use bitcoin_rs_consensus::primitives::{
    AssumeUtxoData, Block, BlockImage, ConsensusDecode, Hash256, Header, Network, OutPoint, Txid,
    deserialize, hex::hex_encode,
};
use bitcoin_rs_execution::recovery::{
    ConvertedCheckpoint, publish_converted_checkpoint, publish_snapshot_base_checkpoint,
    snapshot_base_checkpoint_compatible,
};
use bitcoin_rs_storage::checkpoint::{
    CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CURRENT_FORMAT, CURRENT_VERSION,
    CheckpointManifestV1, CheckpointOpen, CheckpointReference, CurrentV1, HEADERS_FILE,
    MANIFEST_FILE, decode_hex, digest_engine_dir, open_current_checkpoint_at, read_file,
};
pub(crate) const UTXO_FILE: &str = "utxo-v4.dat";
const EPOCH3_JOURNAL_DIR: &str = "chainstate-journal";
use crate::legacy_undo::decode_legacy_undo_record;
use bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus;
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::pruning::{block_body_key, block_undo_key};
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::contract::{
    BlockChangeInputs, SpentOutputLookup, block_spent_outputs, build_block_changes,
    decode_undo_record_for_block, encode_undo_record, rewrite_overwrite_restores,
};
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::utxo::snapshot::stream_snapshot_v4_records;
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsAccumulator};
use bitcoin_rs_storage::utxo::{
    SnapshotCoin, SnapshotCoinObserver, UtxoError, read_snapshot_strict_v4_observed,
};
use bitcoin_rs_storage::{
    BlockFilePosition, ColumnFamily, FlatFileBlockStore, KvStore, StorageBackend,
};
use cap_fs_ext::DirExt;
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};

struct NamespacePaths<'a> {
    name: &'a str,
    dst_path: &'a Path,
    scratch_path: &'a Path,
    from_root: &'a Dir,
    to_root: &'a Dir,
}

pub(crate) fn run_conversion(args: CliArgs) -> Result<ConversionReport, ConvertError> {
    let target_engine = args.target_backend()?;
    let roots = validate_and_open_roots(&args)?;

    let source_epoch = read_source_epoch(&roots.from_dir)?;
    if source_epoch != 2
        && source_epoch != 3
        && source_epoch != 4
        && source_epoch != 5
        && source_epoch != 6
    {
        return Err(ConvertError::UnknownEpoch(source_epoch));
    }

    if source_epoch == 3 {
        return run_step_3_to_4(&args, &roots, target_engine);
    }

    if source_epoch == 4 {
        return run_step_4_to_6(&args, &roots, target_engine);
    }

    if source_epoch == 5 {
        return run_step_5_to_6(&args, &roots, target_engine);
    }

    let target_epoch = match source_epoch {
        2 => 3,
        6 => 6,
        _ => return Err(ConvertError::UnknownEpoch(source_epoch)),
    };

    let mut namespaces_report = Vec::new();

    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    let (_, to) = args.convert_roots()?;
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = to.join(rel_path);
        let scratch_base = to.join(".convert-src");
        let scratch_path = scratch_base.join(rel_path);

        let paths = NamespacePaths {
            name: ns_name,
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: &roots.from_dir,
            to_root: &roots.to_dir,
        };
        let report = convert_namespace(paths, source_epoch, target_engine)?;
        namespaces_report.push(report);
    }

    if let (Some(_), Some(pool_to_path)) = (&args.pool_from, &args.pool_to) {
        let pool_from_dir = roots.pool_from_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool source directory".into())
        })?;
        let pool_to_dir = roots.pool_to_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool target directory".into())
        })?;

        let dst_path = pool_to_path.join("ledger");
        let scratch_base = pool_to_path.join(".convert-src");
        let scratch_path = scratch_base.join("ledger");

        let paths = NamespacePaths {
            name: "ledger",
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: pool_from_dir,
            to_root: pool_to_dir,
        };
        let report = convert_namespace(paths, source_epoch, target_engine)?;
        namespaces_report.push(report);
    }

    let mut copied_files = Vec::new();
    let include_journal = source_epoch == 2;
    copy_independent_files(
        &roots.from_dir,
        &roots.to_dir,
        &mut copied_files,
        include_journal,
        true,
    )?;

    cleanup_scratch(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        cleanup_scratch(pool_to_dir)?;
    }

    sync_dir(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        sync_dir(pool_to_dir)?;
    }

    publish_current_schema(&roots.to_dir, target_epoch)?;

    Ok(ConversionReport {
        source_epoch,
        target_epoch,
        namespaces: namespaces_report,
        copied_files,
        checkpoint_stats: None,
        final_stats: None,
        normalized_undo_rows: Vec::new(),
        carried_markers: Vec::new(),
        published_checkpoint: false,
    })
}

fn read_source_epoch(from_dir: &Dir) -> Result<u32, ConvertError> {
    let file = match open_file_read_no_follow(from_dir, "CURRENT_SCHEMA") {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(ConvertError::UnknownEpoch(0));
        }
        Err(err) => return Err(ConvertError::Io(err)),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 16 {
        return Err(ConvertError::UnknownEpoch(0));
    }

    let mut buf = Vec::with_capacity(16);
    file.take(17).read_to_end(&mut buf)?;
    if buf.len() > 16 {
        return Err(ConvertError::UnknownEpoch(0));
    }

    let content = std::str::from_utf8(&buf).map_err(|_| ConvertError::UnknownEpoch(0))?;
    let trimmed = content.trim();
    let epoch = trimmed
        .parse::<u32>()
        .map_err(|_| ConvertError::UnknownEpoch(0))?;
    Ok(epoch)
}

fn convert_namespace(
    paths: NamespacePaths<'_>,
    source_epoch: u32,
    target_engine: StorageBackend,
) -> Result<NamespaceReport, ConvertError> {
    let src_dir = match paths.from_root.open_dir_nofollow(paths.name) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(NamespaceReport {
                namespace: paths.name.to_string(),
                engine: "empty".to_string(),
                families: Vec::new(),
            });
        }
        Err(err) => return Err(ConvertError::Io(err)),
    };

    let scratch_base_name = ".convert-src";
    match paths.to_root.open_dir_nofollow(scratch_base_name) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            paths.to_root.create_dir(scratch_base_name)?;
        }
        Err(err) => return Err(ConvertError::Io(err)),
    }
    let scratch_base_dir = paths.to_root.open_dir_nofollow(scratch_base_name)?;

    match scratch_base_dir.open_dir_nofollow(paths.name) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            scratch_base_dir.create_dir(paths.name)?;
        }
        Err(err) => return Err(ConvertError::Io(err)),
    }
    let scratch_dir = scratch_base_dir.open_dir_nofollow(paths.name)?;

    copy_dir_recursive(&src_dir, &scratch_dir)?;
    sync_dir(&scratch_dir)?;

    let detected = detect_engine(paths.scratch_path, &scratch_dir, source_epoch)?;
    let Some(engine) = detected else {
        return Ok(NamespaceReport {
            namespace: paths.name.to_string(),
            engine: "empty".to_string(),
            families: Vec::new(),
        });
    };

    match paths.to_root.open_dir_nofollow(paths.name) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            paths.to_root.create_dir(paths.name)?;
        }
        Err(err) => return Err(ConvertError::Io(err)),
    }
    let dst_dir = paths.to_root.open_dir_nofollow(paths.name)?;

    let (source_ns, engine_label) = SourceNamespace::open(paths.scratch_path, Some(engine))?;
    let dest_store = open_destination_store(paths.dst_path, target_engine)?;

    let mut family_reports = Vec::new();

    for cf in ColumnFamily::ALL.iter().copied() {
        let mut source_digest = FamilyDigest::new();
        let mut writer = BatchWriter::new(dest_store.as_ref());

        let row_count = source_ns.for_each_row(cf, |key, value| {
            source_digest.update(key, value)?;
            writer.put(cf, key, value)?;
            Ok(())
        })?;
        writer.flush()?;

        let src_digest_hex = source_digest.finalize_hex();

        let (dst_count, dst_digest_hex) = compute_destination_digest(dest_store.as_ref(), cf)?;
        if row_count != dst_count || src_digest_hex != dst_digest_hex {
            return Err(ConvertError::DigestMismatch {
                namespace: paths.name.to_string(),
                family: cf.name().to_string(),
            });
        }

        family_reports.push(FamilyReport {
            family: cf.name().to_string(),
            row_count,
            digest: src_digest_hex,
        });
    }

    drop(dest_store);
    drop(source_ns);

    sync_dir(&dst_dir)?;

    Ok(NamespaceReport {
        namespace: paths.name.to_string(),
        engine: engine_label.to_string(),
        families: family_reports,
    })
}
fn convert_namespace_with_undo_recode(
    paths: NamespacePaths<'_>,
    source_epoch: u32,
    target_engine: StorageBackend,
) -> Result<NamespaceReport, ConvertError> {
    let src_dir = match paths.from_root.open_dir_nofollow(paths.name) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(NamespaceReport {
                namespace: paths.name.to_string(),
                engine: "empty".to_string(),
                families: Vec::new(),
            });
        }
        Err(err) => return Err(ConvertError::Io(err)),
    };
    let scratch_base_name = ".convert-src";
    match paths.to_root.open_dir_nofollow(scratch_base_name) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            paths.to_root.create_dir(scratch_base_name)?;
        }
        Err(err) => return Err(ConvertError::Io(err)),
    }
    let scratch_base_dir = paths.to_root.open_dir_nofollow(scratch_base_name)?;
    match scratch_base_dir.open_dir_nofollow(paths.name) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            scratch_base_dir.create_dir(paths.name)?;
        }
        Err(err) => return Err(ConvertError::Io(err)),
    }
    let scratch_dir = scratch_base_dir.open_dir_nofollow(paths.name)?;
    copy_dir_recursive(&src_dir, &scratch_dir)?;
    sync_dir(&scratch_dir)?;
    let detected = detect_engine(paths.scratch_path, &scratch_dir, source_epoch)?;
    let Some(engine) = detected else {
        return Ok(NamespaceReport {
            namespace: paths.name.to_string(),
            engine: "empty".to_string(),
            families: Vec::new(),
        });
    };
    match paths.to_root.open_dir_nofollow(paths.name) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            paths.to_root.create_dir(paths.name)?;
        }
        Err(err) => return Err(ConvertError::Io(err)),
    }
    let dst_dir = paths.to_root.open_dir_nofollow(paths.name)?;
    let (source_ns, engine_label) = SourceNamespace::open(paths.scratch_path, Some(engine))?;
    let dest_store = open_destination_store(paths.dst_path, target_engine)?;
    let mut family_reports = Vec::new();
    for cf in ColumnFamily::ALL.iter().copied() {
        if cf == ColumnFamily::UndoData {
            let mut writer = BatchWriter::new(dest_store.as_ref());
            let row_count = source_ns.for_each_row(cf, |key, value| {
                if key.len() != 37 {
                    return Err(ConvertError::IncompatibleData(
                        "undo key is not 37 bytes".into(),
                    ));
                }
                let mut hash_bytes = [0_u8; 32];
                hash_bytes.copy_from_slice(&key[5..37]);
                let hash = Hash256::from_le_bytes(&hash_bytes);
                let batch = decode_legacy_undo_record(value, hash).map_err(|e| {
                    ConvertError::IncompatibleData(format!("legacy undo record is unreadable: {e}"))
                })?;
                let recoded = encode_undo_record(&batch, hash);
                writer.put(cf, key, &recoded)?;
                Ok(())
            })?;
            writer.flush()?;
            let (dst_count, dst_digest_hex) = compute_destination_digest(dest_store.as_ref(), cf)?;
            if row_count != dst_count {
                return Err(ConvertError::DigestMismatch {
                    namespace: paths.name.to_string(),
                    family: cf.name().to_string(),
                });
            }
            family_reports.push(FamilyReport {
                family: cf.name().to_string(),
                row_count,
                digest: dst_digest_hex,
            });
            continue;
        }
        let mut source_digest = FamilyDigest::new();
        let mut writer = BatchWriter::new(dest_store.as_ref());
        let row_count = source_ns.for_each_row(cf, |key, value| {
            source_digest.update(key, value)?;
            writer.put(cf, key, value)?;
            Ok(())
        })?;
        writer.flush()?;
        let src_digest_hex = source_digest.finalize_hex();
        let (dst_count, dst_digest_hex) = compute_destination_digest(dest_store.as_ref(), cf)?;
        if row_count != dst_count || src_digest_hex != dst_digest_hex {
            return Err(ConvertError::DigestMismatch {
                namespace: paths.name.to_string(),
                family: cf.name().to_string(),
            });
        }
        family_reports.push(FamilyReport {
            family: cf.name().to_string(),
            row_count,
            digest: src_digest_hex,
        });
    }
    drop(dest_store);
    drop(source_ns);
    sync_dir(&dst_dir)?;
    Ok(NamespaceReport {
        namespace: paths.name.to_string(),
        engine: engine_label.to_string(),
        families: family_reports,
    })
}

fn copy_independent_files(
    from_root: &Dir,
    to_root: &Dir,
    copied_files: &mut Vec<CopiedFileReport>,
    include_journal: bool,
    include_checkpoints: bool,
) -> Result<(), ConvertError> {
    let mut independent_dirs = vec!["blocks", "assumeutxo-historical-checkpoints"];
    if include_checkpoints {
        independent_dirs.push("chainstate-checkpoints");
    }
    if include_journal {
        independent_dirs.push("chainstate-journal");
    }
    const INDEPENDENT_FILES: &[&str] = &[
        "peers.dat",
        "mempool-snapshot.dat",
        "fee-estimator-history.dat",
    ];

    for dir_name in independent_dirs {
        let src_dir = match from_root.open_dir_nofollow(dir_name) {
            Ok(d) => d,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(ConvertError::Io(err)),
        };

        to_root.create_dir(dir_name)?;
        let dst_dir = to_root.open_dir_nofollow(dir_name)?;
        copy_dir_recursive(&src_dir, &dst_dir)?;
        sync_dir(&dst_dir)?;

        collect_copied_files_from_dir(&src_dir, dir_name, copied_files)?;
    }

    for &file_name in INDEPENDENT_FILES {
        let mut src_file = match open_file_read_no_follow(from_root, file_name) {
            Ok(f) => f,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(ConvertError::Io(err)),
        };

        let mut dst_file = create_file_no_follow(to_root, file_name)?;
        let bytes = io::copy(&mut src_file, &mut dst_file)?;
        dst_file.sync_all()?;

        copied_files.push(CopiedFileReport {
            path: file_name.to_string(),
            bytes,
        });
    }

    Ok(())
}

fn collect_copied_files_from_dir(
    dir: &Dir,
    prefix: &str,
    copied_files: &mut Vec<CopiedFileReport>,
) -> Result<(), ConvertError> {
    for entry in dir.entries()? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };

        let rel_path = format!("{prefix}/{name_str}");

        if file_type.is_dir() {
            let child = dir.open_dir_nofollow(name_str)?;
            collect_copied_files_from_dir(&child, &rel_path, copied_files)?;
        } else if file_type.is_file() {
            let file = open_file_read_no_follow(dir, name_str)?;
            let meta = file.metadata()?;
            copied_files.push(CopiedFileReport {
                path: rel_path,
                bytes: meta.len(),
            });
        }
    }
    Ok(())
}

fn cleanup_scratch(dest_dir: &Dir) -> Result<(), ConvertError> {
    for name in [".convert-src", ".convert-scratch"] {
        match dest_dir.remove_dir_all(name) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(ConvertError::Io(err)),
        }
    }
    Ok(())
}

struct CoinRecordCollector {
    records: Vec<(Hash256, Vec<OwnedUtxoOut>)>,
    current_txid: Option<Hash256>,
    current_outputs: Vec<OwnedUtxoOut>,
    stats: CoinStatsAccumulator,
}

struct CollectOutcome {
    records: Vec<(Hash256, Vec<OwnedUtxoOut>)>,
    stats: CoinStats,
}

impl CoinRecordCollector {
    fn new(checkpoint_height: u32) -> Self {
        Self {
            records: Vec::new(),
            current_txid: None,
            current_outputs: Vec::new(),
            stats: CoinStatsAccumulator::with_parallel_muhash(checkpoint_height),
        }
    }

    fn finish(mut self) -> CollectOutcome {
        if let Some(txid) = self.current_txid {
            self.records.push((txid, self.current_outputs));
        }
        CollectOutcome {
            records: self.records,
            stats: self.stats.into_stats(),
        }
    }
}

impl SnapshotCoinObserver for CoinRecordCollector {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
        self.stats.observe_coin(coin);
        if let Some(cur) = self.current_txid {
            if cur != coin.txid {
                let prev_outputs = std::mem::take(&mut self.current_outputs);
                self.records.push((cur, prev_outputs));
                self.current_txid = Some(coin.txid);
            }
        } else {
            self.current_txid = Some(coin.txid);
        }
        self.current_outputs.push(OwnedUtxoOut {
            vout: coin.vout,
            value: coin.value,
            script_pubkey: coin.script_pubkey.to_vec(),
            coinbase: coin.coinbase,
            height: coin.height,
        });
    }
}

fn check_complete_checkpoint(
    from_dir: &Dir,
) -> Result<(Dir, CheckpointReference, CheckpointManifestV1), ConvertError> {
    let opened = open_current_checkpoint_at(from_dir, CHECKPOINT_ROOT)
        .map_err(|_| ConvertError::MissingCheckpoint)?;

    let (generation_dir, reference) = match opened {
        CheckpointOpen::Selected {
            generation_dir,
            reference,
        } => (generation_dir, reference),
        CheckpointOpen::Cold => return Err(ConvertError::MissingCheckpoint),
    };

    let manifest_bytes = read_file(&generation_dir, MANIFEST_FILE, 1024 * 1024)
        .map_err(|_| ConvertError::MissingCheckpoint)?;

    let digest: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    if digest != reference.manifest_sha256 {
        return Err(ConvertError::MissingCheckpoint);
    }

    let manifest: CheckpointManifestV1 =
        sonic_rs::from_slice(&manifest_bytes).map_err(|_| ConvertError::MissingCheckpoint)?;

    let utxo_info = manifest
        .utxo
        .as_ref()
        .ok_or(ConvertError::MissingCheckpoint)?;
    let utxo_file = open_file_read_no_follow(&generation_dir, UTXO_FILE)
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    let meta = utxo_file
        .metadata()
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    if meta.len() != utxo_info.bytes {
        return Err(ConvertError::MissingCheckpoint);
    }
    let expected_digest: [u8; 32] = decode_hex(&utxo_info.sha256)
        .map_err(|_| ConvertError::IncompatibleData("manifest utxo sha256 is malformed".into()))?;
    let mut hasher = Sha256::new();
    let mut reader = utxo_file;
    let mut chunk = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    let found_digest: [u8; 32] = hasher.finalize().into();
    if found_digest != expected_digest {
        return Err(ConvertError::CheckpointDigestMismatch { file: UTXO_FILE });
    }

    let headers_file = open_file_read_no_follow(&generation_dir, HEADERS_FILE)
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    let h_meta = headers_file
        .metadata()
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    if h_meta.len() != manifest.headers.bytes {
        return Err(ConvertError::MissingCheckpoint);
    }

    let coinstats_file = open_file_read_no_follow(&generation_dir, COINSTATS_FILE)
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    let c_meta = coinstats_file
        .metadata()
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    if c_meta.len() != manifest.coinstats.bytes {
        return Err(ConvertError::MissingCheckpoint);
    }

    Ok((generation_dir, reference, manifest))
}

fn verify_checkpoint_statistics(
    manifest: &CheckpointManifestV1,
    snapshot: &bitcoin_rs_storage::utxo::SnapshotLoad,
    stats: &CoinStats,
    record_count: u64,
    output_count: u64,
) -> Result<(), ConvertError> {
    let mismatch =
        |field: &'static str, expected: String, found: String| ConvertError::CheckpointMismatch {
            field,
            expected,
            found,
        };
    let checkpoint_height = manifest.applied_tip.height;
    let tip = checkpoint_tip_hash(manifest)?;
    let utxo = manifest
        .utxo
        .as_ref()
        .ok_or(ConvertError::MissingCheckpoint)?;

    if snapshot.height != checkpoint_height {
        return Err(mismatch(
            "applied_tip.height",
            checkpoint_height.to_string(),
            snapshot.height.to_string(),
        ));
    }
    if snapshot.tip_hash != tip {
        return Err(mismatch(
            "applied_tip.hash",
            tip.to_string_be(),
            snapshot.tip_hash.to_string_be(),
        ));
    }
    if stats.height != checkpoint_height {
        return Err(mismatch(
            "coinstats.height",
            checkpoint_height.to_string(),
            stats.height.to_string(),
        ));
    }
    if manifest.coinstats.height != checkpoint_height {
        return Err(mismatch(
            "coinstats.height",
            checkpoint_height.to_string(),
            manifest.coinstats.height.to_string(),
        ));
    }
    if manifest.coinstats.tx_count != manifest.applied_tip.chain_tx_count {
        return Err(mismatch(
            "coinstats.tx_count",
            manifest.applied_tip.chain_tx_count.to_string(),
            manifest.coinstats.tx_count.to_string(),
        ));
    }
    if stats.utxo_count != manifest.coinstats.utxo_count {
        return Err(mismatch(
            "coinstats.utxo_count",
            manifest.coinstats.utxo_count.to_string(),
            stats.utxo_count.to_string(),
        ));
    }
    if stats.total_amount != manifest.coinstats.total_amount {
        return Err(mismatch(
            "coinstats.total_amount",
            manifest.coinstats.total_amount.to_string(),
            stats.total_amount.to_string(),
        ));
    }
    if stats.bogo_size != manifest.coinstats.bogo_size {
        return Err(mismatch(
            "coinstats.bogo_size",
            manifest.coinstats.bogo_size.to_string(),
            stats.bogo_size.to_string(),
        ));
    }
    let muhash = hex_encode(&stats.muhash.finalize());
    if !muhash.eq_ignore_ascii_case(&manifest.coinstats.muhash) {
        return Err(mismatch(
            "coinstats.muhash",
            muhash,
            manifest.coinstats.muhash.clone(),
        ));
    }
    if output_count != utxo.output_count {
        return Err(mismatch(
            "utxo.output_count",
            utxo.output_count.to_string(),
            output_count.to_string(),
        ));
    }
    if record_count != utxo.record_count {
        return Err(mismatch(
            "utxo.record_count",
            utxo.record_count.to_string(),
            record_count.to_string(),
        ));
    }
    let trailer_sha256 = hex_encode(&Sha256::digest(snapshot.muhash_trailer));
    if !trailer_sha256.eq_ignore_ascii_case(&utxo.muhash_trailer_sha256) {
        return Err(mismatch(
            "utxo.muhash_trailer_sha256",
            trailer_sha256,
            utxo.muhash_trailer_sha256.clone(),
        ));
    }
    if snapshot.muhash_trailer != stats.muhash.finalize() {
        return Err(mismatch(
            "utxo.muhash_trailer",
            muhash,
            hex_encode(&snapshot.muhash_trailer),
        ));
    }
    Ok(())
}

fn scan_destination_coins(
    store: &dyn KvStore,
    height: u32,
) -> Result<(CoinStats, u64, String), ConvertError> {
    let mut digest = FamilyDigest::new();
    let mut stats = CoinStatsAccumulator::with_parallel_muhash(height);
    let mut count = 0_u64;
    let iter = store.iter_prefix(ColumnFamily::Coins, &[])?;
    for row in iter {
        let (key, value) = row?;
        digest.update(&key, &value)?;
        count = count.saturating_add(1);
        let key_bytes: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| ConvertError::IncompatibleData("coin key is not a 32-byte txid".into()))?;
        let txid = Hash256::from_le_bytes(&key_bytes);
        let record = UtxoRecord::from_encoded(value.into_boxed_slice())
            .map_err(|e| ConvertError::IncompatibleData(format!("corrupt coin record: {e}")))?;
        for out in record.outputs() {
            stats.observe_coin(SnapshotCoin {
                txid,
                vout: out.vout,
                value: out.value,
                script_pubkey: out.script_pubkey,
                height: out.height,
                coinbase: out.coinbase,
            });
        }
    }
    Ok((stats.into_stats(), count, digest.finalize_hex()))
}

fn coin_stats_report(stats: &CoinStats, tx_count: u64) -> CoinStatsReport {
    CoinStatsReport {
        height: stats.height,
        utxo_count: stats.utxo_count,
        total_amount: stats.total_amount,
        muhash: hex_encode(&stats.muhash.finalize()),
        tx_count,
    }
}

fn reconcile_replay(
    head: &DurableHead,
    replayed: &CoinStats,
    stored: &CoinStats,
) -> Result<(), ConvertError> {
    let mismatch =
        |field: &'static str, expected: String, found: String| ConvertError::ReplayMismatch {
            field,
            expected,
            found,
        };
    if replayed.height != head.height {
        return Err(mismatch(
            "height",
            head.height.to_string(),
            replayed.height.to_string(),
        ));
    }
    if replayed.tx_count != head.chain_tx_count {
        return Err(mismatch(
            "chain_tx_count",
            head.chain_tx_count.to_string(),
            replayed.tx_count.to_string(),
        ));
    }
    if stored.utxo_count != replayed.utxo_count {
        return Err(mismatch(
            "utxo_count",
            replayed.utxo_count.to_string(),
            stored.utxo_count.to_string(),
        ));
    }
    if stored.total_amount != replayed.total_amount {
        return Err(mismatch(
            "total_amount",
            replayed.total_amount.to_string(),
            stored.total_amount.to_string(),
        ));
    }
    let replayed_muhash = hex_encode(&replayed.muhash.finalize());
    let stored_muhash = hex_encode(&stored.muhash.finalize());
    if replayed_muhash != stored_muhash {
        return Err(mismatch("muhash", replayed_muhash, stored_muhash));
    }
    Ok(())
}

fn normalize_bip30_undo_rows(
    store: &dyn KvStore,
    load_block: &dyn Fn(u32, Hash256) -> Result<Block, ConvertError>,
) -> Result<Vec<NormalizedUndoRowReport>, ConvertError> {
    let mut pending: Vec<([u8; 37], Vec<u8>, NormalizedUndoRowReport)> = Vec::new();
    for &(height, _) in BIP30_DUPLICATE_TXID_EXCEPTIONS.iter() {
        let prefix = block_undo_key(height, Hash256::default());
        let iter = store.iter_prefix(ColumnFamily::UndoData, &prefix[..5])?;
        for row in iter {
            let (key, value) = row?;
            let key: [u8; 37] = key
                .as_slice()
                .try_into()
                .map_err(|_| ConvertError::IncompatibleData("undo key is not 37 bytes".into()))?;
            let mut hash_bytes = [0_u8; 32];
            hash_bytes.copy_from_slice(&key[5..37]);
            let hash = Hash256::from_le_bytes(&hash_bytes);
            if !is_bip30_exception(height, hash) {
                continue;
            }
            let block = load_block(height, hash)?;
            let created_txids: hashbrown::HashSet<Txid> =
                block.txs.iter().map(|tx| tx.txid()).collect();
            let normalized =
                rewrite_overwrite_restores(&value, hash, &created_txids).map_err(|e| {
                    ConvertError::IncompatibleData(format!(
                        "undo record at height {height} is unreadable: {e}"
                    ))
                })?;
            let Some(bytes) = normalized else { continue };
            pending.push((
                key,
                bytes,
                NormalizedUndoRowReport {
                    height,
                    hash: hash.to_string_be(),
                },
            ));
        }
    }
    if pending.is_empty() {
        return Ok(Vec::new());
    }

    let mut batch = store.new_batch();
    let mut reports = Vec::with_capacity(pending.len());
    for (key, value, report) in pending {
        batch.put(ColumnFamily::UndoData, &key, &value);
        reports.push(report);
    }
    store.write_durable(batch)?;
    Ok(reports)
}

fn set_family_report(
    report: &mut NamespaceReport,
    family: ColumnFamily,
    row_count: u64,
    digest: String,
) {
    if let Some(entry) = report
        .families
        .iter_mut()
        .find(|entry| entry.family == family.name())
    {
        entry.row_count = row_count;
        entry.digest = digest;
    } else {
        report.families.push(FamilyReport {
            family: family.name().to_string(),
            row_count,
            digest,
        });
    }
}

fn decode_body_position(bytes: &[u8]) -> Option<BlockFilePosition> {
    if bytes.len() != 16 {
        return None;
    }
    Some(BlockFilePosition {
        file_no: u32::from_le_bytes(bytes[..4].try_into().ok()?),
        offset: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
        len: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
    })
}

struct MapSpentLookup<'a>(&'a HashMap<OutPoint, UtxoCoin>);
fn find_same_block_spends(
    block: &Block,
    created_txids: &hashbrown::HashSet<Txid>,
) -> hashbrown::HashSet<OutPoint> {
    block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .flat_map(|tx| &tx.inputs)
        .map(|input| input.previous_output)
        .filter(|prev| created_txids.contains(&prev.txid))
        .collect()
}

impl SpentOutputLookup for MapSpentLookup<'_> {
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin> {
        self.0.get(outpoint)
    }
}
fn checkpoint_tip_hash(manifest: &CheckpointManifestV1) -> Result<Hash256, ConvertError> {
    Hash256::from_str_be(&manifest.applied_tip.hash).map_err(|_| {
        ConvertError::IncompatibleData("checkpoint applied tip hash is malformed".into())
    })
}

fn load_canonical_block(
    store: &dyn KvStore,
    blocks_store: &FlatFileBlockStore,
    height: u32,
    hash: Hash256,
) -> Result<Block, ConvertError> {
    let pos_bytes = store
        .get(ColumnFamily::BlockBodies, &block_body_key(height, hash))?
        .ok_or(ConvertError::MissingBlockData { height })?;
    let pos = decode_body_position(&pos_bytes).ok_or(ConvertError::MissingBlockData { height })?;
    let Ok(Some(body_bytes)) = blocks_store.load(pos, height, hash.to_le_bytes()) else {
        return Err(ConvertError::MissingBlockData { height });
    };
    let Ok(block) = Block::consensus_decode(&mut &body_bytes[..]) else {
        return Err(ConvertError::MissingBlockData { height });
    };
    let decoded_hash = Hash256::from(block.block_hash());
    if decoded_hash != hash {
        return Err(ConvertError::ReplayMismatch {
            field: "block identity",
            expected: hash.to_string_be(),
            found: decoded_hash.to_string_be(),
        });
    }
    Ok(block)
}

fn replay_block_coin_effects(
    store: &dyn KvStore,
    height: u32,
    hash: Hash256,
    block: &Block,
    stats: &mut CoinStats,
) -> Result<(), ConvertError> {
    let undo_key = block_undo_key(height, hash);
    let Ok(Some(undo_bytes)) = store.get(ColumnFamily::UndoData, &undo_key) else {
        return Err(ConvertError::MissingBlockData { height });
    };

    let Ok(undo) = decode_undo_record_for_block(&undo_bytes, block) else {
        return Err(ConvertError::MissingBlockData { height });
    };

    let spent_spends = block_spent_outputs(block, height, &undo)
        .map_err(|_| ConvertError::MissingBlockData { height })?;

    let spent_map: HashMap<OutPoint, UtxoCoin> = spent_spends
        .into_iter()
        .flatten()
        .map(|c| (c.outpoint, c))
        .collect();

    let block_txids_set: hashbrown::HashSet<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let same_block_spent = find_same_block_spends(block, &block_txids_set);

    let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let add_cap = block.txs.iter().map(|t| t.outputs.len()).sum();
    let rem_cap = block.txs.iter().map(|t| t.inputs.len()).sum();
    let image = BlockImage::from_local(block.clone());
    let change_inputs = BlockChangeInputs {
        block: &image,
        height,
        txids: &txids,
        same_block_spent: Some(&same_block_spent),
        add_capacity: add_cap,
        remove_capacity: rem_cap,
        max_script_size: 10_000,
    };

    let (changes, _undo_batch, _totals) =
        build_block_changes(&change_inputs, &MapSpentLookup(&spent_map)).map_err(|e| {
            ConvertError::IncompatibleData(format!(
                "build_block_changes failed at height {height}: {e}"
            ))
        })?;

    for outpoint in changes.spent_outpoints() {
        let coin = spent_map.get(outpoint).ok_or_else(|| {
            ConvertError::IncompatibleData(format!(
                "spent coin {outpoint:?} is missing from the undo record at height {height}"
            ))
        })?;
        stats.remove_utxo(outpoint, &coin.txout, coin.height, coin.coinbase);
    }
    for add in changes.adds() {
        stats.insert_utxo(&add.outpoint, &add.txout, add.height, add.coinbase);
    }
    stats.finish_block(height, u64::try_from(block.txs.len()).unwrap_or(u64::MAX));

    let mut spent_by_txid: HashMap<Hash256, HashSet<u32>> = HashMap::new();
    for op in changes.spent_outpoints() {
        spent_by_txid
            .entry(Hash256::from(op.txid))
            .or_default()
            .insert(op.vout);
    }

    let mut adds_by_txid: HashMap<Hash256, Vec<OwnedUtxoOut>> = HashMap::new();
    for add in changes.adds() {
        adds_by_txid
            .entry(Hash256::from(add.outpoint.txid))
            .or_default()
            .push(OwnedUtxoOut {
                vout: add.outpoint.vout,
                value: add.txout.value.to_sat(),
                script_pubkey: add.txout.script_pubkey.as_bytes().to_vec(),
                coinbase: add.coinbase,
                height: add.height,
            });
    }
    let mut batch = store.new_batch();
    for (txid, outputs) in adds_by_txid {
        let record = UtxoRecord::from_owned_outputs(txid, &outputs)
            .map_err(|e| ConvertError::IncompatibleData(format!("invalid utxo record: {e}")))?;
        batch.put(ColumnFamily::Coins, &txid.to_le_bytes(), record.bytes());
    }

    for (txid, spent_vouts) in spent_by_txid {
        if spent_vouts.is_empty() {
            continue;
        }
        let existing_bytes = store
            .get(ColumnFamily::Coins, &txid.to_le_bytes())?
            .ok_or_else(|| {
                ConvertError::IncompatibleData(format!("missing coin record for spent txid {txid}"))
            })?;
        let existing_record = UtxoRecord::from_encoded(existing_bytes.into_boxed_slice())
            .map_err(|e| ConvertError::IncompatibleData(format!("corrupt coin record: {e}")))?;
        let mut remaining: Vec<OwnedUtxoOut> = existing_record
            .outputs()
            .filter(|out| !spent_vouts.contains(&out.vout))
            .map(|out| OwnedUtxoOut {
                vout: out.vout,
                value: out.value,
                script_pubkey: out.script_pubkey.to_vec(),
                coinbase: out.coinbase,
                height: out.height,
            })
            .collect();
        remaining.sort_by_key(|o| o.vout);

        if remaining.is_empty() {
            batch.delete(ColumnFamily::Coins, &txid.to_le_bytes());
        } else {
            let updated = UtxoRecord::from_owned_outputs(txid, &remaining).map_err(|e| {
                ConvertError::IncompatibleData(format!("re-encode utxo record: {e}"))
            })?;
            batch.put(ColumnFamily::Coins, &txid.to_le_bytes(), updated.bytes());
        }
    }

    store.write_durable(batch)?;
    Ok(())
}

fn convert_historical_checkpoints(
    from_dir: &Dir,
    to_path: &Path,
    target_engine: StorageBackend,
) -> Result<(), ConvertError> {
    let source = match from_dir.open_dir(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
    {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let scratch_path = to_path.join(".convert-scratch");
    std::fs::create_dir_all(&scratch_path)?;
    for entry in source.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| name.starts_with("gen-")) else {
            continue;
        };
        let generation_dir = source.open_dir(name)?;
        let mut utxo_file = match open_file_read_no_follow(&generation_dir, UTXO_FILE) {
            Ok(file) => file.into_std(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let manifest_bytes = read_file(&generation_dir, MANIFEST_FILE, 1024 * 1024)
            .map_err(|_| ConvertError::MissingCheckpoint)?;
        let mut manifest: CheckpointManifestV1 =
            sonic_rs::from_slice(&manifest_bytes).map_err(|error| {
                ConvertError::IncompatibleData(format!(
                    "historical checkpoint {name} manifest: {error}"
                ))
            })?;
        utxo_file.rewind()?;
        let collector = CoinRecordCollector::new(manifest.applied_tip.height);
        let (snapshot_load, collector) =
            read_snapshot_strict_v4_observed(&mut utxo_file, collector).map_err(|error| {
                ConvertError::IncompatibleData(format!(
                    "corrupt historical utxo-v4.dat in {name}: {error}"
                ))
            })?;
        let CollectOutcome { records, stats } = collector.finish();
        let record_count = u64::try_from(records.len()).unwrap_or(u64::MAX);
        let output_count = records.iter().fold(0_u64, |total, (_, outputs)| {
            total.saturating_add(u64::try_from(outputs.len()).unwrap_or(u64::MAX))
        });
        verify_checkpoint_statistics(
            &manifest,
            &snapshot_load,
            &stats,
            record_count,
            output_count,
        )?;
        let mut rows = Vec::with_capacity(records.len());
        for (txid, outputs) in records {
            let record = UtxoRecord::from_owned_outputs(txid, &outputs)
                .map_err(|e| ConvertError::IncompatibleData(format!("invalid utxo record: {e}")))?;
            rows.push((txid.to_le_bytes().to_vec(), record.bytes().to_vec()));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let engine_path = to_path
            .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
            .join(name)
            .join("chainstate");
        let engine = open_destination_store(&engine_path, target_engine)?;
        engine.ingest_sorted(ColumnFamily::Coins, &mut rows.into_iter(), &scratch_path)?;
        engine.flush()?;
        drop(engine);
        let chainstate_dir = Dir::open_ambient_dir(&engine_path, ambient_authority())?;
        manifest.engine = Some(digest_engine_dir(&chainstate_dir).map_err(|error| {
            ConvertError::IncompatibleData(format!("historical engine image: {error}"))
        })?);
        let to_root = Dir::open_ambient_dir(to_path, ambient_authority())?;
        let generation_dir = to_root
            .open_dir_nofollow(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)?
            .open_dir_nofollow(name)?;
        retire_historical_utxo_payload(&generation_dir, manifest)?;
    }
    Ok(())
}

fn retire_historical_utxo_payload(
    generation_dir: &Dir,
    mut manifest: CheckpointManifestV1,
) -> Result<(), ConvertError> {
    manifest.utxo = None;
    let bytes = sonic_rs::to_vec(&manifest).map_err(|error| {
        ConvertError::IncompatibleData(format!("historical manifest encode: {error}"))
    })?;
    generation_dir.remove_file(MANIFEST_FILE)?;
    let mut manifest_file = create_file_no_follow(generation_dir, MANIFEST_FILE)?;
    manifest_file.write_all(&bytes)?;
    manifest_file.sync_all()?;
    match generation_dir.remove_file(UTXO_FILE) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    sync_dir(generation_dir)?;
    Ok(())
}

fn carry_full_revalidation_marker(
    from_dir: &Dir,
    to_dir: &Dir,
) -> Result<Vec<String>, ConvertError> {
    let journal = match from_dir.open_dir(EPOCH3_JOURNAL_DIR) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut marker = match open_file_read_no_follow(&journal, FULL_REVALIDATION_MARKER) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    marker.read_to_end(&mut bytes)?;
    let mut copy = create_file_no_follow(to_dir, FULL_REVALIDATION_MARKER)?;
    copy.write_all(&bytes)?;
    copy.sync_all()?;
    sync_dir(to_dir)?;
    Ok(vec![FULL_REVALIDATION_MARKER.to_owned()])
}

const EPOCH3_ARTIFACT_LIMIT: u64 = 64 * 1024 * 1024;

fn publish_epoch4_checkpoint(
    checkpoint_dir: &Dir,
    manifest: &CheckpointManifestV1,
    to_path: &Path,
    engine: &dyn KvStore,
) -> Result<(), ConvertError> {
    let generation = manifest.generation;
    let directory = format!("gen-{generation:020}");
    let root_path = to_path.join(CHECKPOINT_ROOT);
    let generation_path = root_path.join(&directory);
    std::fs::create_dir_all(&generation_path)?;
    for name in [HEADERS_FILE, COINSTATS_FILE] {
        let bytes = read_file(checkpoint_dir, name, EPOCH3_ARTIFACT_LIMIT)?;
        write_synced(&generation_path.join(name), &bytes)?;
    }
    engine.flush()?;
    engine.checkpoint(&generation_path.join("chainstate"))?;
    let chainstate_dir =
        Dir::open_ambient_dir(generation_path.join("chainstate"), ambient_authority())?;
    let mut published = manifest.clone();
    published.utxo = None;
    published.engine = Some(digest_engine_dir(&chainstate_dir).map_err(|error| {
        ConvertError::IncompatibleData(format!("checkpoint engine image: {error}"))
    })?);
    let manifest_bytes = sonic_rs::to_vec(&published)
        .map_err(|error| ConvertError::IncompatibleData(format!("checkpoint manifest: {error}")))?;
    write_synced(&generation_path.join(MANIFEST_FILE), &manifest_bytes)?;
    let current = CurrentV1 {
        format: CURRENT_FORMAT.to_owned(),
        version: CURRENT_VERSION,
        generation,
        directory,
        manifest_sha256: hex_encode(&Sha256::digest(&manifest_bytes)),
    };
    let current_bytes = sonic_rs::to_vec(&current)
        .map_err(|error| ConvertError::IncompatibleData(format!("CURRENT: {error}")))?;
    write_synced(&root_path.join(CURRENT_FILE), &current_bytes)?;
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), ConvertError> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn checkpoint_network(name: &str) -> Result<Network, ConvertError> {
    match name {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet3),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(ConvertError::IncompatibleData(format!(
            "unknown checkpoint network {other}"
        ))),
    }
}

fn run_step_3_to_4(
    args: &CliArgs,
    roots: &crate::fs_util::OpenedRoots,
    target_engine: StorageBackend,
) -> Result<ConversionReport, ConvertError> {
    let (checkpoint_dir, _reference, manifest) = check_complete_checkpoint(&roots.from_dir)?;
    let (_, to_path) = args.convert_roots()?;

    let mut namespaces_report = Vec::new();

    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = to_path.join(rel_path);
        let scratch_base = to_path.join(".convert-src");
        let scratch_path = scratch_base.join(rel_path);

        let paths = NamespacePaths {
            name: ns_name,
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: &roots.from_dir,
            to_root: &roots.to_dir,
        };
        let report = convert_namespace_with_undo_recode(paths, 3, target_engine)?;
        namespaces_report.push(report);
    }

    if let (Some(_), Some(pool_to_path)) = (&args.pool_from, &args.pool_to) {
        let pool_from_dir = roots.pool_from_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool source directory".into())
        })?;
        let pool_to_dir = roots.pool_to_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool target directory".into())
        })?;

        let dst_path = pool_to_path.join("ledger");
        let scratch_base = pool_to_path.join(".convert-src");
        let scratch_path = scratch_base.join("ledger");

        let paths = NamespacePaths {
            name: "ledger",
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: pool_from_dir,
            to_root: pool_to_dir,
        };
        let report = convert_namespace_with_undo_recode(paths, 3, target_engine)?;
        namespaces_report.push(report);
    }

    let mut copied_files = Vec::new();
    copy_independent_files(
        &roots.from_dir,
        &roots.to_dir,
        &mut copied_files,
        false,
        false,
    )?;

    convert_historical_checkpoints(&roots.from_dir, to_path, target_engine)?;

    let cs_dst_path = to_path.join("chainstate");
    let dest_store = open_destination_store(&cs_dst_path, target_engine)?;

    let utxo_file_obj =
        open_file_read_no_follow(&checkpoint_dir, UTXO_FILE).map_err(ConvertError::Io)?;
    let mut std_file = utxo_file_obj.into_std();
    std_file.rewind()?;

    let collector = CoinRecordCollector::new(manifest.applied_tip.height);
    let (snapshot_load, collector) = read_snapshot_strict_v4_observed(&mut std_file, collector)
        .map_err(|e| {
            ConvertError::IncompatibleData(format!("corrupt checkpoint utxo-v4.dat: {e}"))
        })?;

    let CollectOutcome { records, mut stats } = collector.finish();
    let record_count = u64::try_from(records.len()).unwrap_or(u64::MAX);
    let output_count = records.iter().fold(0_u64, |total, (_, outputs)| {
        total.saturating_add(u64::try_from(outputs.len()).unwrap_or(u64::MAX))
    });
    verify_checkpoint_statistics(
        &manifest,
        &snapshot_load,
        &stats,
        record_count,
        output_count,
    )?;
    stats.tx_count = manifest.applied_tip.chain_tx_count;
    let checkpoint_stats_report = coin_stats_report(&stats, manifest.applied_tip.chain_tx_count);
    let mut replay_stats = stats;

    let mut sorted_rows = Vec::with_capacity(records.len());
    for (txid, outputs) in records {
        let record = UtxoRecord::from_owned_outputs(txid, &outputs)
            .map_err(|e| ConvertError::IncompatibleData(format!("invalid utxo record: {e}")))?;
        let key = txid.to_le_bytes().to_vec();
        let value = record.bytes().to_vec();
        sorted_rows.push((key, value));
    }
    sorted_rows.sort_by(|a, b| a.0.cmp(&b.0));

    let scratch_ingest_path = to_path.join(".convert-scratch");
    std::fs::create_dir_all(&scratch_ingest_path)?;
    dest_store.ingest_sorted(
        ColumnFamily::Coins,
        &mut sorted_rows.into_iter(),
        &scratch_ingest_path,
    )?;

    let head_row = dest_store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)?;
    let Some(bytes) = head_row else {
        return Err(ConvertError::IncompatibleData(
            "missing durable head row".into(),
        ));
    };
    let Some(durable_head) = DurableHead::decode(&bytes) else {
        return Err(ConvertError::IncompatibleData(
            "corrupt durable head frame".into(),
        ));
    };

    let checkpoint_height = manifest.applied_tip.height;
    if durable_head.height < checkpoint_height {
        return Err(ConvertError::IncompatibleData(format!(
            "durable head height {} is below checkpoint height {}",
            durable_head.height, checkpoint_height
        )));
    }

    let flat_blocks_store = FlatFileBlockStore::open(to_path)?;

    let checkpoint_hash = checkpoint_tip_hash(&manifest)?;
    let mut chain: Vec<(u32, Hash256)> = Vec::new();
    let mut parent = durable_head.tip;
    for height in (checkpoint_height + 1..=durable_head.height).rev() {
        let block = load_canonical_block(dest_store.as_ref(), &flat_blocks_store, height, parent)?;
        chain.push((height, parent));
        parent = Hash256::from(block.header.prev_blockhash);
    }
    if parent != checkpoint_hash {
        return Err(ConvertError::ReplayMismatch {
            field: "checkpoint ancestry",
            expected: checkpoint_hash.to_string_be(),
            found: parent.to_string_be(),
        });
    }
    chain.reverse();
    let mut suffix_headers = Vec::with_capacity(chain.len());
    for (height, hash) in chain {
        let block = load_canonical_block(dest_store.as_ref(), &flat_blocks_store, height, hash)?;
        replay_block_coin_effects(dest_store.as_ref(), height, hash, &block, &mut replay_stats)?;
        suffix_headers.push(block.header);
    }

    let normalized_undo_rows = normalize_bip30_undo_rows(dest_store.as_ref(), &|height, hash| {
        load_canonical_block(dest_store.as_ref(), &flat_blocks_store, height, hash)
    })?;
    let (mut final_stats, coins_count, coins_digest) =
        scan_destination_coins(dest_store.as_ref(), durable_head.height)?;
    reconcile_replay(&durable_head, &replay_stats, &final_stats)?;
    let undo_digest = if normalized_undo_rows.is_empty() {
        None
    } else {
        Some(compute_destination_digest(
            dest_store.as_ref(),
            ColumnFamily::UndoData,
        )?)
    };
    drop(dest_store);

    let final_stats_report = coin_stats_report(&replay_stats, replay_stats.tx_count);

    if let Some(cs_report) = namespaces_report
        .iter_mut()
        .find(|n| n.namespace == "chainstate")
    {
        set_family_report(cs_report, ColumnFamily::Coins, coins_count, coins_digest);
        if let Some((undo_count, undo_digest)) = undo_digest {
            set_family_report(cs_report, ColumnFamily::UndoData, undo_count, undo_digest);
        }
    }

    cleanup_scratch(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        cleanup_scratch(pool_to_dir)?;
    }

    sync_dir(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        sync_dir(pool_to_dir)?;
    }

    let equal_head =
        durable_head.height == checkpoint_height && durable_head.tip == checkpoint_hash;
    let engine = open_destination_store(&cs_dst_path, target_engine)?;
    if equal_head {
        publish_epoch4_checkpoint(&checkpoint_dir, &manifest, to_path, engine.as_ref())?;
    } else {
        final_stats.tx_count = durable_head.chain_tx_count;
        publish_converted_checkpoint(
            &roots.from_dir,
            &roots.to_dir,
            to_path,
            checkpoint_network(&manifest.network)?,
            ConvertedCheckpoint {
                headers: &suffix_headers,
                tip_height: durable_head.height,
                tip_hash: durable_head.tip,
                chain_tx_count: durable_head.chain_tx_count,
                stats: final_stats,
            },
            engine.as_ref(),
        )
        .map_err(ConvertError::CheckpointPublish)?;
    }
    drop(engine);
    let _snapshot_outcome =
        finalize_snapshot_base(roots, to_path, target_engine, &mut namespaces_report)?;
    let carried_markers = carry_full_revalidation_marker(&roots.from_dir, &roots.to_dir)?;
    publish_current_schema(&roots.to_dir, 6)?;

    Ok(ConversionReport {
        source_epoch: 3,
        target_epoch: 6,
        namespaces: namespaces_report,
        copied_files,
        checkpoint_stats: Some(checkpoint_stats_report),
        final_stats: Some(final_stats_report),
        normalized_undo_rows,
        carried_markers,
        published_checkpoint: true,
    })
}

const SNAPSHOT_NETWORKS: [Network; 5] = [
    Network::Mainnet,
    Network::Testnet3,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

fn pinned_for_base(height: u32, hash: Hash256) -> Option<(Network, &'static AssumeUtxoData)> {
    for network in SNAPSHOT_NETWORKS {
        if let Some(pinned) = network.assume_utxo_for_height(height)
            && pinned.block_hash == hash
        {
            return Some((network, pinned));
        }
    }
    None
}

fn snapshot_base_of(head: &DurableHead) -> Option<(u32, Hash256)> {
    match head.assumeutxo {
        AssumeUtxoDiskStatus::Validating {
            base_height,
            base_hash,
            ..
        }
        | AssumeUtxoDiskStatus::Finalized {
            base_height,
            base_hash,
            ..
        } => Some((base_height, base_hash)),
        AssumeUtxoDiskStatus::Uninitialized | AssumeUtxoDiskStatus::Failed { .. } => None,
    }
}
fn snapshot_archive_base_dir(from_dir: &Dir, base: &str) -> Result<Dir, ConvertError> {
    let invalid = |reason: String| ConvertError::SnapshotArchiveInvalid {
        base: base.to_owned(),
        reason,
    };
    let root = from_dir
        .open_dir_nofollow("assumeutxo")
        .map_err(|_| invalid("missing assumeutxo archive".to_owned()))?;
    root.open_dir_nofollow(base)
        .map_err(|_| invalid("missing snapshot base archive".to_owned()))
}

fn read_snapshot_archive_headers(
    from_dir: &Dir,
    pinned: &AssumeUtxoData,
) -> Result<Vec<Header>, ConvertError> {
    let base = pinned.block_hash.to_string();
    let invalid = |reason: String| ConvertError::SnapshotArchiveInvalid {
        base: base.clone(),
        reason,
    };
    let dir = snapshot_archive_base_dir(from_dir, &base)?;
    let file = open_file_read_no_follow(&dir, "headers.dat")
        .map_err(|_| invalid("missing headers.dat".to_owned()))?;
    if file.metadata()?.len() != (u64::from(pinned.height) + 1) * 80 {
        return Err(invalid(format!(
            "headers.dat length does not match pinned height {}",
            pinned.height
        )));
    }
    let mut std_file = file.into_std();
    let mut bytes = Vec::new();
    std_file.read_to_end(&mut bytes)?;
    bytes
        .as_chunks::<80>()
        .0
        .iter()
        .map(|chunk| deserialize::<Header>(chunk).map_err(|error| invalid(error.to_string())))
        .collect()
}

fn verify_snapshot_archive_coins(
    from_dir: &Dir,
    pinned: &AssumeUtxoData,
) -> Result<(), ConvertError> {
    let base = pinned.block_hash.to_string();
    let invalid = |reason: String| ConvertError::SnapshotArchiveInvalid {
        base: base.clone(),
        reason,
    };
    let dir = snapshot_archive_base_dir(from_dir, &base)?;
    let file = open_file_read_no_follow(&dir, "coins.dat")
        .map_err(|_| invalid("missing coins.dat".to_owned()))?;
    let mut std_file = file.into_std();
    let streamed = stream_snapshot_v4_records(&mut std_file, |_: Hash256, _: &UtxoRecord| {
        Ok::<(), UtxoError>(())
    })
    .map_err(|error| invalid(format!("coins.dat: {error}")))?;
    if streamed.height != pinned.height || streamed.tip_hash != pinned.block_hash {
        return Err(invalid(
            "coins.dat identity does not match the pinned base".to_owned(),
        ));
    }
    if streamed.hash_serialized != pinned.hash_serialized {
        return Err(invalid(
            "coins.dat hash does not match the pinned commitment".to_owned(),
        ));
    }
    Ok(())
}

struct SnapshotStepOutcome {
    checkpoint_stats: Option<CoinStatsReport>,
    final_stats: Option<CoinStatsReport>,
    published_checkpoint: bool,
}

fn finalize_snapshot_base(
    roots: &crate::fs_util::OpenedRoots,
    to_path: &Path,
    target_engine: StorageBackend,
    namespaces_report: &mut [NamespaceReport],
) -> Result<SnapshotStepOutcome, ConvertError> {
    let cs_dst_path = to_path.join("chainstate");
    let dest_store = open_destination_store(&cs_dst_path, target_engine)?;
    let durable_head =
        match dest_store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)? {
            Some(bytes) => Some(DurableHead::decode(&bytes).ok_or_else(|| {
                ConvertError::IncompatibleData("corrupt durable head frame".into())
            })?),
            None => None,
        };
    let mut published_checkpoint = false;
    let mut checkpoint_stats = None;
    let mut final_stats = None;
    if let Some(head) = durable_head.as_ref()
        && let Some((base_height, base_hash)) = snapshot_base_of(head)
    {
        let (network, pinned) = pinned_for_base(base_height, base_hash).ok_or_else(|| {
            ConvertError::IncompatibleData(format!(
                "unrecognized snapshot base {base_hash} at height {base_height}"
            ))
        })?;
        let compatible =
            snapshot_base_checkpoint_compatible(&roots.to_dir, Some(to_path), network, pinned)
                .map_err(ConvertError::CheckpointPublish)?;
        if !compatible {
            if head.height != base_height {
                return Err(ConvertError::MissingCheckpoint);
            }
            let headers = read_snapshot_archive_headers(&roots.from_dir, pinned)?;
            verify_snapshot_archive_coins(&roots.from_dir, pinned)?;
            let (mut stats, coins_count, coins_digest) =
                scan_destination_coins(dest_store.as_ref(), head.height)?;
            stats.tx_count = pinned.chain_tx_count;
            let stats_report = coin_stats_report(&stats, pinned.chain_tx_count);
            publish_snapshot_base_checkpoint(
                &roots.to_dir,
                to_path,
                network,
                &headers,
                pinned,
                dest_store.as_ref(),
            )
            .map_err(ConvertError::CheckpointPublish)?;
            published_checkpoint = true;
            checkpoint_stats = Some(stats_report.clone());
            final_stats = Some(stats_report);
            if let Some(cs_report) = namespaces_report
                .iter_mut()
                .find(|n| n.namespace == "chainstate")
            {
                set_family_report(cs_report, ColumnFamily::Coins, coins_count, coins_digest);
            }
        }
    }
    Ok(SnapshotStepOutcome {
        checkpoint_stats,
        final_stats,
        published_checkpoint,
    })
}

fn run_step_4_to_6(
    args: &CliArgs,
    roots: &crate::fs_util::OpenedRoots,
    target_engine: StorageBackend,
) -> Result<ConversionReport, ConvertError> {
    let (_, to_path) = args.convert_roots()?;
    let mut namespaces_report = Vec::new();
    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = to_path.join(rel_path);
        let scratch_base = to_path.join(".convert-src");
        let scratch_path = scratch_base.join(rel_path);
        let paths = NamespacePaths {
            name: ns_name,
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: &roots.from_dir,
            to_root: &roots.to_dir,
        };
        let report = convert_namespace_with_undo_recode(paths, 4, target_engine)?;
        namespaces_report.push(report);
    }
    if let (Some(_), Some(pool_to_path)) = (&args.pool_from, &args.pool_to) {
        let pool_from_dir = roots.pool_from_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool source directory".into())
        })?;
        let pool_to_dir = roots.pool_to_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool target directory".into())
        })?;
        let dst_path = pool_to_path.join("ledger");
        let scratch_base = pool_to_path.join(".convert-src");
        let scratch_path = scratch_base.join("ledger");
        let paths = NamespacePaths {
            name: "ledger",
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: pool_from_dir,
            to_root: pool_to_dir,
        };
        let report = convert_namespace_with_undo_recode(paths, 4, target_engine)?;
        namespaces_report.push(report);
    }
    let mut copied_files = Vec::new();
    copy_independent_files(
        &roots.from_dir,
        &roots.to_dir,
        &mut copied_files,
        false,
        true,
    )?;
    let SnapshotStepOutcome {
        checkpoint_stats,
        final_stats,
        published_checkpoint,
    } = finalize_snapshot_base(roots, to_path, target_engine, &mut namespaces_report)?;
    let carried_markers = carry_full_revalidation_marker(&roots.from_dir, &roots.to_dir)?;
    cleanup_scratch(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        cleanup_scratch(pool_to_dir)?;
    }
    sync_dir(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        sync_dir(pool_to_dir)?;
    }
    publish_current_schema(&roots.to_dir, 6)?;
    Ok(ConversionReport {
        source_epoch: 4,
        target_epoch: 6,
        namespaces: namespaces_report,
        copied_files,
        checkpoint_stats,
        final_stats,
        normalized_undo_rows: Vec::new(),
        carried_markers,
        published_checkpoint,
    })
}
fn run_step_5_to_6(
    args: &CliArgs,
    roots: &crate::fs_util::OpenedRoots,
    target_engine: StorageBackend,
) -> Result<ConversionReport, ConvertError> {
    let (_, to_path) = args.convert_roots()?;
    let mut namespaces_report = Vec::new();
    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = to_path.join(rel_path);
        let scratch_base = to_path.join(".convert-src");
        let scratch_path = scratch_base.join(rel_path);
        let paths = NamespacePaths {
            name: ns_name,
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: &roots.from_dir,
            to_root: &roots.to_dir,
        };
        let report = convert_namespace_with_undo_recode(paths, 5, target_engine)?;
        namespaces_report.push(report);
    }
    if let (Some(_), Some(pool_to_path)) = (&args.pool_from, &args.pool_to) {
        let pool_from_dir = roots.pool_from_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool source directory".into())
        })?;
        let pool_to_dir = roots.pool_to_dir.as_ref().ok_or_else(|| {
            ConvertError::InvalidOperation("missing pool target directory".into())
        })?;
        let dst_path = pool_to_path.join("ledger");
        let scratch_base = pool_to_path.join(".convert-src");
        let scratch_path = scratch_base.join("ledger");
        let paths = NamespacePaths {
            name: "ledger",
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: pool_from_dir,
            to_root: pool_to_dir,
        };
        let report = convert_namespace_with_undo_recode(paths, 5, target_engine)?;
        namespaces_report.push(report);
    }
    let mut copied_files = Vec::new();
    copy_independent_files(
        &roots.from_dir,
        &roots.to_dir,
        &mut copied_files,
        false,
        true,
    )?;
    let SnapshotStepOutcome {
        checkpoint_stats,
        final_stats,
        published_checkpoint,
    } = finalize_snapshot_base(roots, to_path, target_engine, &mut namespaces_report)?;
    let carried_markers = carry_full_revalidation_marker(&roots.from_dir, &roots.to_dir)?;
    cleanup_scratch(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        cleanup_scratch(pool_to_dir)?;
    }
    sync_dir(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        sync_dir(pool_to_dir)?;
    }
    publish_current_schema(&roots.to_dir, 6)?;
    Ok(ConversionReport {
        source_epoch: 5,
        target_epoch: 6,
        namespaces: namespaces_report,
        copied_files,
        checkpoint_stats,
        final_stats,
        normalized_undo_rows: Vec::new(),
        carried_markers,
        published_checkpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::{
        Amount, BlockHash, CompactTarget, Header, LockTime, Script, Sequence, Tx, TxIn, TxOut,
    };
    use bitcoin_rs_storage::memory_kv::MemoryKvStore;
    use bitcoin_rs_storage::utxo::contract::{decode_undo_record, encode_undo_record};

    fn overwrite_fixture() -> Result<(u32, Hash256, Block, OutPoint, MemoryKvStore), String> {
        let (height, hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
        let coinbase = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes(vec![0x51]),
                sequence: Sequence::MAX,
                witness: Default::default(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        };
        let txid = coinbase.txid();
        let overwritten = OutPoint::new(txid, 0);
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash(Hash256::default()),
                merkle_root: Hash256::default(),
                time: 1_300_000_000,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 1,
            },
            txs: vec![coinbase],
        };
        let undo = bitcoin_rs_storage::utxo::contract::UndoBatch::from_parts(
            vec![bitcoin_rs_storage::utxo::contract::UtxoAdd::new(
                overwritten,
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                },
                true,
                91_722,
            )],
            Vec::new(),
        );
        let store = MemoryKvStore::default();
        store
            .put(
                ColumnFamily::UndoData,
                &block_undo_key(height, hash),
                &encode_undo_record(&undo, hash),
            )
            .map_err(|e| e.to_string())?;
        Ok((height, hash, block, overwritten, store))
    }

    #[test]
    fn normalize_bip30_undo_rows_drops_overwrite_restores() -> Result<(), String> {
        let (height, hash, block, overwritten, store) = overwrite_fixture()?;
        let load_block = |requested_height: u32, requested_hash: Hash256| {
            if requested_height == height && requested_hash == hash {
                Ok(block.clone())
            } else {
                Err(ConvertError::MissingBlockData {
                    height: requested_height,
                })
            }
        };

        let rows = normalize_bip30_undo_rows(&store, &load_block).map_err(|e| e.to_string())?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].height, height);

        let stored = store
            .get(ColumnFamily::UndoData, &block_undo_key(height, hash))
            .map_err(|e| e.to_string())?
            .ok_or("normalized row disappeared")?;
        let batch = decode_undo_record(&stored, hash).map_err(|e| e.to_string())?;
        assert!(batch.restores().is_empty());
        assert!(batch.removes().is_empty());
        assert!(
            batch
                .restores()
                .iter()
                .all(|add| add.outpoint != overwritten)
        );
        Ok(())
    }

    #[test]
    fn reconcile_refuses_a_coin_count_that_differs_from_the_replay() -> Result<(), String> {
        let head = DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: Hash256::default(),
            chain_tx_count: 0,
            body_extent: None,
            undo_extent: None,
        };
        let replayed = CoinStatsAccumulator::with_parallel_muhash(0).into_stats();
        let mut stored = CoinStatsAccumulator::with_parallel_muhash(0).into_stats();
        stored.utxo_count += 1;
        let error = reconcile_replay(&head, &replayed, &stored)
            .err()
            .ok_or_else(|| "a coin count that differs from the replay must refuse".to_owned())?;
        match error {
            ConvertError::ReplayMismatch {
                field: "utxo_count",
                ..
            } => Ok(()),
            other => Err(format!("unexpected refusal: {other}")),
        }
    }
    #[test]
    fn undo_recode_drops_created_outputs_and_preserves_spent_coins() -> Result<(), String> {
        use crate::legacy_undo::{decode_legacy_undo_record, encode_legacy_undo_record};
        use bitcoin_rs_storage::utxo::contract::{UndoBatch, UtxoAdd};
        let hash = Hash256::from_le_bytes(&[0x09; 32]);
        let mut restores = Vec::new();
        for (txid_byte, vout, sats) in [(0x01_u8, 0_u32, 50_000_u64), (0x02_u8, 7_u32, 1_u64)] {
            let outpoint = OutPoint::new(Hash256::from_le_bytes(&[txid_byte; 32]).into(), vout);
            let txout = TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: Script::from_bytes(vec![0x51]),
            };
            restores.push(UtxoAdd::new(outpoint, txout, false, 11));
        }
        let removes = vec![OutPoint::new(Hash256::from_le_bytes(&[0x03; 32]).into(), 0)];
        let batch = UndoBatch::from_parts(restores, removes);
        let old_bytes = encode_legacy_undo_record(&batch, hash);
        assert_eq!(old_bytes[0], 1);
        let legacy = decode_legacy_undo_record(&old_bytes, hash).map_err(|e| e.to_string())?;
        assert_eq!(legacy.restores().len(), 2);
        assert_eq!(legacy.removes().len(), 1);
        let recoded = encode_undo_record(&legacy, hash);
        assert_eq!(recoded[0], 2);
        let mut expected_len = 37_usize;
        for add in legacy.restores() {
            let script_len = add.txout.script_pubkey.len();
            expected_len = expected_len
                .saturating_add(36)
                .saturating_add(8)
                .saturating_add(1)
                .saturating_add(script_len)
                .saturating_add(1)
                .saturating_add(4);
        }
        assert_eq!(recoded.len(), expected_len);
        let decoded = decode_undo_record(&recoded, hash).map_err(|e| e.to_string())?;
        assert_eq!(decoded.restores(), legacy.restores());
        assert!(decoded.removes().is_empty());
        let copied = decode_undo_record(&old_bytes, hash);
        assert!(copied.is_err());
        Ok(())
    }
}
