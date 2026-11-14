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
    Amount, Block, BlockImage, ConsensusDecode, Hash256, Network, OutPoint, Script, TxOut, Txid,
    hex::hex_encode,
};
use bitcoin_rs_execution::recovery::{ConvertedCheckpoint, publish_converted_checkpoint};
use bitcoin_rs_storage::checkpoint::{
    CHECKPOINT_ROOT, COINSTATS_FILE, CURRENT_FILE, CURRENT_FORMAT, CURRENT_VERSION,
    CheckpointManifestV1, CheckpointOpen, CheckpointReference, CurrentV1, HEADERS_FILE,
    HISTORICAL_CHECKPOINT_ROOT, MANIFEST_FILE, decode_hex, open_current_checkpoint_at, read_file,
};
pub(crate) const UTXO_FILE: &str = "utxo-v4.dat";
const EPOCH3_JOURNAL_DIR: &str = "chainstate-journal";
use bitcoin_rs_storage::assumeutxo::{AssumeUtxoDiskStatus, HistoricalCheckpointRef};
use bitcoin_rs_storage::durable_head::{DURABLE_HEAD_KEY, DurableHead};
use bitcoin_rs_storage::pruning::{block_body_key, block_undo_key};
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::contract::{
    BlockChangeInputs, SpentOutputLookup, block_spent_outputs, build_block_changes,
    decode_undo_record_for_block, rewrite_overwrite_restores,
};
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsAccumulator};
use bitcoin_rs_storage::utxo::{
    SnapshotCoin, SnapshotCoinObserver, read_snapshot_strict_v4_observed,
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
    report_name: &'a str,
    dst_path: &'a Path,
    scratch_path: &'a Path,
    from_root: &'a Dir,
    to_root: &'a Dir,
}

pub(crate) fn run_conversion(args: CliArgs) -> Result<ConversionReport, ConvertError> {
    let target_engine = args.target_backend()?;
    let roots = validate_and_open_roots(&args)?;

    let source_epoch = read_source_epoch(&roots.from_dir)?;
    if source_epoch != 2 && source_epoch != 3 && source_epoch != 4 {
        return Err(ConvertError::UnknownEpoch(source_epoch));
    }

    if source_epoch == 3 {
        return run_step_3_to_4(&args, &roots, target_engine);
    }

    let target_epoch = match source_epoch {
        2 => 3,
        4 => 4,
        _ => return Err(ConvertError::UnknownEpoch(source_epoch)),
    };

    let mut namespaces_report = Vec::new();

    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = args.to.join(rel_path);
        let scratch_base = args.to.join(".convert-src");
        let scratch_path = scratch_base.join(rel_path);

        let paths = NamespacePaths {
            name: ns_name,
            report_name: ns_name,
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
            report_name: "ledger",
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
    let include_checkpoints = source_epoch == 2;
    let include_historical = source_epoch != 4;
    copy_independent_files(
        &roots.from_dir,
        &roots.to_dir,
        &mut copied_files,
        include_journal,
        include_checkpoints,
        include_historical,
    )?;
    if source_epoch == 4 {
        let mut ctx = NestedImageContext {
            from_root: &roots.from_dir,
            to_root: &roots.to_dir,
            to_base: &args.to,
            target_engine,
            copied_files: &mut copied_files,
            reports: &mut namespaces_report,
        };
        convert_nested_checkpoint_images(&mut ctx)?;
    }
    let carried_markers = if source_epoch == 4 {
        copy_full_revalidation_marker(&roots.from_dir, &roots.to_dir)?
    } else {
        Vec::new()
    };

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
        carried_markers,
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
                namespace: paths.report_name.to_string(),
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
            namespace: paths.report_name.to_string(),
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
                namespace: paths.report_name.to_string(),
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
        namespace: paths.report_name.to_string(),
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
    include_historical: bool,
) -> Result<(), ConvertError> {
    let mut independent_dirs = vec!["blocks", "assumeutxo"];
    if include_historical {
        independent_dirs.push("assumeutxo-historical-checkpoints");
    }
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
        copy_independent_file(from_root, to_root, file_name, file_name, copied_files)?;
    }

    copy_scoped_peers_books(from_root, to_root, copied_files)?;

    Ok(())
}

fn copy_independent_file(
    from_root: &Dir,
    to_root: &Dir,
    file_name: &str,
    report_path: &str,
    copied_files: &mut Vec<CopiedFileReport>,
) -> Result<(), ConvertError> {
    let mut src_file = match open_file_read_no_follow(from_root, file_name) {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ConvertError::Io(err)),
    };

    let mut dst_file = create_file_no_follow(to_root, file_name)?;
    let bytes = io::copy(&mut src_file, &mut dst_file)?;
    dst_file.sync_all()?;

    copied_files.push(CopiedFileReport {
        path: report_path.to_string(),
        bytes,
    });
    Ok(())
}

fn is_scoped_peers_book(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("peers-") else {
        return false;
    };
    let Some(hex) = rest.strip_suffix(".dat") else {
        return false;
    };
    hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn copy_scoped_peers_books(
    from_root: &Dir,
    to_root: &Dir,
    copied_files: &mut Vec<CopiedFileReport>,
) -> Result<(), ConvertError> {
    let mut scoped: Vec<String> = Vec::new();
    for entry in from_root.entries()? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if is_scoped_peers_book(name) {
            scoped.push(name.to_string());
        }
    }
    scoped.sort();

    for name in &scoped {
        copy_independent_file(from_root, to_root, name, name, copied_files)?;
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

struct NestedImageContext<'a> {
    from_root: &'a Dir,
    to_root: &'a Dir,
    to_base: &'a Path,
    target_engine: StorageBackend,
    copied_files: &'a mut Vec<CopiedFileReport>,
    reports: &'a mut Vec<NamespaceReport>,
}

const GENERATION_ENGINE_DIR: &str = "chainstate";

fn convert_nested_checkpoint_images(ctx: &mut NestedImageContext<'_>) -> Result<(), ConvertError> {
    for root_name in [CHECKPOINT_ROOT, HISTORICAL_CHECKPOINT_ROOT] {
        convert_generation_root(ctx, root_name)?;
    }
    Ok(())
}

fn convert_generation_root(
    ctx: &mut NestedImageContext<'_>,
    root_name: &str,
) -> Result<(), ConvertError> {
    let src_root = match ctx.from_root.open_dir_nofollow(root_name) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ConvertError::Io(err)),
    };
    let dst_root = open_or_create_dir_nofollow(ctx.to_root, root_name)?;

    let mut generation_names = Vec::new();
    for entry in src_root.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(ConvertError::InvalidOperation(
                "non-UTF8 file name encountered in checkpoint root".into(),
            ));
        };
        let file_type = entry.file_type()?;
        if file_type.is_dir() && is_generation_dir_name(name_str) {
            generation_names.push(name_str.to_string());
        } else {
            let report_prefix = format!("{root_name}/{name_str}");
            let mut copy = GenerationCopy {
                src: &src_root,
                dst: &dst_root,
                report_prefix: &report_prefix,
                copied_files: &mut *ctx.copied_files,
            };
            copy_generation_root_entry(&mut copy, name_str, file_type)?;
        }
    }
    generation_names.sort();
    for name in &generation_names {
        convert_generation_image(&src_root, &dst_root, ctx, root_name, name)?;
    }
    sync_dir(&dst_root)?;
    Ok(())
}

struct GenerationCopy<'a> {
    src: &'a Dir,
    dst: &'a Dir,
    report_prefix: &'a str,
    copied_files: &'a mut Vec<CopiedFileReport>,
}

fn copy_generation_root_entry(
    ctx: &mut GenerationCopy<'_>,
    name: &str,
    file_type: cap_std::fs::FileType,
) -> Result<(), ConvertError> {
    if file_type.is_file() {
        copy_independent_file(ctx.src, ctx.dst, name, ctx.report_prefix, ctx.copied_files)?;
        return Ok(());
    }
    if !file_type.is_dir() {
        return Err(ConvertError::InvalidOperation(format!(
            "unsupported entry '{name}' in checkpoint root"
        )));
    }
    let child_src = ctx.src.open_dir_nofollow(name)?;
    let child_dst = open_or_create_dir_nofollow(ctx.dst, name)?;
    copy_dir_recursive(&child_src, &child_dst)?;
    collect_copied_files_from_dir(&child_src, ctx.report_prefix, ctx.copied_files)
}

fn is_generation_dir_name(name: &str) -> bool {
    match name.strip_prefix("gen-") {
        Some(digits) => digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

fn open_or_create_dir_nofollow(parent: &Dir, name: &str) -> Result<Dir, ConvertError> {
    match parent.open_dir_nofollow(name) {
        Ok(dir) => Ok(dir),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            parent.create_dir(name)?;
            Ok(parent.open_dir_nofollow(name)?)
        }
        Err(err) => Err(ConvertError::Io(err)),
    }
}

fn convert_generation_image(
    src_root: &Dir,
    dst_root: &Dir,
    ctx: &mut NestedImageContext<'_>,
    root_name: &str,
    name: &str,
) -> Result<(), ConvertError> {
    let src_gen = src_root.open_dir_nofollow(name)?;
    let dst_gen = open_or_create_dir_nofollow(dst_root, name)?;
    let report_prefix = format!("{root_name}/{name}");
    let mut copy = GenerationCopy {
        src: &src_gen,
        dst: &dst_gen,
        report_prefix: &report_prefix,
        copied_files: &mut *ctx.copied_files,
    };
    copy_generation_sidecars(&mut copy, name)?;
    let engine_dir = match src_gen.open_dir_nofollow(GENERATION_ENGINE_DIR) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            sync_dir(&dst_gen)?;
            return Ok(());
        }
        Err(err) if err.kind() == io::ErrorKind::NotADirectory => {
            return Err(ConvertError::IncompatibleData(format!(
                "checkpoint generation {name} has a malformed engine entry"
            )));
        }
        Err(err) => return Err(ConvertError::Io(err)),
    };
    let memory_name = bitcoin_rs_storage::memory_kv::MEMORY_KV_FILE;
    match engine_dir.symlink_metadata(memory_name) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(ConvertError::IncompatibleData(
                    "checkpoint memory image must be a regular file".into(),
                ));
            }
            for entry in engine_dir.entries()? {
                if entry?.file_name() != std::ffi::OsStr::new(memory_name) {
                    return Err(ConvertError::IncompatibleData(
                        "checkpoint memory image contains unrelated engine files".into(),
                    ));
                }
            }
            let mut file = open_file_read_no_follow(&engine_dir, memory_name)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            bitcoin_rs_storage::memory_kv::MemoryKvStore::from_bytes(&bytes)?;
            let destination = open_or_create_dir_nofollow(&dst_gen, GENERATION_ENGINE_DIR)?;
            copy_independent_file(
                &engine_dir,
                &destination,
                memory_name,
                &format!("{report_prefix}/{GENERATION_ENGINE_DIR}/{memory_name}"),
                ctx.copied_files,
            )?;
            sync_dir(&destination)?;
            sync_dir(&dst_gen)?;
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    drop(engine_dir);
    let report_name = format!("{root_name}/{name}/{GENERATION_ENGINE_DIR}");
    let scratch_base = ctx.to_base.join(root_name).join(name).join(".convert-src");
    let scratch_path = scratch_base.join(GENERATION_ENGINE_DIR);
    let dst_path = ctx
        .to_base
        .join(root_name)
        .join(name)
        .join(GENERATION_ENGINE_DIR);
    let paths = NamespacePaths {
        name: GENERATION_ENGINE_DIR,
        report_name: &report_name,
        dst_path: &dst_path,
        scratch_path: &scratch_path,
        from_root: &src_gen,
        to_root: &dst_gen,
    };
    let report = convert_namespace(paths, 4, ctx.target_engine)?;
    cleanup_scratch(&dst_gen)?;
    sync_dir(&dst_gen)?;
    if report.engine != "empty" {
        ctx.reports.push(report);
    }
    Ok(())
}

fn copy_generation_sidecars(
    copy: &mut GenerationCopy<'_>,
    generation: &str,
) -> Result<(), ConvertError> {
    for entry in copy.src.entries()? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let child_name = entry.file_name();
        let Some(child) = child_name.to_str() else {
            return Err(ConvertError::InvalidOperation(
                "non-UTF8 file name encountered in checkpoint generation".into(),
            ));
        };
        if child == GENERATION_ENGINE_DIR {
            continue;
        }
        let report_path = format!("{}/{child}", copy.report_prefix);
        if file_type.is_file() {
            copy_independent_file(copy.src, copy.dst, child, &report_path, copy.copied_files)?;
        } else if file_type.is_dir() {
            let child_src = copy.src.open_dir_nofollow(child)?;
            let child_dst = open_or_create_dir_nofollow(copy.dst, child)?;
            copy_dir_recursive(&child_src, &child_dst)?;
            collect_copied_files_from_dir(&child_src, &report_path, copy.copied_files)?;
        } else {
            return Err(ConvertError::InvalidOperation(format!(
                "unsupported entry '{child}' in checkpoint generation {generation}"
            )));
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
    let expected_headers_digest: [u8; 32] = decode_hex(&manifest.headers.sha256).map_err(|_| {
        ConvertError::IncompatibleData("manifest headers sha256 is malformed".into())
    })?;
    let mut headers_hasher = Sha256::new();
    let mut headers_reader = headers_file;
    let mut headers_chunk = vec![0_u8; 64 * 1024];
    loop {
        let read = headers_reader.read(&mut headers_chunk)?;
        if read == 0 {
            break;
        }
        headers_hasher.update(&headers_chunk[..read]);
    }
    let found_headers_digest: [u8; 32] = headers_hasher.finalize().into();
    if found_headers_digest != expected_headers_digest {
        return Err(ConvertError::CheckpointDigestMismatch { file: HEADERS_FILE });
    }

    let coinstats_file = open_file_read_no_follow(&generation_dir, COINSTATS_FILE)
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    let c_meta = coinstats_file
        .metadata()
        .map_err(|_| ConvertError::MissingCheckpoint)?;
    if c_meta.len() != manifest.coinstats.bytes {
        return Err(ConvertError::MissingCheckpoint);
    }
    let expected_coinstats_digest: [u8; 32] =
        decode_hex(&manifest.coinstats.sha256).map_err(|_| {
            ConvertError::IncompatibleData("manifest coinstats sha256 is malformed".into())
        })?;
    let mut coinstats_hasher = Sha256::new();
    let mut coinstats_reader = coinstats_file;
    let mut coinstats_chunk = vec![0_u8; 64 * 1024];
    loop {
        let read = coinstats_reader.read(&mut coinstats_chunk)?;
        if read == 0 {
            break;
        }
        coinstats_hasher.update(&coinstats_chunk[..read]);
    }
    let found_coinstats_digest: [u8; 32] = coinstats_hasher.finalize().into();
    if found_coinstats_digest != expected_coinstats_digest {
        return Err(ConvertError::CheckpointDigestMismatch {
            file: COINSTATS_FILE,
        });
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

    for txid in adds_by_txid.keys() {
        let overwritten = store.get(ColumnFamily::Coins, &txid.to_le_bytes())?;
        let Some(bytes) = overwritten else {
            continue;
        };
        let record = UtxoRecord::from_encoded(bytes.into_boxed_slice())
            .map_err(|e| ConvertError::IncompatibleData(format!("corrupt coin record: {e}")))?;
        let spent = spent_by_txid.get(txid);
        for out in record.outputs() {
            if spent.is_some_and(|spent_vouts| spent_vouts.contains(&out.vout)) {
                continue;
            }
            let txout = TxOut {
                value: Amount::from_sat(out.value),
                script_pubkey: Script::from_bytes(out.script_pubkey.to_vec()),
            };
            stats.remove_utxo(
                &OutPoint::new((*txid).into(), out.vout),
                &txout,
                out.height,
                out.coinbase,
            );
        }
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
) -> Result<Vec<(HistoricalCheckpointRef, HistoricalCheckpointRef)>, ConvertError> {
    let source = match from_dir.open_dir(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
    {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let scratch_path = to_path.join(".convert-scratch");
    std::fs::create_dir_all(&scratch_path)?;
    let mut references = Vec::new();
    for entry in source.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| name.starts_with("gen-")) else {
            continue;
        };
        let generation_dir = source.open_dir(name)?;
        match generation_dir.symlink_metadata(UTXO_FILE) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(ConvertError::IncompatibleData(
                    "historical utxo payload must be a regular file".into(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        }
        let manifest_bytes = read_file(&generation_dir, MANIFEST_FILE, 1024 * 1024)
            .map_err(|_| ConvertError::MissingCheckpoint)?;
        let manifest: CheckpointManifestV1 =
            sonic_rs::from_slice(&manifest_bytes).map_err(|error| {
                ConvertError::IncompatibleData(format!(
                    "historical checkpoint {name} manifest: {error}"
                ))
            })?;
        let old_reference = HistoricalCheckpointRef {
            checkpoint: CheckpointReference {
                generation: manifest.generation,
                manifest_sha256: Sha256::digest(&manifest_bytes).into(),
            },
            height: manifest.applied_tip.height,
            hash: checkpoint_tip_hash(&manifest)?,
        };
        if name != format!("gen-{:020}", manifest.generation) {
            return Err(ConvertError::IncompatibleData(
                "historical generation does not match manifest".into(),
            ));
        }
        let utxo = manifest
            .utxo
            .as_ref()
            .ok_or(ConvertError::MissingCheckpoint)?;
        bitcoin_rs_storage::checkpoint::require_filename(&utxo.file, UTXO_FILE)
            .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
        let mut utxo_file = bitcoin_rs_storage::checkpoint::verify_artifact(
            &generation_dir,
            UTXO_FILE,
            utxo.bytes,
            &utxo.sha256,
        )
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?
        .into_std();
        bitcoin_rs_storage::checkpoint::require_filename(&manifest.headers.file, HEADERS_FILE)
            .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
        bitcoin_rs_storage::checkpoint::verify_artifact(
            &generation_dir,
            HEADERS_FILE,
            manifest.headers.bytes,
            &manifest.headers.sha256,
        )
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
        bitcoin_rs_storage::checkpoint::require_filename(&manifest.coinstats.file, COINSTATS_FILE)
            .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
        bitcoin_rs_storage::checkpoint::verify_artifact(
            &generation_dir,
            COINSTATS_FILE,
            manifest.coinstats.bytes,
            &manifest.coinstats.sha256,
        )
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
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
        let to_root = Dir::open_ambient_dir(to_path, ambient_authority())?;
        let generation_dir = to_root
            .open_dir_nofollow(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)?
            .open_dir_nofollow(name)?;
        let manifest_sha256 = retire_historical_utxo_payload(&generation_dir, manifest)?;
        let mut new_reference = old_reference;
        new_reference.checkpoint.manifest_sha256 = manifest_sha256;
        references.push((old_reference, new_reference));
    }
    match read_file(&source, CURRENT_FILE, 1024 * 1024) {
        Ok(bytes) => {
            let mut current: CurrentV1 = sonic_rs::from_slice(&bytes)
                .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
            let old_sha256 = decode_hex::<32>(&current.manifest_sha256)
                .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
            let (_, replacement) = references
                .iter()
                .find(|(old, _)| {
                    old.checkpoint.generation == current.generation
                        && old.checkpoint.manifest_sha256 == old_sha256
                        && current.directory == format!("gen-{:020}", current.generation)
                        && current.format == CURRENT_FORMAT
                        && current.version == CURRENT_VERSION
                })
                .ok_or_else(|| {
                    ConvertError::IncompatibleData(
                        "historical CURRENT does not authenticate a converted generation".into(),
                    )
                })?;
            current.manifest_sha256 = hex_encode(&replacement.checkpoint.manifest_sha256);
            let bytes = sonic_rs::to_vec(&current)
                .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
            write_synced(
                &to_path
                    .join(bitcoin_rs_storage::checkpoint::HISTORICAL_CHECKPOINT_ROOT)
                    .join(CURRENT_FILE),
                &bytes,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(references)
}

fn retire_historical_utxo_payload(
    generation_dir: &Dir,
    mut manifest: CheckpointManifestV1,
) -> Result<[u8; 32], ConvertError> {
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
    Ok(Sha256::digest(&bytes).into())
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
    copy_full_revalidation_marker(&journal, to_dir)
}

fn copy_full_revalidation_marker(
    from_dir: &Dir,
    to_dir: &Dir,
) -> Result<Vec<String>, ConvertError> {
    const REQUIRED_MARKER_BYTES: u64 = 9;
    let bytes = match read_file(from_dir, FULL_REVALIDATION_MARKER, REQUIRED_MARKER_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut copy = create_file_no_follow(to_dir, FULL_REVALIDATION_MARKER)?;
    copy.write_all(&bytes)?;
    copy.sync_all()?;
    sync_dir(to_dir)?;
    Ok(vec![FULL_REVALIDATION_MARKER.to_owned()])
}

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
    let data_dir = Dir::open_ambient_dir(to_path, ambient_authority())?;
    let root_dir = open_or_create_dir_nofollow(&data_dir, CHECKPOINT_ROOT)?;
    let generation_dir = open_or_create_dir_nofollow(&root_dir, &directory)?;
    sync_dir(&data_dir)?;
    sync_dir(&root_dir)?;
    for (name, bytes, sha256) in [
        (
            HEADERS_FILE,
            manifest.headers.bytes,
            manifest.headers.sha256.as_str(),
        ),
        (
            COINSTATS_FILE,
            manifest.coinstats.bytes,
            manifest.coinstats.sha256.as_str(),
        ),
    ] {
        copy_checkpoint_artifact_synced(checkpoint_dir, &generation_dir, name, bytes, sha256)?;
    }
    let mut published = manifest.clone();
    published.utxo = None;
    let manifest_bytes = sonic_rs::to_vec(&published)
        .map_err(|error| ConvertError::IncompatibleData(format!("checkpoint manifest: {error}")))?;
    write_synced(&generation_path.join(MANIFEST_FILE), &manifest_bytes)?;
    engine.checkpoint(&generation_path.join("chainstate"))?;
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

fn copy_checkpoint_artifact_synced(
    source: &Dir,
    destination: &Dir,
    name: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(), ConvertError> {
    let expected_digest = decode_hex::<32>(expected_sha256)
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
    let input = open_file_read_no_follow(source, name)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(ConvertError::IncompatibleData(format!(
            "checkpoint artifact {name:?} length or type mismatch"
        )));
    }
    let mut input = input.take(expected_bytes.saturating_add(1));
    let temporary = format!("{name}.tmp");
    let mut output = create_file_no_follow(destination, &temporary)?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(u64::try_from(count).map_err(io::Error::other)?)
            .ok_or_else(|| ConvertError::IncompatibleData("artifact byte count overflow".into()))?;
        if bytes > expected_bytes {
            return Err(ConvertError::IncompatibleData(format!(
                "checkpoint artifact {name:?} length or SHA256 mismatch"
            )));
        }
        hasher.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if bytes != expected_bytes || digest != expected_digest {
        return Err(ConvertError::IncompatibleData(format!(
            "checkpoint artifact {name:?} length or SHA256 mismatch"
        )));
    }
    output.sync_all()?;
    drop(output);
    destination.rename(&temporary, destination, name)?;
    sync_dir(destination)?;
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), ConvertError> {
    let parent = path.parent().ok_or_else(|| {
        ConvertError::IncompatibleData("checkpoint file path has no parent directory".into())
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        ConvertError::IncompatibleData("checkpoint file path has no file name".into())
    })?;
    let mut tmp_name = file_name.to_owned();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp_path, path)?;
    let dir = Dir::open_ambient_dir(parent, ambient_authority())?;
    sync_dir(&dir)?;
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

    let mut namespaces_report = Vec::new();

    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = args.to.join(rel_path);
        let scratch_base = args.to.join(".convert-src");
        let scratch_path = scratch_base.join(rel_path);

        let paths = NamespacePaths {
            name: ns_name,
            report_name: ns_name,
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: &roots.from_dir,
            to_root: &roots.to_dir,
        };
        let report = convert_namespace(paths, 3, target_engine)?;
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
            report_name: "ledger",
            dst_path: &dst_path,
            scratch_path: &scratch_path,
            from_root: pool_from_dir,
            to_root: pool_to_dir,
        };
        let report = convert_namespace(paths, 3, target_engine)?;
        namespaces_report.push(report);
    }

    let mut copied_files = Vec::new();
    copy_independent_files(
        &roots.from_dir,
        &roots.to_dir,
        &mut copied_files,
        false,
        false,
        true,
    )?;

    let historical_references =
        convert_historical_checkpoints(&roots.from_dir, &args.to, target_engine)?;

    let cs_dst_path = args.to.join("chainstate");
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

    let scratch_ingest_path = args.to.join(".convert-scratch");
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
    let Some(mut durable_head) = DurableHead::decode(&bytes) else {
        return Err(ConvertError::IncompatibleData(
            "corrupt durable head frame".into(),
        ));
    };
    let mut head_rebound = false;
    if let AssumeUtxoDiskStatus::Validating {
        checkpoint: Some(reference),
        ..
    } = &mut durable_head.assumeutxo
    {
        let (_, replacement) = historical_references
            .iter()
            .find(|(old, _)| old == reference)
            .ok_or_else(|| {
                ConvertError::IncompatibleData(
                    "durable head does not authenticate a converted historical checkpoint".into(),
                )
            })?;
        *reference = *replacement;
        let mut writer = BatchWriter::new(dest_store.as_ref());
        writer.put(
            ColumnFamily::UtxoMeta,
            DURABLE_HEAD_KEY,
            &durable_head.encode(),
        )?;
        writer.flush()?;
        head_rebound = true;
    }

    let checkpoint_height = manifest.applied_tip.height;
    if durable_head.height < checkpoint_height {
        return Err(ConvertError::IncompatibleData(format!(
            "durable head height {} is below checkpoint height {}",
            durable_head.height, checkpoint_height
        )));
    }

    let flat_blocks_store = FlatFileBlockStore::open(&args.to)?;

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
    let meta_digest = if head_rebound {
        Some(compute_destination_digest(
            dest_store.as_ref(),
            ColumnFamily::UtxoMeta,
        )?)
    } else {
        None
    };
    drop(dest_store);

    let final_stats_report = coin_stats_report(&replay_stats, replay_stats.tx_count);

    if let Some(cs_report) = namespaces_report
        .iter_mut()
        .find(|n| n.namespace == "chainstate")
    {
        set_family_report(cs_report, ColumnFamily::Coins, coins_count, coins_digest);
        if let Some((count, digest)) = meta_digest {
            set_family_report(cs_report, ColumnFamily::UtxoMeta, count, digest);
        }
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
        bitcoin_rs_execution::recovery::validate_conversion_checkpoint_artifacts(
            &checkpoint_dir,
            &_reference,
            checkpoint_network(&manifest.network)?,
        )
        .map_err(|error| ConvertError::IncompatibleData(error.to_string()))?;
        publish_epoch4_checkpoint(&checkpoint_dir, &manifest, &args.to, engine.as_ref())?;
    } else {
        final_stats.tx_count = durable_head.chain_tx_count;
        publish_converted_checkpoint(
            &roots.from_dir,
            &roots.to_dir,
            &args.to,
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
    let carried_markers = carry_full_revalidation_marker(&roots.from_dir, &roots.to_dir)?;
    publish_current_schema(&roots.to_dir, 4)?;

    Ok(ConversionReport {
        source_epoch: 3,
        target_epoch: 4,
        namespaces: namespaces_report,
        copied_files,
        checkpoint_stats: Some(checkpoint_stats_report),
        final_stats: Some(final_stats_report),
        normalized_undo_rows,
        carried_markers,
        published_checkpoint: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, CompactTarget, Header, LockTime, Script, Sequence, Tx, TxIn,
        TxOut,
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
    fn normalize_bip30_undo_rows_moves_overwrite_restores_to_removes() -> Result<(), String> {
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
        assert!(batch.removes().contains(&overwritten));
        assert!(
            batch
                .restores()
                .iter()
                .all(|add| add.outpoint != overwritten)
        );
        assert!(batch.restores().is_empty());
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
    fn write_synced_replaces_without_touching_prior_readers() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("CURRENT");
        write_synced(&path, b"old").map_err(|e| e.to_string())?;
        let link = dir.path().join("CURRENT.prior");
        std::fs::hard_link(&path, &link).map_err(|e| e.to_string())?;
        write_synced(&path, b"new").map_err(|e| e.to_string())?;
        let current = std::fs::read(&path).map_err(|e| e.to_string())?;
        if current != b"new" {
            return Err("replacement write must publish the new bytes".to_owned());
        }
        let prior = std::fs::read(&link).map_err(|e| e.to_string())?;
        if prior != b"old" {
            return Err("replacement write must leave the prior committed bytes intact".to_owned());
        }
        if dir.path().join("CURRENT.tmp").exists() {
            return Err("replacement write must not leave a temp file behind".to_owned());
        }
        Ok(())
    }

    #[test]
    fn replay_removes_outputs_destroyed_by_a_txid_overwrite() -> Result<(), String> {
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
        let height = 101_u32;
        let hash = Hash256::from(block.block_hash());

        let store = MemoryKvStore::default();
        let overwritten = OwnedUtxoOut {
            vout: 0,
            value: 40_000,
            script_pubkey: vec![0x51],
            coinbase: true,
            height: 91_722,
        };
        let old_record = UtxoRecord::from_owned_outputs(txid.into(), &[overwritten])
            .map_err(|e| e.to_string())?;
        store
            .put(
                ColumnFamily::Coins,
                &Hash256::from(txid).to_le_bytes(),
                old_record.bytes(),
            )
            .map_err(|e| e.to_string())?;

        let image = BlockImage::from_local(block.clone());
        let txids = vec![txid];
        let change_inputs = BlockChangeInputs {
            block: &image,
            height,
            txids: &txids,
            same_block_spent: None,
            add_capacity: 1,
            remove_capacity: 0,
            max_script_size: 10_000,
        };
        let spent_lookup: HashMap<OutPoint, UtxoCoin> = HashMap::new();
        let (_, undo, _) = build_block_changes(&change_inputs, &MapSpentLookup(&spent_lookup))
            .map_err(|e| e.to_string())?;
        store
            .put(
                ColumnFamily::UndoData,
                &block_undo_key(height, hash),
                &encode_undo_record(&undo, hash),
            )
            .map_err(|e| e.to_string())?;

        let mut checkpoint_accumulator = CoinStatsAccumulator::with_parallel_muhash(91_722);
        checkpoint_accumulator.observe_coin(SnapshotCoin {
            txid: txid.into(),
            vout: 0,
            value: 40_000,
            script_pubkey: &[0x51],
            height: 91_722,
            coinbase: true,
        });
        let mut replayed = checkpoint_accumulator.into_stats();
        replay_block_coin_effects(&store, height, hash, &block, &mut replayed)
            .map_err(|e| e.to_string())?;

        let (stored, _, _) = scan_destination_coins(&store, height).map_err(|e| e.to_string())?;
        if replayed.utxo_count != 1 {
            return Err(format!(
                "replay must drop the overwritten output, found {} coins",
                replayed.utxo_count
            ));
        }
        if replayed.utxo_count != stored.utxo_count || replayed.total_amount != stored.total_amount
        {
            return Err("replay stats must match the destination scan".to_owned());
        }
        if hex_encode(&replayed.muhash.finalize()) != hex_encode(&stored.muhash.finalize()) {
            return Err("replay muhash must match the destination scan".to_owned());
        }
        Ok(())
    }
}
