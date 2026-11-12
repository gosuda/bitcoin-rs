use std::io::{self, Read};
use std::path::Path;

use crate::cli::CliArgs;
use crate::error::ConvertError;
use crate::fs_util::{
    copy_dir_recursive, create_file_no_follow, open_file_read_no_follow, publish_current_schema,
    sync_dir, validate_and_open_roots,
};
use crate::report::{ConversionReport, CopiedFileReport, FamilyReport, NamespaceReport};
use crate::source::{SourceNamespace, detect_engine};
use crate::target::{
    BatchWriter, FamilyDigest, compute_destination_digest, open_destination_store,
};
use bitcoin_rs_storage::{ColumnFamily, StorageBackend};
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;

const TARGET_EPOCH: u32 = 3;

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
    if source_epoch != 2 && source_epoch != 3 {
        return Err(ConvertError::UnknownEpoch(source_epoch));
    }

    let mut namespaces_report = Vec::new();

    let node_namespaces = [("chainstate", "chainstate"), ("txindex", "txindex")];
    for &(ns_name, rel_path) in &node_namespaces {
        let dst_path = args.to.join(rel_path);
        let scratch_base = args.to.join(".convert-src");
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
    copy_independent_files(&roots.from_dir, &roots.to_dir, &mut copied_files)?;

    cleanup_scratch(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        cleanup_scratch(pool_to_dir)?;
    }

    sync_dir(&roots.to_dir)?;
    if let Some(pool_to_dir) = &roots.pool_to_dir {
        sync_dir(pool_to_dir)?;
    }

    publish_current_schema(&roots.to_dir, TARGET_EPOCH)?;

    Ok(ConversionReport {
        source_epoch,
        target_epoch: TARGET_EPOCH,
        namespaces: namespaces_report,
        copied_files,
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

fn copy_independent_files(
    from_root: &Dir,
    to_root: &Dir,
    copied_files: &mut Vec<CopiedFileReport>,
) -> Result<(), ConvertError> {
    const INDEPENDENT_DIRS: &[&str] = &[
        "blocks",
        "chainstate-checkpoints",
        "assumeutxo-historical-checkpoints",
        "chainstate-journal",
    ];

    const INDEPENDENT_FILES: &[&str] = &[
        "peers.dat",
        "mempool-snapshot.dat",
        "fee-estimator-history.dat",
    ];

    for &dir_name in INDEPENDENT_DIRS {
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
        copy_independent_file(from_root, to_root, file_name, copied_files)?;
    }

    copy_scoped_peers_books(from_root, to_root, copied_files)?;

    Ok(())
}

fn copy_independent_file(
    from_root: &Dir,
    to_root: &Dir,
    file_name: &str,
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
        path: file_name.to_string(),
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
        copy_independent_file(from_root, to_root, name, copied_files)?;
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
    match dest_dir.remove_dir_all(".convert-src") {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ConvertError::Io(err)),
    }
}
