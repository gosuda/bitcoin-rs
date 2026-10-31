//! Offline allocation snapshot with block-frame and file-class accounting.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, CWD, StatxFlags};
use serde::Serialize;

use crate::frames::{self, FileFrames};

#[derive(Default, Serialize)]
pub(super) struct Bytes {
    apparent_bytes: u64,
    allocated_bytes: u64,
}

fn add_metadata(
    apparent_bytes: &mut u64,
    allocated_bytes: &mut u64,
    metadata: &fs::Metadata,
) -> io::Result<()> {
    *apparent_bytes = apparent_bytes
        .checked_add(metadata.len())
        .ok_or_else(|| io::Error::other("apparent byte count overflow"))?;
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::other("allocated byte count overflow"))?;
    *allocated_bytes = allocated_bytes
        .checked_add(allocated)
        .ok_or_else(|| io::Error::other("allocated byte count overflow"))?;
    Ok(())
}

impl Bytes {
    fn add(&mut self, metadata: &fs::Metadata) -> io::Result<()> {
        add_metadata(
            &mut self.apparent_bytes,
            &mut self.allocated_bytes,
            metadata,
        )
    }
}

#[derive(Default, Serialize)]
pub(super) struct BlockFileBytes {
    apparent_bytes: u64,
    allocated_bytes: u64,
    records: u64,
    payload_bytes: u64,
    framing_bytes: u64,
    unframed_bytes: u64,
    other_bytes: u64,
    files: Vec<FileFrames>,
}

impl BlockFileBytes {
    fn add_entry(&mut self, metadata: &fs::Metadata) -> io::Result<()> {
        add_metadata(
            &mut self.apparent_bytes,
            &mut self.allocated_bytes,
            metadata,
        )
    }

    fn add_frames(&mut self, split: &frames::FrameSplit) -> io::Result<()> {
        self.records = self
            .records
            .checked_add(split.records)
            .ok_or_else(|| io::Error::other("record count overflow"))?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(split.payload_bytes)
            .ok_or_else(|| io::Error::other("payload byte count overflow"))?;
        self.framing_bytes = self
            .framing_bytes
            .checked_add(split.framing_bytes)
            .ok_or_else(|| io::Error::other("framing byte count overflow"))?;
        self.unframed_bytes = self
            .unframed_bytes
            .checked_add(split.unframed_bytes)
            .ok_or_else(|| io::Error::other("unframed byte count overflow"))?;
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<()> {
        let framed = self
            .payload_bytes
            .checked_add(self.framing_bytes)
            .and_then(|bytes| bytes.checked_add(self.unframed_bytes))
            .ok_or_else(|| io::Error::other("framed byte count overflow"))?;
        self.other_bytes = self
            .apparent_bytes
            .checked_sub(framed)
            .ok_or_else(|| io::Error::other("framed bytes exceed block-file entries"))?;
        Ok(())
    }
}

#[derive(Default, Serialize)]
pub(super) struct Classes {
    block_files: BlockFileBytes,
    undo_data_named_dirs: Bytes,
    kv: Bytes,
}

impl Classes {
    fn finalize(&mut self) -> io::Result<()> {
        self.block_files.finalize()?;
        self.block_files
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct Report {
    format: &'static str,
    observation: &'static str,
    family_attribution: &'static str,
    undo_attribution: &'static str,
    totals: Bytes,
    namespaces: BTreeMap<String, Bytes>,
    classes: Classes,
}

const MAX_DEPTH: u32 = 32;
const BLOCK_FILES_DIRECTORY: &str = "blocks";
const BLOCK_FILE_PREFIX: &str = "blk";
const BLOCK_FILE_SUFFIX: &str = ".dat";
const BLOCK_FILE_MIN_DIGITS: usize = 5;
const UNDO_FAMILY_DIRECTORY: &str = "undo_data";

#[derive(Clone, Copy)]
enum Class {
    BlockFiles,
    Undo,
    Kv,
}

pub(super) fn measure(root: &Path) -> io::Result<Report> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(io::Error::other("data directory must be a real directory"));
    }
    let mount = mount_id(root)?;
    let mut report = Report {
        format: "bitcoin-rs-storage-allocation-v1",
        observation: "offline_snapshot_lower_bound",
        family_attribution: "path_named_family_directories",
        undo_attribution: "unattributed_inside_kv",
        totals: Bytes::default(),
        namespaces: BTreeMap::new(),
        classes: Classes::default(),
    };
    let mut seen = HashSet::new();
    visit(
        root,
        Path::new(""),
        ".",
        metadata.dev(),
        mount,
        &mut seen,
        &mut report,
        0,
    )?;
    report.classes.finalize()?;
    if report.classes.undo_data_named_dirs.apparent_bytes > 0 {
        report.undo_attribution = "path_named_directory";
    }
    Ok(report)
}

fn mount_id(path: &Path) -> io::Result<u64> {
    let metadata = rustix::fs::statx(
        CWD,
        path,
        AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )?;
    if !StatxFlags::from_bits_retain(metadata.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(io::Error::other(format!(
            "mount identity is unavailable for {}",
            path.display()
        )));
    }
    Ok(metadata.stx_mnt_id)
}

fn class_of(relative: &Path) -> Class {
    if relative
        .components()
        .next()
        .is_some_and(|first| first.as_os_str() == BLOCK_FILES_DIRECTORY)
    {
        return Class::BlockFiles;
    }
    if relative
        .components()
        .any(|component| component.as_os_str() == UNDO_FAMILY_DIRECTORY)
    {
        return Class::Undo;
    }
    Class::Kv
}

fn is_block_file(relative: &Path) -> bool {
    if relative.parent() != Some(Path::new(BLOCK_FILES_DIRECTORY)) {
        return false;
    }
    let Some(name) = relative.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(digits) = name
        .strip_prefix(BLOCK_FILE_PREFIX)
        .and_then(|rest| rest.strip_suffix(BLOCK_FILE_SUFFIX))
    else {
        return false;
    };
    digits.len() >= BLOCK_FILE_MIN_DIGITS && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn visit(
    path: &Path,
    relative: &Path,
    namespace: &str,
    device: u64,
    mount: u64,
    seen: &mut HashSet<(u64, u64)>,
    report: &mut Report,
    depth: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !(metadata.is_dir() || metadata.is_file())
        || metadata.dev() != device
        || mount_id(path)? != mount
    {
        return Err(io::Error::other(format!(
            "unsupported entry or mount crossing: {}",
            path.display()
        )));
    }
    report.namespaces.entry(namespace.to_owned()).or_default();
    if !seen.insert((metadata.dev(), metadata.ino())) {
        return Ok(());
    }
    report.totals.add(&metadata)?;
    report
        .namespaces
        .entry(namespace.to_owned())
        .or_default()
        .add(&metadata)?;
    match class_of(relative) {
        Class::BlockFiles => {
            report.classes.block_files.add_entry(&metadata)?;
            if metadata.is_file() && is_block_file(relative) {
                let split = frames::file_frames(path)?;
                report.classes.block_files.add_frames(&split)?;
                let label = relative
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 block file path"))?;
                report
                    .classes
                    .block_files
                    .files
                    .push(FileFrames::new(label.to_owned(), &split));
            }
        }
        Class::Undo => report.classes.undo_data_named_dirs.add(&metadata)?,
        Class::Kv => report.classes.kv.add(&metadata)?,
    }
    if metadata.is_dir() {
        if depth >= MAX_DEPTH {
            return Err(io::Error::other(format!(
                "directory nesting exceeds {MAX_DEPTH} at {}",
                path.display()
            )));
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name;
            let child_namespace = if namespace == "." {
                name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::other("non-UTF-8 top-level entry"))?;
                name.as_str()
            } else {
                namespace
            };
            let child_relative: PathBuf = relative.join(entry.file_name());
            visit(
                &entry.path(),
                &child_relative,
                child_namespace,
                device,
                mount,
                seen,
                report,
                depth + 1,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn len_of(bytes: &[u8]) -> io::Result<u64> {
        u64::try_from(bytes.len()).map_err(|_| io::Error::other("fixture too large"))
    }

    fn block_file_bytes() -> io::Result<Vec<u8>> {
        let mut bytes = crate::frames::encode_record(&[0x11; 40], 0)?;
        bytes.extend_from_slice(&crate::frames::encode_record(&[0x22; 60], 1)?);
        Ok(bytes)
    }

    #[test]
    fn block_frames_undo_rows_and_kv_are_attributed_exactly() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let blocks = dir.path().join(BLOCK_FILES_DIRECTORY);
        fs::create_dir(&blocks)?;
        let body = block_file_bytes()?;
        fs::write(blocks.join("blk00000.dat"), &body)?;
        let undo = dir.path().join(UNDO_FAMILY_DIRECTORY);
        fs::create_dir(&undo)?;
        let undo_row = b"one undo row";
        fs::write(undo.join("0000000000000001"), undo_row)?;
        fs::write(dir.path().join("kv-a"), [0x33_u8; 1000])?;
        fs::hard_link(dir.path().join("kv-a"), dir.path().join("kv-b"))?;

        let report = measure(dir.path())?;

        assert_eq!(
            report.classes.block_files.records, 2,
            "oracle: the fixture wrote two framed records"
        );
        assert_eq!(
            report.classes.block_files.payload_bytes, 100,
            "oracle: two bodies of 40 and 60 bytes"
        );
        assert_eq!(
            report.classes.block_files.framing_bytes,
            2 * frames::RECORD_HEADER_LEN,
            "oracle: two 44-byte record headers"
        );
        assert_eq!(
            report.classes.block_files.unframed_bytes, 0,
            "oracle: a complete block file has no unframed tail"
        );
        assert_eq!(
            report.classes.block_files.files.len(),
            1,
            "oracle: one block file was walked"
        );
        assert_eq!(
            report.classes.block_files.files[0].path, "blocks/blk00000.dat",
            "oracle: the walk names the walked file relative to the root"
        );
        assert_eq!(
            report.classes.block_files.apparent_bytes,
            fs::metadata(&blocks)?.len() + len_of(&body)?,
            "oracle: the block-file class holds the blocks directory and its file"
        );
        assert_eq!(
            report.classes.block_files.other_bytes,
            fs::metadata(&blocks)?.len(),
            "oracle: bytes outside record payload and framing are the directory metadata"
        );
        assert_eq!(
            report.classes.undo_data_named_dirs.apparent_bytes,
            fs::metadata(&undo)?.len() + len_of(undo_row)?,
            "oracle: the undo row and its directory are attributed to undo"
        );
        assert_eq!(
            report.classes.kv.apparent_bytes,
            fs::metadata(dir.path())?.len() + 1000,
            "oracle: the hard link is counted once in the KV class"
        );
        let class_apparent = report
            .classes
            .block_files
            .apparent_bytes
            .checked_add(report.classes.undo_data_named_dirs.apparent_bytes)
            .and_then(|bytes| bytes.checked_add(report.classes.kv.apparent_bytes));
        assert_eq!(
            class_apparent,
            Some(report.totals.apparent_bytes),
            "oracle: the classes partition the apparent totals"
        );
        let class_allocated = report
            .classes
            .block_files
            .allocated_bytes
            .checked_add(report.classes.undo_data_named_dirs.allocated_bytes)
            .and_then(|bytes| bytes.checked_add(report.classes.kv.allocated_bytes));
        assert_eq!(
            class_allocated,
            Some(report.totals.allocated_bytes),
            "oracle: the classes partition the allocated totals"
        );
        assert_eq!(
            report.family_attribution, "path_named_family_directories",
            "oracle: the report states how family bytes were attributed"
        );
        assert_eq!(
            report.undo_attribution, "path_named_directory",
            "oracle: a path-named undo directory makes the undo bytes available"
        );
        Ok(())
    }

// FP-01
    #[test]
    fn sparse_file_and_hard_link_are_not_double_counted() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = fs::File::create(dir.path().join("a"))?;
        file.set_len(16 * 1024 * 1024)?;
        fs::hard_link(dir.path().join("a"), dir.path().join("b"))?;
        let report = measure(dir.path())?;
        let root = fs::metadata(dir.path())?;
        let data = file.metadata()?;
        assert_eq!(report.totals.apparent_bytes, root.len() + data.len());
        assert_eq!(
            report.totals.allocated_bytes,
            (root.blocks() + data.blocks()) * 512
        );
        assert_eq!(
            report.namespaces["a"].apparent_bytes + report.namespaces["b"].apparent_bytes,
            data.len()
        );
        assert_eq!(
            report.namespaces["a"].allocated_bytes + report.namespaces["b"].allocated_bytes,
            data.blocks() * 512
        );
        assert!(
            (report.namespaces["a"].apparent_bytes == data.len()
                && report.namespaces["b"].apparent_bytes == 0)
                || (report.namespaces["b"].apparent_bytes == data.len()
                    && report.namespaces["a"].apparent_bytes == 0)
        );
        Ok(())
    }

    #[test]
    fn nesting_beyond_max_depth_is_refused() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut parent = dir.path().to_path_buf();
        for level in 0..=MAX_DEPTH {
            parent = parent.join(format!("level{level}"));
            fs::create_dir(&parent)?;
        }
        fs::write(parent.join("data"), b"too deep")?;
        let failure = match measure(dir.path()) {
            Ok(_) => return Err(io::Error::other("deep nesting was accepted")),
            Err(failure) => failure,
        };
        assert!(
            failure.to_string().contains("nesting exceeds"),
            "unexpected error: {failure}"
        );
        Ok(())
    }

// FP-01, FP-02
    #[test]
    fn namespace_totals_match_and_measurement_leaves_files_unchanged() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        for name in ["chainstate", "blocks", "txindex"] {
            fs::create_dir(dir.path().join(name))?;
            fs::write(dir.path().join(name).join("data"), b"operator data")?;
        }
        let report = measure(dir.path())?;
        assert_eq!(report.namespaces.len(), 4);
        let root = fs::metadata(dir.path())?;
        assert_eq!(
            report.undo_attribution, "unattributed_inside_kv",
            "oracle: without a path-named undo directory the tool must not report undo bytes"
        );
        assert_eq!(report.namespaces["."].apparent_bytes, root.len());
        assert_eq!(report.namespaces["."].allocated_bytes, root.blocks() * 512);
        assert_eq!(
            report.totals.allocated_bytes,
            report
                .namespaces
                .values()
                .map(|b| b.allocated_bytes)
                .sum::<u64>()
        );
        for name in ["chainstate", "blocks", "txindex"] {
            assert_eq!(
                fs::read(dir.path().join(name).join("data"))?,
                b"operator data"
            );
            assert_eq!(fs::read_dir(dir.path().join(name))?.count(), 1);
        }
        Ok(())
    }

// FP-02
    #[test]
    fn refuses_symlinks_and_special_entries() -> io::Result<()> {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir()?;
        symlink(dir.path(), dir.path().with_extension("link"))?;
        assert!(measure(&dir.path().with_extension("link")).is_err());
        fs::remove_file(dir.path().with_extension("link"))?;
        symlink("/etc/passwd", dir.path().join("link"))?;
        assert!(measure(dir.path()).is_err());
        fs::remove_file(dir.path().join("link"))?;
        let _socket = UnixListener::bind(dir.path().join("socket"))?;
        assert!(measure(dir.path()).is_err());
        Ok(())
    }
}
