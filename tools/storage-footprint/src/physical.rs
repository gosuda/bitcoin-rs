//! Custody-grade physical storage-footprint ledger (Unix).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use bitcoin_rs_storage::block_file::{complete_framed_stats, is_block_file_name};

use crate::logical::LogicalOwner;
use crate::physical_types::{
    ALLOCATED_BLOCK_BYTES, FootprintError, PhysicalCategory, PhysicalLedger, PhysicalNamespace,
    PhysicalObservationKind,
};

impl From<Errno> for FootprintError {
    fn from(error: Errno) -> Self {
        Self::Io(io::Error::from(error))
    }
}

/// Opened data-directory descriptor that every physical walk is anchored at.
pub struct DataDirAnchor {
    fd: OwnedFd,
    display: String,
}

impl DataDirAnchor {
    /// Opens `path` as a directory without following a final symlink.
    pub fn open(path: &Path) -> Result<Self, FootprintError> {
        let display = path.display().to_string();
        let fd = match rfs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::LOOP) => {
                return Err(FootprintError::Symlink { path: display });
            }
            Err(Errno::NOTDIR) if is_symlink_path(path) => {
                return Err(FootprintError::Symlink { path: display });
            }
            Err(Errno::NOTDIR) => {
                return Err(FootprintError::NotADirectory { path: display });
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self { fd, display })
    }

    /// Two-pass allocated-block walk rooted at this descriptor.
    pub fn measure_physical(&self) -> Result<PhysicalLedger, FootprintError> {
        let first = collect_tree(self.fd.as_fd(), &self.display)?;
        let second = collect_tree(self.fd.as_fd(), &self.display)?;
        if let Some(path) = first_change(&first, &second) {
            return Err(FootprintError::ChangedDuringCollection { path });
        }
        Ok(summarize_physical(&first))
    }

    /// Logical framed bytes of `blocks/blk*.dat`, opened via this descriptor.
    pub fn logical_flat_block_files(&self) -> Result<LogicalOwner, FootprintError> {
        logical_flat_block_files(self.fd.as_fd())
    }

    /// Opens a direct child directory without following a symlink or remount.
    pub fn open_child_dir(&self, name: &str) -> Result<Option<OwnedFd>, FootprintError> {
        open_child_dir(self.fd.as_fd(), name)
    }

    /// Reads a direct child regular file without following a symlink.
    pub fn read_child_file(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, FootprintError> {
        read_child_file(self.fd.as_fd(), name, max_bytes)
    }
}

/// Filesystem path that refers to an already-opened descriptor.
#[must_use]
pub(crate) fn opened_fd_path(fd: BorrowedFd<'_>) -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::ffi::OsStrExt as _;

        rfs::getpath(fd).map_or_else(
            |_| std::path::PathBuf::from(format!("/dev/fd/{}", fd.as_raw_fd())),
            |path| std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path.as_bytes())),
        )
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        std::path::PathBuf::from(format!("/dev/fd/{}", fd.as_raw_fd()))
    }
}

/// Whether `path` currently resolves to the same inode `fd` holds.
pub(crate) fn opened_path_matches_fd(fd: BorrowedFd<'_>, path: &Path) -> io::Result<bool> {
    let held = rfs::fstat(fd)?;
    let resolved = rfs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let resolved = rfs::fstat(&resolved)?;
    Ok(u64_from_stat(held.st_dev) == u64_from_stat(resolved.st_dev)
        && u64_from_stat(held.st_ino) == u64_from_stat(resolved.st_ino))
}

/// Whether `dir` contains any entry other than `.` and `..`.
pub(crate) fn dir_has_entries(dir: BorrowedFd<'_>) -> Result<bool, FootprintError> {
    let mut entries = rfs::Dir::read_from(dir)?;
    for entry in &mut entries {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| FootprintError::InvalidName {
                parent: ".".to_owned(),
            })?;
        if name == "." || name == ".." {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

/// Opens `path` and measures the physical ledger. A convenience over [`DataDirAnchor`].
pub fn measure_physical_tree(path: &Path) -> Result<PhysicalLedger, FootprintError> {
    DataDirAnchor::open(path)?.measure_physical()
}

fn nofollow_read() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InodeSnapshot {
    dev: u64,
    ino: u64,
    nlink: u64,
    blocks: u64,
    size: u64,
    is_dir: bool,
}

impl InodeSnapshot {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            dev: u64_from_stat(stat.st_dev),
            ino: u64_from_stat(stat.st_ino),
            nlink: u64_from_stat(stat.st_nlink),
            blocks: u64_from_stat(stat.st_blocks),
            size: u64_from_stat(stat.st_size),
            is_dir: FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
        }
    }

    fn allocated_bytes(self) -> u64 {
        self.blocks.saturating_mul(ALLOCATED_BLOCK_BYTES)
    }
}

fn u64_from_stat(value: impl TryInto<u64>) -> u64 {
    value.try_into().unwrap_or(0)
}

fn collect_tree(
    root: BorrowedFd<'_>,
    display: &str,
) -> Result<BTreeMap<String, InodeSnapshot>, FootprintError> {
    let root_stat = rfs::fstat(root)?;
    if FileType::from_raw_mode(root_stat.st_mode) != FileType::Directory {
        return Err(FootprintError::NotADirectory {
            path: display.to_owned(),
        });
    }
    let mut out = BTreeMap::new();
    walk_dir(root, "", &root_stat, &mut out)?;
    Ok(out)
}

fn walk_dir(
    dir: BorrowedFd<'_>,
    rel: &str,
    root_stat: &Stat,
    out: &mut BTreeMap<String, InodeSnapshot>,
) -> Result<(), FootprintError> {
    let dir_stat = rfs::fstat(dir)?;
    if FileType::from_raw_mode(dir_stat.st_mode) == FileType::Symlink {
        return Err(FootprintError::Symlink {
            path: display_rel(rel),
        });
    }
    if dir_stat.st_dev != root_stat.st_dev {
        return Err(FootprintError::MountCrossing {
            path: display_rel(rel),
        });
    }
    out.insert(rel.to_owned(), InodeSnapshot::from_stat(&dir_stat));

    let mut entries = rfs::Dir::read_from(dir)?;
    let mut names: Vec<String> = Vec::new();
    for entry in &mut entries {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| FootprintError::InvalidName {
                parent: display_rel(rel),
            })?;
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.to_owned());
    }
    names.sort_unstable();
    for name in &names {
        let child_rel = join_rel(rel, name);
        let listed = rfs::statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        match FileType::from_raw_mode(listed.st_mode) {
            FileType::Symlink => {
                return Err(FootprintError::Symlink { path: child_rel });
            }
            FileType::Directory | FileType::RegularFile => {}
            other => {
                return Err(FootprintError::UnsupportedEntry {
                    path: child_rel,
                    kind: file_kind_name(other),
                });
            }
        }
        let child = match rfs::openat(dir, name.as_str(), nofollow_read(), Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::LOOP) => {
                return Err(FootprintError::Symlink { path: child_rel });
            }
            Err(error) => return Err(error.into()),
        };
        let child_stat = rfs::fstat(&child)?;
        match FileType::from_raw_mode(child_stat.st_mode) {
            FileType::Symlink => {
                return Err(FootprintError::Symlink { path: child_rel });
            }
            FileType::Directory => {
                if child_stat.st_dev != root_stat.st_dev {
                    return Err(FootprintError::MountCrossing { path: child_rel });
                }
                walk_dir(child.as_fd(), &child_rel, root_stat, out)?;
            }
            FileType::RegularFile => {
                if child_stat.st_dev != root_stat.st_dev {
                    return Err(FootprintError::MountCrossing { path: child_rel });
                }
                out.insert(child_rel, InodeSnapshot::from_stat(&child_stat));
            }
            other => {
                return Err(FootprintError::UnsupportedEntry {
                    path: child_rel,
                    kind: file_kind_name(other),
                });
            }
        }
    }
    Ok(())
}

fn open_child_dir(dir: BorrowedFd<'_>, name: &str) -> Result<Option<OwnedFd>, FootprintError> {
    let parent = rfs::fstat(dir)?;
    match rfs::openat(
        dir,
        name,
        nofollow_read() | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let child = rfs::fstat(&fd)?;
            require_directory(&child, name)?;
            require_same_dev(&parent, &child, name)?;
            Ok(Some(fd))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(FootprintError::Symlink {
            path: name.to_owned(),
        }),
        Err(Errno::NOTDIR) => Err(FootprintError::NotADirectory {
            path: name.to_owned(),
        }),
        Err(error) => Err(error.into()),
    }
}

fn read_child_file(
    dir: BorrowedFd<'_>,
    name: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, FootprintError> {
    let parent = rfs::fstat(dir)?;
    let listed = match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    require_regular_file(&listed, name)?;
    let child = match rfs::openat(dir, name, nofollow_read(), Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => {
            return Err(FootprintError::Symlink {
                path: name.to_owned(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let child_stat = rfs::fstat(&child)?;
    require_regular_file(&child_stat, name)?;
    require_same_dev(&parent, &child_stat, name)?;
    let limit = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut limited = File::from(child).take(limit);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn require_regular_file(stat: &Stat, path: &str) -> Result<(), FootprintError> {
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => Ok(()),
        FileType::Symlink => Err(FootprintError::Symlink {
            path: path.to_owned(),
        }),
        other => Err(FootprintError::UnsupportedEntry {
            path: path.to_owned(),
            kind: file_kind_name(other),
        }),
    }
}

fn require_directory(stat: &Stat, path: &str) -> Result<(), FootprintError> {
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => Ok(()),
        FileType::Symlink => Err(FootprintError::Symlink {
            path: path.to_owned(),
        }),
        FileType::RegularFile => Err(FootprintError::NotADirectory {
            path: path.to_owned(),
        }),
        other => Err(FootprintError::UnsupportedEntry {
            path: path.to_owned(),
            kind: file_kind_name(other),
        }),
    }
}

fn require_same_dev(root: &Stat, child: &Stat, path: &str) -> Result<(), FootprintError> {
    if child.st_dev == root.st_dev {
        Ok(())
    } else {
        Err(FootprintError::MountCrossing {
            path: path.to_owned(),
        })
    }
}

fn file_kind_name(kind: FileType) -> &'static str {
    match kind {
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::CharacterDevice => "char",
        FileType::BlockDevice => "block",
        FileType::Symlink => "symlink",
        FileType::Directory => "directory",
        FileType::RegularFile => "file",
        FileType::Unknown => "other",
    }
}

fn first_change(
    left: &BTreeMap<String, InodeSnapshot>,
    right: &BTreeMap<String, InodeSnapshot>,
) -> Option<String> {
    for (path, snapshot) in left {
        match right.get(path) {
            Some(other) if other == snapshot => {}
            Some(_) | None => return Some(display_rel(path)),
        }
    }
    right
        .keys()
        .find(|path| !left.contains_key(*path))
        .map(|path| display_rel(path))
}

fn summarize_physical(tree: &BTreeMap<String, InodeSnapshot>) -> PhysicalLedger {
    let mut seen = BTreeSet::new();
    let mut namespaces: BTreeMap<String, PhysicalNamespace> = BTreeMap::new();
    let mut residual = PhysicalNamespace::new("residual");
    let mut allocated_bytes = 0_u64;

    for (path, snapshot) in tree {
        let identity = (snapshot.dev, snapshot.ino);
        let bytes = if seen.insert(identity) {
            snapshot.allocated_bytes()
        } else {
            0
        };
        allocated_bytes = allocated_bytes.saturating_add(bytes);

        if path.is_empty() {
            residual.add(PhysicalCategory::Metadata, bytes);
            continue;
        }
        match path.split_once('/') {
            None if snapshot.is_dir => {
                namespaces
                    .entry(path.clone())
                    .or_insert_with(|| PhysicalNamespace::new(path.clone()))
                    .add(PhysicalCategory::Metadata, bytes);
            }
            None => residual.add(classify_root_file(path), bytes),
            Some((namespace, rest)) => {
                namespaces
                    .entry(namespace.to_owned())
                    .or_insert_with(|| PhysicalNamespace::new(namespace))
                    .add(classify_inside(namespace, rest), bytes);
            }
        }
    }

    PhysicalLedger {
        namespaces: namespaces.into_values().collect(),
        residual,
        allocated_bytes,
        inode_count: u64::try_from(seen.len()).unwrap_or(u64::MAX),
        observation_kind: PhysicalObservationKind::SnapshotLowerBound,
        high_water_allocated_bytes: None,
    }
}

fn classify_root_file(name: &str) -> PhysicalCategory {
    match name {
        "CURRENT_SCHEMA"
        | ".CURRENT_SCHEMA.tmp"
        | "process-epoch"
        | ".process-epoch.lock"
        | ".process-epoch.tmp" => PhysicalCategory::Metadata,
        _ if is_json_sidecar(name) => PhysicalCategory::Metadata,
        _ => PhysicalCategory::Unattributed,
    }
}

fn is_json_sidecar(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || lower.ends_with(".json.prev")
        || lower.ends_with(".json.tmp")
}

fn classify_inside(namespace: &str, rel_within: &str) -> PhysicalCategory {
    if namespace == "blocks" {
        let name = rel_within.rsplit('/').next().unwrap_or(rel_within);
        if is_block_file_name(name) {
            return PhysicalCategory::Data;
        }
        return PhysicalCategory::Unattributed;
    }
    if namespace == "chainstate-checkpoints" || namespace == "chainstate-journal" {
        return PhysicalCategory::Data;
    }
    classify_kv_file(rel_within)
}

fn classify_kv_file(rel: &str) -> PhysicalCategory {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let path = Path::new(name);
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(ext.as_deref(), Some("jnl" | "log"))
        || rel.contains("/journal/")
        || rel.starts_with("journal/")
    {
        return PhysicalCategory::Wal;
    }
    if matches!(ext.as_deref(), Some("sst" | "redb" | "dat" | "mdb" | "db"))
        || rel.starts_with("keyspaces/")
    {
        return PhysicalCategory::Data;
    }
    let lower = name.to_ascii_lowercase();
    if lower == "current"
        || lower == "identity"
        || lower == "lock"
        || lower.starts_with("manifest")
        || lower.starts_with("options")
        || ext.as_deref() == Some("meta")
    {
        return PhysicalCategory::Metadata;
    }
    PhysicalCategory::Unattributed
}

fn logical_flat_block_files(root: BorrowedFd<'_>) -> Result<LogicalOwner, FootprintError> {
    let root_stat = rfs::fstat(root)?;
    let blocks = match rfs::openat(
        root,
        "blocks",
        nofollow_read() | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            return Ok(LogicalOwner::new("blocks.flat_files", 0, 0, 0));
        }
        Err(Errno::LOOP) => {
            return Err(FootprintError::Symlink {
                path: "blocks".to_owned(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let blocks_stat = rfs::fstat(&blocks)?;
    require_directory(&blocks_stat, "blocks")?;
    require_same_dev(&root_stat, &blocks_stat, "blocks")?;
    let mut rows = 0_u64;
    let mut value_bytes = 0_u64;
    let mut entries = rfs::Dir::read_from(&blocks)?;
    let mut names = Vec::new();
    for entry in &mut entries {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| FootprintError::InvalidName {
                parent: "blocks".to_owned(),
            })?;
        if name == "." || name == ".." {
            continue;
        }
        if is_block_file_name(name) {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    for name in names {
        let child_rel = format!("blocks/{name}");
        let listed = rfs::statat(blocks.as_fd(), name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        require_regular_file(&listed, &child_rel)?;
        let child = match rfs::openat(
            blocks.as_fd(),
            name.as_str(),
            nofollow_read(),
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::LOOP) => {
                return Err(FootprintError::Symlink { path: child_rel });
            }
            Err(error) => return Err(error.into()),
        };
        let child_stat = rfs::fstat(&child)?;
        require_regular_file(&child_stat, &child_rel)?;
        require_same_dev(&root_stat, &child_stat, &child_rel)?;
        let mut file = File::from(child);
        let (file_rows, framed) = complete_framed_stats(&mut file)?;
        rows = rows.saturating_add(file_rows);
        value_bytes = value_bytes.saturating_add(framed);
    }
    Ok(LogicalOwner::new("blocks.flat_files", rows, 0, value_bytes))
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        let mut joined =
            String::with_capacity(parent.len().saturating_add(name.len()).saturating_add(1));
        joined.push_str(parent);
        joined.push('/');
        joined.push_str(name);
        joined
    }
}

fn display_rel(rel: &str) -> String {
    if rel.is_empty() {
        ".".to_owned()
    } else {
        rel.to_owned()
    }
}

fn is_symlink_path(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}
