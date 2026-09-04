//! Custody-grade logical and physical storage-footprint ledgers.
//!
//! The two ledgers are independently owned and must not be summed. Logical
//! owners report exact serialized key and value bytes. Physical namespaces
//! report allocated filesystem blocks. Shared database files make exact
//! physical attribution to a logical owner impossible; the physical ledger is
//! the source of the data-directory budget.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::{ColumnFamily, KvStore, StorageError, complete_framed_stats, is_block_file_name};

/// POSIX `st_blocks` unit: allocated bytes = `st_blocks * 512`.
const ALLOCATED_BLOCK_BYTES: u64 = 512;

/// Errors from custody-grade footprint collection.
#[derive(Debug, thiserror::Error)]
pub enum FootprintError {
    /// A symlink was present in the data-directory tree.
    #[error("symlink at {path}")]
    Symlink {
        /// Path relative to the opened data directory, or the open path.
        path: String,
    },
    /// A child inode lived on a different mount than the data directory.
    #[error("mount crossing at {path}")]
    MountCrossing {
        /// Path relative to the opened data directory.
        path: String,
    },
    /// An inode identity or allocated size changed between the two collection walks.
    #[error("data directory changed during collection at {path}")]
    ChangedDuringCollection {
        /// Path that differed between walks.
        path: String,
    },
    /// A supplied high-water mark was below the measured snapshot.
    #[error("high-water {high_water} is below snapshot {snapshot}")]
    HighWaterBelowSnapshot {
        /// Conservative peak supplied by the caller.
        high_water: u64,
        /// Allocated bytes observed in the snapshot.
        snapshot: u64,
    },
    /// A directory entry name was not valid UTF-8.
    #[error("non-UTF-8 path component under {parent}")]
    InvalidName {
        /// Parent relative path.
        parent: String,
    },
    /// The supplied path is not a directory.
    #[error("{path} is not a directory")]
    NotADirectory {
        /// Path that failed to open as a directory.
        path: String,
    },
    /// A FIFO, device, or other non-file/non-directory entry was present.
    #[error("unsupported file type {kind} at {path}")]
    UnsupportedEntry {
        /// Path relative to the opened data directory.
        path: String,
        /// File-type spelling.
        kind: &'static str,
    },
    /// Filesystem or OS I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Key-value or block-file read failure.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),
}

impl From<Errno> for FootprintError {
    fn from(error: Errno) -> Self {
        Self::Io(io::Error::from(error))
    }
}

/// How a physical observation relates to a create/allocate/delete peak.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalObservationKind {
    /// One consistent snapshot. A lower bound on the true peak.
    SnapshotLowerBound,
    /// Snapshot plus an external conservative high-water (quota or isolated FS).
    ConservativeHighWater,
}

impl PhysicalObservationKind {
    /// Stable evidence spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotLowerBound => "snapshot_lower_bound",
            Self::ConservativeHighWater => "conservative_high_water",
        }
    }
}

/// Physical file-role category inside a namespace, or the unattributed residual.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PhysicalCategory {
    /// Primary payload of the namespace (SST tables, block files, checkpoint bytes).
    Data,
    /// Write-ahead / journal residue inside a key-value namespace.
    Wal,
    /// Engine manifests, options, locks, and directory inodes.
    Metadata,
    /// Compaction temporaries and anything the collector will not guess.
    Unattributed,
}

impl PhysicalCategory {
    /// Stable evidence spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Wal => "wal",
            Self::Metadata => "metadata",
            Self::Unattributed => "unattributed",
        }
    }
}

/// Exact serialized key and value bytes for one logical owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalOwner {
    /// `{namespace}.{column_family}` or a named subsystem such as `blocks.flat_files`.
    pub name: String,
    /// Number of rows or framed records.
    pub rows: u64,
    /// Sum of serialized key lengths.
    pub key_bytes: u64,
    /// Sum of serialized value lengths.
    pub value_bytes: u64,
    /// `key_bytes + value_bytes`. Not a filesystem allocation.
    pub serialized_bytes: u64,
}

impl LogicalOwner {
    fn new(name: impl Into<String>, rows: u64, key_bytes: u64, value_bytes: u64) -> Self {
        Self {
            name: name.into(),
            rows,
            key_bytes,
            value_bytes,
            serialized_bytes: key_bytes.saturating_add(value_bytes),
        }
    }
}

/// Logical owner ledger. Do not add these bytes to the physical ledger.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LogicalLedger {
    /// Owners in stable name order.
    pub owners: Vec<LogicalOwner>,
}

impl LogicalLedger {
    /// Sum of serialized key and value bytes across owners.
    ///
    /// This is a logical-ledger total only. It is not a data-directory budget.
    #[must_use]
    pub fn serialized_bytes(&self) -> u64 {
        self.owners.iter().fold(0, |total, owner| {
            total.saturating_add(owner.serialized_bytes)
        })
    }

    /// Inserts `owner` and keeps owners sorted by name.
    pub fn push(&mut self, owner: LogicalOwner) {
        self.owners.push(owner);
        self.owners
            .sort_by(|left, right| left.name.cmp(&right.name));
    }
}

/// Allocated bytes for one top-level storage namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalNamespace {
    /// Top-level directory name, or `residual` for data-directory root files.
    pub name: String,
    /// Allocated bytes attributed to this namespace (hard links counted once globally).
    pub allocated_bytes: u64,
    /// Per-category allocated bytes. Sum equals `allocated_bytes`.
    pub categories: BTreeMap<&'static str, u64>,
}

impl PhysicalNamespace {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            allocated_bytes: 0,
            categories: BTreeMap::new(),
        }
    }

    fn add(&mut self, category: PhysicalCategory, bytes: u64) {
        self.allocated_bytes = self.allocated_bytes.saturating_add(bytes);
        let slot = self.categories.entry(category.as_str()).or_insert(0);
        *slot = slot.saturating_add(bytes);
    }
}

/// Physical namespace ledger. This is the source of the data-directory budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalLedger {
    /// One row per top-level directory.
    pub namespaces: Vec<PhysicalNamespace>,
    /// Root-level files and the data-directory inode.
    pub residual: PhysicalNamespace,
    /// Allocated bytes of the whole tree, hard links counted once.
    pub allocated_bytes: u64,
    /// Distinct `(device, inode)` identities counted.
    pub inode_count: u64,
    /// Whether this observation can satisfy a peak-budget gate.
    pub observation_kind: PhysicalObservationKind,
    /// Conservative peak when `observation_kind` is [`PhysicalObservationKind::ConservativeHighWater`].
    pub high_water_allocated_bytes: Option<u64>,
}

impl PhysicalLedger {
    /// Data-directory budget figure: the physical total, never a logical sum.
    #[must_use]
    pub const fn data_directory_allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    /// Peak used by a budget gate: high-water when present, otherwise the snapshot.
    #[must_use]
    pub fn budget_bytes(&self) -> u64 {
        self.high_water_allocated_bytes
            .unwrap_or(self.allocated_bytes)
    }

    /// Records an external conservative peak. The peak must be at least the snapshot.
    pub fn with_high_water(mut self, high_water: u64) -> Result<Self, FootprintError> {
        if high_water < self.allocated_bytes {
            return Err(FootprintError::HighWaterBelowSnapshot {
                high_water,
                snapshot: self.allocated_bytes,
            });
        }
        self.high_water_allocated_bytes = Some(high_water);
        self.observation_kind = PhysicalObservationKind::ConservativeHighWater;
        Ok(self)
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
    ///
    /// Returns `Ok(None)` when the name is missing or the payload is larger
    /// than `max_bytes`. The opened descriptor is typed with `fstat`.
    pub fn read_child_file(
        &self,
        name: &str,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, FootprintError> {
        read_child_file(self.fd.as_fd(), name, max_bytes)
    }
}

/// Filesystem path that refers to an already-opened descriptor.
///
/// Used so key-value backends, which take a pathname, open the same inode the
/// anchor already holds rather than re-resolving `config.data_dir`.
#[must_use]
pub fn opened_fd_path(fd: BorrowedFd<'_>) -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::path::PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::path::PathBuf::from(format!("/dev/fd/{}", fd.as_raw_fd()))
    }
}

/// Whether `dir` contains any entry other than `.` and `..`.
pub fn dir_has_entries(dir: BorrowedFd<'_>) -> Result<bool, FootprintError> {
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

/// Exact serialized key and value bytes for one column family.
pub fn logical_column_family<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
) -> Result<LogicalOwner, StorageError> {
    logical_column_family_named(store, cf, cf.name())
}

/// Exact serialized key and value bytes for every column family in `store`.
///
/// Owner names are `{namespace}.{column_family}`.
pub fn logical_store_owners<S: KvStore>(
    store: &S,
    namespace: &str,
) -> Result<Vec<LogicalOwner>, StorageError> {
    let mut owners = Vec::with_capacity(ColumnFamily::ALL.len());
    for cf in ColumnFamily::ALL.iter().copied() {
        let name = format!("{namespace}.{}", cf.name());
        owners.push(logical_column_family_named(store, cf, &name)?);
    }
    Ok(owners)
}

fn logical_column_family_named<S: KvStore>(
    store: &S,
    cf: ColumnFamily,
    name: &str,
) -> Result<LogicalOwner, StorageError> {
    let mut rows = 0_u64;
    let mut key_bytes = 0_u64;
    let mut value_bytes = 0_u64;
    for item in store.iter_prefix(cf, &[])? {
        let (key, value) = item?;
        rows = rows.saturating_add(1);
        key_bytes = key_bytes.saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX));
        value_bytes = value_bytes.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
    }
    Ok(LogicalOwner::new(name, rows, key_bytes, value_bytes))
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
            dev: stat.st_dev,
            ino: stat.st_ino,
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
    let mut names = Vec::new();
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
    for name in names {
        let child_rel = join_rel(rel, &name);
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
    if namespace == crate::BLOCK_FILE_DIRECTORY {
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
        crate::BLOCK_FILE_DIRECTORY,
        nofollow_read() | OFlags::DIRECTORY,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            return Ok(LogicalOwner::new("blocks.flat_files", 0, 0, 0));
        }
        Err(Errno::LOOP) => {
            return Err(FootprintError::Symlink {
                path: crate::BLOCK_FILE_DIRECTORY.to_owned(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let blocks_stat = rfs::fstat(&blocks)?;
    require_directory(&blocks_stat, crate::BLOCK_FILE_DIRECTORY)?;
    require_same_dev(&root_stat, &blocks_stat, crate::BLOCK_FILE_DIRECTORY)?;
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
                parent: crate::BLOCK_FILE_DIRECTORY.to_owned(),
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
        let child_rel = format!("{}/{name}", crate::BLOCK_FILE_DIRECTORY);
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

#[cfg(test)]
mod comparison_tests {
    use super::{InodeSnapshot, first_change};
    use std::collections::BTreeMap;

    fn snap(ino: u64, blocks: u64) -> InodeSnapshot {
        InodeSnapshot {
            dev: 1,
            ino,
            nlink: 1,
            blocks,
            size: blocks.saturating_mul(512),
            is_dir: false,
        }
    }

    #[test]
    fn stable_snapshots_have_no_change() {
        let mut tree = BTreeMap::new();
        tree.insert("chainstate".to_owned(), snap(2, 8));
        assert_eq!(first_change(&tree, &tree), None);
    }

    #[test]
    fn size_change_is_reported() {
        let mut first = BTreeMap::new();
        first.insert("blocks/blk00000.dat".to_owned(), snap(3, 8));
        let mut second = first.clone();
        second.insert("blocks/blk00000.dat".to_owned(), snap(3, 16));
        assert_eq!(
            first_change(&first, &second).as_deref(),
            Some("blocks/blk00000.dat")
        );
    }

    #[test]
    fn new_path_is_reported() {
        let mut first = BTreeMap::new();
        first.insert("chainstate".to_owned(), snap(2, 8));
        let mut second = first.clone();
        second.insert("txindex".to_owned(), snap(4, 4));
        assert_eq!(first_change(&first, &second).as_deref(), Some("txindex"));
    }
}
