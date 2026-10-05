//! Types for custody-grade physical storage-footprint ledgers.

use bitcoin_rs_storage::StorageError;
use std::collections::BTreeMap;
use std::io;

/// POSIX `st_blocks` unit: allocated bytes = `st_blocks * 512`.
pub const ALLOCATED_BLOCK_BYTES: u64 = 512;

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

/// How a physical observation relates to a create/allocate/delete peak.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
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

/// Allocated bytes for one top-level storage namespace.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PhysicalNamespace {
    /// Top-level directory name, or `residual` for data-directory root files.
    pub name: String,
    /// Allocated bytes attributed to this namespace (hard links counted once globally).
    pub allocated_bytes: u64,
    /// Per-category allocated bytes. Sum equals `allocated_bytes`.
    pub categories: BTreeMap<&'static str, u64>,
}

impl PhysicalNamespace {
    /// Creates a new physical namespace.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            allocated_bytes: 0,
            categories: BTreeMap::new(),
        }
    }

    /// Adds allocated bytes to the given category.
    pub fn add(&mut self, category: PhysicalCategory, bytes: u64) {
        self.allocated_bytes = self.allocated_bytes.saturating_add(bytes);
        let slot = self.categories.entry(category.as_str()).or_insert(0);
        *slot = slot.saturating_add(bytes);
    }
}

/// Custody-grade physical allocation ledger of a data-directory tree.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PhysicalLedger {
    /// Non-residual namespaces in display order.
    pub namespaces: Vec<PhysicalNamespace>,
    /// Root-level files and directories outside known namespaces.
    pub residual: PhysicalNamespace,
    /// Allocated bytes of the whole tree, hard links counted once.
    pub allocated_bytes: u64,
    /// Distinct non-directory inodes counted.
    pub inode_count: u64,
    /// Snapshot versus conservative high-water.
    pub observation_kind: PhysicalObservationKind,
    /// Conservative peak when supplied.
    pub high_water_allocated_bytes: Option<u64>,
}

impl PhysicalLedger {
    /// Peak used by a budget gate: high-water when present, otherwise the snapshot.
    #[must_use]
    pub fn budget_bytes(&self) -> u64 {
        self.high_water_allocated_bytes
            .unwrap_or(self.allocated_bytes)
    }

    /// Extends a snapshot observation with an external conservative high-water mark.
    pub fn with_high_water(mut self, high_water: u64) -> Result<Self, FootprintError> {
        if high_water < self.allocated_bytes {
            return Err(FootprintError::HighWaterBelowSnapshot {
                high_water,
                snapshot: self.allocated_bytes,
            });
        }
        self.observation_kind = PhysicalObservationKind::ConservativeHighWater;
        self.high_water_allocated_bytes = Some(high_water);
        Ok(self)
    }
}
