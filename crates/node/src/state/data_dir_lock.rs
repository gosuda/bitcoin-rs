//! Process-exclusive data-directory lock.
//!
//! A node owns its data directory for as long as any handle that can write it
//! lives: the `.lock` file is acquired before the directory's schema check and
//! process epoch, so a second process — or a second open inside this one —
//! fails before it can touch any datadir state, instead of failing later on a
//! backend store lock with a backend-specific message. The posture follows the
//! epoch lock in `crates/chainstate/src/events.rs`: capability-scoped open, no
//! symlink following, regular files only. Core's contract is `LockDirectory`
//! (`bitcoin-core/src/init.cpp:1254-1269`).
//!
//! The lock has no owner of its own. [`crate::storage_backend`] hands a clone
//! to every store it opens (chainstate store, block files, txindex store) as a
//! `StoreGuard`, and each store drops it after its engine or file handle has
//! closed. Every consumer of a store therefore keeps the directory locked
//! until its last use: a detached RPC connection thread holding the chainstate,
//! an index worker, or an embedder's retained clone. A field on `NodeState` or
//! `Node` could not give that, since a handle can outlive both.
//!
//! The name has one owner: [`DATA_DIR_LOCK_FILE`] lives in
//! `bitcoin_rs_storage::checkpoint::fs` because the schema classifier there
//! must exempt the lock file from its fresh-directory scan.

use bitcoin_rs_storage::checkpoint::fs::DATA_DIR_LOCK_FILE;
use cap_fs_ext::FollowSymlinks;
use cap_fs_ext::OpenOptionsFollowExt as _;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;

/// Failure to acquire the data-directory lock.
#[derive(Debug, Error)]
pub enum DataDirLockError {
    /// Another live node (process or open) holds the directory.
    #[error("Cannot obtain a lock on directory {path}. bitcoin-rs is probably already running.")]
    InUse {
        /// The contended data directory.
        path: PathBuf,
    },
    /// The directory or lock file could not be opened.
    #[error("Cannot write to directory '{path}'; check permissions.")]
    Io {
        /// The data directory that could not be locked.
        path: PathBuf,
        /// The open or lock failure.
        source: io::Error,
    },
    /// `.lock` exists but is not a regular file.
    #[error("{path}/{DATA_DIR_LOCK_FILE} is not a regular file")]
    NotRegularFile {
        /// The data directory holding the non-regular lock entry.
        path: PathBuf,
    },
}

/// The held data-directory lock; dropping it releases the directory.
#[derive(Debug)]
pub(crate) struct DataDirLock {
    _file: std::fs::File,
}

impl DataDirLock {
    /// Acquires the process-exclusive lock on `data_dir`, creating the lock
    /// file when absent. The file is never deleted: a stale `.lock` is just a
    /// file, and the open-file lock — not its existence — is the ownership
    /// proof.
    pub(crate) fn acquire(data_dir: &Path) -> Result<Self, DataDirLockError> {
        let io_error = |source| DataDirLockError::Io {
            path: data_dir.to_path_buf(),
            source,
        };
        let dir = cap_std::fs::Dir::open_ambient_dir(data_dir, cap_std::ambient_authority())
            .map_err(io_error)?;
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        let locked = dir
            .open_with(DATA_DIR_LOCK_FILE, &options)
            .map_err(io_error)?;
        // Directory-entry type is only a precheck; validate the opened inode
        // so a substituted FIFO can never be locked or held.
        let metadata = locked.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(DataDirLockError::NotRegularFile {
                path: data_dir.to_path_buf(),
            });
        }
        let file = locked.into_std();
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(DataDirLockError::InUse {
                path: data_dir.to_path_buf(),
            }),
            Err(std::fs::TryLockError::Error(source)) => Err(io_error(source)),
        }
    }
}
