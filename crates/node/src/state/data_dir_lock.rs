use bitcoin_rs_storage::checkpoint::fs::DATA_DIR_LOCK_FILE;
use cap_fs_ext::FollowSymlinks;
use cap_fs_ext::MetadataExt as _;
use cap_fs_ext::OpenOptionsFollowExt as _;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataDirLockError {
    #[error("Cannot obtain a lock on directory {path}. bitcoin-rs is probably already running.")]
    InUse { path: PathBuf },
    #[error("Cannot write to directory '{path}'; check permissions.")]
    Io { path: PathBuf, source: io::Error },
    #[error("{path}/{DATA_DIR_LOCK_FILE} is not a regular file")]
    NotRegularFile { path: PathBuf },
}

/// POSIX record locks are not inherited across fork, so a child between fork
/// and exec cannot keep the kernel lock alive the way an `flock` holder would;
/// the registry restores the per-process exclusivity that POSIX ownership
/// semantics do not provide, and its lock is held across check, open, lock,
/// insert, close, and remove so check-then-act stays atomic.
///
/// The kernel lock is a POSIX `F_SETLK` record lock. It does not conflict with
/// the BSD `flock` that this change replaced, so during an upgrade or
/// downgrade a binary from the other side of this change can open the same
/// data directory. Stopping the old process before starting the new one is a
/// required upgrade step.
static HELD_DATA_DIRS: LazyLock<Mutex<HashSet<(u64, u64)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn held_data_dirs() -> &'static Mutex<HashSet<(u64, u64)>> {
    &HELD_DATA_DIRS
}

#[derive(Debug)]
pub(crate) struct DataDirLock {
    _file: Option<std::fs::File>,
    dir_key: (u64, u64),
}

#[cfg(unix)]
fn try_exclusive_lock(file: &std::fs::File) -> io::Result<()> {
    rustix::fs::fcntl_lock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(io::Error::from)
}

#[cfg(not(unix))]
fn try_exclusive_lock(file: &std::fs::File) -> io::Result<()> {
    file.try_lock().map_err(|error| std::io::Error::from(error))
}

impl DataDirLock {
    pub(crate) fn acquire(data_dir: &Path) -> Result<Self, DataDirLockError> {
        let io_error = |source| DataDirLockError::Io {
            path: data_dir.to_path_buf(),
            source,
        };
        let dir = cap_std::fs::Dir::open_ambient_dir(data_dir, cap_std::ambient_authority())
            .map_err(io_error)?;
        let dir_key = {
            let metadata = dir.dir_metadata().map_err(io_error)?;
            (metadata.dev(), metadata.ino())
        };
        let mut held = held_data_dirs().lock();
        if held.contains(&dir_key) {
            return Err(DataDirLockError::InUse {
                path: data_dir.to_path_buf(),
            });
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        let locked = dir
            .open_with(DATA_DIR_LOCK_FILE, &options)
            .map_err(io_error)?;
        let metadata = locked.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(DataDirLockError::NotRegularFile {
                path: data_dir.to_path_buf(),
            });
        }
        let file = locked.into_std();
        match try_exclusive_lock(&file) {
            Ok(()) => {
                held.insert(dir_key);
                Ok(Self {
                    _file: Some(file),
                    dir_key,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(DataDirLockError::InUse {
                    path: data_dir.to_path_buf(),
                })
            }
            Err(error) => Err(io_error(error)),
        }
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        let file = self._file.take();
        let mut held = held_data_dirs().lock();
        drop(file);
        held.remove(&self.dir_key);
    }
}
