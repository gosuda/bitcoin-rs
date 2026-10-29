use bitcoin_rs_storage::checkpoint::fs::DATA_DIR_LOCK_FILE;
use cap_fs_ext::FollowSymlinks;
use cap_fs_ext::OpenOptionsFollowExt as _;
use std::io;
use std::path::Path;
use std::path::PathBuf;
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

#[derive(Debug)]
pub(crate) struct DataDirLock {
    _file: std::fs::File,
}

impl DataDirLock {
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
