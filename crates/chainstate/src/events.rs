//! Coherent chain-event publication and durable process epoch allocation.

use bitcoin_rs_primitives::Hash256;
use parking_lot::RwLock;
use std::io;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PROCESS_EPOCH_FILE: &str = "process-epoch";

const PROCESS_EPOCH_LOCK_FILE: &str = ".process-epoch.lock";

const PROCESS_EPOCH_TEMP: &str = ".process-epoch.tmp";

const PROCESS_EPOCH_MAX_BYTES: u64 = 32;

/// Failures while opening a datadir and allocating its process epoch.
#[derive(Debug, thiserror::Error)]
pub enum DataDirError {
    #[error("read {PROCESS_EPOCH_FILE}")]
    ReadProcessEpoch {
        #[source]
        source: io::Error,
    },
    #[error("{PROCESS_EPOCH_FILE} is not valid UTF-8")]
    ProcessEpochNotUtf8 {
        #[source]
        source: core::str::Utf8Error,
    },
    #[error("{PROCESS_EPOCH_FILE} is corrupt; refusing to start rather than reuse epochs")]
    ProcessEpochCorrupt {
        #[source]
        source: core::num::ParseIntError,
    },
    #[error("open process epoch lock {PROCESS_EPOCH_LOCK_FILE}")]
    OpenLock {
        #[source]
        source: io::Error,
    },
    #[error("process epoch lock {PROCESS_EPOCH_LOCK_FILE} is not a regular file")]
    LockNotRegularFile,
    #[error("inspect process epoch lock {PROCESS_EPOCH_LOCK_FILE}")]
    InspectLock {
        #[source]
        source: io::Error,
    },
    #[error("lock process epoch file {PROCESS_EPOCH_LOCK_FILE}")]
    LockFile {
        #[source]
        source: io::Error,
    },
    #[error("process epoch counter exhausted")]
    EpochExhausted,
    #[error("remove stale {PROCESS_EPOCH_TEMP}")]
    RemoveStaleTemp {
        #[source]
        source: io::Error,
    },
    #[error("create {PROCESS_EPOCH_TEMP}")]
    CreateTemp {
        #[source]
        source: io::Error,
    },
    #[error("write {PROCESS_EPOCH_TEMP}")]
    WriteTemp {
        #[source]
        source: io::Error,
    },
    #[error("sync {PROCESS_EPOCH_TEMP}")]
    SyncTemp {
        #[source]
        source: io::Error,
    },
    #[error("publish {PROCESS_EPOCH_FILE}")]
    PublishEpoch {
        #[source]
        source: io::Error,
    },
    #[error("sync data dir after allocating the process epoch")]
    SyncDataDir {
        #[source]
        source: io::Error,
    },
    #[error("open data_dir {path}")]
    OpenDataDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("validate CURRENT_SCHEMA for datadir {path}")]
    ValidateSchema {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSnapshot {
    pub epoch: u64,
    pub sequence: u64,
    pub tip_hash: Hash256,
    pub tip_height: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HintKind {
    Connected,
    Disconnected,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChainEventHint {
    pub kind: HintKind,
    pub height: u32,
    pub hash: Hash256,
    pub epoch: u64,
    pub sequence: u64,
}

pub struct ChainEventPublisher {
    epoch: u64,
    sequence: AtomicU64,
    snapshot: RwLock<ChainSnapshot>,
}

impl ChainEventPublisher {
    pub fn new(initial: ChainSnapshot) -> Self {
        Self {
            epoch: initial.epoch,
            sequence: AtomicU64::new(initial.sequence),
            snapshot: RwLock::new(initial),
        }
    }

    #[must_use]
    pub fn detached(epoch: u64) -> Self {
        Self::new(ChainSnapshot {
            epoch,
            sequence: 0,
            tip_hash: Hash256::from_le_bytes(&[0; 32]),
            tip_height: 0,
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        *self.snapshot.read()
    }

    pub fn record(&self, kind: HintKind, height: u32, hash: Hash256) -> ChainEventHint {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        *self.snapshot.write() = ChainSnapshot {
            epoch: self.epoch,
            sequence,
            tip_hash: hash,
            tip_height: height,
        };
        ChainEventHint {
            kind,
            height,
            hash,
            epoch: self.epoch,
            sequence,
        }
    }
}

fn load_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64, DataDirError> {
    let bytes = match bitcoin_rs_storage::checkpoint::fs::read_file(
        dir,
        PROCESS_EPOCH_FILE,
        PROCESS_EPOCH_MAX_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(source) => return Err(DataDirError::ReadProcessEpoch { source }),
    };
    let text = core::str::from_utf8(&bytes)
        .map_err(|source| DataDirError::ProcessEpochNotUtf8 { source })?;
    text.trim()
        .parse::<u64>()
        .map_err(|source| DataDirError::ProcessEpochCorrupt { source })
}

pub fn allocate_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64, DataDirError> {
    use cap_fs_ext::FollowSymlinks;
    use cap_fs_ext::OpenOptionsFollowExt as _;
    use cap_fs_ext::OpenOptionsSyncExt as _;

    let mut lock_options = cap_std::fs::OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    let lock = {
        let mut retries = 0;
        loop {
            match dir.open_with(PROCESS_EPOCH_LOCK_FILE, &lock_options) {
                Ok(lock) => break lock,
                Err(error) if error.kind() == io::ErrorKind::NotFound && retries < 2 => {
                    retries += 1;
                }
                Err(source) => return Err(DataDirError::OpenLock { source }),
            }
        }
    };
    let lock_metadata = lock
        .metadata()
        .map_err(|source| DataDirError::InspectLock { source })?;
    if !lock_metadata.is_file() {
        return Err(DataDirError::LockNotRegularFile);
    }
    let lock = lock.into_std();
    lock.lock()
        .map_err(|source| DataDirError::LockFile { source })?;

    let epoch = load_process_epoch(dir)?
        .checked_add(1)
        .ok_or(DataDirError::EpochExhausted)?;
    let bytes = format!("{epoch}\n").into_bytes();
    match dir.remove_file(PROCESS_EPOCH_TEMP) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(DataDirError::RemoveStaleTemp { source }),
    }

    let allocation = (|| -> Result<(), DataDirError> {
        let mut file = bitcoin_rs_storage::checkpoint::fs::create_file(dir, PROCESS_EPOCH_TEMP)
            .map_err(|source| DataDirError::CreateTemp { source })?;
        file.write_all(&bytes)
            .map_err(|source| DataDirError::WriteTemp { source })?;
        file.sync_all()
            .map_err(|source| DataDirError::SyncTemp { source })?;
        drop(file);
        dir.rename(PROCESS_EPOCH_TEMP, dir, PROCESS_EPOCH_FILE)
            .map_err(|source| DataDirError::PublishEpoch { source })?;
        bitcoin_rs_storage::checkpoint::fs::sync_dir(dir)
            .map_err(|source| DataDirError::SyncDataDir { source })
    })();
    if allocation.is_err() {
        let _ = dir.remove_file(PROCESS_EPOCH_TEMP);
    }
    allocation?;

    drop(lock);
    Ok(epoch)
}

pub fn initialize_data_dir(path: &std::path::Path) -> Result<u64, DataDirError> {
    let dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(path).map_err(|source| {
        DataDirError::OpenDataDir {
            path: path.to_path_buf(),
            source,
        }
    })?;
    bitcoin_rs_storage::checkpoint::fs::ensure_current_schema(&dir).map_err(|source| {
        DataDirError::ValidateSchema {
            path: path.to_path_buf(),
            source,
        }
    })?;
    allocate_process_epoch(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumed_snapshot_continues_sequence() {
        let publisher = ChainEventPublisher::new(ChainSnapshot {
            epoch: 7,
            sequence: 41,
            tip_hash: Hash256::from_le_bytes(&[1; 32]),
            tip_height: 10,
        });

        let event = publisher.record(HintKind::Connected, 11, Hash256::from_le_bytes(&[2; 32]));
        assert_eq!(event.epoch, 7);
        assert_eq!(event.sequence, 42);
        assert_eq!(publisher.snapshot().sequence, 42);
    }
}
