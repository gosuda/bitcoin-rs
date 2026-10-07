//! Coherent chain-event publication and durable process epoch allocation.

use anyhow::Context as _;
use anyhow::{Result, bail};
use bitcoin_rs_primitives::Hash256;
use parking_lot::RwLock;
use std::io;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// A coherent, non-torn view of the applied chain tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainSnapshot {
    /// Persisted process epoch, strictly monotonic per data dir.
    pub epoch: u64,
    /// Commit counter; starts at `1` on the first `record` of a run.
    pub sequence: u64,
    /// Applied tip block hash (genesis hash before the first commit).
    pub tip_hash: Hash256,
    /// Applied tip height (`0` at genesis).
    pub tip_height: u32,
}

/// Which committed chain event a [`ChainEventHint`] describes.
#[derive(Debug, PartialEq, Eq)]
pub enum HintKind {
    /// A block was committed onto the tip.
    Connected,
    /// The tip moved back to its parent during a disconnect/reorg.
    Disconnected,
}

/// One committed chain event as sequenced by
/// [`ChainEventPublisher::record`].
#[derive(Debug, PartialEq, Eq)]
pub struct ChainEventHint {
    /// Whether the block was added to or removed from the tip.
    pub kind: HintKind,
    /// Height of the block the event committed.
    pub height: u32,
    /// Hash of the block the event committed.
    pub hash: Hash256,
    /// Process epoch the event belongs to.
    pub epoch: u64,
    /// Commit-counter value assigned to this event.
    pub sequence: u64,
}

/// Single write path for chain events.
pub struct ChainEventPublisher {
    epoch: u64,
    sequence: AtomicU64,
    snapshot: RwLock<ChainSnapshot>,
}

impl ChainEventPublisher {
    /// Creates a publisher that continues the supplied process-epoch snapshot.
    pub fn new(initial: ChainSnapshot) -> Self {
        Self {
            epoch: initial.epoch,
            sequence: AtomicU64::new(initial.sequence),
            snapshot: RwLock::new(initial),
        }
    }

    /// Publisher detached from any node, for test handle composition only.
    #[must_use]
    pub fn detached(epoch: u64) -> Self {
        Self::new(ChainSnapshot {
            epoch,
            sequence: 0,
            tip_hash: Hash256::from_le_bytes(&[0; 32]),
            tip_height: 0,
        })
    }

    /// Returns the process epoch this publisher stamps events with.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the current snapshot without changing any state.
    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        *self.snapshot.read()
    }

    /// Records one committed connect or disconnect.
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

const PROCESS_EPOCH_FILE: &str = "process-epoch";

const PROCESS_EPOCH_LOCK_FILE: &str = ".process-epoch.lock";

const PROCESS_EPOCH_TEMP: &str = ".process-epoch.tmp";

// A u64 in decimal is at most 20 digits; the trailing newline makes 21.
const PROCESS_EPOCH_MAX_BYTES: u64 = 32;

/// Reads the persisted process epoch; `0` when the data dir has none yet.
fn load_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {
    let bytes = match bitcoin_rs_storage::checkpoint::fs::read_file(
        dir,
        PROCESS_EPOCH_FILE,
        PROCESS_EPOCH_MAX_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| format!("read {PROCESS_EPOCH_FILE}"));
        }
    };
    let text = core::str::from_utf8(&bytes)
        .with_context(|| format!("{PROCESS_EPOCH_FILE} is not valid UTF-8"))?;
    text.trim().parse::<u64>().with_context(|| {
        format!("{PROCESS_EPOCH_FILE} is corrupt; refusing to start rather than reuse epochs")
    })
}

/// Allocates the next process epoch, durably, before first use.
pub fn allocate_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {
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
    // Create-on-first-use races: when several processes open the absent lock
    // at once, one creator's entry can disappear behind another's rename on
    // this platform (reproduced with cap-std 4.0.3) and the loser's create
    // reports NotFound. A loser's retry is itself still a create of the
    // absent path until some creator's file lands, so a bounded settle loop
    // (at most two extra attempts) waits out overlapping in-flight creates
    // — 8-way startups cluster the losers — without weakening the
    // `follow`/`nonblock` posture.
    let lock = {
        let mut retries = 0;
        loop {
            match dir.open_with(PROCESS_EPOCH_LOCK_FILE, &lock_options) {
                Ok(lock) => break lock,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && retries < 2 => {
                    retries += 1;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("open process epoch lock {PROCESS_EPOCH_LOCK_FILE}")
                    });
                }
            }
        }
    };
    let lock_metadata = lock
        .metadata()
        .with_context(|| format!("inspect process epoch lock {PROCESS_EPOCH_LOCK_FILE}"))?;
    if !lock_metadata.is_file() {
        bail!("process epoch lock {PROCESS_EPOCH_LOCK_FILE} is not a regular file");
    }
    #[cfg(not(windows))]
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .with_context(|| format!("lock process epoch file {PROCESS_EPOCH_LOCK_FILE}"))?;
    #[cfg(windows)]
    windows_lock_file_exclusive(&lock)
        .with_context(|| format!("lock process epoch file {PROCESS_EPOCH_LOCK_FILE}"))?;

    let epoch = load_process_epoch(dir)?
        .checked_add(1)
        .context("process epoch counter exhausted")?;
    let bytes = format!("{epoch}\n").into_bytes();
    match dir.remove_file(PROCESS_EPOCH_TEMP) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("remove stale {PROCESS_EPOCH_TEMP}"));
        }
    }

    let allocation = (|| -> Result<()> {
        let mut file = bitcoin_rs_storage::checkpoint::fs::create_file(dir, PROCESS_EPOCH_TEMP)
            .with_context(|| format!("create {PROCESS_EPOCH_TEMP}"))?;
        file.write_all(&bytes)
            .with_context(|| format!("write {PROCESS_EPOCH_TEMP}"))?;
        file.sync_all()
            .with_context(|| format!("sync {PROCESS_EPOCH_TEMP}"))?;
        drop(file);
        dir.rename(PROCESS_EPOCH_TEMP, dir, PROCESS_EPOCH_FILE)
            .with_context(|| format!("publish {PROCESS_EPOCH_FILE}"))?;
        bitcoin_rs_storage::checkpoint::fs::sync_dir(dir)
            .context("sync data dir after allocating the process epoch")
    })();
    if allocation.is_err() {
        let _ = dir.remove_file(PROCESS_EPOCH_TEMP);
    }
    allocation?;

    // `lock` intentionally remains live until after the directory durability
    // barrier above. Dropping it here releases the cross-process transaction.
    #[cfg(windows)]
    let _ = windows_unlock_file(&lock);
    drop(lock);
    Ok(epoch)
}

#[cfg(windows)]
fn windows_lock_file_exclusive(file: &cap_std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle: HANDLE = file.as_raw_handle();
    // SAFETY: A zeroed OVERLAPPED struct is the documented initialized state for synchronous locking.
    let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
    // SAFETY: `handle` is an open OS file handle and `overlapped` points to valid initialized stack memory.
    let ret = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &raw mut overlapped,
        )
    };
    if ret == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn windows_unlock_file(file: &cap_std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let handle: HANDLE = file.as_raw_handle();
    // SAFETY: A zeroed OVERLAPPED struct is the documented initialized state for synchronous unlocking.
    let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
    // SAFETY: `handle` is an open OS file handle and `overlapped` points to valid initialized stack memory.
    let ret = unsafe { UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &raw mut overlapped) };
    if ret == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Validates the chainstate data-directory schema and allocates this process epoch.
pub fn initialize_data_dir(path: &std::path::Path) -> Result<u64> {
    let dir = bitcoin_rs_storage::checkpoint::fs::open_data_dir(path)
        .with_context(|| format!("open data_dir {}", path.display()))?;
    bitcoin_rs_storage::checkpoint::fs::ensure_current_schema(&dir)
        .with_context(|| format!("validate CURRENT_SCHEMA for datadir {}", path.display()))?;
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
