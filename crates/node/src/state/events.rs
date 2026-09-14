//! Coherent chain-event publication and durable process epoch allocation.

use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use bitcoin_rs_primitives::Hash256;
use parking_lot::RwLock;
use std::io;
use std::io::Write as _;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// A coherent, non-torn view of the applied chain tip.
///
/// The only writer replaces the whole cell under one `RwLock`, so a reader
/// never observes a torn mix of two commit points. This is a live value: it is
/// never persisted per-event. `epoch` changes only across process restarts,
/// `sequence` advances once per committed connect/disconnect (`0` means no
/// committed event yet this run), and the tip fields name the block that
/// sequence was advanced for.
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

/// Single write path for chain events.
///
/// [`Self::record`] advances the commit sequence and replaces the snapshot
/// cell. Production wiring goes through `NodeState::open`; [`Self::detached`]
/// exists for `Chainstate` composition in tests.
pub struct ChainEventPublisher {
    epoch: u64,
    sequence: AtomicU64,
    snapshot: RwLock<ChainSnapshot>,
}

impl bitcoin_rs_index::reconcile::ChainCursorSource for ChainEventPublisher {
    fn cursor(&self) -> bitcoin_rs_index::reconcile::ConsumerCursor {
        let snapshot = self.snapshot();
        bitcoin_rs_index::reconcile::ConsumerCursor {
            epoch: snapshot.epoch,
            sequence: snapshot.sequence,
            height: snapshot.tip_height,
            hash: snapshot.tip_hash,
        }
    }
}

impl ChainEventPublisher {
    pub(super) fn new(epoch: u64, initial: ChainSnapshot) -> Self {
        Self {
            epoch,
            sequence: AtomicU64::new(0),
            snapshot: RwLock::new(initial),
        }
    }

    /// Publisher detached from any node, for test handle composition only.
    /// Anchors at an empty tip; records still sequence and publish normally.
    #[must_use]
    pub fn detached(epoch: u64) -> Self {
        Self::new(
            epoch,
            ChainSnapshot {
                epoch,
                sequence: 0,
                tip_hash: Hash256::from_le_bytes(&[0; 32]),
                tip_height: 0,
            },
        )
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
    ///
    /// Publication order is fixed: advance the sequence, then replace the
    /// snapshot cell. Sequence values start at `1`; a snapshot with sequence
    /// `0` means no committed event yet.
    pub fn record(&self, height: u32, hash: Hash256) {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        *self.snapshot.write() = ChainSnapshot {
            epoch: self.epoch,
            sequence,
            tip_hash: hash,
            tip_height: height,
        };
    }
}

const PROCESS_EPOCH_FILE: &str = "process-epoch";

const PROCESS_EPOCH_LOCK_FILE: &str = ".process-epoch.lock";

const PROCESS_EPOCH_TEMP: &str = ".process-epoch.tmp";

// A u64 in decimal is at most 20 digits; the trailing newline makes 21.
const PROCESS_EPOCH_MAX_BYTES: u64 = 32;

/// Reads the persisted process epoch; `0` when the data dir has none yet.
///
/// A corrupt file is an error, not a reset: silently restarting the counter
/// would let a new run reuse an epoch old consumer cursors live in.
fn load_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {
    let bytes =
        match crate::checkpoint::fs::read_file(dir, PROCESS_EPOCH_FILE, PROCESS_EPOCH_MAX_BYTES) {
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
///
/// The persistent lock serializes the complete load → increment → temporary
/// file sync → rename → data-directory sync transaction across processes.
/// Keeping its descriptor alive through the final directory sync matters:
/// opening the data directory does not freeze its namespace or mount topology.
/// The epoch itself lives outside the re-writable checkpoint tree, so a
/// checkpoint wipe or resync can never regress it. A crash before the rename
/// may leave a temporary file; gaps are fine, but reuse is not.
pub(super) fn allocate_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {
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
    let lock = dir
        .open_with(PROCESS_EPOCH_LOCK_FILE, &lock_options)
        .with_context(|| format!("open process epoch lock {PROCESS_EPOCH_LOCK_FILE}"))?;
    let lock_metadata = lock
        .metadata()
        .with_context(|| format!("inspect process epoch lock {PROCESS_EPOCH_LOCK_FILE}"))?;
    if !lock_metadata.is_file() {
        bail!("process epoch lock {PROCESS_EPOCH_LOCK_FILE} is not a regular file");
    }
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
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
        let mut file = crate::checkpoint::fs::create_file(dir, PROCESS_EPOCH_TEMP)
            .with_context(|| format!("create {PROCESS_EPOCH_TEMP}"))?;
        file.write_all(&bytes)
            .with_context(|| format!("write {PROCESS_EPOCH_TEMP}"))?;
        file.sync_all()
            .with_context(|| format!("sync {PROCESS_EPOCH_TEMP}"))?;
        drop(file);
        dir.rename(PROCESS_EPOCH_TEMP, dir, PROCESS_EPOCH_FILE)
            .with_context(|| format!("publish {PROCESS_EPOCH_FILE}"))?;
        crate::checkpoint::fs::sync_dir(dir)
            .context("sync data dir after allocating the process epoch")
    })();
    if allocation.is_err() {
        let _ = dir.remove_file(PROCESS_EPOCH_TEMP);
    }
    allocation?;

    // `lock` intentionally remains live until after the directory durability
    // barrier above. Dropping it here releases the cross-process transaction.
    drop(lock);
    Ok(epoch)
}
