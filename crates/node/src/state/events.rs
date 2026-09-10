//! Applied-chain event publication and durable process-epoch allocation.
//!
//! Owns the live coherent snapshot cell, bounded nonblocking hint channel, and
//! serialized on-disk epoch transaction. `NodeState` composes this owner; apply
//! records committed results, and derived consumers reconcile from snapshots.
//! This move preserves publication order, channel capacity, lock lifetime,
//! epoch filenames, typed failures, and file/directory durability barriers.

use std::io::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::{Receiver, Sender};
use parking_lot::RwLock;

use super::INBOUND_BLOCK_CHANNEL_LIMIT;

// Bounds chain-event hints between the block-apply commit path and
// reconciliation consumers (#77). Hints are wake-ups, never data: a consumer
// that misses one recovers by reconciling `ChainSnapshot` against its own
// cursor using the chain itself. The bound is single-sourced from the
// inbound-block bound so both channels share the same flood posture; a full
// channel drops the hint and never blocks the commit path.
pub(crate) const CHAIN_HINT_CHANNEL_LIMIT: usize = INBOUND_BLOCK_CHANNEL_LIMIT;

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

/// Which committed chain event a [`ChainEventHint`] describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HintKind {
    /// A block was committed onto the tip.
    Connected,
    /// The tip moved back to its parent during a disconnect/reorg.
    Disconnected,
}

/// Wake-up for reconciliation consumers: one committed connect or disconnect.
///
/// Hints are not a replay log and carry no payload to apply. A dropped hint is
/// not a bug — it loses only the wake-up, and the consumer recovers by
/// reconciling a fresh [`ChainSnapshot`] against its own cursor using the
/// chain itself: ancestry via `BlockTree::active_node_at_height` and
/// `BlockTree::find_common_ancestor` (crates/chain), bodies via
/// `BlockBodyStore::load_block_body` (`bitcoin_rs_storage::block_body`). The `epoch` field is
/// what makes a persisted consumer cursor `(epoch, sequence)` stale on
/// restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Single write path for chain events: [`Self::record`] advances the commit
/// sequence, replaces the snapshot cell, then emits the hint, in that order.
///
/// A consumer woken by a hint therefore always reads a snapshot at least as
/// fresh as the hint. Production wiring goes through `NodeState::open`;
/// [`Self::detached`] exists for `Chainstate` composition in tests.
pub struct ChainEventPublisher {
    epoch: u64,
    sequence: AtomicU64,
    snapshot: RwLock<ChainSnapshot>,
    hints: Sender<ChainEventHint>,
}

impl ChainEventPublisher {
    pub(super) fn new(epoch: u64, initial: ChainSnapshot) -> (Self, Receiver<ChainEventHint>) {
        let (hints, receiver) = crossbeam_channel::bounded(CHAIN_HINT_CHANNEL_LIMIT);
        (
            Self {
                epoch,
                sequence: AtomicU64::new(0),
                snapshot: RwLock::new(initial),
                hints,
            },
            receiver,
        )
    }

    /// Publisher detached from any node, for test handle composition only.
    /// Anchors at an empty tip; records still sequence and publish normally.
    #[must_use]
    pub fn detached(epoch: u64) -> (Self, Receiver<ChainEventHint>) {
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
    /// Publication order is fixed: advance the sequence, replace the snapshot
    /// cell, then `try_send` the hint. A full hint channel drops the hint and
    /// never blocks or fails the commit path — consumers reconcile from the
    /// chain, so only the wake-up is lost. Sequence values start at `1`; a
    /// snapshot with sequence `0` means no committed event yet.
    pub fn record(&self, kind: HintKind, height: u32, hash: Hash256) -> ChainEventHint {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        *self.snapshot.write() = ChainSnapshot {
            epoch: self.epoch,
            sequence,
            tip_hash: hash,
            tip_height: height,
        };
        let hint = ChainEventHint {
            kind,
            height,
            hash,
            epoch: self.epoch,
            sequence,
        };
        let _ = self.hints.try_send(hint);
        hint
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
        match crate::checkpoint_fs::read_file(dir, PROCESS_EPOCH_FILE, PROCESS_EPOCH_MAX_BYTES) {
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
        let mut file = crate::checkpoint_fs::create_file(dir, PROCESS_EPOCH_TEMP)
            .with_context(|| format!("create {PROCESS_EPOCH_TEMP}"))?;
        file.write_all(&bytes)
            .with_context(|| format!("write {PROCESS_EPOCH_TEMP}"))?;
        file.sync_all()
            .with_context(|| format!("sync {PROCESS_EPOCH_TEMP}"))?;
        drop(file);
        dir.rename(PROCESS_EPOCH_TEMP, dir, PROCESS_EPOCH_FILE)
            .with_context(|| format!("publish {PROCESS_EPOCH_FILE}"))?;
        crate::checkpoint_fs::sync_dir(dir)
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
