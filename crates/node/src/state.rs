//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`NodeConfig`], the
//! data-directory path, and the open chainstate storage backend. Subsystem
//! wiring (chain / utxo / mempool
//! / index / p2p / rpc / script_index) parks here as the integration point matures.

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::{Block, Tx, Txid, deserialize};
use bitcoin_rs_rpc::context::{
    BlockBodyMetadata, BlockBodySource, BlockLog, NetworkState, PruneResult, PruneService,
    PruneServiceError, PruneStatus, ZmqNotification,
};
use core::fmt;
use core::mem::size_of;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_storage::pruning::{
    PrunePolicy, reclaim_staged_flat_block_files, stage_block_and_undo_prune,
};
use bitcoin_rs_storage::{ColumnFamily, FlatFileBlockStore, KvStore, WriteBatch};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::{Mutex, RwLock};

use crate::NodeConfig;

// One active generation of outbound requests is enough to keep the drain fed;
// extra backlog is overload and must fail fast at producers.
pub(crate) const P2P_OUTBOUND_QUEUE_LIMIT: usize = 8;

// Bounds transient inbound-block buffering between the per-peer listener
// threads and the single-threaded `BlockSync::tick` drain. Decoded inbound
// blocks carry the full `Block` plus preserved wire bytes (up to ~4 MiB each),
// so an unbounded channel lets a fast or flooding peer accumulate blocks faster
// than they drain — an OOM vector. A full channel applies TCP backpressure to
// the sending peer's listener thread; `tick` drains independently and holds no
// lock a listener needs, so the bound cannot deadlock. Sized well above the
// in-flight request window (`PENDING_BUDGET` = 128) so honest delivery, which
// wakes the drain on every block, is never throttled.
pub(crate) const INBOUND_BLOCK_CHANNEL_LIMIT: usize = 256;
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
/// `PruneBodyStore::load_block_body` (`crate::apply`). The `epoch` field is
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
/// [`Self::detached`] exists for `ApplyHandles` composition in tests.
pub struct ChainEventPublisher {
    epoch: u64,
    sequence: AtomicU64,
    snapshot: RwLock<ChainSnapshot>,
    hints: Sender<ChainEventHint>,
}

impl ChainEventPublisher {
    fn new(epoch: u64, initial: ChainSnapshot) -> (Self, Receiver<ChainEventHint>) {
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
fn allocate_process_epoch(dir: &cap_std::fs::Dir) -> Result<u64> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

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

/// Errors produced when applying a block to the node state.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Clean shutdown has closed block-apply admission.
    #[error("block apply rejected because clean shutdown has begun")]
    Shutdown,
    /// The block's previous header hash does not match the current tip's hash.
    #[error("prev hash mismatch: tip {tip}, block prev {prev}")]
    PrevHashMismatch {
        /// Current tip header hash, big-endian hex.
        tip: bitcoin_rs_primitives::Hash256,
        /// Block's previous header hash, big-endian hex.
        prev: bitcoin_rs_primitives::Hash256,
    },
    /// Height arithmetic overflowed `u32::MAX`.
    #[error("height overflow at tip {0}")]
    HeightOverflow(u32),
    /// Summing a block's input or output values left the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    /// A block's non-coinbase outputs exceed the inputs they spend.
    ///
    /// Per-transaction verification rejects this first, so reaching it means
    /// the two disagree; refuse rather than treat the block as fee-free.
    #[error("block creates more value than it spends")]
    BlockOutputsExceedInputs,
    /// The block header hash does not satisfy its declared proof-of-work target.
    #[error("proof-of-work: header hash {hash} exceeds declared target")]
    ProofOfWork {
        /// Block header hash, big-endian display.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Declared target exceeds the network's proof-of-work limit.
    #[error("declared target exceeds network max_target")]
    TargetAboveLimit,
    /// Declared `nBits` does not match the parent block's `nBits` at a non-retarget height.
    #[error(
        "nBits {actual:08x} does not match parent {expected:08x} at non-retarget height {height}"
    )]
    NbitsNonRetargetMismatch {
        /// This block's `nBits`.
        actual: u32,
        /// Parent block's `nBits`.
        expected: u32,
        /// Block height.
        height: u32,
    },
    /// Consensus validation rejected the block.
    #[error("consensus: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    /// Block-tree insertion rejected the header.
    #[error("chain: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    /// UTXO commit failed during block apply.
    #[error("utxo commit: {0}")]
    UtxoCommit(#[from] bitcoin_rs_utxo::UtxoError),
    /// Persisting the canonical prunable block body failed.
    #[error("block body persistence: {0}")]
    BlockBodyPersistence(#[from] bitcoin_rs_storage::StorageError),
    /// Persisting the UTXO undo record failed.
    ///
    /// Fatal for the block: without a recoverable undo record the node could
    /// not disconnect it, so the block must not be applied.
    #[error("undo persistence: {0}")]
    UndoPersistence(#[source] bitcoin_rs_storage::StorageError),
    /// Journal durability or retention cannot recover within configured bounds.
    ///
    /// Refused before this block mutates chainstate; retry is safe after the
    /// journal flushes or a checkpoint compacts retained segments.
    #[error("chainstate journal backpressure stopped block apply: {0}")]
    JournalBackpressure(String),
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: bitcoin_rs_primitives::Txid,
        /// Output index of the unresolvable spend.
        vout: u32,
    },
    /// The undo record for a block being disconnected is absent.
    ///
    /// Fatal: without it the UTXO set cannot be restored, and guessing would
    /// silently corrupt the chainstate.
    #[error("no undo record for block {hash} at height {height}")]
    UndoRecordMissing {
        /// Block whose record is absent.
        hash: bitcoin_rs_primitives::Hash256,
        /// Height the block was applied at.
        height: u32,
    },
    /// A stored undo record could not be decoded.
    #[error("undo record for block {hash} is unreadable: {reason}")]
    UndoRecordUnreadable {
        /// Block whose record is unreadable.
        hash: bitcoin_rs_primitives::Hash256,
        /// Why the codec rejected it.
        reason: String,
    },
    /// Reading a stored undo record failed.
    #[error("undo record read: {0}")]
    UndoRead(#[source] bitcoin_rs_storage::StorageError),
    /// The block asked to be disconnected is not the applied tip.
    ///
    /// Blocks must be disconnected tip-first. Taking one from the middle would
    /// restore outputs that its descendants have already spent.
    #[error("block {hash} is not the applied tip {tip}")]
    DisconnectNotTip {
        /// Block the caller asked to disconnect.
        hash: bitcoin_rs_primitives::Hash256,
        /// Block that is actually applied.
        tip: bitcoin_rs_primitives::Hash256,
    },
    /// The supplied block body does not match its own header.
    ///
    /// The header hash commits to the merkle root, not to the transactions the
    /// caller handed over. A body swapped under a matching header would roll
    /// the index back over the wrong rows.
    #[error("block {hash} body does not match its header merkle root")]
    DisconnectBodyMismatch {
        /// Block whose body was rejected.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Rewinding the block-level coinstats failed.
    ///
    /// The per-coin fields ride the UTXO change listener and are already
    /// reversed by the undo; only height and transaction count are set
    /// directly, and a refusal here means they do not describe the block being
    /// disconnected.
    #[error("coinstats rewind: {0}")]
    CoinStatsRewind(#[source] bitcoin_rs_utxo::stats::CoinStatsRewindError),
}

/// The outcome of a refused or failed block disconnect.
///
/// Two variants because the caller must act differently, and a single error
/// type let that distinction live in prose where it can be missed. Every
/// disconnect failure is one or the other; there is no third case.
#[derive(Debug, thiserror::Error)]
pub enum DisconnectError {
    /// Refused before anything was touched. The chain is exactly as it was.
    ///
    /// Safe to report and carry on: no rollback started, so no state is half
    /// applied. Every check that can produce this runs in the planning step
    /// precisely so that refusing stays free.
    #[error("disconnect refused: {0}")]
    Refused(#[source] Box<ApplyError>),
    /// Failed after the rollback began. Some state is rolled back and some is
    /// not, and which is which depends on where it stopped.
    ///
    /// Fatal. Do not retry: the UTXO commit fires the set's change listener and
    /// coinstats is registered as one, so a second pass double-counts even
    /// where the set itself converges. Stop applying blocks and report the
    /// block named here, which is why the hash and height are carried rather
    /// than left for the caller to reconstruct.
    #[error(
        "disconnect of block {hash} at height {height} failed after mutation began, chain state is partial: {source}"
    )]
    Fatal {
        /// Block whose disconnect wedged.
        hash: bitcoin_rs_primitives::Hash256,
        /// Height it was applied at.
        height: u32,
        /// What failed.
        #[source]
        source: Box<ApplyError>,
    },
    /// Rolled back cleanly, but the in-flight marker could not be cleared.
    ///
    /// The chain is consistent and no data is lost. What is broken is the
    /// interlock: the marker still says a disconnect was in flight, so the next
    /// start refuses until it is cleared. Reported rather than folded into
    /// success because a caller that heard "done" would restart into a refusal
    /// it had no warning of.
    #[error(
        "disconnect of block {hash} at height {height} completed but the in-flight marker remains set: {source}"
    )]
    MarkerStuck {
        /// Block that was disconnected.
        hash: bitcoin_rs_primitives::Hash256,
        /// Height it was applied at.
        height: u32,
        /// Why the marker could not be cleared.
        #[source]
        source: Box<ApplyError>,
    },
}

enum NodeStorage {
    #[cfg(feature = "rocksdb")]
    RocksDb(Arc<bitcoin_rs_storage::RocksDbStore>),
    #[cfg(feature = "fjall")]
    Fjall(Arc<bitcoin_rs_storage::FjallStore>),
    #[cfg(feature = "redb")]
    Redb(Arc<bitcoin_rs_storage::RedbStore>),
    #[cfg(feature = "mdbx")]
    Mdbx(Arc<bitcoin_rs_storage::MdbxStore>),
}

impl NodeStorage {
    /// Opens the configured backend for the chainstate namespace with its
    /// cache share from the process budget.
    fn open(config: &NodeConfig, chainstate_cache_bytes: u64) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Ok(Self::RocksDb(Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(
                    &chainstate_dir,
                    chainstate_cache_bytes,
                )
                .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "fjall")]
            "fjall" => Ok(Self::Fjall(Arc::new(
                bitcoin_rs_storage::FjallStore::open_with_cache(
                    &chainstate_dir,
                    chainstate_cache_bytes,
                )
                .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "redb")]
            "redb" => Ok(Self::Redb(Arc::new(
                bitcoin_rs_storage::RedbStore::open_with_cache(
                    &chainstate_dir,
                    chainstate_cache_bytes,
                )
                .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "mdbx")]
            "mdbx" => Ok(Self::Mdbx(Arc::new(
                bitcoin_rs_storage::MdbxStore::open_with_cache(
                    &chainstate_dir,
                    chainstate_cache_bytes,
                )
                .map_err(anyhow::Error::new)?,
            ))),
            other => bail!(
                "unsupported storage backend: {other} (compiled features = {CompiledStorageFeatures})"
            ),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                let _ = store;
                "rocksdb"
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => {
                let _ = store;
                "fjall"
            }
            #[cfg(feature = "redb")]
            Self::Redb(store) => {
                let _ = store;
                "redb"
            }
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => {
                let _ = store;
                "mdbx"
            }
            #[cfg(not(any(
                feature = "rocksdb",
                feature = "fjall",
                feature = "redb",
                feature = "mdbx"
            )))]
            _ => match *self {},
        }
    }

    fn prune_service(
        &self,
        block_files: &Arc<FlatFileBlockStore>,
        block_body_store: &Arc<dyn crate::apply::PruneBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: crate::apply::PruneAuthority,
        durable_tip_height: &Arc<AtomicU32>,
    ) -> Result<Arc<dyn PruneService>> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                authority,
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                authority,
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                authority,
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                authority,
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(not(any(
                feature = "rocksdb",
                feature = "fjall",
                feature = "redb",
                feature = "mdbx"
            )))]
            _ => match *self {},
        }
    }

    fn block_body_store(
        &self,
        files: Arc<FlatFileBlockStore>,
    ) -> Arc<dyn crate::apply::PruneBodyStore> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
            )),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
            )),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
            )),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
            )),
            #[cfg(not(any(
                feature = "rocksdb",
                feature = "fjall",
                feature = "redb",
                feature = "mdbx"
            )))]
            _ => match *self {},
        }
    }

    /// Builds the undo store for the configured backend.
    ///
    /// Mandatory rather than optional: without undo records the node cannot
    /// disconnect a block, so it could advance its tip into a chain it is
    /// unable to leave.
    fn undo_store(&self) -> Arc<dyn crate::apply::UndoStore> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Arc::new(crate::apply::KvUndoStore::new(Arc::clone(store))),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Arc::new(crate::apply::KvUndoStore::new(Arc::clone(store))),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Arc::new(crate::apply::KvUndoStore::new(Arc::clone(store))),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Arc::new(crate::apply::KvUndoStore::new(Arc::clone(store))),
            #[cfg(not(any(
                feature = "rocksdb",
                feature = "fjall",
                feature = "redb",
                feature = "mdbx"
            )))]
            _ => match *self {},
        }
    }

    fn journal_writer(
        &self,
        dir: cap_std::fs::Dir,
        bootstrap: JournalBootstrap,
    ) -> Result<crate::chainstate_journal::SharedJournalWriter> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => build_journal_writer(dir, Arc::clone(store), bootstrap),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => build_journal_writer(dir, Arc::clone(store), bootstrap),
            #[cfg(feature = "redb")]
            Self::Redb(store) => build_journal_writer(dir, Arc::clone(store), bootstrap),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => build_journal_writer(dir, Arc::clone(store), bootstrap),
        }
    }

    #[cfg(test)]
    fn stored_prune_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_storage::pruning::block_body_key(height, hash);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                Ok(store.get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?)
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(store.get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(store.get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(store.get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?),
            #[cfg(not(any(
                feature = "rocksdb",
                feature = "fjall",
                feature = "redb",
                feature = "mdbx"
            )))]
            _ => match *self {},
        }
    }

    #[cfg(test)]
    fn stored_prune_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_storage::pruning::block_undo_key(height, hash);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(not(any(
                feature = "rocksdb",
                feature = "fjall",
                feature = "redb",
                feature = "mdbx"
            )))]
            _ => match *self {},
        }
    }
}

#[derive(Clone, Copy)]
struct JournalBootstrap {
    open_existing: bool,
    base_generation: u64,
    height: u32,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
    chain_tx_count: u64,
    config: crate::config::ChainstateJournalConfig,
}

fn build_journal_writer<S: KvStore + 'static>(
    dir: cap_std::fs::Dir,
    store: Arc<S>,
    bootstrap: JournalBootstrap,
) -> Result<crate::chainstate_journal::SharedJournalWriter> {
    let mut writer = if bootstrap.open_existing {
        crate::chainstate_journal::JournalWriter::open(dir, store)?
    } else {
        crate::chainstate_journal::JournalWriter::initialize(
            dir,
            store,
            bootstrap.base_generation,
            (0, 0),
            bootstrap.height,
            bootstrap.block_hash,
            bootstrap.prev_hash,
            bootstrap.chain_tx_count,
        )?
    };
    writer.configure(
        bootstrap.config.blocks,
        Duration::from_secs(bootstrap.config.seconds),
        bootstrap.config.rotate_mib,
        bootstrap.config.max_journal_mib,
        bootstrap.config.max_lag_blocks,
        Duration::from_secs(bootstrap.config.max_lag_seconds),
    )?;
    Ok(crate::chainstate_journal::shared_journal_writer(writer))
}

struct StoredBlockBodySource {
    store: Arc<dyn crate::apply::PruneBodyStore>,
}

impl StoredBlockBodySource {
    fn new(store: Arc<dyn crate::apply::PruneBodyStore>) -> Self {
        Self { store }
    }
}

impl BlockBodySource for StoredBlockBodySource {
    fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::BlockHash) -> Option<Vec<u8>> {
        self.store.load_block_body(height, hash.0).ok().flatten()
    }

    fn disk_usage(&self) -> Option<u64> {
        self.store.disk_usage()
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::BlockHash,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        // `None` is overloaded here: it means both "this store cannot slice"
        // and "the read failed". Callers must treat either as a reason to fall
        // back to the whole body, so the return type stays — but this is the
        // hot path for every ScriptIndex history call now, and an I/O error that
        // silently degrades into a full block scan is exactly the failure that
        // would otherwise show up only as unexplained latency.
        match self
            .store
            .load_block_body_range(height, hash.0, offset, len)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::debug!(
                    %error,
                    height,
                    offset,
                    len,
                    "ranged block body read failed; falling back to the whole body"
                );
                None
            }
        }
    }

    fn block_body_metadata(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::BlockHash,
    ) -> Option<BlockBodyMetadata> {
        self.store
            .block_body_metadata(height, hash.0)
            .ok()
            .flatten()
            .map(|(body_size, tx_count)| BlockBodyMetadata {
                body_size,
                tx_count,
            })
    }
}

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";

/// A checkpoint restore more than this many blocks behind the durable
/// applied-tip witness is a catastrophic rollback, not a routine resume.
/// The restore is still accepted — the chainstate is valid — but the node
/// logs at ERROR and the warning snapshot carries the gap so operators
/// and RPC consumers can see the node is starting far behind where it was.
const STALE_RESTORE_ERROR_THRESHOLD: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeSource {
    Cold,
    Checkpoint,
    Journal,
}

pub(crate) const CHAINSTATE_JOURNAL_DIR: &str = crate::chainstate_journal::JOURNAL_DIR_NAME;

fn requires_full_revalidation(data_dir: &Path) -> bool {
    data_dir
        .join(CHAINSTATE_JOURNAL_DIR)
        .join(crate::chainstate_journal::FULL_REVALIDATION_MARKER)
        .is_file()
}

struct InitialChainstate {
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    tree: bitcoin_rs_chain::BlockTree,
    applied_tip: Option<TipSnapshot>,
    chain_tx_count: u64,
    resume_source: ResumeSource,
    journal_bootstrap: Option<JournalBootstrap>,
}

fn reset_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("remove {}", path.display())),
    }
    std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    crate::checkpoint_fs::open_data_dir(&path).with_context(|| format!("open {}", path.display()))
}

fn open_journal_dir(data_dir: &Path) -> Result<cap_std::fs::Dir> {
    let path = data_dir.join(CHAINSTATE_JOURNAL_DIR);
    std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    crate::checkpoint_fs::open_data_dir(&path).with_context(|| format!("open {}", path.display()))
}

fn checkpoint_bootstrap(
    restored: &crate::checkpoint::RestoredChainstate,
    config: crate::config::ChainstateJournalConfig,
    open_existing: bool,
) -> Result<JournalBootstrap> {
    let node = restored.tree.node(restored.applied_tip.tip_id)?;
    let prev_hash = match node.parent {
        Some(parent) => restored.tree.node(parent)?.hash.to_le_bytes(),
        None => [0_u8; 32],
    };
    Ok(JournalBootstrap {
        open_existing,
        base_generation: restored.generation,
        height: restored.applied_tip.height,
        block_hash: restored.applied_tip.hash.to_le_bytes(),
        prev_hash,
        chain_tx_count: restored.chain_tx_count,
        config,
    })
}

fn restored_initial(
    restored: crate::checkpoint::RestoredChainstate,
    config: crate::config::ChainstateJournalConfig,
    open_existing: bool,
    resume_source: ResumeSource,
) -> Result<InitialChainstate> {
    let journal_bootstrap = config
        .enabled
        .then(|| checkpoint_bootstrap(&restored, config, open_existing))
        .transpose()?;
    Ok(InitialChainstate {
        utxo: restored.utxo,
        coin_stats: restored.coin_stats,
        tree: restored.tree,
        applied_tip: Some(restored.applied_tip),
        chain_tx_count: restored.chain_tx_count,
        resume_source,
        journal_bootstrap,
    })
}

fn cold_initial_chainstate(
    config: &NodeConfig,
    journal_config: crate::config::ChainstateJournalConfig,
    reset_journal: bool,
) -> Result<InitialChainstate> {
    if journal_config.enabled && reset_journal {
        drop(reset_journal_dir(&config.data_dir)?);
    }
    Ok(InitialChainstate {
        utxo: UtxoSet::new(),
        coin_stats: bitcoin_rs_utxo::stats::CoinStats::default(),
        tree: bitcoin_rs_chain::BlockTree::new(),
        applied_tip: None,
        chain_tx_count: 0,
        resume_source: ResumeSource::Cold,
        journal_bootstrap: journal_config.enabled.then_some(JournalBootstrap {
            open_existing: false,
            base_generation: 0,
            height: 0,
            block_hash: config.network.genesis_block_hash().to_le_bytes(),
            prev_hash: [0_u8; 32],
            chain_tx_count: 1,
            config: journal_config,
        }),
    })
}

fn prepare_initial_chainstate(
    checkpoint_load: crate::checkpoint::CheckpointLoad,
    checkpoint_data_dir: &cap_std::fs::Dir,
    checkpoint_config: crate::checkpoint::HeaderCheckpointConfig,
    config: &NodeConfig,
) -> Result<InitialChainstate> {
    let journal_config = config.chainstate_journal;
    if requires_full_revalidation(&config.data_dir) {
        metrics::counter!(
            "node.chainstate_journal.fallback_total",
            "reason" => "full_revalidation_marker"
        )
        .increment(1);
        tracing::warn!(
            restore_source = "cold",
            reason = "fork_below_checkpoint_base",
            "chainstate restore requires full validation"
        );
        return cold_initial_chainstate(config, journal_config, false);
    }
    let crate::checkpoint::CheckpointLoad::Complete(restored) = checkpoint_load else {
        if journal_config.enabled {
            metrics::counter!(
                "node.chainstate_journal.fallback_total",
                "reason" => "no_checkpoint"
            )
            .increment(1);
        }
        tracing::info!(
            restore_source = "cold",
            reason = "no_complete_checkpoint",
            "chainstate restore selected"
        );
        return cold_initial_chainstate(config, journal_config, true);
    };
    let restored = *restored;
    if !journal_config.enabled {
        tracing::info!(
            restore_source = "checkpoint",
            height = restored.applied_tip.height,
            hash = %restored.applied_tip.hash,
            chain_tx_count = restored.chain_tx_count,
            reason = "journal_disabled",
            "chainstate restore selected"
        );
        return restored_initial(restored, journal_config, false, ResumeSource::Checkpoint);
    }

    replay_checkpoint_journal(
        restored,
        checkpoint_data_dir,
        checkpoint_config,
        config,
        journal_config,
    )
}

fn replay_checkpoint_journal(
    restored: crate::checkpoint::RestoredChainstate,
    checkpoint_data_dir: &cap_std::fs::Dir,
    checkpoint_config: crate::checkpoint::HeaderCheckpointConfig,
    config: &NodeConfig,
    journal_config: crate::config::ChainstateJournalConfig,
) -> Result<InitialChainstate> {
    let base_generation = restored.generation;
    let base_height = restored.applied_tip.height;
    let journal_dir = open_journal_dir(&config.data_dir)?;
    let replay_started = std::time::Instant::now();
    let replay = crate::chainstate_journal::replay_from_journal(
        &journal_dir,
        base_generation,
        restored.tree,
        restored.utxo,
        restored.coin_stats,
        restored.applied_tip,
        restored.chain_tx_count,
    );
    let replay_seconds = replay_started.elapsed().as_secs_f64();
    metrics::histogram!("node.chainstate_journal.replay_seconds").record(replay_seconds);
    drop(journal_dir);
    match replay {
        crate::chainstate_journal::ReplayOutcome::Replayed(replayed) => {
            let replayed_records = replayed.applied_tip.height.saturating_sub(base_height);
            let (restore_source, resume_source) = if replayed_records == 0 {
                ("checkpoint", ResumeSource::Checkpoint)
            } else {
                ("journal", ResumeSource::Journal)
            };
            tracing::info!(
                restore_source,
                checkpoint_generation = base_generation,
                checkpoint_height = base_height,
                height = replayed.applied_tip.height,
                hash = %replayed.applied_tip.hash,
                replayed_records,
                chain_tx_count = replayed.chain_tx_count,
                replay_seconds,
                "chainstate restore selected"
            );
            let bootstrap = JournalBootstrap {
                open_existing: true,
                base_generation,
                height: replayed.applied_tip.height,
                block_hash: replayed.applied_tip.hash.to_le_bytes(),
                prev_hash: [0_u8; 32],
                chain_tx_count: replayed.chain_tx_count,
                config: journal_config,
            };
            Ok(InitialChainstate {
                utxo: replayed.utxo,
                coin_stats: replayed.coin_stats,
                tree: replayed.tree,
                applied_tip: Some(replayed.applied_tip),
                chain_tx_count: replayed.chain_tx_count,
                resume_source,
                journal_bootstrap: Some(bootstrap),
            })
        }
        crate::chainstate_journal::ReplayOutcome::Fallback(error) => {
            let reason = error.reason();
            metrics::counter!(
                "node.chainstate_journal.fallback_total",
                "reason" => reason
            )
            .increment(1);
            if error.is_checksum_failure() {
                metrics::counter!("node.chainstate_journal.checksum_failures_total").increment(1);
            }
            tracing::warn!(
                restore_source = "checkpoint",
                checkpoint_generation = base_generation,
                checkpoint_height = base_height,
                reason,
                %error,
                replay_seconds,
                "chainstate journal rejected; checkpoint recovery selected"
            );
            drop(reset_journal_dir(&config.data_dir)?);
            let reloaded = crate::checkpoint::load_checkpoint_from_dir(
                checkpoint_data_dir,
                checkpoint_config,
            )?;
            let crate::checkpoint::CheckpointLoad::Complete(reloaded) = reloaded else {
                bail!("checkpoint disappeared while recovering from journal fallback");
            };
            restored_initial(*reloaded, journal_config, false, ResumeSource::Checkpoint)
        }
    }
}

fn load_pruneheight<S: KvStore>(store: &S) -> Result<Option<u32>> {
    let Some(bytes) = store.get(ColumnFamily::UtxoMeta, PRUNEHEIGHT_METADATA_KEY)? else {
        return Ok(None);
    };
    if bytes.len() != size_of::<u32>() {
        bail!("invalid persisted pruneheight length {}", bytes.len());
    }
    let mut encoded = [0_u8; size_of::<u32>()];
    encoded.copy_from_slice(&bytes);
    Ok(Some(u32::from_be_bytes(encoded)))
}

/// Storage-backed implementation of RPC manual pruning.
pub struct NodePruneService<S: KvStore> {
    store: Arc<S>,
    block_files: Arc<FlatFileBlockStore>,
    block_body_store: Arc<dyn crate::apply::PruneBodyStore>,
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    authority: crate::apply::PruneAuthority,
    pruneheight: Mutex<Option<u32>>,
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Undo pruning is bounded by this, not by the in-memory applied tip, which
    /// can run far ahead of it.
    durable_tip_height: Arc<AtomicU32>,
}

impl<S: KvStore> NodePruneService<S> {
    /// Creates a manual pruning service over the chainstate store and RPC block cache.
    pub(crate) fn new(
        store: Arc<S>,
        block_files: Arc<FlatFileBlockStore>,
        block_body_store: Arc<dyn crate::apply::PruneBodyStore>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        authority: crate::apply::PruneAuthority,
        durable_tip_height: Arc<AtomicU32>,
    ) -> Result<Self> {
        let pruneheight = load_pruneheight(&*store)?;
        Ok(Self {
            store,
            block_files,
            block_body_store,
            blocks,
            transactions,
            authority,
            pruneheight: Mutex::new(pruneheight),
            durable_tip_height,
        })
    }
}

impl<S: KvStore> PruneService for NodePruneService<S> {
    fn prune_to_height(
        &self,
        requested_height: u32,
    ) -> core::result::Result<PruneResult, PruneServiceError> {
        let policy = PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: CORE_REORG_SAFETY_MARGIN,
        };
        let authority = self
            .authority
            .begin()
            .map_err(|error| PruneServiceError::failed(error.to_string()))?;
        let applied_tip_height = authority
            .applied_tip_height()
            .ok_or_else(|| PruneServiceError::failed("applied tip is unavailable"))?;
        let mut pruneheight = self.pruneheight.lock();
        let updated_pruneheight =
            pruneheight.map_or(requested_height, |height| height.max(requested_height));
        let safe_prune_height = applied_tip_height.saturating_sub(policy.retention_depth());
        if updated_pruneheight > safe_prune_height {
            return Err(PruneServiceError::failed(
                "prune height is within reorg safety margin",
            ));
        }
        let pruner_tip = updated_pruneheight
            .checked_add(policy.retention_depth())
            .ok_or_else(|| PruneServiceError::failed("prune height overflow"))?;

        let prune_candidates: Vec<(u32, bitcoin_rs_primitives::BlockHash, usize)> = {
            let blocks = self.blocks.read();
            blocks
                .iter()
                .filter(|record| record.height < updated_pruneheight && record.tx_count > 0)
                .map(|record| (record.height, record.hash, record.tx_count))
                .collect()
        };

        let mut pruned_txids = Vec::new();
        for (height, hash, tx_count) in prune_candidates {
            if tx_count == 0 {
                continue;
            }
            let bytes = self
                .block_body_store
                .load_block_body(height, hash.0)
                .map_err(|error| PruneServiceError::failed(error.to_string()))?
                .unwrap_or_default();
            if bytes.is_empty() {
                continue;
            }
            let block = deserialize::<Block>(&bytes).map_err(|error| {
                PruneServiceError::failed(format!(
                    "stored block body at height {height} failed decode: {error}"
                ))
            })?;
            pruned_txids.extend(block.txs.iter().map(Tx::txid));
        }
        let mut batch = self.store.new_batch();
        let (block_outcome, undo_outcome, prunable_files) = stage_block_and_undo_prune(
            &*self.store,
            &mut batch,
            &self.block_files,
            pruner_tip,
            self.durable_tip_height.load(Ordering::Acquire),
            policy,
        )
        .map_err(|err| PruneServiceError::failed(err.to_string()))?;
        batch.put(
            ColumnFamily::UtxoMeta,
            PRUNEHEIGHT_METADATA_KEY,
            &updated_pruneheight.to_be_bytes(),
        );
        self.store
            .write(batch)
            .map_err(|err| PruneServiceError::failed(err.to_string()))?;
        reclaim_staged_flat_block_files(&*self.store, &self.block_files, &prunable_files)
            .map_err(|err| PruneServiceError::failed(err.to_string()))?;

        if !pruned_txids.is_empty() {
            let mut transactions = self.transactions.write();
            for txid in pruned_txids {
                transactions.remove(&txid);
            }
        }

        *pruneheight = Some(updated_pruneheight);

        Ok(PruneResult {
            requested_height,
            pruneheight: updated_pruneheight,
            block_rows_removed: block_outcome.blocks_removed,
            undo_rows_removed: undo_outcome.blocks_removed,
            bytes_freed: block_outcome
                .bytes_freed
                .saturating_add(undo_outcome.bytes_freed),
        })
    }

    fn status(&self) -> PruneStatus {
        PruneStatus {
            pruned: true,
            pruneheight: *self.pruneheight.lock(),
        }
    }
}

const COMPILED_STORAGE_FEATURES: &[&str] = &[
    #[cfg(feature = "rocksdb")]
    "rocksdb",
    #[cfg(feature = "fjall")]
    "fjall",
    #[cfg(feature = "redb")]
    "redb",
    #[cfg(feature = "mdbx")]
    "mdbx",
];

struct CompiledStorageFeatures;

impl fmt::Display for CompiledStorageFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((first, rest)) = COMPILED_STORAGE_FEATURES.split_first() else {
            return f.write_str("none");
        };

        f.write_str(first)?;
        for feature in rest {
            f.write_str(",")?;
            f.write_str(feature)?;
        }
        Ok(())
    }
}

fn tx_index_capabilities(config: &NodeConfig) -> bitcoin_rs_index::IndexCapabilities {
    bitcoin_rs_index::IndexCapabilities {
        // ScriptIndex-backed Esplora responses need exact historical
        // transactions to render prevouts and calculate fees. This is an
        // internal dependency; `tx_index_query` below still exposes it to Core
        // RPCs only for an explicit --txindex configuration.
        tx_lookup: config.txindex || config.script_index.is_enabled(),
        script_history: config.script_index.keeps_history(),
    }
}

fn build_tx_index_open_spec(
    config: &NodeConfig,
    txindex_cache_bytes: u64,
    epoch: u64,
) -> Result<Option<crate::txindex_worker::TxIndexOpenSpec>> {
    let enabled = tx_index_capabilities(config);
    if enabled.is_empty() {
        return Ok(None);
    }
    if config.prune_target_mb > 0 {
        bail!("transaction and script indexing are not compatible with -prune");
    }
    let batch_limits = match config.storage_backend.as_str() {
        #[cfg(feature = "rocksdb")]
        "rocksdb" => crate::txindex_worker::ROCKSDB_BATCH_LIMITS,
        #[cfg(feature = "fjall")]
        "fjall" => crate::txindex_worker::DEFAULT_BATCH_LIMITS,
        #[cfg(feature = "redb")]
        "redb" => crate::txindex_worker::REDB_BATCH_LIMITS,
        #[cfg(feature = "mdbx")]
        "mdbx" => crate::txindex_worker::DEFAULT_BATCH_LIMITS,
        other => bail!("unsupported storage backend for txindex: {other}"),
    };
    let canonical_data_root = config
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| config.data_dir.clone());
    Ok(Some(crate::txindex_worker::TxIndexOpenSpec {
        data_dir: config.data_dir.clone(),
        namespace: "txindex",
        storage_backend: config.storage_backend.clone(),
        cache_bytes: txindex_cache_bytes,
        batch_limits,
        epoch,
        enabled,
        rollback_rebuild_cutover: crate::txindex_worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER,
        canonical_data_root,
    }))
}

struct TxIndexSpawn {
    spec: crate::txindex_worker::TxIndexOpenSpec,
    generation: crate::txindex_worker::Generation,
    block_source: crate::NodeBlockSource,
    body_source: Arc<dyn BlockBodySource>,
    wake_rx: Receiver<()>,
    recovery_reporter: Arc<crate::recovery_evidence::RecoveryReporter>,
}

/// Aggregate handle to a running node.
pub struct NodeState {
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Published by `write_clean_checkpoint` and read by the pruner, which must
    /// not delete an undo record a crash-restore would still need.
    durable_tip_height: Arc<AtomicU32>,
    config: NodeConfig,
    data_dir: PathBuf,
    #[cfg(test)]
    resume_source: ResumeSource,
    storage: NodeStorage,
    block_body_store: Arc<dyn crate::apply::PruneBodyStore>,
    utxo: Arc<UtxoSet>,
    coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    tx_index_spawn: Option<TxIndexSpawn>,
    tx_index_worker: Option<crate::txindex_worker::TxIndexWorker>,
    tx_index_lifecycle: Option<Arc<arc_swap::ArcSwap<crate::txindex_worker::TxIndexLifecycle>>>,
    /// Stable query adapter for txindex/script-index, constructed before open.
    tx_index_adapter: Option<Arc<crate::txindex_worker::TxIndexQueryAdapter>>,
    /// Live capability report backing `getcapabilities`.
    capabilities: Arc<crate::capabilities::NodeCapabilities>,
    prune_service: Option<Arc<dyn PruneService>>,
    zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    active_zmq_notifications: Vec<ZmqNotification>,
    mempool: Arc<RwLock<Mempool>>,
    /// The single mutation gateway in front of `mempool`.
    mempool_gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    /// Template-coordinator wake for authoritative mutations and tip moves.
    mining_generation: Arc<crate::mining::MiningGenerationSignal>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Cumulative transaction count through `applied_tip`, `0` when unknown.
    /// Shared with `ApplyHandles`, which maintains it, and with the RPC context.
    chain_tx_count: Arc<AtomicU64>,
    block_tree: Arc<RwLock<bitcoin_rs_chain::BlockTree>>,
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    network: Arc<RwLock<NetworkState>>,
    /// Shared P2P admission switch controlled by `setnetworkactive`.
    network_active: Arc<AtomicBool>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    banned: Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    p2p_outbound_tx: crossbeam_channel::Sender<std::net::SocketAddr>,
    p2p_outbound_rx: Arc<Mutex<crossbeam_channel::Receiver<std::net::SocketAddr>>>,
    inbound_headers_tx: Sender<bitcoin_rs_p2p::InboundHeaders>,
    inbound_headers_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundHeaders>>>,
    inbound_blocks_tx: Sender<bitcoin_rs_p2p::InboundBlock>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    chain_events: Arc<ChainEventPublisher>,
    chain_event_hints_rx: Arc<Mutex<Receiver<ChainEventHint>>>,
    apply_handles: crate::apply::ApplyHandles,
    sync: Arc<crate::BlockSync>,
    /// Process-wide rollback-evidence warning snapshot (`ArcSwap`).
    warning_store: Arc<crate::recovery_evidence::WarningStore>,
}

impl NodeState {
    /// Opens (or creates) the node's data directory and configured storage
    /// backend.
    /// Derived-index workers are constructed dormant (`Opening`) and started
    /// by [`Self::start_index_workers`] once crash recovery has made the
    /// applied tip authoritative; `start_node` performs both steps.
    #[allow(clippy::arc_with_non_send_sync)]
    #[allow(clippy::too_many_lines)]
    pub fn open(
        config: NodeConfig,
        mempool_observer: Option<&Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
    ) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let checkpoint_data_dir = crate::checkpoint_fs::open_data_dir(&config.data_dir)
            .with_context(|| format!("open data_dir {}", config.data_dir.display()))?;
        crate::checkpoint_fs::ensure_current_schema(&checkpoint_data_dir).with_context(|| {
            format!(
                "validate CURRENT_SCHEMA for datadir {}",
                config.data_dir.display()
            )
        })?;
        // Allocate the process epoch before anything else can consume one:
        // durable, strictly greater than every earlier run of this data dir.
        let epoch = allocate_process_epoch(&checkpoint_data_dir)?;
        let checkpoint_config = crate::checkpoint::HeaderCheckpointConfig {
            network: config.network,
            genesis: config.network.genesis_block_hash(),
        };
        let checkpoint_load =
            crate::checkpoint::load_checkpoint_from_dir(&checkpoint_data_dir, checkpoint_config)?;

        // Divide the process cache budget across the persistent namespaces
        // that exist in this deployment. A disabled txindex share redistributes
        // to chainstate.
        let cache_budget = bitcoin_rs_storage::clamp_dbcache_bytes(config.dbcache_mb);
        let cache_shares = bitcoin_rs_storage::split_cache_budget(
            cache_budget,
            !tx_index_capabilities(&config).is_empty(),
        );
        let chainstate_cache_bytes = cache_shares[0].bytes;
        let txindex_cache_bytes = cache_shares[1].bytes;
        let storage = NodeStorage::open(&config, chainstate_cache_bytes)?;
        let undo_store = storage.undo_store();
        // Before anything reads the chainstate, let alone serves or syncs it.
        // A node that starts on a torn chainstate builds on it, and every block
        // it adds makes the damage harder to find.
        if let Some(marker) = undo_store
            .load_disconnect_marker()
            .map_err(anyhow::Error::new)?
        {
            let force_full_revalidation = requires_full_revalidation(&config.data_dir);
            if marker.phase == crate::apply::DisconnectPhase::RolledBack && force_full_revalidation
            {
                undo_store.disarm_disconnect().map_err(anyhow::Error::new)?;
                tracing::warn!(
                    height = marker.height,
                    hash = %marker.hash,
                    "accepting completed deep reorg; full chain validation is required"
                );
            } else {
                // Names directories rather than a `-reindex` option, because this
                // node has no reindex. An instruction the operator cannot follow is
                // worse than none.
                //
                // Remove the authoritative views. The marker covers a disconnect
                // that did not reach a clean UTXO-and-tip checkpoint. TxIndex rows
                // are derived state outside this marker, but a retained TxIndex
                // watermark can stall rollback because wiping the chainstate
                // removes the body positions the index refers to. Include the txindex
                // path so the operator action is complete.
                bail!(
                    "refusing to start: a disconnect of block {hash} at height {height} did not \
                     reach a clean checkpoint, so the UTXO set and chain tip cannot be trusted \
                     together. The node cannot repair this in place. Remove or quarantine \
                     {chainstate}, {checkpoints}, and {txindex}, then resync.",
                    hash = marker.hash,
                    height = marker.height,
                    chainstate = config.data_dir.join("chainstate").display(),
                    checkpoints = config.data_dir.join("chainstate-checkpoints").display(),
                    txindex = config.data_dir.join("txindex").display(),
                );
            }
        }
        let block_files =
            Arc::new(FlatFileBlockStore::open(&config.data_dir).map_err(anyhow::Error::new)?);
        let block_body_store = storage.block_body_store(Arc::clone(&block_files));

        let zmq_endpoints = config.zmq_endpoints();
        let active_zmq_notifications: Vec<_> = zmq_endpoints
            .iter()
            .flat_map(|endpoint| {
                endpoint.topics.iter().map(|topic| {
                    ZmqNotification::new(
                        topic.notifier_type(),
                        endpoint.endpoint.clone(),
                        endpoint.effective_hwm(),
                    )
                })
            })
            .collect();
        #[cfg(feature = "zmq")]
        let zmq_publisher: Arc<dyn crate::ZmqPublisher> = if zmq_endpoints.is_empty() {
            Arc::new(crate::NoOpZmqPublisher)
        } else {
            Arc::new(crate::SocketZmqPublisher::bind(zmq_endpoints)?)
        };
        #[cfg(not(feature = "zmq"))]
        let zmq_publisher: Arc<dyn crate::ZmqPublisher> = {
            let _ = &zmq_endpoints;
            Arc::new(crate::NoOpZmqPublisher)
        };
        let InitialChainstate {
            utxo: mut utxo_set,
            coin_stats: initial_coin_stats,
            tree: block_tree_value,
            applied_tip: restored_applied_tip,
            chain_tx_count: restored_chain_tx_count,
            resume_source,
            journal_bootstrap,
        } = prepare_initial_chainstate(
            checkpoint_load,
            &checkpoint_data_dir,
            checkpoint_config,
            &config,
        )?;
        if resume_source == ResumeSource::Checkpoint {
            tracing::info!(
                height = restored_applied_tip.as_ref().map_or(0, |tip| tip.height),
                hash = %restored_applied_tip
                    .as_ref()
                    .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash),
                "restored chainstate checkpoint"
            );
        }
        // A2: Create the process-wide rollback-evidence warning store before
        // any detection or worker spawn. One ArcSwap holds the complete
        // immutable snapshot; getblockchaininfo loads one per request.
        let warning_store = Arc::new(crate::recovery_evidence::WarningStore::new());
        // A2: Read the durable applied-tip witness and detect checkpoint
        // fallback. Emit a structured WARN, update the warning snapshot, and
        // durably publish the event marker — only after all conditions hold:
        // valid format/bounds, matching genesis, older writer epoch, and
        // strictly greater witness height than the restored tip.
        let genesis_hex = config.network.genesis_block_hash().to_string_be();
        // One reporter routes every rollback fact of this process — the
        // checkpoint fallback detected here and the index-ahead rewinds the
        // txindex worker detects later — through the same warning store and
        // event marker.
        let recovery_reporter = Arc::new(crate::recovery_evidence::RecoveryReporter::new(
            Arc::clone(&warning_store),
            config.data_dir.clone(),
            genesis_hex.clone(),
            epoch,
        ));
        let restored_height = restored_applied_tip.as_ref().map_or(0, |tip| tip.height);
        let restored_hash = restored_applied_tip
            .as_ref()
            .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash)
            .to_string_be();
        if let Some(witness) =
            crate::recovery_evidence::read_witness(&config.data_dir, &genesis_hex)
        {
            if let Some((witness_height, _)) = crate::recovery_evidence::detect_checkpoint_fallback(
                &witness,
                epoch,
                &genesis_hex,
                restored_height,
            ) {
                let source = match resume_source {
                    ResumeSource::Cold => "cold",
                    ResumeSource::Checkpoint => "checkpoint",
                    ResumeSource::Journal => "journal",
                };
                recovery_reporter
                    .report_checkpoint_fallback(
                        witness_height,
                        restored_height,
                        &restored_hash,
                        source,
                        &witness.block_hash,
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.as_secs()),
                    )
                    .context("write checkpoint-fallback event marker")?;
                let gap = witness_height.saturating_sub(restored_height);
                if gap > STALE_RESTORE_ERROR_THRESHOLD {
                    tracing::error!(
                        witness_height,
                        restored_height,
                        gap,
                        threshold = STALE_RESTORE_ERROR_THRESHOLD,
                        "stale checkpoint restore: chainstate is {gap} blocks behind \
                         the last durable applied-tip witness — no committed journal \
                         suffix covers the gap, so the node is proceeding with a valid \
                         but far-behind tip and the sync layer must re-fetch it"
                    );
                }
            }
        }
        // Anchor the initial snapshot before `restored_applied_tip` is moved
        // into the applied-tip slot: a restored node resumes at its restored
        // tip, a fresh one at genesis, both with an untouched sequence.
        let initial_snapshot = ChainSnapshot {
            epoch,
            sequence: 0,
            tip_hash: restored_applied_tip
                .as_ref()
                .map_or_else(|| config.network.genesis_block_hash(), |tip| tip.hash),
            tip_height: restored_applied_tip.as_ref().map_or(0, |tip| tip.height),
        };
        let coin_stats_listener =
            bitcoin_rs_utxo::stats::CoinStatsListener::new(initial_coin_stats);
        utxo_set.set_listener(Box::new(coin_stats_listener.clone()));
        let journal = match journal_bootstrap {
            Some(bootstrap) => {
                Some(storage.journal_writer(open_journal_dir(&config.data_dir)?, bootstrap)?)
            }
            None => None,
        };
        let utxo = Arc::new(utxo_set);
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let block_tree = Arc::new(RwLock::new(block_tree_value));
        let chain_tip = block_tree.read().tip_handle();
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        if let Some(restored_applied_tip) = restored_applied_tip {
            applied_tip.store(Some(Arc::new(restored_applied_tip)));
        }
        let blocks = Arc::new(RwLock::new(BlockLog::new()));
        let chain_tx_count = Arc::new(AtomicU64::new(restored_chain_tx_count));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        // Created before the txindex worker spawn: the worker mirrors this
        // publisher's snapshot into its persisted consumer cursor.
        let (chain_events_raw, chain_event_hints_rx_raw) =
            ChainEventPublisher::new(epoch, initial_snapshot);
        let shutdown = Arc::new(AtomicBool::new(false));
        let chain_events = Arc::new(chain_events_raw);
        let tx_index_open_spec = build_tx_index_open_spec(&config, txindex_cache_bytes, epoch)?;
        let (tx_index_runtime, tx_index_spawn, tx_index_lifecycle, tx_index_adapter) =
            match tx_index_open_spec {
                Some(spec) => {
                    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
                    let runtime = Arc::new(crate::txindex_worker::TxIndexRuntime::new(wake_tx));
                    let body_source: Arc<dyn bitcoin_rs_rpc::context::BlockBodySource> =
                        Arc::new(StoredBlockBodySource::new(Arc::clone(&block_body_store)));
                    let block_source = crate::NodeBlockSource::new(Arc::clone(&blocks))
                        .with_block_body_source(Arc::clone(&body_source))
                        .with_block_tree(Arc::clone(&block_tree));
                    let lifecycle: Arc<arc_swap::ArcSwap<crate::txindex_worker::TxIndexLifecycle>> =
                        Arc::new(arc_swap::ArcSwap::from_pointee(
                            crate::txindex_worker::TxIndexLifecycle::Opening,
                        ));
                    let adapter = Arc::new(crate::txindex_worker::TxIndexQueryAdapter::new(
                        Arc::clone(&lifecycle),
                    ));
                    let generation = crate::txindex_worker::Generation::new(spec.epoch);
                    (
                        Some(runtime),
                        Some(TxIndexSpawn {
                            spec,
                            generation,
                            block_source,
                            body_source,
                            wake_rx,
                            recovery_reporter: Arc::clone(&recovery_reporter),
                        }),
                        Some(lifecycle),
                        Some(adapter),
                    )
                }
                None => (None, None, None, None),
            };
        let capabilities = Arc::new(crate::capabilities::NodeCapabilities::new(
            crate::capabilities::CapabilityInputs {
                tx_lifecycle: tx_index_lifecycle.clone(),
                tx_runtime: tx_index_runtime.clone(),
                txindex_enabled: crate::capabilities::txindex_enabled(&config),
            },
        ));
        let network = Arc::new(RwLock::new(NetworkState::default()));
        let network_active = Arc::new(AtomicBool::new(true));
        let banned = Arc::new(RwLock::new(Vec::new()));
        let peer_table = Arc::new(bitcoin_rs_p2p::PeerTable::new());
        let (p2p_outbound_tx, p2p_outbound_rx_raw) =
            crossbeam_channel::bounded(P2P_OUTBOUND_QUEUE_LIMIT);
        let p2p_outbound_rx = Arc::new(Mutex::new(p2p_outbound_rx_raw));
        let (inbound_headers_tx, inbound_headers_rx_raw) =
            crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            crossbeam_channel::bounded::<bitcoin_rs_p2p::InboundBlock>(INBOUND_BLOCK_CHANNEL_LIMIT);
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let chain_event_hints_rx = Arc::new(Mutex::new(chain_event_hints_rx_raw));
        // The template-coordinator wake exists from node birth so the apply
        // path and the gateway can fire it before `run` builds the
        // coordinator; the coordinator attaches itself once constructed.
        let mining_generation = Arc::new(crate::mining::MiningGenerationSignal::new());
        // One node-owned gateway: every admission (RPC sendrawtransaction,
        // embedded broadcast, reorg re-admission, block-connect eviction)
        // mutates through this instance, so publication order equals commit
        // order process-wide. The sequence observer rides along only when a
        // `--zmq-pub-sequence` endpoint is configured; the mining
        // generation wake always does.
        let mempool_gateway = {
            let publisher = Arc::clone(&zmq_publisher);
            let sequence: Option<Arc<dyn bitcoin_rs_mempool::MempoolObserver>> =
                if publisher.wants_notifications() {
                    let observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver> = Arc::new(
                        crate::mempool_observer::MempoolSequenceObserver::new(publisher),
                    );
                    Some(observer)
                } else {
                    mempool_observer.cloned()
                };
            let observer = crate::mempool_observer::NodeMutationObserver::new(
                sequence,
                Arc::clone(&mining_generation),
            );
            // Intern it: one gateway per pool, so every route that resolves
            // the pool - including a test attaching its own observer leg -
            // reaches this instance and its observer slot.
            bitcoin_rs_mempool::MempoolGateway::shared_with(
                Arc::clone(&mempool),
                Arc::new(observer),
            )
        };
        let apply_handles = crate::apply::ApplyHandles {
            network: config.network,
            chain_tip: Arc::clone(&chain_tip),
            applied_tip: Arc::clone(&applied_tip),
            chain_tx_count: Arc::clone(&chain_tx_count),
            block_tree: Arc::clone(&block_tree),
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            tx_index_runtime: tx_index_runtime.clone(),
            mempool: Arc::clone(&mempool),
            mempool_gateway: Arc::clone(&mempool_gateway),
            mining_generation: Arc::clone(&mining_generation),
            blocks: Arc::clone(&blocks),
            transactions: Arc::clone(&transactions),
            zmq_publisher: Arc::clone(&zmq_publisher),
            chain_events: Arc::clone(&chain_events),
            block_body_store: Some(Arc::clone(&block_body_store)),
            undo_store,
            admission: Arc::new(crate::apply::ApplyAdmission::new()),
            shutdown: Arc::clone(&shutdown),
            chain_transition: Arc::new(parking_lot::Mutex::new(())),
            assume_valid_height: config.assume_valid_height,
            assume_valid_gate: Arc::new(crate::apply::AssumeValidGate::new(
                config.network,
                config.assume_valid_height,
            )),
            journal,
        };
        apply_handles.assume_valid_gate.evaluate(&block_tree.read());
        let sync = Arc::new(crate::BlockSync::new(
            apply_handles.clone(),
            Arc::clone(&peer_table),
            Arc::clone(&inbound_headers_rx),
            Arc::clone(&inbound_blocks_rx),
        ));
        // A restored checkpoint is durable at its own height by definition, so
        // start there rather than at zero, which would refuse all undo pruning.
        let durable_tip_height = Arc::new(AtomicU32::new(
            applied_tip.load().as_ref().map_or(0, |tip| tip.height),
        ));
        let prune_service = if config.prune_target_mb > 0 {
            Some(storage.prune_service(
                &block_files,
                &block_body_store,
                Arc::clone(&blocks),
                Arc::clone(&transactions),
                apply_handles.prune_authority(),
                &durable_tip_height,
            )?)
        } else {
            None
        };
        tracing::info!(
            backend = storage.kind(),
            chainstate_dir = %config.data_dir.join("chainstate").display(),
            chainstate_cache_bytes,
            txindex_cache_bytes,
            total_cache_bytes = cache_budget,
            "opened storage backend with effective cache capacities"
        );
        let data_dir = config.data_dir.clone();
        Ok(Self {
            durable_tip_height,
            config,
            data_dir,
            #[cfg(test)]
            resume_source,
            storage,
            block_body_store,
            utxo,
            coin_stats,
            tx_index_runtime,
            tx_index_spawn,
            tx_index_worker: None,
            tx_index_lifecycle,
            tx_index_adapter,
            capabilities,
            prune_service,
            zmq_publisher,
            active_zmq_notifications,
            mempool,
            mempool_gateway,
            mining_generation,
            chain_tip,
            applied_tip,
            chain_tx_count: Arc::clone(&chain_tx_count),
            block_tree,
            blocks,
            transactions,
            network,
            network_active,
            peer_table,
            banned,
            p2p_outbound_tx,
            p2p_outbound_rx,
            inbound_headers_tx,
            inbound_headers_rx,
            inbound_blocks_tx,
            inbound_blocks_rx,
            chain_events: Arc::clone(&chain_events),
            chain_event_hints_rx,
            apply_handles,
            sync,
            warning_store,
        })
    }

    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[cfg(test)]
    pub(crate) const fn resume_source(&self) -> ResumeSource {
        self.resume_source
    }

    /// Publishes a durable clean checkpoint and returns the published
    /// generation, or an error if there is no applied tip.
    ///
    /// This is the public boundary for the private checkpoint machinery; it
    /// keeps `CheckpointWrite`, `CheckpointError`, and the checkpoint module
    /// internal to the crate.
    pub fn publish_checkpoint(&self) -> Result<u64> {
        match self.write_clean_checkpoint()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                bail!("checkpoint refused: no applied tip to publish")
            }
            crate::checkpoint::CheckpointWrite::Published { generation } => Ok(generation),
        }
    }

    /// Creates a [`crate::checkpoint_worker::CheckpointPublisher`] from this
    /// state's shared handles, for use by the periodic checkpoint worker.
    ///
    /// The publisher owns its own `Dir` handle (reopened from the data-dir
    /// path) and cloned `Arc`s, so it can be moved into a background thread
    /// without borrowing from `self`.
    pub(crate) fn checkpoint_publisher(
        &self,
    ) -> core::result::Result<
        crate::checkpoint_worker::CheckpointPublisher,
        crate::checkpoint::CheckpointError,
    > {
        Ok(crate::checkpoint_worker::CheckpointPublisher {
            admission: Arc::clone(&self.apply_handles.admission),
            undo_store: Arc::clone(&self.apply_handles.undo_store),
            block_body_store: Arc::clone(&self.block_body_store),
            applied_tip: Arc::clone(&self.applied_tip),
            checkpoint_data_dir: crate::checkpoint_fs::open_data_dir(&self.data_dir)
                .map_err(crate::checkpoint::CheckpointError::Io)?,
            network: self.config.network,
            genesis_hash: self.config.network.genesis_block_hash(),
            block_tree: Arc::clone(&self.block_tree),
            utxo: Arc::clone(&self.utxo),
            coin_stats: Arc::clone(&self.coin_stats),
            chain_tx_count: Arc::clone(&self.chain_tx_count),
            journal: self.apply_handles.journal.clone(),
            data_dir: self.data_dir.clone(),
            chain_events: Arc::clone(&self.chain_events),
            durable_tip_height: Arc::clone(&self.durable_tip_height),
        })
    }

    /// Spawns the periodic checkpoint worker with a custom cadence.
    ///
    /// Production wiring goes through `start_node`, which uses
    /// [`crate::checkpoint_worker::CHECKPOINT_INTERVAL_BLOCKS`] and
    /// [`crate::checkpoint_worker::CHECKPOINT_INTERVAL_SECS`]. This method
    /// is `pub` so integration tests can use a small cadence.
    ///
    /// Returns the worker's join handle. The worker exits when the node's
    /// shutdown flag is set.
    pub fn start_periodic_checkpoint(
        &self,
        interval_blocks: u32,
        interval_secs: Duration,
    ) -> Result<std::thread::JoinHandle<()>> {
        let publisher = self.checkpoint_publisher().map_err(anyhow::Error::new)?;
        Ok(crate::checkpoint_worker::spawn_periodic_checkpoint_worker(
            publisher,
            Arc::clone(&self.shutdown()),
            interval_blocks,
            interval_secs,
        )?)
    }

    pub(crate) fn write_clean_checkpoint(
        &self,
    ) -> core::result::Result<crate::checkpoint::CheckpointWrite, crate::checkpoint::CheckpointError>
    {
        self.checkpoint_publisher()?.publish()
    }

    /// Returns the configured storage backend that was opened.
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        self.storage.kind()
    }

    /// Returns the shared UTXO set handle.
    #[must_use]
    pub fn utxo(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Returns the shared coinstats listener handle.
    #[must_use]
    pub fn coin_stats(&self) -> Arc<bitcoin_rs_utxo::stats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    /// Returns the node-owned complete transaction-index query adapter.
    #[must_use]
    pub fn tx_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery>> {
        if !self.config.txindex {
            return None;
        }
        self.tx_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns transaction lookup for internal Esplora projections.
    ///
    /// `--scriptindex` builds this dependency as well, but that does not
    /// enable or advertise the Core `--txindex` contract.
    #[must_use]
    pub fn esplora_tx_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery>> {
        self.tx_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::TxIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns the node-owned complete generic script-index query adapter.
    #[must_use]
    pub fn script_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery>> {
        if !self.config.script_index.is_enabled() {
            return None;
        }
        self.tx_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery> = adapter.clone();
            q
        })
    }

    /// Starts the derived-index workers. Call only once the applied tip is
    /// authoritative — after crash recovery — so the index reconciles against
    /// the real chainstate and never mistakes a recovered gap for a stale branch.
    pub fn start_index_workers(&mut self) -> anyhow::Result<()> {
        let Some(spawn) = self.tx_index_spawn.take() else {
            return Ok(());
        };
        let runtime = self
            .tx_index_runtime
            .as_ref()
            .context("txindex runtime missing for a pending worker spawn")?;
        let lifecycle = self
            .tx_index_lifecycle
            .as_ref()
            .context("txindex lifecycle missing for a pending worker spawn")?;
        let worker = crate::txindex_worker::TxIndexWorker::spawn_with_open(
            Arc::clone(runtime),
            spawn.spec,
            Arc::clone(lifecycle),
            spawn.generation,
            Arc::clone(&self.applied_tip),
            Arc::clone(&self.block_tree),
            Some(Arc::clone(&self.block_body_store)),
            spawn.block_source,
            Some(spawn.body_source),
            Arc::clone(&self.chain_events),
            spawn.recovery_reporter,
            Arc::clone(&self.apply_handles.shutdown),
            spawn.wake_rx,
        )
        .context("spawn txindex worker")?;
        self.tx_index_worker = Some(worker);
        Ok(())
    }

    /// Returns the live capability report provider for `getcapabilities`.
    #[must_use]
    pub fn capability_provider(&self) -> Arc<dyn bitcoin_rs_rpc::context::CapabilityProvider> {
        self.capabilities.clone()
    }

    /// Returns the manual pruning service when pruning is enabled.
    #[must_use]
    pub fn prune_service(&self) -> Option<Arc<dyn PruneService>> {
        self.prune_service.as_ref().map(Arc::clone)
    }

    /// Returns the configured ZMQ publisher handle (default: `NoOpZmqPublisher`).
    #[must_use]
    pub fn zmq_publisher(&self) -> Arc<dyn crate::ZmqPublisher> {
        Arc::clone(&self.zmq_publisher)
    }

    /// Returns active ZMQ notification metadata for RPC reporting.
    #[must_use]
    pub fn active_zmq_notifications(&self) -> Vec<ZmqNotification> {
        self.active_zmq_notifications.clone()
    }

    /// Returns the shared mempool handle.
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(&self.mempool)
    }

    /// Returns the node-owned mutation gateway in front of `mempool`.
    ///
    /// Every mempool mutation in this process — RPC admission, embedded
    /// broadcast, reorg re-admission, block-connect eviction — commits
    /// through this one instance, so observers observe a single ordered
    /// stream.
    #[must_use]
    pub fn mempool_gateway(&self) -> Arc<bitcoin_rs_mempool::MempoolGateway> {
        Arc::clone(&self.mempool_gateway)
    }

    /// Returns the mining generation wake shared with the apply path and the
    /// gateway observer. The template coordinator attaches itself here.
    #[must_use]
    pub fn mining_generation_signal(&self) -> Arc<crate::mining::MiningGenerationSignal> {
        Arc::clone(&self.mining_generation)
    }

    /// Returns the shared best-chain tip handle.
    #[must_use]
    pub fn chain_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.chain_tip)
    }

    /// Returns the shared best-applied-block tip handle.
    ///
    /// This handle lags `chain_tip()` when headers are accepted ahead of blocks
    /// being downloaded and applied. RPC consumers showing user-visible state
    /// (best block hash, block count) read this; sync-progress consumers read
    /// `chain_tip()`.
    #[must_use]
    pub fn applied_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.applied_tip)
    }

    /// Returns the shared block-tree handle.
    #[must_use]
    pub fn block_tree(&self) -> Arc<RwLock<bitcoin_rs_chain::BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    /// Shares the cumulative chain transaction-count handle with the RPC layer.
    #[must_use]
    pub fn chain_tx_count_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.chain_tx_count)
    }

    /// Returns the shared block-records handle exposed to RPC handlers.
    #[must_use]
    pub fn blocks(&self) -> Arc<RwLock<BlockLog>> {
        Arc::clone(&self.blocks)
    }

    /// Returns a durable block body reader for metadata-only block records.
    #[must_use]
    pub(crate) fn block_body_source(&self) -> Arc<dyn BlockBodySource> {
        Arc::new(StoredBlockBodySource::new(Arc::clone(
            &self.block_body_store,
        )))
    }

    /// Returns the shared txid → transaction map exposed to RPC handlers.
    #[must_use]
    pub fn transactions(&self) -> Arc<RwLock<HashMap<Txid, Tx>>> {
        Arc::clone(&self.transactions)
    }

    /// Returns the shared network-counters handle exposed to RPC handlers.
    #[must_use]
    pub fn network(&self) -> Arc<RwLock<NetworkState>> {
        Arc::clone(&self.network)
    }

    /// Returns the shared P2P admission switch exposed to RPC and P2P workers.
    #[must_use]
    pub fn network_active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.network_active)
    }

    /// Returns the shared manual IP/subnet ban list exposed to RPC and P2P.
    #[must_use]
    pub fn banned_subnets(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>> {
        Arc::clone(&self.banned)
    }

    #[must_use]
    /// Returns the authoritative table of live peer sessions.
    pub fn peer_table(&self) -> Arc<bitcoin_rs_p2p::PeerTable> {
        Arc::clone(&self.peer_table)
    }
    /// Returns a cloned sender that RPC `addnode` uses to request outbound P2P connections.
    #[must_use]
    pub fn p2p_outbound_sender(&self) -> crossbeam_channel::Sender<std::net::SocketAddr> {
        self.p2p_outbound_tx.clone()
    }

    /// Returns the shared receiver consumed by the outbound P2P drain worker.
    #[must_use]
    pub fn p2p_outbound_receiver(
        &self,
    ) -> Arc<Mutex<crossbeam_channel::Receiver<std::net::SocketAddr>>> {
        Arc::clone(&self.p2p_outbound_rx)
    }

    /// Returns the rollback-evidence warning store for `getblockchaininfo`.
    #[must_use]
    pub(crate) fn warning_store(&self) -> Arc<crate::recovery_evidence::WarningStore> {
        Arc::clone(&self.warning_store)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// block headers into. The matching `Receiver` is polled by
    /// `BlockSync::tick` to extend the `BlockTree`.
    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// block headers into. The matching `Receiver` is polled by
    /// `BlockSync::tick` to extend the `BlockTree`.
    pub fn inbound_headers_sender(&self) -> Sender<bitcoin_rs_p2p::InboundHeaders> {
        self.inbound_headers_tx.clone()
    }

    /// Returns the shared receiver handle consumed by `BlockSync::tick`.
    ///
    /// Exposed so tests and `BlockSync::new` can wire the channel; production
    /// code calls `state.sync()` and lets the orchestrator own the drain.
    #[must_use]
    pub fn inbound_headers_rx_handle(
        &self,
    ) -> Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundHeaders>>> {
        Arc::clone(&self.inbound_headers_rx)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// blocks into for verification and relay.
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin_rs_p2p::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }

    /// Returns the shared receiver handle consumed by `BlockSync::tick`.
    ///
    /// Exposed so tests and `BlockSync::new` can wire the channel; production
    /// code calls `state.sync()` and lets the orchestrator own the drain.
    #[must_use]
    pub fn inbound_blocks_rx_handle(&self) -> Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>> {
        Arc::clone(&self.inbound_blocks_rx)
    }

    /// Returns the current coherent chain snapshot: the applied tip stamped
    /// with the process epoch and the commit sequence.
    #[must_use]
    pub fn active_chain_snapshot(&self) -> ChainSnapshot {
        self.chain_events.snapshot()
    }

    /// Returns the chain-event publisher. The apply path records committed
    /// connects/disconnects through it; consumers read the snapshot from it.
    #[must_use]
    pub fn chain_event_publisher(&self) -> Arc<ChainEventPublisher> {
        Arc::clone(&self.chain_events)
    }

    /// Returns the shared hint receiver handle for reconciliation consumers.
    #[must_use]
    pub fn chain_event_hints(&self) -> Arc<Mutex<Receiver<ChainEventHint>>> {
        Arc::clone(&self.chain_event_hints_rx)
    }

    /// Returns the shared block-download orchestrator.
    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    /// Returns the process-wide shutdown signal shared by all runtime workers.
    #[must_use]
    pub fn shutdown(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.apply_handles.shutdown)
    }

    /// Bounded txindex-worker shutdown: requests the worker shutdown, waits up
    /// to `deadline` for a clean join, and detaches on
    /// expiry. On detach, revokes the generation token and publishes
    /// `ShutdownAbandoned` so queries return typed `Unavailable` instead of
    /// hitting a torn reader.
    pub(crate) fn bounded_index_shutdown(&mut self, deadline: Duration) {
        let start = std::time::Instant::now();
        if let Some(runtime) = &self.tx_index_runtime {
            runtime.request_shutdown();
        }
        // Take the worker out of self so we can join it without holding self
        // mutably across the wait.
        let tx_index_worker = self.tx_index_worker.take();
        let tx_deadline = start + deadline;
        let tx_joined = if let Some(mut worker) = tx_index_worker {
            let mut joined = false;
            while std::time::Instant::now() < tx_deadline {
                if worker.is_finished() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                worker.join();
                joined = true;
            } else {
                tracing::warn!("txindex worker still blocked; abandoning join");
                // Revoke the generation token so late publication is a no-op.
                if let Some(generation_token) = &worker.generation {
                    generation_token.revoke();
                }
                if let Some(lifecycle) = &self.tx_index_lifecycle {
                    lifecycle.store(Arc::new(
                        crate::txindex_worker::TxIndexLifecycle::ShutdownAbandoned,
                    ));
                }
                // Poison the namespace so it cannot be reclaimed in this process.
                worker.poison_namespace();
                // Detach the join handle so Drop does not block on join.
                // The worker thread continues running but will exit after
                // shutdown is observed; Drop is a no-op for the handle.
                worker.detach();
            }
            joined
        } else {
            true
        };
        let _ = tx_joined;
    }

    /// Snapshot of the handle set needed by `crate::apply::apply_block`.
    #[must_use]
    pub fn apply_handles(&self) -> crate::apply::ApplyHandles {
        self.apply_handles.clone()
    }

    /// Synthetically applies `block` as the next tip after consensus checks.
    ///
    /// Delegates to `crate::apply::apply_block` over the shared handles.
    pub fn apply_block(&self, block: &Block) -> core::result::Result<TipSnapshot, ApplyError> {
        crate::apply::apply_block(&self.apply_handles, block)
    }

    #[cfg(test)]
    pub(crate) fn check_coinbase_maturity(
        &self,
        block: &Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        crate::apply::check_coinbase_maturity(&self.apply_handles, block, height)
    }
}

impl Drop for NodeState {
    fn drop(&mut self) {
        let _admission = self.apply_handles.admission.close();
        // Safety net: if `bounded_index_shutdown` was not called (e.g. in
        // tests that drop `NodeState` directly), still request shutdown and
        // `bounded_index_shutdown` took them.
        if let Some(runtime) = &self.tx_index_runtime {
            runtime.request_shutdown();
        }
        if let Some(worker) = self.tx_index_worker.take() {
            worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::encode::double_sha256;
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, consensus_bytes,
    };
    use bitcoin_rs_rpc::context::BlockRecord;

    fn publish_applied_tip_height(state: &NodeState, height: u32) {
        let mut hash = [0_u8; 32];
        hash[..size_of::<u32>()].copy_from_slice(&height.to_le_bytes());
        state.applied_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: bitcoin_rs_chain::node::NodeId::new(height),
            height,
            chainwork: bitcoin_rs_chain::node::ChainWork::ZERO,
            hash: bitcoin_rs_primitives::Hash256::from_le_bytes(&hash),
        })));
    }

    #[test]
    fn full_revalidation_marker_is_sticky_when_journal_is_disabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.chainstate_journal.enabled = false;
        let journal_dir = config.data_dir.join(CHAINSTATE_JOURNAL_DIR);
        let marker = journal_dir.join(crate::chainstate_journal::FULL_REVALIDATION_MARKER);
        std::fs::create_dir_all(&journal_dir)?;
        std::fs::write(&marker, b"force full validation\n")?;

        assert!(requires_full_revalidation(&config.data_dir));
        Ok(())
    }

    #[test]
    fn open_constructs_empty_handles() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::NodeConfig {
            data_dir: dir.path().join("node"),
            ..crate::NodeConfig::default()
        };

        let state = NodeState::open(config, None)?;
        let utxo = state.utxo();
        let mempool = state.mempool();

        assert!(
            Arc::strong_count(&utxo) >= 2,
            "caller and NodeState should both hold a strong ref"
        );
        assert!(Arc::strong_count(&mempool) >= 2);
        assert_eq!(mempool.read().len(), 0, "fresh mempool must be empty");

        Ok(())
    }

    #[test]
    fn open_constructs_empty_block_tree() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let tree = state.block_tree();

        assert!(
            tree.read().is_empty(),
            "freshly opened tree has zero headers"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_coin_stats_listener() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let snapshot = state.coin_stats().snapshot();
        assert_eq!(
            snapshot.tx_count, 0,
            "freshly opened coin_stats has zero txs"
        );
        Ok(())
    }

    #[test]
    fn open_skips_tx_index_when_disabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

        assert!(
            state.tx_index_query().is_none(),
            "txindex disabled by default"
        );
        assert!(
            !state.data_dir().join("txindex").exists(),
            "disabled txindex must not create storage"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_tx_index_when_enabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        let mut state = NodeState::open(config, None)?;
        state.start_index_workers()?;
        let (Some(a), Some(b)) = (state.tx_index_query(), state.tx_index_query()) else {
            panic!("txindex query engine missing when enabled");
        };
        assert!(Arc::ptr_eq(&a, &b), "txindex query handle must be stable");
        // The worker opens the store asynchronously; the directory appears
        // once its open completes, not during NodeState::open.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !state.data_dir().join("txindex").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "enabled txindex worker did not create storage within 30s"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    #[test]
    fn index_workers_start_only_when_asked() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        let mut state = NodeState::open(config, None)?;

        assert!(state.tx_index_lifecycle.as_ref().is_some_and(|lifecycle| {
            matches!(
                lifecycle.load().as_ref(),
                crate::txindex_worker::TxIndexLifecycle::Opening
            )
        }));
        assert!(state.tx_index_worker.is_none());

        state.start_index_workers()?;
        assert!(state.tx_index_worker.is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while state.tx_index_lifecycle.as_ref().is_some_and(|lifecycle| {
            matches!(
                lifecycle.load().as_ref(),
                crate::txindex_worker::TxIndexLifecycle::Opening
            )
        }) {
            assert!(
                std::time::Instant::now() < deadline,
                "txindex lifecycle remained Opening"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    #[test]
    fn script_index_builds_without_advertising_core_txindex() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = false;
        config.script_index = crate::config::ScriptIndexMode::Full;

        let mut state = NodeState::open(config, None)?;
        state.start_index_workers()?;

        assert!(state.apply_handles().tx_index_runtime.is_some());
        assert!(state.tx_index_query().is_none());
        assert!(state.esplora_tx_index_query().is_some());
        assert!(state.script_index_query().is_some());
        // The script-index worker shares the txindex storage; it is created
        // asynchronously once the worker's open completes.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !state.data_dir().join("txindex").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "script-index worker did not create storage within 30s"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    /// Opens a node in each accepted `scriptindex` mode and asserts the
    /// concrete answer for `unspent_outputs`, rather than only the `full` path.
    ///
    /// This is the guard that the two accepted modes give distinct, concrete
    /// answers instead of both degrading to `Retry`.
    #[test]
    fn script_index_modes_give_concrete_unspent_outputs_answers() -> anyhow::Result<()> {
        use bitcoin_rs_index::ScriptHash;
        use bitcoin_rs_rpc::context::TxQueryError;

        // Genesis is applied in each case so the index worker has at least one
        // block to index. Without it the worker never publishes a
        // `ScriptHistory` watermark and every mode retries forever, which would
        // make both cases indistinguishable.
        let scripthash = ScriptHash::from_script_bytes(&[0x51, 0x01]);

        // `disabled`: no script index at all, so no query adapter is handed
        // out. The answer is a definite "not available", not a retry.
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = false;
        config.script_index = crate::config::ScriptIndexMode::Disabled;
        let state = NodeState::open(config, None)?;
        let _ = state.apply_block(&crate::Network::Regtest.genesis_block())?;
        assert!(
            state.script_index_query().is_none(),
            "disabled must not hand out a script-index query adapter"
        );
        drop(state);

        // `full`: the accepted mode. It converges on a concrete answer — an
        // empty set for an unfunded script — rather than retrying forever.
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = false;
        config.script_index = crate::config::ScriptIndexMode::Full;
        let mut state = NodeState::open(config, None)?;
        state.start_index_workers()?;
        let _ = state.apply_block(&crate::Network::Regtest.genesis_block())?;
        let Some(query) = state.script_index_query() else {
            panic!("full mode must hand out a script-index query adapter")
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match query.unspent_outputs(scripthash) {
                Ok(records) => {
                    assert!(
                        records.is_empty(),
                        "an unfunded script has no unspent outputs"
                    );
                    break;
                }
                // The worker indexes asynchronously, so it is legitimately
                // still opening for a bounded interval.
                Err(TxQueryError::Retry | TxQueryError::Unavailable(_)) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "full mode must converge on a concrete answer, not retry forever"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("unexpected script-index error: {error}"),
            }
        }
        Ok(())
    }

    #[test]
    fn drop_joins_txindex_worker_before_reopen() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;

        {
            let mut state = NodeState::open(config.clone(), None)?;
            state.start_index_workers()?;
            assert!(state.tx_index_query().is_some());
        }

        let reopened = NodeState::open(config, None)?;
        assert!(reopened.tx_index_query().is_some());
        Ok(())
    }

    #[test]
    fn open_rejects_txindex_with_pruning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        config.prune_target_mb = 1;

        let error = match NodeState::open(config, None) {
            Ok(_) => anyhow::bail!("txindex with pruning must be rejected"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("transaction and script indexing are not compatible with -prune"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_block_sync_orchestrator() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let sync_a = state.sync();
        let sync_b = state.sync();
        assert!(
            Arc::ptr_eq(&sync_a, &sync_b),
            "sync handle is stable across calls"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_applied_tip() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

        assert!(
            state.applied_tip().load_full().is_none(),
            "freshly opened applied_tip is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_table() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

        assert!(
            state.peer_table().is_empty(),
            "freshly opened table is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_table_again() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;

        assert!(state.peer_table().is_empty());
        Ok(())
    }

    #[test]
    fn zmq_publisher_handle_defaults_to_noop() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let publisher = state.zmq_publisher();
        // No-op publisher accepts publish calls silently.
        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        Ok(())
    }

    #[test]
    fn zmq_publisher_handle_reports_active_metadata() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.notifications.zmq = vec![
            crate::zmq_publisher::ZmqEndpointConfig {
                endpoint: "inproc://state-zmq-block".to_owned(),
                topics: vec![
                    crate::zmq_publisher::ZmqTopic::HashBlock,
                    crate::zmq_publisher::ZmqTopic::RawBlock,
                ],
                hwm: Some(17),
            },
            crate::zmq_publisher::ZmqEndpointConfig {
                endpoint: "inproc://state-zmq-tx".to_owned(),
                topics: vec![
                    crate::zmq_publisher::ZmqTopic::HashTx,
                    crate::zmq_publisher::ZmqTopic::RawTx,
                ],
                hwm: Some(20),
            },
        ];
        let state = NodeState::open(config, None)?;

        let notifications = state.active_zmq_notifications();
        let notification_types: Vec<_> = notifications
            .iter()
            .map(|notification| notification.notification_type.as_str())
            .collect();
        let hwms: Vec<_> = notifications
            .iter()
            .map(|notification| notification.hwm)
            .collect();
        assert_eq!(
            notification_types,
            ["pubhashblock", "pubrawblock", "pubhashtx", "pubrawtx"]
        );
        assert_eq!(hwms, [17, 17, 20, 20]);
        Ok(())
    }

    #[test]
    fn inbound_headers_sender_is_unbounded_clone_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let tx1 = state.inbound_headers_sender();
        let tx2 = state.inbound_headers_sender();
        tx1.send(bitcoin_rs_p2p::InboundHeaders {
            headers: Vec::new(),
            source: None,
        })
        .map_err(|err| anyhow::anyhow!("send via tx1 failed: {err}"))?;
        tx2.send(bitcoin_rs_p2p::InboundHeaders {
            headers: Vec::new(),
            source: None,
        })
        .map_err(|err| anyhow::anyhow!("send via tx2 failed: {err}"))?;
        Ok(())
    }

    #[test]
    fn inbound_blocks_sender_is_clonable_into_listener_threads() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let _tx1 = state.inbound_blocks_sender();
        let _tx2 = state.inbound_blocks_sender();
        Ok(())
    }

    #[test]
    fn inbound_blocks_channel_is_bounded_against_flood() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let tx = state.inbound_blocks_sender();
        let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        // No `tick` drains the channel in this unit test, so it fills to the
        // bound; the block past the limit must be rejected rather than queued
        // (the OOM-flood guard), proving backpressure engages at the producer.
        for _ in 0..super::INBOUND_BLOCK_CHANNEL_LIMIT {
            tx.try_send(bitcoin_rs_p2p::InboundBlock::from_decoded(block.clone()))
                .unwrap_or_else(|e| panic!("send within the bound must succeed: {e}"));
        }
        let overflow = tx.try_send(bitcoin_rs_p2p::InboundBlock::from_decoded(block));
        assert!(
            matches!(overflow, Err(crossbeam_channel::TrySendError::Full(_))),
            "channel must reject blocks past INBOUND_BLOCK_CHANNEL_LIMIT, got {overflow:?}",
        );
        Ok(())
    }

    #[test]
    fn open_constructs_full_rpc_handle_set() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::NodeConfig {
            data_dir: dir.path().join("node"),
            ..crate::NodeConfig::default()
        };

        let state = NodeState::open(config, None)?;
        let chain_tip = state.chain_tip();
        let blocks = state.blocks();
        let transactions = state.transactions();
        let network = state.network();

        assert!(chain_tip.load().is_none(), "fresh chain tip must be empty");
        assert!(blocks.read().is_empty(), "fresh blocks must be empty");
        assert!(
            transactions.read().is_empty(),
            "fresh transactions must be empty"
        );
        assert_eq!(network.read().connection_count, 0);

        Ok(())
    }

    #[test]
    fn apply_handles_follow_txindex_availability() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("without-txindex");
        config.p2p_listen.clear();
        config.txindex = false;
        let state = NodeState::open(config, None)?;
        assert!(state.apply_handles().tx_index_runtime.is_none());

        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("with-txindex");
        config.p2p_listen.clear();
        config.txindex = true;
        let state = NodeState::open(config, None)?;
        assert!(state.apply_handles().tx_index_runtime.is_some());
        Ok(())
    }

    #[test]
    fn prune_service_is_absent_when_config_disables_pruning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 0;

        let state = NodeState::open(config, None)?;

        assert!(state.prune_service().is_none());
        Ok(())
    }

    #[test]
    fn apply_block_persists_body_under_pruning_key_when_pruning_disabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 0;
        let state = NodeState::open(config, None)?;
        let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());

        assert!(state.prune_service().is_none());
        state.apply_block(&block)?;

        assert_eq!(
            state.blocks.read().first().map(|record| record.body_size),
            Some(consensus_bytes(&block).len())
        );
        assert_eq!(
            state.block_body_store.load_block_body(0, hash)?.as_deref(),
            Some(consensus_bytes(&block).as_slice())
        );
        Ok(())
    }

    #[test]
    fn persisting_same_block_body_twice_appends_once() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7_u8; 32]);
        let body = b"idempotent block body";

        state.block_body_store.persist_block_body(42, hash, body)?;
        let block_file = state.data_dir.join("blocks").join("blk00000.dat");
        let first_len = std::fs::metadata(&block_file)?.len();
        state.block_body_store.persist_block_body(42, hash, body)?;
        let second_len = std::fs::metadata(block_file)?.len();

        assert_eq!(second_len, first_len);
        assert_eq!(
            state.block_body_store.load_block_body(42, hash)?.as_deref(),
            Some(body.as_slice())
        );
        Ok(())
    }

    #[test]
    fn new_datadir_initializes_current_schema_before_storage() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::write(config.data_dir.join(".CURRENT_SCHEMA.tmp"), b"partial")?;

        let data_dir = config.data_dir.clone();
        let _state = NodeState::open(config, None)?;
        assert_eq!(
            std::fs::read(data_dir.join(crate::checkpoint_fs::CURRENT_SCHEMA_FILE))?,
            crate::checkpoint_fs::current_schema_bytes()
        );
        assert!(!data_dir.join(".CURRENT_SCHEMA.tmp").exists());
        assert!(data_dir.join("chainstate").exists());
        Ok(())
    }

    #[test]
    fn unmarked_nonempty_datadir_adopts_baseline_schema() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("legacy-node");
        config.p2p_listen.clear();
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::write(config.data_dir.join("legacy-state"), b"old")?;

        let data_dir = config.data_dir.clone();
        let _state = NodeState::open(config, None)?;
        assert_eq!(
            std::fs::read(data_dir.join(crate::checkpoint_fs::CURRENT_SCHEMA_FILE))?,
            b"0\n"
        );
        assert!(
            data_dir.join("chainstate").exists(),
            "baseline adoption must initialize storage"
        );
        Ok(())
    }

    #[test]
    fn mismatched_datadir_schema_is_refused_before_storage_opens() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("old-node");
        config.p2p_listen.clear();
        std::fs::create_dir_all(&config.data_dir)?;
        std::fs::write(
            config
                .data_dir
                .join(crate::checkpoint_fs::CURRENT_SCHEMA_FILE),
            b"1\n",
        )?;

        let data_dir = config.data_dir.clone();
        let Err(error) = NodeState::open(config, None) else {
            anyhow::bail!("mismatched datadir schema unexpectedly opened");
        };
        let message = format!("{error:#}");
        assert!(message.contains("CURRENT_SCHEMA is not the current datadir schema epoch"));
        assert!(message.contains("full resync"));
        assert!(!data_dir.join("chainstate").exists());
        Ok(())
    }

    #[test]
    fn apply_block_with_serialized_persists_same_body_as_apply_block() -> anyhow::Result<()> {
        let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
        let serialized = bytes::Bytes::from(consensus_bytes(&block));

        let dir_a = tempfile::tempdir()?;
        let mut config_a = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config_a.data_dir = dir_a.path().join("node-a");
        config_a.p2p_listen.clear();
        config_a.prune_target_mb = 0;
        let state_a = NodeState::open(config_a, None)?;
        state_a.apply_block(&block)?;

        let dir_b = tempfile::tempdir()?;
        let mut config_b = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config_b.data_dir = dir_b.path().join("node-b");
        config_b.p2p_listen.clear();
        config_b.prune_target_mb = 0;
        let state_b = NodeState::open(config_b, None)?;
        crate::apply::apply_block_with_serialized(&state_b.apply_handles(), &block, serialized)?;

        let body_a = state_a
            .block_body_store
            .load_block_body(0, hash)?
            .ok_or_else(|| anyhow::anyhow!("apply_block body missing"))?;
        let body_b = state_b
            .block_body_store
            .load_block_body(0, hash)?
            .ok_or_else(|| anyhow::anyhow!("apply_block_with_serialized body missing"))?;
        assert_eq!(body_a, body_b);
        Ok(())
    }

    /// Undo pruning must respect the durable tip, not the in-memory one.
    ///
    /// The applied tip can run far ahead of the last clean checkpoint. Pruning
    /// undo to the in-memory tip deletes the record for the block the
    /// checkpoint names, and a crash then restores a chainstate that cannot
    /// disconnect its own tip.
    #[test]
    fn the_chain_transaction_count_survives_a_checkpoint_restart() -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;

        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();

        let expected = {
            let state = NodeState::open(config.clone(), None)?;
            assert_eq!(
                state.chain_tx_count_handle().load(Ordering::Relaxed),
                0,
                "a node that has applied nothing cannot know the count"
            );

            let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
            let genesis_tx_count = u64::try_from(genesis.txs.len())?;
            let _tip = state.apply_block(&genesis)?;
            let counted = state.chain_tx_count_handle().load(Ordering::Relaxed);
            assert_eq!(counted, genesis_tx_count, "genesis establishes the count");

            assert!(matches!(
                state.write_clean_checkpoint()?,
                crate::checkpoint::CheckpointWrite::Published { .. }
            ));
            counted
        };

        // The block-record log is rebuilt empty on every open, so before this
        // change the count was unrecoverable after a restart: the applied tip
        // came back from the checkpoint at its real height with nothing behind
        // it to sum. The number now rides along with the tip.
        let resumed = NodeState::open(config, None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        assert!(
            resumed.blocks().read().is_empty(),
            "the record log really does start empty; the count cannot come from it"
        );
        assert_eq!(
            resumed.chain_tx_count_handle().load(Ordering::Relaxed),
            expected
        );
        Ok(())
    }

    #[test]
    fn undo_pruning_keeps_records_the_durable_tip_still_needs() -> anyhow::Result<()> {
        fn hash(height: u32) -> anyhow::Result<bitcoin_rs_primitives::Hash256> {
            let byte = u8::try_from(height)
                .map_err(|_| anyhow::anyhow!("test height {height} exceeds u8"))?;
            Ok(bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32]))
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config, None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);

        for height in 10_u32..=12 {
            let hash = hash(height)?;
            state
                .block_body_store
                .persist_block_body(height, hash, b"block-body")?;
            state
                .apply_handles()
                .undo_store
                .persist_undo(height, hash, b"undo-body")?;
            state.blocks.write().push(BlockRecord {
                hash: BlockHash::from(hash),
                height,
                body_size: 1,
                header: None,
                tx_count: 0,
                time: 0,
            });
        }

        // No checkpoint has been written, so nothing is durable above genesis.
        assert_eq!(
            state.durable_tip_height.load(Ordering::Acquire),
            0,
            "the fixture must have no durable checkpoint, or this proves nothing"
        );

        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        let result = service
            .prune_to_height(11)
            .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

        assert_eq!(
            result.undo_rows_removed, 0,
            "no undo record may go while a crash would restore below all of them"
        );
        assert!(
            state.storage.stored_prune_undo(10, hash(10)?)?.is_some(),
            "the record a restore would need must survive"
        );
        Ok(())
    }

    #[test]
    fn prune_service_deletes_seeded_storage_rows_and_advances_pruneheight() -> anyhow::Result<()> {
        fn hash(height: u32) -> anyhow::Result<bitcoin_rs_primitives::Hash256> {
            let byte = u8::try_from(height)
                .map_err(|_| anyhow::anyhow!("test height {height} exceeds u8"))?;
            Ok(bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32]))
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config, None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);

        for height in 10_u32..=12 {
            let hash = hash(height)?;
            state
                .block_body_store
                .persist_block_body(height, hash, b"block-body")?;
            state
                .apply_handles()
                .undo_store
                .persist_undo(height, hash, b"undo-body")?;
            state.blocks.write().push(BlockRecord {
                hash: BlockHash::from(hash),
                height,
                body_size: 1,
                header: None,
                tx_count: 0,
                time: 0,
            });
        }

        // A node pruning old history has a durable tip far above it. Undo
        // records within the reorg-safety margin of that tip are kept, so the
        // durable tip has to clear height 11 by more than the margin for this
        // prune to touch anything. Without that the prune is correctly refused,
        // which the sibling test asserts.
        state
            .durable_tip_height
            .store(11 + CORE_REORG_SAFETY_MARGIN, Ordering::Release);

        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        let result = service
            .prune_to_height(11)
            .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

        assert_eq!(result.pruneheight, 11);
        assert_eq!(result.block_rows_removed, 1);
        assert_eq!(result.undo_rows_removed, 1);
        assert!(state.storage.stored_prune_body(10, hash(10)?)?.is_none());
        assert!(state.storage.stored_prune_undo(10, hash(10)?)?.is_none());
        assert!(state.storage.stored_prune_body(11, hash(11)?)?.is_some());
        assert!(state.storage.stored_prune_undo(11, hash(11)?)?.is_some());
        assert!(state.storage.stored_prune_body(12, hash(12)?)?.is_some());
        assert!(state.storage.stored_prune_undo(12, hash(12)?)?.is_some());

        Ok(())
    }

    #[test]
    fn prune_reclaims_whole_files_and_keeps_current_file() -> anyhow::Result<()> {
        fn seed<S: KvStore>(
            store: &S,
            height: u32,
            hash: bitcoin_rs_primitives::Hash256,
        ) -> anyhow::Result<()> {
            let position = bitcoin_rs_storage::BlockFilePosition {
                file_no: 0,
                offset: 0,
                len: 0,
            };
            let mut batch = store.new_batch();
            batch.put(
                bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::pruning::block_body_key(height, hash),
                &position.encode(),
            );
            batch.put(
                bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::block_file_max_height_key(0),
                &bitcoin_rs_storage::encode_block_file_max_height(height),
            );
            store.write(batch)?;
            Ok(())
        }

        fn metadata_exists<S: KvStore>(store: &S) -> anyhow::Result<bool> {
            Ok(store
                .get(
                    bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                    &bitcoin_rs_storage::block_file_max_height_key(0),
                )?
                .is_some())
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        std::fs::create_dir_all(&config.data_dir)?;
        let blocks_dir = config.data_dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir)?;
        let prunable_file = blocks_dir.join("blk00000.dat");
        let current_file = blocks_dir.join("blk00001.dat");
        std::fs::write(&prunable_file, [])?;
        std::fs::write(&current_file, [])?;
        let state = NodeState::open(config, None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[10_u8; 32]);

        match &state.storage {
            #[cfg(feature = "rocksdb")]
            NodeStorage::RocksDb(store) => seed(&**store, 10, hash)?,
            #[cfg(feature = "fjall")]
            NodeStorage::Fjall(store) => seed(&**store, 10, hash)?,
            #[cfg(feature = "redb")]
            NodeStorage::Redb(store) => seed(&**store, 10, hash)?,
            #[cfg(feature = "mdbx")]
            NodeStorage::Mdbx(store) => seed(&**store, 10, hash)?,
        }
        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        service
            .prune_to_height(11)
            .map_err(|error| anyhow::anyhow!("prune failed: {error}"))?;

        assert!(!prunable_file.exists());
        assert!(current_file.exists());
        assert!(state.storage.stored_prune_body(10, hash)?.is_none());
        let has_metadata = match &state.storage {
            #[cfg(feature = "rocksdb")]
            NodeStorage::RocksDb(store) => metadata_exists(&**store)?,
            #[cfg(feature = "fjall")]
            NodeStorage::Fjall(store) => metadata_exists(&**store)?,
            #[cfg(feature = "redb")]
            NodeStorage::Redb(store) => metadata_exists(&**store)?,
            #[cfg(feature = "mdbx")]
            NodeStorage::Mdbx(store) => metadata_exists(&**store)?,
        };
        assert!(!has_metadata);
        Ok(())
    }

    /// Pruning a block file must reduce what the node reports as its disk size.
    ///
    /// `getblockchaininfo.size_on_disk` used to be the sum of every block
    /// record's `body_size`. Pruning does not remove records — it clears their
    /// cached bodies and leaves the rest — so that sum could not move, and a
    /// pruned node went on reporting bytes it no longer had, under the one field
    /// an operator reads to check that pruning worked.
    ///
    /// This asserts both halves: the store's figure falls by exactly the file
    /// that was deleted, and the record sum does not move at all. The second is
    /// what makes the first worth having.
    #[test]
    fn pruning_a_block_file_reduces_the_reported_disk_size() -> anyhow::Result<()> {
        fn seed_file_height<S: KvStore>(store: &S, height: u32) -> anyhow::Result<()> {
            let mut batch = store.new_batch();
            batch.put(
                bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::block_file_max_height_key(0),
                &bitcoin_rs_storage::encode_block_file_max_height(height),
            );
            store.write(batch)?;
            Ok(())
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;

        std::fs::create_dir_all(&config.data_dir)?;

        // Two files present before the store opens, so the earlier one is not
        // the append target and is therefore prunable. Same shape as
        // `prune_reclaims_whole_files_and_keeps_current_file`, but with bytes in
        // it, because bytes are what is being counted.
        let blocks_dir = config.data_dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir)?;
        let prunable_file = blocks_dir.join("blk00000.dat");
        let prunable_bytes = vec![7_u8; 4_096];
        std::fs::write(&prunable_file, &prunable_bytes)?;
        std::fs::write(blocks_dir.join("blk00001.dat"), [])?;

        let state = NodeState::open(config, None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
        let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        // The hash is not needed: this test counts bytes in files, not bodies.
        let record = BlockRecord::from_block(10, &block);
        let record_sum_before = u64::try_from(record.body_size)?;
        state.blocks.write().push(record);

        let Some(before) = state.block_body_store.disk_usage() else {
            anyhow::bail!("a flat-file store must report its usage");
        };
        assert!(
            before >= u64::try_from(prunable_bytes.len())?,
            "the fixture's bytes must be accounted for"
        );

        // Tell the pruner that file 0 tops out at height 10, so pruning to 11
        // makes it prunable.
        match &state.storage {
            #[cfg(feature = "rocksdb")]
            NodeStorage::RocksDb(store) => seed_file_height(&**store, 10)?,
            #[cfg(feature = "fjall")]
            NodeStorage::Fjall(store) => seed_file_height(&**store, 10)?,
            #[cfg(feature = "redb")]
            NodeStorage::Redb(store) => seed_file_height(&**store, 10)?,
            #[cfg(feature = "mdbx")]
            NodeStorage::Mdbx(store) => seed_file_height(&**store, 10)?,
        }

        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        service
            .prune_to_height(11)
            .map_err(|error| anyhow::anyhow!("prune failed: {error}"))?;

        assert!(!prunable_file.exists(), "the fixture must actually prune");
        let Some(after) = state.block_body_store.disk_usage() else {
            anyhow::bail!("a flat-file store must report its usage");
        };
        assert_eq!(
            after,
            before.saturating_sub(u64::try_from(prunable_bytes.len())?),
            "the reported size must fall by exactly the file that was deleted"
        );

        // The number this replaces, unmoved — which is the defect.
        let record_sum_after = state.blocks.read().iter().fold(0_u64, |total, entry| {
            total.saturating_add(u64::try_from(entry.body_size).unwrap_or(0))
        });
        assert_eq!(
            record_sum_after, record_sum_before,
            "the block-record sum cannot see pruning, which is why it is not \
             what size_on_disk reports"
        );
        Ok(())
    }

    #[test]
    fn manual_prune_removes_pruned_block_transactions_from_cache() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config, None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);

        let pruned_block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let pruned_hash = Hash256::from_le_bytes(pruned_block.block_hash().as_bytes());
        state.block_body_store.persist_block_body(
            10,
            pruned_hash,
            &consensus_bytes(&pruned_block),
        )?;
        state
            .apply_handles()
            .undo_store
            .persist_undo(10, pruned_hash, b"undo-body")?;
        state
            .blocks
            .write()
            .push(BlockRecord::from_block(10, &pruned_block));

        let pruned_tx = pruned_block.txs[0].clone();
        let pruned_txid = pruned_tx.txid();
        let unrelated_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let unrelated_txid = unrelated_tx.txid();

        {
            let mut transactions = state.transactions.write();
            transactions.insert(pruned_txid, pruned_tx);
            transactions.insert(unrelated_txid, unrelated_tx);
        }

        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        service
            .prune_to_height(11)
            .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

        let transactions = state.transactions.read();
        assert!(!transactions.contains_key(&pruned_txid));
        assert!(transactions.contains_key(&unrelated_txid));
        Ok(())
    }

    #[test]
    fn prune_service_restores_persisted_pruneheight_on_reopen() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;

        {
            let state = NodeState::open(config.clone(), None)?;
            publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
            let Some(service) = state.prune_service() else {
                anyhow::bail!("prune service should exist when prune_target_mb > 0");
            };
            let result = service
                .prune_to_height(11)
                .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
            assert_eq!(result.pruneheight, 11);
        }

        let reopened = NodeState::open(config, None)?;
        let Some(service) = reopened.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        assert_eq!(service.status().pruneheight, Some(11));

        Ok(())
    }

    #[test]
    fn prune_waits_for_chain_transition_and_revalidates_applied_tip() -> anyhow::Result<()> {
        use std::time::Duration;

        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config.clone(), None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };

        let handles = state.apply_handles();
        let transition = handles.chain_transition.lock();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let (done_while_locked, result) = std::thread::scope(|scope| -> anyhow::Result<_> {
            let service = Arc::clone(&service);
            let worker = scope.spawn(move || {
                let _ = started_tx.send(());
                let result = service.prune_to_height(11);
                let _ = done_tx.send(());
                result
            });
            started_rx.recv_timeout(Duration::from_secs(5))?;
            let done_while_locked = done_rx.recv_timeout(Duration::from_millis(100));
            publish_applied_tip_height(&state, 10 + CORE_REORG_SAFETY_MARGIN);
            drop(transition);
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!("prune worker panicked"))?;
            Ok((done_while_locked, result))
        })?;
        let status_after = service.status();
        drop(service);
        drop(handles);
        drop(state);
        let reopened = NodeState::open(config, None)?;
        let Some(reopened_service) = reopened.prune_service() else {
            anyhow::bail!("prune service should exist after reopen");
        };

        assert!(
            matches!(
                done_while_locked,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "pruning entered while another chain transition held authority"
        );
        assert!(
            matches!(
                &result,
                Err(PruneServiceError::Failed(message))
                    if message == "prune height is within reorg safety margin"
            ),
            "pruning did not reject the tip observed under authority: {result:?}"
        );
        assert_eq!(status_after.pruneheight, None);
        assert_eq!(reopened_service.status().pruneheight, None);
        Ok(())
    }

    #[test]
    fn prune_refuses_after_apply_admission_closes() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config, None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };

        state.apply_handles.admission.close_permanently();
        let result = service.prune_to_height(11);

        assert!(
            matches!(
                &result,
                Err(PruneServiceError::Failed(message))
                    if message == "block apply rejected because clean shutdown has begun"
            ),
            "pruning ignored closed chain-mutation admission: {result:?}"
        );
        assert_eq!(service.status().pruneheight, None);
        Ok(())
    }

    /// Overlapping prune calls must commit in acquisition order.
    ///
    /// A lower request blocks inside body-store load while holding
    /// `pruneheight`; a higher contender must neither enter that load nor
    /// finish until the lower call releases, and both persisted and in-memory
    /// pruneheight end at the higher value.
    #[cfg(feature = "fjall")]
    #[allow(clippy::too_many_lines)]
    #[test]
    fn prune_to_height_serializes_overlapping_calls() -> anyhow::Result<()> {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;
        use std::time::Duration;

        struct BlockingPruneBodyStore {
            entered: Barrier,
            release: Barrier,
            block_once: AtomicBool,
            loads: AtomicUsize,
        }

        impl crate::apply::PruneBodyStore for BlockingPruneBodyStore {
            fn load_block_body(
                &self,
                _height: u32,
                _hash: bitcoin_rs_primitives::Hash256,
            ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
                self.loads.fetch_add(1, Ordering::AcqRel);
                if self.block_once.swap(false, Ordering::AcqRel) {
                    self.entered.wait();
                    self.release.wait();
                }
                Ok(None)
            }

            fn persist_block_body(
                &self,
                _height: u32,
                _hash: bitcoin_rs_primitives::Hash256,
                _body: &[u8],
            ) -> Result<(), bitcoin_rs_storage::StorageError> {
                Ok(())
            }

            fn sync(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir()?;
        let mut authority_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        authority_config.data_dir = dir.path().join("authority");
        authority_config.p2p_listen.clear();
        let authority_state = NodeState::open(authority_config, None)?;
        publish_applied_tip_height(&authority_state, 12 + CORE_REORG_SAFETY_MARGIN);
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(data_dir.join("chainstate"))?;
        let store = Arc::new(bitcoin_rs_storage::FjallStore::open(
            data_dir.join("chainstate"),
        )?);
        let block_files = Arc::new(FlatFileBlockStore::open(&data_dir)?);
        let body_store = Arc::new(BlockingPruneBodyStore {
            entered: Barrier::new(2),
            release: Barrier::new(2),
            block_once: AtomicBool::new(true),
            loads: AtomicUsize::new(0),
        });
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = body_store.clone();
        let blocks = Arc::new(RwLock::new(BlockLog::new()));
        let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[10_u8; 32]);
        blocks.write().push(BlockRecord {
            hash: BlockHash::from(hash),
            height: 10,
            body_size: 1,
            header: None,
            tx_count: 1,
            time: 0,
        });
        let service = Arc::new(NodePruneService::new(
            Arc::clone(&store),
            block_files,
            body_handle,
            Arc::clone(&blocks),
            Arc::new(RwLock::new(HashMap::new())),
            authority_state.apply_handles().prune_authority(),
            Arc::new(AtomicU32::new(11 + CORE_REORG_SAFETY_MARGIN)),
        )?);

        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| -> anyhow::Result<()> {
            let lower_service = Arc::clone(&service);
            let lower = scope.spawn(move || lower_service.prune_to_height(11));
            body_store.entered.wait();

            let higher_service = Arc::clone(&service);
            let higher = scope.spawn(move || {
                let _ = started_tx.send(());
                let result = higher_service.prune_to_height(12);
                let _ = done_tx.send(());
                result
            });
            let higher_started = started_rx.recv_timeout(Duration::from_secs(5));
            let higher_done = done_rx.recv_timeout(Duration::from_millis(100));
            let loads_while_lower_blocked = body_store.loads.load(Ordering::Acquire);
            body_store.release.wait();
            let lower_join = lower.join();
            let higher_join = higher.join();
            higher_started
                .map_err(|error| anyhow::anyhow!("higher prune did not start: {error}"))?;
            let lower_result = lower_join
                .map_err(|_| anyhow::anyhow!("lower prune panicked"))?
                .map_err(|err| anyhow::anyhow!("lower prune failed: {err}"))?;
            let higher_result = higher_join
                .map_err(|_| anyhow::anyhow!("higher prune panicked"))?
                .map_err(|err| anyhow::anyhow!("higher prune failed: {err}"))?;
            assert!(
                matches!(higher_done, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
                "higher prune committed while lower still held the pruneheight lock; done_rx={higher_done:?}"
            );
            assert_eq!(
                loads_while_lower_blocked, 1,
                "higher prune must not enter body-store load while lower holds pruneheight; loads={loads_while_lower_blocked}"
            );
            assert_eq!(lower_result.pruneheight, 11);
            assert_eq!(higher_result.pruneheight, 12);
            Ok(())
        })?;

        assert_eq!(service.status().pruneheight, Some(12));
        assert_eq!(load_pruneheight(&*store)?, Some(12));
        Ok(())
    }

    #[test]
    fn clean_checkpoint_reopens_and_applies_the_next_block() -> anyhow::Result<()> {
        fn stable_hash(
            view: &bitcoin_rs_utxo::UtxoSetView<'_>,
        ) -> Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_utxo::UtxoError> {
            view.hash_serialized_3()
        }
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let genesis_tip = state.apply_block(&genesis)?;
        let expected_utxo_hash = state.utxo().with_stable_view(stable_hash)?;
        let expected_stats = state.coin_stats().snapshot();
        assert!(matches!(
            state.write_clean_checkpoint()?,
            crate::checkpoint::CheckpointWrite::Published { .. }
        ));
        drop(state);

        let mut reopen_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        reopen_config.data_dir = data_dir.clone();
        reopen_config.p2p_listen.clear();
        let resumed = NodeState::open(reopen_config.clone(), None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        let applied = resumed
            .applied_tip()
            .load_full()
            .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
        assert_eq!(applied.height, genesis_tip.height);
        assert_eq!(applied.hash, genesis_tip.hash);
        assert_eq!(
            resumed.chain_tip().load_full().as_deref(),
            Some(applied.as_ref())
        );
        assert_eq!(
            resumed.utxo().with_stable_view(stable_hash)?,
            expected_utxo_hash
        );
        assert_eq!(resumed.coin_stats().snapshot(), expected_stats);
        assert!(resumed.blocks().read().is_empty());
        assert!(resumed.transactions().read().is_empty());
        assert!(resumed.mempool().read().is_empty());

        let next = mined_regtest_child(genesis.block_hash())?;
        let next_tip = resumed.apply_block(&next)?;
        assert_eq!(next_tip.height, 1);
        assert_eq!(
            next_tip.hash.to_le_bytes(),
            next.block_hash().0.to_le_bytes()
        );
        let listener_after_apply = resumed.coin_stats().snapshot();
        let mut rescanned = resumed.utxo().with_stable_view(|view| {
            bitcoin_rs_utxo::stats::scan_coin_stats(view, next_tip.height, true)
        })?;
        rescanned.tx_count = listener_after_apply.tx_count;
        assert_eq!(
            listener_after_apply.total_amount, rescanned.total_amount,
            "checkpoint resume must keep rolling CoinStats attached to UTXO commits"
        );
        resumed.write_clean_checkpoint()?;

        let root = data_dir.join("chainstate-checkpoints");
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
        let directory = current
            .get("directory")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
        let snapshot_file = std::fs::File::open(root.join(directory).join("utxo-v4.dat"))?;
        let mut snapshot_reader = std::io::BufReader::new(snapshot_file);
        let snapshot = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut snapshot_reader)?;
        assert_ne!(snapshot.muhash_trailer, [0_u8; 384]);
        assert_eq!(snapshot.muhash_trailer, rescanned.muhash.finalize());
        drop(resumed);

        let resumed_again = NodeState::open(reopen_config, None)?;
        assert_eq!(resumed_again.resume_source(), ResumeSource::Checkpoint);
        assert_eq!(resumed_again.coin_stats().snapshot(), rescanned);
        Ok(())
    }

    #[test]
    fn clean_checkpoint_lifecycle_is_backend_neutral() -> anyhow::Result<()> {
        let backends = vec![
            #[cfg(feature = "fjall")]
            "fjall",
            #[cfg(feature = "rocksdb")]
            "rocksdb",
            #[cfg(feature = "redb")]
            "redb",
            #[cfg(feature = "mdbx")]
            "mdbx",
        ];

        for backend in backends {
            let dir = tempfile::tempdir()?;
            let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join(backend);
            config.storage_backend = backend.to_owned();
            config.p2p_listen.clear();
            let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
            state.write_clean_checkpoint()?;
            drop(state);

            let resumed = NodeState::open(config, None)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            resumed.apply_block(&mined_regtest_child(genesis.block_hash())?)?;
        }
        Ok(())
    }

    #[test]
    fn rolling_coinstats_resume_continues_through_next_block() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node-g2");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        state.apply_block(&genesis)?;
        let before = state.coin_stats().snapshot();
        state.write_clean_checkpoint()?;
        drop(state);

        let mut reopen_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        reopen_config.data_dir = data_dir;
        reopen_config.p2p_listen.clear();
        let resumed = NodeState::open(reopen_config, None)?;
        assert_eq!(resumed.coin_stats().snapshot(), before);
        resumed.apply_block(&mined_regtest_child(genesis.block_hash())?)?;
        let rolling = resumed.coin_stats().snapshot();
        let mut scanned = resumed.utxo().with_stable_view(|view| {
            bitcoin_rs_utxo::stats::scan_coin_stats(view, rolling.height, true)
        })?;
        scanned.tx_count = rolling.tx_count;
        // The listener is attached only after checkpoint/journal restoration,
        // then tracks subsequent live UTXO mutations without double-counting
        // the restored snapshot.
        assert_eq!(
            rolling.total_amount, scanned.total_amount,
            "restored state must receive subsequent rolling UTXO notifications"
        );
        Ok(())
    }

    #[test]
    fn journal_replay_restores_state_above_checkpoint() -> anyhow::Result<()> {
        fn stable_hash(
            view: &bitcoin_rs_utxo::UtxoSetView<'_>,
        ) -> Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_utxo::UtxoError> {
            view.hash_serialized_3()
        }

        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("journal-resume");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir;
        config.p2p_listen.clear();
        config.chainstate_journal.blocks = 1;

        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let first = NodeState::open(config.clone(), None)?;
        first.apply_block(&genesis)?;
        first.write_clean_checkpoint()?;
        drop(first);

        // The first reopen discards the pre-checkpoint journal generation and
        // initializes one whose authenticated base is the published checkpoint.
        let base = NodeState::open(config.clone(), None)?;
        assert_eq!(base.resume_source(), ResumeSource::Checkpoint);
        let child = mined_regtest_child(genesis.block_hash())?;
        let expected_tip = base.apply_block(&child)?;
        let expected_utxo = base.utxo().with_stable_view(stable_hash)?;
        let expected_stats = base.coin_stats().snapshot();
        let expected_tx_count = base.chain_tx_count_handle().load(Ordering::Relaxed);
        drop(base);

        let resumed = NodeState::open(config, None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Journal);
        let resumed_tip = resumed
            .applied_tip()
            .load_full()
            .ok_or_else(|| std::io::Error::other("journal replay did not publish a tip"))?;
        assert_eq!(resumed_tip.as_ref(), &expected_tip);
        assert_eq!(resumed.utxo().with_stable_view(stable_hash)?, expected_utxo);
        assert_eq!(resumed.coin_stats().snapshot(), expected_stats);
        assert_eq!(
            resumed.chain_tx_count_handle().load(Ordering::Relaxed),
            expected_tx_count
        );
        Ok(())
    }

    #[test]
    fn shutdown_arc_is_shared_with_apply_handles() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        assert!(Arc::ptr_eq(
            &state.shutdown(),
            &state.apply_handles().shutdown
        ));
        Ok(())
    }

    #[test]
    fn checkpoint_refuses_inflight_disconnect_and_preserves_state() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        state.apply_block(&genesis)?;
        assert!(matches!(
            state.write_clean_checkpoint()?,
            crate::checkpoint::CheckpointWrite::Published { .. }
        ));

        let checkpoint_root = data_dir.join("chainstate-checkpoints");
        let armed_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xab; 32]);
        let armed_height = 10;
        state
            .apply_handles()
            .undo_store
            .arm_disconnect(armed_height, armed_hash)?;
        let marker_before = state.apply_handles().undo_store.load_disconnect_marker()?;
        let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
        let mut dirs_before = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&checkpoint_root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs_before.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }

        let result = state.write_clean_checkpoint();
        let Err(crate::checkpoint::CheckpointError::DisconnectInFlight { hash, height }) = result
        else {
            anyhow::bail!("expected DisconnectInFlight refusal, got {result:?}");
        };
        assert_eq!(hash, armed_hash);
        assert_eq!(height, armed_height);

        let marker_after = state.apply_handles().undo_store.load_disconnect_marker()?;
        let current_after = std::fs::read(checkpoint_root.join("CURRENT"))?;
        let mut dirs_after = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(&checkpoint_root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs_after.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }

        assert_eq!(marker_before, marker_after);
        assert_eq!(current_before, current_after);
        assert_eq!(dirs_before, dirs_after);
        Ok(())
    }

    #[test]
    fn torn_disconnect_refusal_names_authoritative_stores_to_remove() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config.clone(), None)?;
        state.apply_handles().undo_store.arm_disconnect(
            10,
            bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xcd; 32]),
        )?;
        drop(state);

        let error = match NodeState::open(config, None) {
            Ok(_) => anyhow::bail!("node reopened with an armed disconnect marker"),
            Err(error) => error,
        };
        let message = error.to_string();
        for store in ["chainstate", "chainstate-checkpoints", "txindex"] {
            let path = data_dir.join(store);
            assert!(
                message.contains(&path.display().to_string()),
                "startup refusal omitted {}: {message}",
                path.display()
            );
        }
        Ok(())
    }

    #[test]
    fn publish_checkpoint_refuses_when_no_applied_tip() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config, None)?;
        let Err(error) = state.publish_checkpoint() else {
            anyhow::bail!("checkpoint publication succeeded without an applied tip");
        };
        assert!(
            error.to_string().contains("no applied tip"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn publish_checkpoint_returns_generation_and_reopens() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir;
        config.p2p_listen.clear();
        let state = NodeState::open(config.clone(), None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let tip = state.apply_block(&genesis)?;
        let generation = state.publish_checkpoint()?;
        assert!(
            generation > 0,
            "published checkpoint must have a positive generation"
        );
        drop(state);

        let resumed = NodeState::open(config, None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        let applied = resumed
            .applied_tip()
            .load_full()
            .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
        assert_eq!(applied.height, tip.height);
        assert_eq!(applied.hash, tip.hash);
        Ok(())
    }

    #[test]
    fn process_epoch_is_strictly_monotonic_across_restart() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();

        let first = NodeState::open(config.clone(), None)?
            .active_chain_snapshot()
            .epoch;
        let second = NodeState::open(config.clone(), None)?
            .active_chain_snapshot()
            .epoch;
        let third = NodeState::open(config, None)?.active_chain_snapshot().epoch;
        assert!(first > 0, "a fresh data dir allocates epoch 1, got {first}");
        assert!(
            second > first,
            "restart must never reuse an epoch: {first} -> {second}"
        );
        assert!(
            third > second,
            "restart must never reuse an epoch: {second} -> {third}"
        );
        Ok(())
    }

    #[test]
    fn active_chain_snapshot_starts_at_genesis_on_fresh_node() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();

        let state = NodeState::open(config.clone(), None)?;
        let epoch = state.chain_event_publisher().epoch();
        assert_eq!(
            state.active_chain_snapshot(),
            ChainSnapshot {
                epoch,
                sequence: 0,
                tip_hash: config.network.genesis_block_hash(),
                tip_height: 0,
            },
            "a node that committed nothing anchors at genesis with sequence 0"
        );
        Ok(())
    }

    #[test]
    fn active_chain_snapshot_anchors_at_restored_tip_after_restart() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();

        let (tip, first_epoch) = {
            let state = NodeState::open(config.clone(), None)?;
            let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
            let tip = state.apply_block(&genesis)?;
            assert!(matches!(
                state.write_clean_checkpoint()?,
                crate::checkpoint::CheckpointWrite::Published { .. }
            ));
            (tip, state.active_chain_snapshot().epoch)
        };

        let resumed = NodeState::open(config, None)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        let snapshot = resumed.active_chain_snapshot();
        assert_eq!(snapshot.tip_hash, tip.hash);
        assert_eq!(snapshot.tip_height, tip.height);
        assert_eq!(
            snapshot.sequence, 0,
            "a restart resets the sequence, never the epoch"
        );
        assert!(
            snapshot.epoch > first_epoch,
            "restart must advance the epoch: {} -> {}",
            first_epoch,
            snapshot.epoch
        );
        Ok(())
    }

    #[test]
    fn record_publishes_snapshot_and_hints_in_commit_order() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();

        let state = NodeState::open(config, None)?;
        let publisher = state.chain_event_publisher();
        let epoch = publisher.epoch();
        let hash_a = Hash256::from_le_bytes(&[0xAA; 32]);
        let hash_b = Hash256::from_le_bytes(&[0xBB; 32]);

        let first = publisher.record(HintKind::Connected, 1, hash_a);
        let second = publisher.record(HintKind::Disconnected, 0, hash_b);

        let expected_first = ChainEventHint {
            kind: HintKind::Connected,
            height: 1,
            hash: hash_a,
            epoch,
            sequence: 1,
        };
        let expected_second = ChainEventHint {
            kind: HintKind::Disconnected,
            height: 0,
            hash: hash_b,
            epoch,
            sequence: 2,
        };
        assert_eq!(first, expected_first);
        assert_eq!(second, expected_second);
        assert_eq!(
            publisher.snapshot(),
            state.active_chain_snapshot(),
            "node and publisher expose one snapshot view"
        );
        assert_eq!(
            state.active_chain_snapshot(),
            ChainSnapshot {
                epoch,
                sequence: 2,
                tip_hash: hash_b,
                tip_height: 0,
            },
            "the last committed event wins the snapshot cell"
        );

        let rx = state.chain_event_hints();
        let mut hints = Vec::new();
        let hint_rx = rx.lock();
        while let Ok(hint) = hint_rx.try_recv() {
            hints.push(hint);
        }
        assert_eq!(
            hints,
            vec![expected_first, expected_second],
            "one hint per committed event, in commit order"
        );
        Ok(())
    }

    #[test]
    fn record_drops_hints_when_channel_full() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();

        let state = NodeState::open(config, None)?;
        let publisher = state.chain_event_publisher();
        let rx = state.chain_event_hints();
        for sequence in 1..=super::CHAIN_HINT_CHANNEL_LIMIT {
            let sequence = u64::try_from(sequence)?;
            let mut tip = [0_u8; 32];
            tip[..8].copy_from_slice(&sequence.to_le_bytes());
            publisher.record(
                HintKind::Connected,
                u32::try_from(sequence)?,
                Hash256::from_le_bytes(&tip),
            );
        }

        // The next record finds a full channel: the hint is dropped by
        // design, while the commit itself still lands and the snapshot
        // still advances. Dropping never blocks or fails the commit path.
        let overflow = publisher.record(
            HintKind::Connected,
            u32::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)?,
            Hash256::from_le_bytes(&[0xFF; 32]),
        );
        assert_eq!(
            overflow.sequence,
            u64::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)? + 1,
            "the record itself is sequenced even when its hint is dropped"
        );
        assert_eq!(
            state.active_chain_snapshot(),
            ChainSnapshot {
                epoch: publisher.epoch(),
                sequence: overflow.sequence,
                tip_hash: Hash256::from_le_bytes(&[0xFF; 32]),
                tip_height: u32::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)?,
            },
        );

        let mut drained = Vec::new();
        let drain_rx = rx.lock();
        while let Ok(hint) = drain_rx.try_recv() {
            drained.push(hint.sequence);
        }
        assert_eq!(
            drained.len(),
            super::CHAIN_HINT_CHANNEL_LIMIT,
            "exactly the bounded hints are queued"
        );
        assert_eq!(drained[0], 1, "the oldest hint survives at the front");
        assert_eq!(
            drained.last().copied(),
            Some(u64::try_from(super::CHAIN_HINT_CHANNEL_LIMIT)?),
            "the overflow hint is the one that was dropped"
        );
        Ok(())
    }

    #[test]
    fn corrupt_process_epoch_file_refuses_start() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(&data_dir)?;
        std::fs::write(data_dir.join("process-epoch"), b"seven\n")?;

        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir;
        config.p2p_listen.clear();

        let Err(error) = NodeState::open(config, None) else {
            anyhow::bail!("a corrupt process-epoch file must refuse startup");
        };
        assert!(
            error.to_string().contains("process-epoch"),
            "the refusal names the corrupt file: {error}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("node").join("process-epoch"))?,
            b"seven\n",
            "the refusal must not reset the persisted epoch"
        );
        Ok(())
    }

    #[test]
    fn process_epoch_allocation_is_unique_across_processes() -> anyhow::Result<()> {
        const CHILD_DIR_ENV: &str = "BITCOIN_RS_TEST_EPOCH_CHILD_DIR";
        const CHILDREN: usize = 8;
        // Subprocess mode: this same test binary was re-exec'd by the parent
        // below. Park on the start barrier, then allocate one epoch.
        if let Ok(data_dir) = std::env::var(CHILD_DIR_ENV) {
            let data_dir = std::path::PathBuf::from(data_dir);
            let dir = cap_std::fs::Dir::open_ambient_dir(&data_dir, cap_std::ambient_authority())?;
            std::fs::write(data_dir.join(format!("ready-{}", std::process::id())), b"")?;
            let go = data_dir.join("go");
            let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
            while !go.exists() {
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!("epoch child never saw the start barrier");
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let epoch = super::allocate_process_epoch(&dir)?;
            std::fs::write(
                data_dir.join(format!("epoch-{}", std::process::id())),
                format!("{epoch}\n"),
            )?;
            std::process::exit(0);
        }

        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(&data_dir)?;

        // Harness test names are crate-relative; `module_path!()` is not.
        let test_name = concat!(
            module_path!(),
            "::process_epoch_allocation_is_unique_across_processes"
        )
        .split("::")
        .skip(1)
        .collect::<Vec<_>>()
        .join("::");
        let exe = std::env::current_exe()?;
        let mut children = Vec::new();
        for _ in 0..CHILDREN {
            children.push(
                std::process::Command::new(&exe)
                    .args(["--exact", &test_name])
                    .env(CHILD_DIR_ENV, &data_dir)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?,
            );
        }

        // Every child must be alive and parked before any allocates, so all
        // eight genuinely contend for the same lock file on one data dir.
        let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
        loop {
            let ready = std::fs::read_dir(&data_dir)?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
                .count();
            if ready == CHILDREN {
                break;
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("epoch children never became ready: {ready}/{CHILDREN}");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        std::fs::write(data_dir.join("go"), b"")?;

        let mut epochs = Vec::new();
        for child in children {
            let output = child.wait_with_output()?;
            anyhow::ensure!(
                output.status.success(),
                "epoch child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        for entry in std::fs::read_dir(&data_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("epoch-") {
                let text = std::fs::read_to_string(entry.path())?;
                epochs.push(text.trim().parse::<u64>()?);
            }
        }
        epochs.sort_unstable();
        assert_eq!(
            epochs.len(),
            CHILDREN,
            "each child reports exactly one epoch"
        );
        for (index, epoch) in epochs.iter().enumerate() {
            assert_eq!(
                *epoch,
                u64::try_from(index)? + 1,
                "concurrent children must each own one distinct epoch: {epochs:?}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(data_dir.join("process-epoch"))?,
            format!("{}\n", epochs[CHILDREN - 1]),
            "the persisted file must name the highest allocated epoch"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_epoch_lock_refuses_start() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(&data_dir)?;
        std::fs::write(data_dir.join("process-epoch"), b"41\n")?;
        std::os::unix::fs::symlink("process-epoch", data_dir.join(".process-epoch.lock"))?;

        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();

        let Err(error) = NodeState::open(config, None) else {
            anyhow::bail!("a symlinked epoch lock must refuse startup");
        };
        assert!(
            error.to_string().contains("process epoch lock"),
            "the refusal names the lock target: {error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(data_dir.join("process-epoch"))?,
            "41\n",
            "the symlink must not be followed and the epoch must not reset"
        );
        Ok(())
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn non_regular_epoch_lock_refuses_start() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(&data_dir)?;
        std::fs::write(data_dir.join("process-epoch"), b"7\n")?;
        let lock_dir = cap_std::fs::Dir::open_ambient_dir(&data_dir, cap_std::ambient_authority())?;
        rustix::fs::mkfifoat(
            &lock_dir,
            ".process-epoch.lock",
            rustix::fs::Mode::from_raw_mode(0o600),
        )?;

        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();

        let Err(error) = NodeState::open(config, None) else {
            anyhow::bail!("a non-regular epoch lock must refuse startup");
        };
        assert!(
            error.to_string().contains("not a regular file"),
            "the refusal names the lock type: {error:#}"
        );
        assert_eq!(
            std::fs::read_to_string(data_dir.join("process-epoch"))?,
            "7\n",
            "the refusal must not reset the persisted epoch"
        );
        Ok(())
    }

    fn mined_regtest_child(prev_blockhash: BlockHash) -> anyhow::Result<Block> {
        let coinbase = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![1, 1],
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
        };
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time: 1_296_688_603,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = merkle_root(&block.txs)
            .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
        while !pow_met(block.header.bits, block.block_hash().0) {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
        }
        Ok(block)
    }

    /// Pairwise double-SHA256 fold over little-endian txid bytes, duplicating
    /// the last leaf on odd levels (the native stand-in for
    /// `compute_merkle_root`).
    fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
        let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        if leaves.is_empty() {
            return None;
        }
        while leaves.len() > 1 {
            let original_len = leaves.len();
            let mut next = Vec::with_capacity(original_len.div_ceil(2));
            for pos in 0..original_len.div_ceil(2) {
                let left = leaves[2 * pos];
                let right = leaves[(2 * pos + 1).min(original_len - 1)];
                let mut pair = [0_u8; 64];
                pair[..32].copy_from_slice(&left);
                pair[32..].copy_from_slice(&right);
                next.push(double_sha256(&pair).to_le_bytes());
            }
            leaves = next;
        }
        Some(Hash256::from_le_bytes(&leaves[0]))
    }

    /// Regtest-easy compact-target `PoW` check over the hash as a 256-bit
    /// little-endian integer (mirrors `chain::pow::compact_is_met_by` for the
    /// >3-exponent, 3-byte-mantissa forms these fixtures mine).
    fn pow_met(bits: u32, hash: Hash256) -> bool {
        let exponent = u8::try_from(bits >> 24).unwrap_or(0);
        let mantissa = bits & 0x007f_ffff;
        if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
            return false;
        }
        let bytes = hash.as_byte_array();
        let low = usize::from(exponent - 3);
        let window = u32::from(bytes[low])
            | u32::from(bytes[low + 1]) << 8
            | u32::from(bytes[low + 2]) << 16;
        window <= mantissa && bytes[usize::from(exponent)..].iter().all(|&byte| byte == 0)
    }

    // -----------------------------------------------------------------------
    // A2 cycle 3: witness is published only after CURRENT root fsync
    // -----------------------------------------------------------------------

    #[test]
    fn witness_is_published_only_after_current_root_sync() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();

        let state = NodeState::open(config.clone(), None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        let tip = state.apply_block(&genesis)?;

        // Publish a checkpoint — witness must be written after Published.
        state.publish_checkpoint()?;
        let witness_path = data_dir.join("applied-tip-witness.json");
        assert!(
            witness_path.exists(),
            "witness file must exist after checkpoint publication"
        );
        let genesis_hex = config.network.genesis_block_hash().to_string_be();
        let witness = crate::recovery_evidence::read_witness(&data_dir, &genesis_hex)
            .ok_or_else(|| anyhow::anyhow!("witness must be readable"))?;
        assert_eq!(witness.height, tip.height);
        assert_eq!(witness.block_hash, tip.hash.to_string_be());
        drop(state);

        // Now inject a failpoint at CurrentRootSync — the last stage before
        // the checkpoint is considered Published. The checkpoint must fail,
        // and no new witness must be written for the failed checkpoint.
        let dir2 = tempfile::tempdir()?;
        let data_dir2 = dir2.path().join("node");
        let mut config2 = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config2.data_dir = data_dir2.clone();
        config2.p2p_listen.clear();

        let state2 = NodeState::open(config2.clone(), None)?;
        let genesis2 = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        state2.apply_block(&genesis2)?;

        // Inject failpoint at the final root fsync — checkpoint fails before
        // returning Published, so no witness should be written.
        crate::checkpoint::inject_next_checkpoint_failpoint(
            crate::checkpoint::CheckpointFailpoint::CurrentRootSync,
        );
        let result = state2.publish_checkpoint();
        assert!(
            result.is_err(),
            "checkpoint must fail when CurrentRootSync fails"
        );
        let witness_path2 = data_dir2.join("applied-tip-witness.json");
        assert!(
            !witness_path2.exists(),
            "no witness must be written when checkpoint fails before publication"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #208: a checkpoint restore far behind the durable witness must be loud
    // -----------------------------------------------------------------------

    #[test]
    fn stale_checkpoint_restore_surfaces_warning_not_silence() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node");
        let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        config.script_index = crate::config::ScriptIndexMode::Disabled;

        // Apply genesis and publish a checkpoint at height 0.
        let state = NodeState::open(config.clone(), None)?;
        let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
        state.apply_block(&genesis)?;
        state.write_clean_checkpoint()?;
        drop(state);

        // Simulate the #208 scenario: the node previously ran far ahead
        // (height 5000) and published a checkpoint there, writing a witness
        // at that height. A crash or clean stop left the checkpoint tree
        // pinned at height 0 while the witness records height 5000.
        let genesis_hex = config.network.genesis_block_hash().to_string_be();
        let stale_witness = crate::recovery_evidence::AppliedTipWitness::new(
            genesis_hex,
            1, // older epoch
            5000,
            "cccc",
            1000,
        );
        crate::recovery_evidence::write_witness(&data_dir, &stale_witness)?;

        // Reopen: the checkpoint at height 0 is restored, the witness at
        // 5000 triggers checkpoint-fallback detection. The warning store
        // must carry the fallback warning — the restore must not be silent.
        let resumed = NodeState::open(config.clone(), None)?;
        let warnings = resumed.warning_store().warnings();
        assert!(
            !warnings.is_empty(),
            "a stale checkpoint restore 5000 blocks behind the witness must \
             produce at least one rollback warning, not silence"
        );
        assert!(
            warnings.iter().any(|w| w.contains("height 5000")),
            "the warning must name the witness height; got: {warnings:?}"
        );
        assert_eq!(
            resumed.resume_source(),
            ResumeSource::Checkpoint,
            "the checkpoint is still accepted — it is valid, just stale"
        );
        Ok(())
    }
}
