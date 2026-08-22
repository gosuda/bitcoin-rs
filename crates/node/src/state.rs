//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`Config`], the
//! data-directory path, the open chainstate storage backend, and the replay log
//! used by [`crate::crash_recovery`]. Subsystem wiring (chain / utxo / mempool
//! / index / p2p / rpc / electrum) parks here as the integration point matures.

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hex::FromHex as _;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_rpc::{
    BlockBodyMetadata, BlockBodySource, BlockRecord, NetworkState, PruneResult, PruneService,
    PruneServiceError, PruneStatus, ZmqNotification,
};
use compact_str::CompactString;
use core::fmt;
use core::mem::size_of;
use crossbeam_channel::{Receiver, Sender};
use hashbrown::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_pruning::policy::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_pruning::{
    PrunePolicy, reclaim_staged_flat_block_files, stage_block_and_undo_prune,
};
use bitcoin_rs_storage::{ColumnFamily, FlatFileBlockStore, KvStore, WriteBatch};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::{Mutex, RwLock};

use crate::Config;

type FilterIndexHandle = Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>;

struct DisabledFilterIndex;

impl bitcoin_rs_filters::FilterIndexLike for DisabledFilterIndex {
    fn wants_filters(&self) -> bool {
        false
    }

    fn put_filter(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
        _prev_header: bitcoin_rs_primitives::Hash256,
        _filter_bytes: &[u8],
    ) -> std::result::Result<bitcoin_rs_primitives::Hash256, bitcoin_rs_filters::FilterIndexError>
    {
        Ok(bitcoin_rs_primitives::Hash256::default())
    }

    fn filter_header(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
    ) -> std::result::Result<
        Option<bitcoin_rs_primitives::Hash256>,
        bitcoin_rs_filters::FilterIndexError,
    > {
        Ok(None)
    }
}

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
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: bitcoin_rs_primitives::Hash256,
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
    /// Reading a BIP157 filter header failed.
    ///
    /// A broken backend, not a missing row: an absent header is answered by
    /// skipping the filter write, which keeps the chain moving.
    #[error("filter header lookup: {0}")]
    FilterHeaderLookup(#[source] bitcoin_rs_filters::FilterIndexError),
    /// Rewinding the block-level coinstats failed.
    ///
    /// The per-coin fields ride the UTXO change listener and are already
    /// reversed by the undo; only height and transaction count are set
    /// directly, and a refusal here means they do not describe the block being
    /// disconnected.
    #[error("coinstats rewind: {0}")]
    CoinStatsRewind(#[source] bitcoin_rs_coinstats::CoinStatsRewindError),
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
    fn open(config: &Config) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Ok(Self::RocksDb(Arc::new(
                bitcoin_rs_storage::RocksDbStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "fjall")]
            "fjall" => Ok(Self::Fjall(Arc::new(
                bitcoin_rs_storage::FjallStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "redb")]
            "redb" => Ok(Self::Redb(Arc::new(
                bitcoin_rs_storage::RedbStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            ))),
            #[cfg(feature = "mdbx")]
            "mdbx" => Ok(Self::Mdbx(Arc::new(
                bitcoin_rs_storage::MdbxStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
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
        }
    }

    fn prune_service(
        &self,
        block_files: &Arc<FlatFileBlockStore>,
        block_body_store: &Arc<dyn crate::apply::PruneBodyStore>,
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
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
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                Arc::clone(durable_tip_height),
            )?)),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(Arc::new(NodePruneService::new(
                Arc::clone(store),
                Arc::clone(block_files),
                Arc::clone(block_body_store),
                blocks,
                transactions,
                Arc::clone(durable_tip_height),
            )?)),
        }
    }

    fn block_body_store(
        &self,
        files: Arc<FlatFileBlockStore>,
        data_dir: &Path,
    ) -> Result<Arc<dyn crate::apply::PruneBodyStore>> {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
                data_dir,
            )?)),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
                data_dir,
            )?)),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
                data_dir,
            )?)),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(Arc::new(crate::apply::FlatFilePruneBodyStore::open(
                Arc::clone(store),
                files,
                data_dir,
            )?)),
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
        }
    }

    #[cfg(test)]
    fn stored_prune_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_pruning::block_body_key(height, hash);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(store.get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)?),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(store.get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)?),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(store.get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)?),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(store.get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)?),
        }
    }

    #[cfg(test)]
    fn stored_prune_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>> {
        let key = bitcoin_rs_pruning::block_undo_key(height, hash);
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(feature = "redb")]
            Self::Redb(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => Ok(store.get(ColumnFamily::UndoData, &key)?),
        }
    }
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
    fn block_body(&self, height: u32, hash: bitcoin_rs_primitives::Hash256) -> Option<Vec<u8>> {
        self.store.load_block_body(height, hash).ok().flatten()
    }

    fn block_body_range(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        offset: u32,
        len: u32,
    ) -> Option<Vec<u8>> {
        // `None` is overloaded here: it means both "this store cannot slice"
        // and "the read failed". Callers must treat either as a reason to fall
        // back to the whole body, so the return type stays — but this is the
        // hot path for every Electrum history call now, and an I/O error that
        // silently degrades into a full block scan is exactly the failure that
        // would otherwise show up only as unexplained latency.
        match self.store.load_block_body_range(height, hash, offset, len) {
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
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Option<BlockBodyMetadata> {
        self.store
            .block_body_metadata(height, hash)
            .ok()
            .flatten()
            .map(|(body_size, tx_count)| BlockBodyMetadata {
                body_size,
                tx_count,
            })
    }
}

const PRUNEHEIGHT_METADATA_KEY: &[u8] = b"node:pruneheight";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeSource {
    Cold,
    HeadersOnly,
    Checkpoint,
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
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
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
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
        durable_tip_height: Arc<AtomicU32>,
    ) -> Result<Self> {
        let pruneheight = load_pruneheight(&*store)?;
        Ok(Self {
            store,
            block_files,
            block_body_store,
            blocks,
            transactions,
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
        let mut blocks = self.blocks.write();
        let mut pruneheight = self.pruneheight.lock();
        let policy = PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: CORE_REORG_SAFETY_MARGIN,
        };
        let updated_pruneheight =
            pruneheight.map_or(requested_height, |height| height.max(requested_height));
        let pruner_tip = updated_pruneheight
            .checked_add(policy.retention_depth())
            .ok_or_else(|| PruneServiceError::failed("prune height overflow"))?;

        let mut pruned_txids = Vec::new();
        for record in blocks
            .iter()
            .filter(|record| record.height < updated_pruneheight)
        {
            if record.tx_count == 0 {
                continue;
            }
            let bytes = if record.block_hex.is_empty() {
                self.block_body_store
                    .load_block_body(record.height, record.hash)
                    .map_err(|error| PruneServiceError::failed(error.to_string()))?
                    .unwrap_or_default()
            } else {
                Vec::<u8>::from_hex(&record.block_hex).map_err(|error| {
                    PruneServiceError::failed(format!(
                        "cached block body at height {} is not valid hex: {error}",
                        record.height
                    ))
                })?
            };
            if bytes.is_empty() {
                continue;
            }
            let block = deserialize::<bitcoin::Block>(&bytes).map_err(|error| {
                PruneServiceError::failed(format!(
                    "cached block body at height {} failed decode: {error}",
                    record.height
                ))
            })?;
            pruned_txids.extend(block.txdata.iter().map(Transaction::compute_txid));
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

        for record in blocks.iter_mut() {
            if record.height < updated_pruneheight {
                record.block_hex = String::new();
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

struct OpenTxIndex {
    writer: Arc<dyn crate::txindex_worker::TxIndexWriter>,
    reader: Arc<dyn bitcoin_rs_index::IndexReader>,
    batch_limits: bitcoin_rs_index::PreparedBatchLimits,
}

fn open_writer<S>(
    store: &Arc<S>,
) -> Result<bitcoin_rs_index::IndexWriter<S>, bitcoin_rs_index::IndexError>
where
    S: bitcoin_rs_storage::KvStore,
{
    match bitcoin_rs_index::IndexWriter::open(Arc::clone(store)) {
        Ok(writer) => Ok(writer),
        Err(bitcoin_rs_index::IndexError::LegacyCursorlessIndex) => {
            bitcoin_rs_index::IndexWriter::reset_legacy(store.as_ref())?;
            bitcoin_rs_index::IndexWriter::open(Arc::clone(store))
        }
        Err(error) => Err(error),
    }
}

fn open_tx_index_store<S>(
    store: Arc<S>,
    batch_limits: bitcoin_rs_index::PreparedBatchLimits,
) -> Result<OpenTxIndex>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
{
    let writer = open_writer(&store)?;
    let writer: Arc<dyn crate::txindex_worker::TxIndexWriter> =
        Arc::new(parking_lot::Mutex::new(writer));
    let reader: Arc<dyn bitcoin_rs_index::IndexReader> =
        Arc::new(bitcoin_rs_index::Indexer::new(store));
    Ok(OpenTxIndex {
        writer,
        reader,
        batch_limits,
    })
}

fn open_tx_index(config: &Config) -> Result<Option<OpenTxIndex>> {
    if !config.txindex {
        return Ok(None);
    }
    if config.prune_target_mb > 0 {
        bail!("-txindex is not compatible with -prune");
    }

    let txindex_dir = config.data_dir.join("txindex");
    std::fs::create_dir_all(&txindex_dir)
        .with_context(|| format!("create txindex_dir {}", txindex_dir.display()))?;
    match config.storage_backend.as_str() {
        #[cfg(feature = "rocksdb")]
        "rocksdb" => {
            let store = Arc::new(
                bitcoin_rs_storage::RocksDbStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            Ok(Some(open_tx_index_store(
                store,
                crate::txindex_worker::ROCKSDB_BATCH_LIMITS,
            )?))
        }
        #[cfg(feature = "fjall")]
        "fjall" => {
            let store = Arc::new(
                bitcoin_rs_storage::FjallStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            Ok(Some(open_tx_index_store(
                store,
                crate::txindex_worker::DEFAULT_BATCH_LIMITS,
            )?))
        }
        #[cfg(feature = "redb")]
        "redb" => {
            let store = Arc::new(
                bitcoin_rs_storage::RedbTxIndexStore::open(&txindex_dir)
                    .map_err(anyhow::Error::new)?,
            );
            Ok(Some(open_tx_index_store(
                store,
                crate::txindex_worker::REDB_BATCH_LIMITS,
            )?))
        }
        #[cfg(feature = "mdbx")]
        "mdbx" => {
            let store = Arc::new(
                bitcoin_rs_storage::MdbxStore::open(&txindex_dir).map_err(anyhow::Error::new)?,
            );
            Ok(Some(open_tx_index_store(
                store,
                crate::txindex_worker::DEFAULT_BATCH_LIMITS,
            )?))
        }
        other => bail!("unsupported storage backend for txindex: {other}"),
    }
}

fn open_filter_index(config: &Config) -> Result<FilterIndexHandle> {
    if !config.blockfilterindex {
        let filter_index: Box<dyn bitcoin_rs_filters::FilterIndexLike> =
            Box::new(DisabledFilterIndex);
        return Ok(Arc::new(filter_index));
    }

    let filters_dir = config.data_dir.join("filters");
    std::fs::create_dir_all(&filters_dir)
        .with_context(|| format!("create filters_dir {}", filters_dir.display()))?;
    let filter_index: Box<dyn bitcoin_rs_filters::FilterIndexLike> =
        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::RocksDbStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "fjall")]
            "fjall" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::FjallStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "redb")]
            "redb" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::RedbStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "mdbx")]
            "mdbx" => Box::new(bitcoin_rs_filters::FilterIndex::new(
                bitcoin_rs_storage::MdbxStore::open(&filters_dir).map_err(anyhow::Error::new)?,
            )),
            other => bail!("unsupported storage backend for filter index: {other}"),
        };
    Ok(Arc::new(filter_index))
}

/// Aggregate handle to a running node.
pub struct NodeState {
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Published by `write_clean_checkpoint` and read by the pruner, which must
    /// not delete an undo record a crash-restore would still need.
    durable_tip_height: Arc<AtomicU32>,
    config: Config,
    data_dir: PathBuf,
    checkpoint_data_dir: cap_std::fs::Dir,
    resume_source: ResumeSource,
    storage: NodeStorage,
    block_body_store: Arc<dyn crate::apply::PruneBodyStore>,
    utxo: Arc<UtxoSet>,
    coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
    tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    tx_index_worker: Option<crate::txindex_worker::TxIndexWorker>,
    tx_index_query: Option<Arc<crate::txindex_worker::TxIndexQueryEngine>>,
    filter_index: FilterIndexHandle,
    prune_service: Option<Arc<dyn PruneService>>,
    zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    active_zmq_notifications: Vec<ZmqNotification>,
    mempool: Arc<RwLock<Mempool>>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Cumulative transaction count through `applied_tip`, `0` when unknown.
    /// Shared with `ApplyHandles`, which maintains it, and with the RPC context.
    chain_tx_count: Arc<AtomicU64>,
    block_tree: Arc<RwLock<bitcoin_rs_chain::BlockTree>>,
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    network: Arc<RwLock<NetworkState>>,
    peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
    /// Per-peer outbound message senders, keyed by remote socket address.
    /// External code pushes messages here; the per-connection thread drains
    /// and writes them to the peer's TCP stream.
    peer_outbound: Arc<RwLock<HashMap<std::net::SocketAddr, bitcoin_rs_p2p::PeerLease>>>,
    banned: Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    p2p_outbound_tx: crossbeam_channel::Sender<std::net::SocketAddr>,
    p2p_outbound_rx: Arc<Mutex<crossbeam_channel::Receiver<std::net::SocketAddr>>>,
    inbound_headers_tx: Sender<bitcoin_rs_p2p::InboundHeaders>,
    inbound_headers_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundHeaders>>>,
    inbound_blocks_tx: Sender<bitcoin_rs_p2p::InboundBlock>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    apply_handles: crate::apply::ApplyHandles,
    sync: Arc<crate::BlockSync>,
    mining_template_id: Arc<ArcSwap<CompactString>>,
    replayed: Mutex<Vec<u32>>,
}

impl NodeState {
    /// Opens (or creates) the node's data directory and configured storage
    /// backend.
    #[allow(clippy::arc_with_non_send_sync)]
    #[allow(clippy::too_many_lines)]
    pub fn open(config: Config) -> Result<Self> {
        config.validate()?;
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let checkpoint_data_dir = crate::checkpoint_fs::open_data_dir(&config.data_dir)
            .with_context(|| format!("open data_dir {}", config.data_dir.display()))?;
        let checkpoint_config = crate::checkpoint::HeaderCheckpointConfig {
            network: config.network,
            genesis: config.network.genesis_block_hash(),
        };
        let checkpoint_load =
            crate::checkpoint::load_checkpoint_from_dir(&checkpoint_data_dir, checkpoint_config)?;
        let g2_muhash_sampler = config
            .g2_muhash_samples
            .clone()
            .map(|path| crate::g2_muhash::G2MuhashSampler::open(path, config.g2_muhash_tip_height))
            .transpose()
            .context("open G2 MuHash sample writer")?
            .map(Arc::new);
        let g14_utxo_commit_sampler = match (
            config.g14_utxo_commit_samples.as_ref(),
            config.g14_utxo_commit_ibd_start_height,
            config.g14_utxo_commit_ibd_stop_height,
            config.g14_utxo_commit_ibd_start_hash.as_ref(),
            config.g14_utxo_commit_ibd_stop_hash.as_ref(),
        ) {
            (None, None, None, None, None) => None,
            (
                Some(path),
                Some(start_height),
                Some(stop_height),
                Some(start_hash),
                Some(stop_hash),
            ) => Some(Arc::new(
                crate::g14_utxo_commit::G14UtxoCommitSampler::open(
                    path.clone(),
                    start_height,
                    stop_height,
                    start_hash.clone(),
                    stop_hash.clone(),
                )
                .context("open G14 UTXO commit sample writer")?,
            )),
            _ => {
                bail!("g14_utxo_commit_samples requires complete G14 UTXO commit IBD window fields")
            }
        };
        let storage = NodeStorage::open(&config)?;
        let undo_store = storage.undo_store();
        // Before anything reads the chainstate, let alone serves or syncs it.
        // A node that starts on a torn chainstate builds on it, and every block
        // it adds makes the damage harder to find.
        if let Some(marker) = undo_store
            .load_disconnect_marker()
            .map_err(anyhow::Error::new)?
        {
            // Names directories rather than a `-reindex` option, because this
            // node has no reindex. An instruction the operator cannot follow is
            // worse than none.
            //
            // Remove the authoritative views. The marker covers a disconnect
            // that did not reach a clean UTXO-and-tip checkpoint. TxIndex and
            // filter rows are derived state outside this marker, but a retained
            // TxIndex watermark can stall rollback because wiping the chainstate
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
        let block_files =
            Arc::new(FlatFileBlockStore::open(&config.data_dir).map_err(anyhow::Error::new)?);
        let block_body_store =
            storage.block_body_store(Arc::clone(&block_files), &config.data_dir)?;

        let filter_index = open_filter_index(&config)?;
        let zmq_publications = config.zmq_publications();
        let active_zmq_notifications: Vec<_> = zmq_publications
            .iter()
            .map(|publication| {
                ZmqNotification::new(
                    publication.topic.notifier_type(),
                    publication.endpoint.clone(),
                    publication.hwm,
                )
            })
            .collect();
        let zmq_publisher: Arc<dyn crate::ZmqPublisher> = if zmq_publications.is_empty() {
            Arc::new(crate::NoOpZmqPublisher)
        } else {
            Arc::new(crate::SocketZmqPublisher::bind(&zmq_publications)?)
        };
        let (
            mut utxo_set,
            initial_coin_stats,
            block_tree_value,
            restored_applied_tip,
            restored_chain_tx_count,
            resume_source,
        ) = match checkpoint_load {
            crate::checkpoint::CheckpointLoad::Cold { reason } => {
                if let Some(reason) = reason {
                    tracing::warn!(%reason, "chainstate checkpoint rejected; starting cold");
                }
                (
                    bitcoin_rs_utxo::UtxoSet::new(),
                    bitcoin_rs_coinstats::CoinStats::default(),
                    bitcoin_rs_chain::BlockTree::new(),
                    None,
                    0,
                    ResumeSource::Cold,
                )
            }
            crate::checkpoint::CheckpointLoad::HeadersOnly { tree, reason } => {
                tracing::warn!(%reason, "chainstate payload rejected; retaining validated headers only");
                (
                    bitcoin_rs_utxo::UtxoSet::new(),
                    bitcoin_rs_coinstats::CoinStats::default(),
                    tree,
                    None,
                    0,
                    ResumeSource::HeadersOnly,
                )
            }
            crate::checkpoint::CheckpointLoad::Complete(restored) => {
                tracing::info!(
                    height = restored.applied_tip.height,
                    hash = %restored.applied_tip.hash,
                    "restored chainstate checkpoint"
                );
                (
                    restored.utxo,
                    restored.coin_stats,
                    restored.tree,
                    Some(restored.applied_tip),
                    restored.chain_tx_count,
                    ResumeSource::Checkpoint,
                )
            }
        };
        let coin_stats_listener = bitcoin_rs_coinstats::CoinStatsListener::new(initial_coin_stats);
        // The rolling coin-stats listener does per-coin MuHash + event work on
        // the block-apply hot path. Bitcoin Core does not maintain rolling UTXO
        // stats during IBD by default; gettxoutsetinfo scans on demand instead
        // (see scan_coin_stats). Only register the listener when G2 MuHash
        // sampling needs the rolling accumulator.
        if config.g2_muhash_samples.is_some() {
            utxo_set.set_listener(Box::new(coin_stats_listener.clone()));
        }
        let utxo = Arc::new(utxo_set);
        let coin_stats = Arc::new(coin_stats_listener);
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let block_tree = Arc::new(RwLock::new(block_tree_value));
        let chain_tip = block_tree.read().tip_handle();
        let applied_tip: Arc<ArcSwapOption<TipSnapshot>> = Arc::new(ArcSwapOption::empty());
        if let Some(restored_applied_tip) = restored_applied_tip {
            applied_tip.store(Some(Arc::new(restored_applied_tip)));
        }
        let blocks = Arc::new(RwLock::new(Vec::new()));
        let chain_tx_count = Arc::new(AtomicU64::new(restored_chain_tx_count));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        let tx_index_open = open_tx_index(&config)?;
        let (tx_index_runtime, tx_index_worker, tx_index_query) = match tx_index_open {
            Some(open) => {
                let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
                let runtime = Arc::new(crate::txindex_worker::TxIndexRuntime::new(wake_tx));
                let body_source: Arc<dyn bitcoin_rs_rpc::BlockBodySource> =
                    Arc::new(StoredBlockBodySource::new(Arc::clone(&block_body_store)));
                let block_source = crate::NodeBlockSource::new(Arc::clone(&blocks))
                    .with_block_body_source(Arc::clone(&body_source))
                    .with_block_tree(Arc::clone(&block_tree));
                let query = Arc::new(crate::txindex_worker::TxIndexQueryEngine::new(
                    Arc::clone(&runtime),
                    Arc::clone(&open.reader),
                    block_source,
                    Arc::clone(&block_tree),
                    Arc::clone(&applied_tip),
                    Some(body_source),
                ));
                let worker = crate::txindex_worker::TxIndexWorker::spawn(
                    Arc::clone(&runtime),
                    open.writer,
                    Arc::clone(&applied_tip),
                    Arc::clone(&block_tree),
                    Some(Arc::clone(&block_body_store)),
                    open.batch_limits,
                    wake_rx,
                )
                .context("spawn txindex worker")?;
                (Some(runtime), Some(worker), Some(query))
            }
            None => (None, None, None),
        };
        let network = Arc::new(RwLock::new(NetworkState::default()));
        let peers = Arc::new(RwLock::new(Vec::new()));
        let banned = Arc::new(RwLock::new(Vec::new()));
        let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
        let (p2p_outbound_tx, p2p_outbound_rx_raw) =
            crossbeam_channel::bounded(P2P_OUTBOUND_QUEUE_LIMIT);
        let p2p_outbound_rx = Arc::new(Mutex::new(p2p_outbound_rx_raw));
        let mining_template_id = Arc::new(ArcSwap::from_pointee(CompactString::new("0")));
        let (inbound_headers_tx, inbound_headers_rx_raw) =
            crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundHeaders>();
        let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
        let (inbound_blocks_tx, inbound_blocks_rx_raw) =
            crossbeam_channel::bounded::<bitcoin_rs_p2p::InboundBlock>(INBOUND_BLOCK_CHANNEL_LIMIT);
        let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
        let shutdown = Arc::new(AtomicBool::new(false));
        let apply_handles = crate::apply::ApplyHandles {
            network: config.network,
            chain_tip: Arc::clone(&chain_tip),
            applied_tip: Arc::clone(&applied_tip),
            chain_tx_count: Arc::clone(&chain_tx_count),
            block_tree: Arc::clone(&block_tree),
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            tx_index_runtime: tx_index_runtime.clone(),
            filter_index: Arc::clone(&filter_index),
            mempool: Arc::clone(&mempool),
            blocks: Arc::clone(&blocks),
            transactions: Arc::clone(&transactions),
            zmq_publisher: Arc::clone(&zmq_publisher),
            filter_header_cache: Arc::new(Mutex::new(None)),
            cache_block_bodies_in_memory: false,
            block_body_store: Some(Arc::clone(&block_body_store)),
            undo_store,
            g2_muhash_sampler,
            g14_utxo_commit_sampler,
            admission: Arc::new(crate::apply::ApplyAdmission::new()),
            shutdown: Arc::clone(&shutdown),
            chain_transition: Arc::new(parking_lot::Mutex::new(())),
            assume_valid_height: config.assume_valid_height,
            assume_valid_gate: Arc::new(crate::apply::AssumeValidGate::new(
                config.network,
                config.assume_valid_height,
            )),
        };
        apply_handles.assume_valid_gate.evaluate(&block_tree.read());
        let sync = Arc::new(crate::BlockSync::new(
            apply_handles.clone(),
            Arc::clone(&peers),
            Arc::clone(&peer_outbound),
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
                &durable_tip_height,
            )?)
        } else {
            None
        };
        tracing::info!(
            backend = storage.kind(),
            chainstate_dir = %config.data_dir.join("chainstate").display(),
            "opened storage backend"
        );
        let data_dir = config.data_dir.clone();
        Ok(Self {
            durable_tip_height,
            config,
            data_dir,
            checkpoint_data_dir,
            resume_source,
            storage,
            block_body_store,
            utxo,
            coin_stats,
            tx_index_runtime,
            tx_index_worker,
            tx_index_query,
            filter_index,
            prune_service,
            zmq_publisher,
            active_zmq_notifications,
            mempool,
            chain_tip,
            applied_tip,
            chain_tx_count: Arc::clone(&chain_tx_count),
            block_tree,
            blocks,
            transactions,
            network,
            peers,
            peer_outbound,
            banned,
            p2p_outbound_tx,
            p2p_outbound_rx,
            inbound_headers_tx,
            inbound_headers_rx,
            inbound_blocks_tx,
            inbound_blocks_rx,
            apply_handles,
            mining_template_id,
            sync,
            replayed: Mutex::new(Vec::new()),
        })
    }

    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

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
            crate::checkpoint::CheckpointWrite::Published { generation } => Ok(generation),
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                bail!("checkpoint refused: no applied tip to publish")
            }
        }
    }

    pub(crate) fn write_clean_checkpoint(
        &self,
    ) -> core::result::Result<crate::checkpoint::CheckpointWrite, crate::checkpoint::CheckpointError>
    {
        let _exclusive_apply = self.apply_handles.admission.close();
        if let Some(marker) = self.apply_handles.undo_store.load_disconnect_marker()?
            && marker.phase == crate::apply::DisconnectPhase::InFlight
        {
            return Err(crate::checkpoint::CheckpointError::DisconnectInFlight {
                hash: marker.hash,
                height: marker.height,
            });
        }
        // A checkpoint may name this tip only after body files then index rows sync.
        self.block_body_store.sync()?;
        let applied_tip = self.applied_tip.load_full();
        let written = crate::checkpoint::write_checkpoint_from_dir(
            &self.checkpoint_data_dir,
            crate::checkpoint::HeaderCheckpointConfig {
                network: self.config.network,
                genesis: self.config.network.genesis_block_hash(),
            },
            &self.block_tree,
            &self.utxo,
            &self.coin_stats,
            applied_tip.as_deref(),
            self.chain_tx_count
                .load(core::sync::atomic::Ordering::Relaxed),
            self.config.g2_muhash_samples.is_some(),
        )?;
        // Remove the marker only after this checkpoint publishes the matching
        // UTXO set and applied tip. TxIndex is outside the authoritative
        // disconnect transaction and recovers from its own atomic watermark.
        self.apply_handles
            .undo_store
            .disarm_disconnect()
            .map_err(crate::checkpoint::CheckpointError::from)?;
        // Everything up to this tip is now recoverable, so undo records below it
        // may be pruned. Published after the write, never before.
        self.durable_tip_height.store(
            applied_tip.as_ref().map_or(0, |tip| tip.height),
            Ordering::Release,
        );
        Ok(written)
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
    pub fn coin_stats(&self) -> Arc<bitcoin_rs_coinstats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    /// Returns the node-owned complete transaction-index query adapter.
    #[must_use]
    pub fn tx_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::TxIndexQuery>> {
        self.tx_index_query.as_ref().map(|query| {
            let adapter: Arc<dyn bitcoin_rs_rpc::TxIndexQuery> = query.clone();
            adapter
        })
    }

    /// Returns the node-owned complete transaction-index adapter for Electrum.
    #[must_use]
    pub(crate) fn tx_index_electrum_adapter(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_electrum::methods::ConfirmedHistoryReader>> {
        self.tx_index_query.as_ref().map(|query| {
            let adapter: Arc<dyn bitcoin_rs_electrum::methods::ConfirmedHistoryReader> =
                query.clone();
            adapter
        })
    }

    /// Returns the shared compact-filter index handle.
    #[must_use]
    pub fn filter_index(&self) -> FilterIndexHandle {
        Arc::clone(&self.filter_index)
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
    pub fn blocks(&self) -> Arc<RwLock<Vec<BlockRecord>>> {
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
    pub fn transactions(&self) -> Arc<RwLock<HashMap<Txid, Transaction>>> {
        Arc::clone(&self.transactions)
    }

    /// Returns the shared network-counters handle exposed to RPC handlers.
    #[must_use]
    pub fn network(&self) -> Arc<RwLock<NetworkState>> {
        Arc::clone(&self.network)
    }

    /// Returns the shared registry of currently-handshook peers.
    #[must_use]
    pub fn peers(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>> {
        Arc::clone(&self.peers)
    }

    /// Returns the shared manual IP/subnet ban list exposed to RPC and P2P.
    #[must_use]
    pub fn banned_subnets(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>> {
        Arc::clone(&self.banned)
    }

    /// Returns the shared per-peer outbound message-sender map.
    ///
    /// External callers can look up a peer's `Sender<Message>` by socket
    /// address and send a message into that peer's outbound queue. The
    /// per-connection thread drains the receiver each iteration of
    /// `run_message_loop` and writes the message via `peer.send`.
    #[must_use]
    pub fn peer_outbound(
        &self,
    ) -> Arc<RwLock<HashMap<std::net::SocketAddr, bitcoin_rs_p2p::PeerLease>>> {
        Arc::clone(&self.peer_outbound)
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

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// `Headers` batches into. The matching `Receiver` is consumed by
    /// `BlockSync::tick` to extend the `BlockTree`.
    #[must_use]
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
    /// `Block` messages into. The matching `Receiver` is consumed by
    /// `BlockSync::tick` to apply downloaded blocks.
    #[must_use]
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

    /// Returns the shared block-download orchestrator.
    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    /// Returns the shared getblocktemplate long-poll id.
    #[must_use]
    pub fn mining_template_id(&self) -> Arc<ArcSwap<CompactString>> {
        Arc::clone(&self.mining_template_id)
    }

    /// Heights walked by the most recent crash-recovery replay.
    #[must_use]
    pub fn replayed_heights(&self) -> Vec<u32> {
        self.replayed.lock().clone()
    }

    /// Records a height in the in-memory replay log.
    pub(crate) fn push_replayed(&self, height: u32) {
        self.replayed.lock().push(height);
    }

    /// Test helper: writes the recovery metadata as if a block at `height`
    /// had just been fully committed. Real block commits flow through the
    /// `crates/utxo` listener; this helper exists so crash-recovery tests
    /// can simulate a chain without bringing up the full subsystem stack.
    pub fn record_synthetic_block_for_recovery(&self, height: u32) -> Result<()> {
        let meta = crate::crash_recovery::Meta {
            height,
            last_committed_height: height,
        };
        crate::crash_recovery::write_meta(self, &meta)
    }

    /// Returns the process-wide shutdown signal shared by all runtime workers.
    #[must_use]
    pub fn shutdown(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.apply_handles.shutdown)
    }

    /// Snapshot of the handle set needed by `crate::apply::apply_block`.
    #[must_use]
    pub fn apply_handles(&self) -> crate::apply::ApplyHandles {
        self.apply_handles.clone()
    }

    /// Synthetically applies `block` as the next tip after consensus checks.
    ///
    /// Delegates to `crate::apply::apply_block` over the shared handles.
    pub fn apply_block(
        &self,
        block: &bitcoin::Block,
    ) -> core::result::Result<TipSnapshot, ApplyError> {
        crate::apply::apply_block(&self.apply_handles, block)
    }

    #[cfg(test)]
    pub(crate) fn check_coinbase_maturity(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        crate::apply::check_coinbase_maturity(&self.apply_handles, block, height)
    }
}

impl Drop for NodeState {
    fn drop(&mut self) {
        let _admission = self.apply_handles.admission.close();
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
    use bitcoin::hashes::Hash as _;

    #[test]
    fn open_constructs_empty_handles() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        let state = NodeState::open(config)?;
        let (Some(a), Some(b)) = (state.tx_index_query(), state.tx_index_query()) else {
            panic!("txindex query engine missing when enabled");
        };
        assert!(Arc::ptr_eq(&a, &b), "txindex query handle must be stable");
        assert!(
            state.data_dir().join("txindex").exists(),
            "enabled txindex must create storage"
        );
        Ok(())
    }

    #[test]
    fn drop_joins_txindex_worker_before_reopen() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;

        {
            let state = NodeState::open(config.clone())?;
            assert!(state.tx_index_query().is_some());
        }

        let reopened = NodeState::open(config)?;
        assert!(reopened.tx_index_query().is_some());
        Ok(())
    }

    #[test]
    fn open_rejects_txindex_with_pruning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.txindex = true;
        config.prune_target_mb = 1;

        let error = match NodeState::open(config) {
            Ok(_) => anyhow::bail!("txindex with pruning must be rejected"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("-txindex is not compatible with -prune"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[cfg(feature = "fjall")]
    #[test]
    fn open_rebuilds_legacy_cursorless_txindex() -> anyhow::Result<()> {
        use bitcoin_rs_storage::{ColumnFamily, KvStore as _};

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.storage_backend = "fjall".to_owned();
        config.txindex = true;

        let txindex_dir = config.data_dir.join("txindex");
        let store = bitcoin_rs_storage::FjallStore::open(&txindex_dir)?;
        store.put(ColumnFamily::TxConfirmed, b"legacy-row", &[])?;
        drop(store);

        let state = NodeState::open(config)?;
        assert!(state.tx_index_query().is_some());
        drop(state);

        let store = bitcoin_rs_storage::FjallStore::open(&txindex_dir)?;
        assert!(
            store
                .iter_prefix(ColumnFamily::TxConfirmed, &[])?
                .next()
                .is_none(),
            "legacy rows must be removed before rebuilding"
        );
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, &[0x00, b'V'])?,
            Some(vec![1, 0, 0, 0])
        );
        Ok(())
    }

    #[test]
    fn open_skips_filter_index_when_disabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let a = state.filter_index();
        let b = state.filter_index();
        assert!(!a.wants_filters(), "blockfilterindex disabled by default");
        assert!(
            !state.data_dir().join("filters").exists(),
            "disabled blockfilterindex must not create storage"
        );
        assert!(
            Arc::ptr_eq(&a, &b),
            "filter_index handle stable across calls"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_filter_index_when_enabled() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.blockfilterindex = true;
        let state = NodeState::open(config)?;
        let a = state.filter_index();
        let b = state.filter_index();
        assert!(a.wants_filters(), "enabled blockfilterindex builds filters");
        assert!(
            Arc::ptr_eq(&a, &b),
            "filter_index handle stable across calls"
        );
        assert!(
            state.data_dir().join("filters").exists(),
            "enabled blockfilterindex must create storage"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_block_sync_orchestrator() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(
            state.applied_tip().load_full().is_none(),
            "freshly opened applied_tip is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_registry() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(
            state.peers().read().is_empty(),
            "freshly opened registry is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_outbound_map() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(state.peer_outbound().read().is_empty());
        Ok(())
    }

    #[test]
    fn zmq_publisher_handle_defaults_to_noop() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let publisher = state.zmq_publisher();
        // No-op publisher accepts publish calls silently.
        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        Ok(())
    }

    #[test]
    fn zmq_publisher_handle_reports_active_metadata() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.zmqpubhashblock = vec!["inproc://state-zmq-pubhashblock".to_owned()];
        config.zmqpubhashtx = vec!["inproc://state-zmq-pubhashtx".to_owned()];
        config.zmqpubrawblock = vec!["inproc://state-zmq-pubrawblock".to_owned()];
        config.zmqpubrawtx = vec!["inproc://state-zmq-pubrawtx".to_owned()];
        config.zmqpubhashblockhwm = Some(17);
        config.zmqpubhashtxhwm = Some(18);
        config.zmqpubrawblockhwm = Some(19);
        config.zmqpubrawtxhwm = Some(20);
        let state = NodeState::open(config)?;

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
            ["pubhashblock", "pubhashtx", "pubrawblock", "pubrawtx"]
        );
        assert_eq!(hwms, [17, 18, 19, 20]);
        Ok(())
    }

    #[test]
    fn inbound_headers_sender_is_unbounded_clone_target() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let _tx1 = state.inbound_blocks_sender();
        let _tx2 = state.inbound_blocks_sender();
        Ok(())
    }

    #[test]
    fn inbound_blocks_channel_is_bounded_against_flood() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let tx = state.inbound_blocks_sender();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
        let chain_tip = state.chain_tip();
        let blocks = state.blocks();
        let transactions = state.transactions();
        let network = state.network();
        let mining_template_id = state.mining_template_id();

        assert!(chain_tip.load().is_none(), "fresh chain tip must be empty");
        assert!(blocks.read().is_empty(), "fresh blocks must be empty");
        assert!(
            transactions.read().is_empty(),
            "fresh transactions must be empty"
        );
        assert_eq!(network.read().connection_count, 0);
        assert_eq!(mining_template_id.load().as_str(), "0");

        Ok(())
    }

    #[test]
    fn apply_handles_follow_txindex_availability() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("without-txindex");
        config.p2p_listen.clear();
        config.txindex = false;
        let state = NodeState::open(config)?;
        assert!(state.apply_handles().tx_index_runtime.is_none());

        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("with-txindex");
        config.p2p_listen.clear();
        config.txindex = true;
        let state = NodeState::open(config)?;
        assert!(state.apply_handles().tx_index_runtime.is_some());
        Ok(())
    }

    #[test]
    fn prune_service_is_absent_when_config_disables_pruning() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 0;

        let state = NodeState::open(config)?;

        assert!(state.prune_service().is_none());
        Ok(())
    }

    #[test]
    fn apply_block_persists_body_under_pruning_key_when_pruning_disabled() -> anyhow::Result<()> {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 0;
        let state = NodeState::open(config)?;
        let block = genesis_block(bitcoin::Network::Regtest);
        let hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());

        assert!(state.prune_service().is_none());
        state.apply_block(&block)?;

        assert_eq!(
            state
                .blocks
                .read()
                .first()
                .map(|record| record.block_hex.as_str()),
            Some("")
        );
        assert_eq!(
            state.block_body_store.load_block_body(0, hash)?.as_deref(),
            Some(serialize(&block).as_slice())
        );
        Ok(())
    }

    #[test]
    fn persisting_same_block_body_twice_appends_once() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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

    #[cfg(feature = "fjall")]
    #[test]
    fn legacy_block_body_datadir_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("legacy-node");
        config.p2p_listen.clear();
        std::fs::create_dir_all(config.data_dir.join("chainstate"))?;
        let store = bitcoin_rs_storage::FjallStore::open(config.data_dir.join("chainstate"))?;
        store.put(
            bitcoin_rs_pruning::BLOCK_DATA_CF,
            &bitcoin_rs_pruning::block_body_key(
                1,
                bitcoin_rs_primitives::Hash256::from_le_bytes(&[1_u8; 32]),
            ),
            b"legacy-inline-body",
        )?;
        drop(store);

        let datadir = config.data_dir.display().to_string();
        let Err(error) = NodeState::open(config) else {
            anyhow::bail!("legacy inline block body unexpectedly opened");
        };
        let message = error.to_string();
        assert!(message.contains(&datadir));
        assert!(message.contains("predates the flat-file block store"));
        assert!(message.contains("must be resynced"));
        Ok(())
    }

    #[test]
    fn apply_block_with_serialized_persists_same_body_as_apply_block() -> anyhow::Result<()> {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;

        let block = genesis_block(bitcoin::Network::Regtest);
        let hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let serialized = bytes::Bytes::from(serialize(&block));

        let dir_a = tempfile::tempdir()?;
        let mut config_a = crate::Config::default_for_network(crate::Network::Regtest);
        config_a.data_dir = dir_a.path().join("node-a");
        config_a.p2p_listen.clear();
        config_a.prune_target_mb = 0;
        let state_a = NodeState::open(config_a)?;
        state_a.apply_block(&block)?;

        let dir_b = tempfile::tempdir()?;
        let mut config_b = crate::Config::default_for_network(crate::Network::Regtest);
        config_b.data_dir = dir_b.path().join("node-b");
        config_b.p2p_listen.clear();
        config_b.prune_target_mb = 0;
        let state_b = NodeState::open(config_b)?;
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
        let data_dir = dir.path().join("node");
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();

        let expected = {
            let state = NodeState::open(config.clone())?;
            assert_eq!(
                state.chain_tx_count_handle().load(Ordering::Relaxed),
                0,
                "a node that has applied nothing cannot know the count"
            );

            let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let genesis_tx_count = u64::try_from(genesis.txdata.len())?;
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
        let resumed = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config)?;

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
                hash,
                height,
                block_hex: "00".to_owned(),
                body_size: 1,
                header_hex: String::new(),
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
    fn prune_service_deletes_seeded_storage_rows_and_clears_cached_bodies() -> anyhow::Result<()> {
        fn hash(height: u32) -> anyhow::Result<bitcoin_rs_primitives::Hash256> {
            let byte = u8::try_from(height)
                .map_err(|_| anyhow::anyhow!("test height {height} exceeds u8"))?;
            Ok(bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32]))
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config)?;

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
                hash,
                height,
                block_hex: "00".to_owned(),
                body_size: 1,
                header_hex: String::new(),
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

        let blocks = state.blocks.read();
        assert_eq!(
            blocks
                .iter()
                .find(|record| record.height == 10)
                .map(|record| record.block_hex.as_str()),
            Some("")
        );
        assert_eq!(
            blocks
                .iter()
                .find(|record| record.height == 10)
                .map(|record| record.block_hex.capacity()),
            Some(0)
        );
        assert_eq!(
            blocks
                .iter()
                .find(|record| record.height == 11)
                .map(|record| record.block_hex.as_str()),
            Some("00")
        );

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
                bitcoin_rs_pruning::BLOCK_DATA_CF,
                &bitcoin_rs_pruning::block_body_key(height, hash),
                &position.encode(),
            );
            batch.put(
                bitcoin_rs_pruning::BLOCK_DATA_CF,
                &bitcoin_rs_storage::block_file_max_height_key(0),
                &bitcoin_rs_storage::encode_block_file_max_height(height),
            );
            store.write(batch)?;
            Ok(())
        }

        fn metadata_exists<S: KvStore>(store: &S) -> anyhow::Result<bool> {
            Ok(store
                .get(
                    bitcoin_rs_pruning::BLOCK_DATA_CF,
                    &bitcoin_rs_storage::block_file_max_height_key(0),
                )?
                .is_some())
        }

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let blocks_dir = config.data_dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir)?;
        let prunable_file = blocks_dir.join("blk00000.dat");
        let current_file = blocks_dir.join("blk00001.dat");
        std::fs::write(&prunable_file, [])?;
        std::fs::write(&current_file, [])?;
        let state = NodeState::open(config)?;
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

    #[test]
    fn manual_prune_removes_pruned_block_transactions_from_cache() -> anyhow::Result<()> {
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::encode::serialize;
        use bitcoin::hashes::Hash as _;

        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;
        let state = NodeState::open(config)?;

        let pruned_block = genesis_block(bitcoin::Network::Regtest);
        let pruned_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(
            pruned_block.block_hash().as_byte_array(),
        );
        state
            .block_body_store
            .persist_block_body(10, pruned_hash, &serialize(&pruned_block))?;
        state
            .apply_handles()
            .undo_store
            .persist_undo(10, pruned_hash, b"undo-body")?;
        state
            .blocks
            .write()
            .push(BlockRecord::from_block_metadata(10, &pruned_block));

        let pruned_tx = pruned_block.txdata[0].clone();
        let pruned_txid = pruned_tx.compute_txid();
        let unrelated_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let unrelated_txid = unrelated_tx.compute_txid();

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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        config.prune_target_mb = 1;

        {
            let state = NodeState::open(config.clone())?;
            let Some(service) = state.prune_service() else {
                anyhow::bail!("prune service should exist when prune_target_mb > 0");
            };
            let result = service
                .prune_to_height(11)
                .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
            assert_eq!(result.pruneheight, 11);
        }

        let reopened = NodeState::open(config)?;
        let Some(service) = reopened.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        assert_eq!(service.status().pruneheight, Some(11));

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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_tip = state.apply_block(&genesis)?;
        let expected_utxo_hash = state.utxo().with_stable_view(stable_hash)?;
        let expected_stats = state.coin_stats().snapshot();
        assert!(matches!(
            state.write_clean_checkpoint()?,
            crate::checkpoint::CheckpointWrite::Published { .. }
        ));
        drop(state);

        let mut reopen_config = crate::Config::default_for_network(crate::Network::Regtest);
        reopen_config.data_dir = data_dir.clone();
        reopen_config.p2p_listen.clear();
        let resumed = NodeState::open(reopen_config.clone())?;
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
            next.block_hash().to_byte_array()
        );
        let listener_after_apply = resumed.coin_stats().snapshot();
        let mut rescanned = resumed.utxo().with_stable_view(|view| {
            bitcoin_rs_coinstats::scan_coin_stats(view, next_tip.height, true)
        })?;
        rescanned.tx_count = listener_after_apply.tx_count;
        assert_ne!(
            listener_after_apply.total_amount, rescanned.total_amount,
            "G2-disabled resume must not receive rolling UTXO notifications"
        );
        resumed.write_clean_checkpoint()?;

        let root = data_dir.join("chainstate-checkpoints");
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("CURRENT"))?)?;
        let directory = current
            .get("directory")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("CURRENT has no generation directory"))?;
        let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(
            root.join(directory).join("manifest-v1.json"),
        )?)?;
        assert_eq!(manifest["utxo"]["trailer_kind"], "scanned");
        let snapshot_file = std::fs::File::open(root.join(directory).join("utxo-v4.dat"))?;
        let mut snapshot_reader = std::io::BufReader::new(snapshot_file);
        let snapshot = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut snapshot_reader)?;
        assert_ne!(snapshot.muhash_trailer, [0_u8; 384]);
        assert_eq!(snapshot.muhash_trailer, rescanned.muhash.finalize());
        drop(resumed);

        let resumed_again = NodeState::open(reopen_config)?;
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
            let mut config = crate::Config::default_for_network(crate::Network::Regtest);
            config.data_dir = dir.path().join(backend);
            config.storage_backend = backend.to_owned();
            config.p2p_listen.clear();
            let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
            let state = NodeState::open(config.clone())?;
            state.apply_block(&genesis)?;
            state.write_clean_checkpoint()?;
            drop(state);

            let resumed = NodeState::open(config)?;
            assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
            resumed.apply_block(&mined_regtest_child(genesis.block_hash())?)?;
        }
        Ok(())
    }

    #[test]
    fn rolling_coinstats_resume_continues_through_next_block() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("node-g2");
        let samples = dir.path().join("g2.samples");
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        config.g2_muhash_samples = Some(samples.clone());
        config.g2_muhash_tip_height = Some(2);
        let state = NodeState::open(config)?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        state.apply_block(&genesis)?;
        let before = state.coin_stats().snapshot();
        state.write_clean_checkpoint()?;
        drop(state);

        let mut reopen_config = crate::Config::default_for_network(crate::Network::Regtest);
        reopen_config.data_dir = data_dir;
        reopen_config.p2p_listen.clear();
        reopen_config.g2_muhash_samples = Some(samples);
        reopen_config.g2_muhash_tip_height = Some(2);
        let resumed = NodeState::open(reopen_config)?;
        assert_eq!(resumed.coin_stats().snapshot(), before);
        resumed.apply_block(&mined_regtest_child(genesis.block_hash())?)?;
        let rolling = resumed.coin_stats().snapshot();
        let mut scanned = resumed.utxo().with_stable_view(|view| {
            bitcoin_rs_coinstats::scan_coin_stats(view, rolling.height, true)
        })?;
        scanned.tx_count = rolling.tx_count;
        assert_eq!(rolling, scanned);
        Ok(())
    }

    #[test]
    fn shutdown_arc_is_shared_with_apply_handles() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir.clone();
        config.p2p_listen.clear();
        let state = NodeState::open(config.clone())?;
        state.apply_handles().undo_store.arm_disconnect(
            10,
            bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xcd; 32]),
        )?;
        drop(state);

        let error = match NodeState::open(config) {
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
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
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = data_dir;
        config.p2p_listen.clear();
        let state = NodeState::open(config.clone())?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let tip = state.apply_block(&genesis)?;
        let generation = state.publish_checkpoint()?;
        assert!(
            generation > 0,
            "published checkpoint must have a positive generation"
        );
        drop(state);

        let resumed = NodeState::open(config)?;
        assert_eq!(resumed.resume_source(), ResumeSource::Checkpoint);
        let applied = resumed
            .applied_tip()
            .load_full()
            .ok_or_else(|| std::io::Error::other("checkpoint did not publish applied tip"))?;
        assert_eq!(applied.height, tip.height);
        assert_eq!(applied.hash, tip.hash);
        Ok(())
    }

    fn mined_regtest_child(prev_blockhash: bitcoin::BlockHash) -> anyhow::Result<bitcoin::Block> {
        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(vec![1, 1]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_296_688_603,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or_else(|| std::io::Error::other("test block has no merkle root"))?;
        let target = block.header.target();
        while block.header.validate_pow(target).is_err() {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("test nonce exhausted"))?;
        }
        Ok(block)
    }
}
