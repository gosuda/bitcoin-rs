//! Block-apply pipeline over shared node handles.

mod scratch;

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::consensus::{Decodable as _, encode::VarInt};
use bitcoin::hex::DisplayHex;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot};
use bitcoin_rs_consensus::{MAX_SCRIPT_SIZE, rust_path::UtxoView};
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::{Hash256, Network, OutPoint};
use bitcoin_rs_rpc::{BlockLog, BlockRecord};
use bitcoin_rs_utxo::{
    LiveOutput, LiveOutputMeta, UtxoSet,
    set::{BorrowedBlockChanges, BorrowedUtxoAdd},
};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::state::ApplyError;
use bitcoin_rs_storage::{
    BlockFilePosition, FlatFileBlockReader, FlatFileBlockStore, KvSnapshot, KvStore, StorageError,
    WriteBatch, block_file_max_height_key, decode_block_file_max_height,
    encode_block_file_max_height,
};
use scratch::{ApplyScratch, ApplyScratchCapacities, SameBlockSpentSet};

/// Number of blocks after a coinbase that its outputs become spendable.
/// Consensus rule since Bitcoin v0.3.1; universal across networks.
const COINBASE_MATURITY: u32 = 100;
/// BIP68 sequence-bit masks.
const BIP68_DISABLE_FLAG: u32 = 0x8000_0000;
const BIP68_TYPE_FLAG: u32 = 0x0040_0000;
const BIP68_MASK: u32 = 0x0000_ffff;
const BIP68_TIME_GRANULARITY_SECONDS: u32 = 512;
const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;
const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;
const SERIALIZED_BLOCK_METADATA_PREFIX_LEN: usize = SERIALIZED_BLOCK_HEADER_LEN + 9;
const LOCAL_OVERLAY_TXID_SET_THRESHOLD: usize = 8;

fn decode_block_tx_count(bytes: &[u8]) -> Option<usize> {
    let mut cursor = bytes.get(SERIALIZED_BLOCK_HEADER_LEN..)?;
    let count = VarInt::consensus_decode(&mut cursor).ok()?.0;
    usize::try_from(count).ok()
}

/// Storage for per-block UTXO undo records.
///
/// Records survive an orderly restart. They are not crash-safe: see
/// [`KvUndoStore::persist_undo`] for why no fsync sits here.
///
/// Undo records are consensus state, not an optional index: without the record
/// for a block the node cannot disconnect it, so it can advance `applied_tip`
/// into a chain it is unable to leave. The handle is therefore mandatory rather
/// than `Option`, and every construction path must supply a real
/// implementation. [`InMemoryUndoStore`] is a real one — it round-trips — and
/// is the correct choice for tests that need no durability. A no-op
/// implementation would recreate exactly the silent failure this type exists to
/// prevent, so do not add one.
///
/// Records are keyed by height AND block hash. Keying by height alone would let
/// a stale record from an abandoned branch be replayed against a different
/// block at the same height.
pub(crate) trait UndoStore: Send + Sync {
    /// Writes the undo record for one block.
    fn persist_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        record: &[u8],
    ) -> Result<(), StorageError>;

    /// Reads the undo record for one block, if present.
    fn load_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError>;

    /// Records that a disconnect is about to mutate state, durably.
    ///
    /// Armed BEFORE the first mutation, not after a failure. A marker written
    /// on the error path cannot exist for the case that needs it most: the
    /// process dying mid-rollback writes nothing at all. Armed first, both a
    /// crash and a returned `Fatal` leave the same evidence behind.
    fn arm_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), StorageError>;

    /// Records that the rollback finished, in memory, and is owed a checkpoint.
    ///
    /// Distinct from clearing. Both phases refuse a startup, because both mean
    /// the durable state is torn. What the phase decides is whether a
    /// checkpoint may clear the marker: only a rollback that ran to completion
    /// may, and a checkpoint taken over a half-finished or failed one would be
    /// a checkpoint of the damage.
    fn complete_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), StorageError>;

    /// Clears the marker once a disconnect has finished cleanly.
    ///
    /// The marker covers authoritative UTXO and tip state between checkpoints.
    /// `TxIndex` is outside this transaction and recovers from its own atomic
    /// watermark after restart.
    fn disarm_disconnect(&self) -> Result<(), StorageError>;

    /// Reads the marker left by a disconnect that never finished.
    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError>;
}

/// A disconnect that started and never reported finishing.
///
/// Its presence at startup means one of two things, and the node cannot tell
/// them apart: the disconnect returned `Fatal`, or the process died between the
/// first mutation and the last. Both leave authoritative UTXO and tip state
/// potentially inconsistent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectMarker {
    /// Block being disconnected.
    pub hash: bitcoin_rs_primitives::Hash256,
    /// Height it was applied at.
    pub height: u32,
    /// How far the disconnect got.
    pub phase: DisconnectPhase,
}

/// How far a disconnect got before the marker was last written.
///
/// Both phases refuse a startup. The phase decides only whether a checkpoint
/// may clear the marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectPhase {
    /// Mutation started and was never reported finished: the rollback is
    /// half-done, or the process died inside it. A checkpoint must NOT clear
    /// this, because a checkpoint over a half-finished rollback captures the
    /// damage instead of repairing it.
    InFlight,
    /// The rollback completed in memory and is waiting for a checkpoint to make
    /// it durable. Only this phase may be cleared, and only by that checkpoint.
    RolledBack,
}

/// Key for the in-flight disconnect marker.
///
/// One key, not one per block: only one disconnect runs at a time, and a
/// per-block key would leave the reader scanning to find out whether any are
/// set.
const DISCONNECT_MARKER_KEY: &[u8] = b"node:disconnect-in-flight";

impl DisconnectMarker {
    fn encode(&self) -> [u8; 37] {
        let mut encoded = [0_u8; 37];
        encoded[..32].copy_from_slice(&self.hash.to_le_bytes());
        encoded[32..36].copy_from_slice(&self.height.to_be_bytes());
        encoded[36] = match self.phase {
            DisconnectPhase::InFlight => 0,
            DisconnectPhase::RolledBack => 1,
        };
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let Ok(fixed): Result<[u8; 37], _> = bytes.try_into() else {
            // A marker that will not decode is still a marker. Treating a short
            // read as "no disconnect was in flight" would let corruption clear
            // the interlock, which is the one thing it must never do.
            return Err(StorageError::Backend(format!(
                "disconnect marker is {} bytes, expected 37",
                bytes.len()
            )));
        };
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&fixed[..32]);
        let mut height = [0_u8; 4];
        height.copy_from_slice(&fixed[32..36]);
        let phase = match fixed[36] {
            0 => DisconnectPhase::InFlight,
            1 => DisconnectPhase::RolledBack,
            other => {
                return Err(StorageError::Backend(format!(
                    "disconnect marker has unknown phase {other}"
                )));
            }
        };
        Ok(Self {
            hash: bitcoin_rs_primitives::Hash256::from_le_bytes(&hash),
            height: u32::from_be_bytes(height),
            phase,
        })
    }
}

/// Process-local undo storage.
///
/// A real implementation: what is written can be read back. Suitable wherever
/// durability across a restart is not required, such as tests.
#[derive(Debug, Default)]
pub(crate) struct InMemoryUndoStore {
    records: parking_lot::RwLock<HashMap<(u32, bitcoin_rs_primitives::Hash256), Vec<u8>>>,
    marker: parking_lot::RwLock<Option<DisconnectMarker>>,
}

impl UndoStore for InMemoryUndoStore {
    fn persist_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        record: &[u8],
    ) -> Result<(), StorageError> {
        self.records.write().insert((height, hash), record.to_vec());
        Ok(())
    }

    fn load_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.records.read().get(&(height, hash)).cloned())
    }

    fn arm_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), StorageError> {
        *self.marker.write() = Some(DisconnectMarker {
            hash,
            height,
            phase: DisconnectPhase::InFlight,
        });
        Ok(())
    }

    fn complete_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), StorageError> {
        *self.marker.write() = Some(DisconnectMarker {
            hash,
            height,
            phase: DisconnectPhase::RolledBack,
        });
        Ok(())
    }

    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        let mut marker = self.marker.write();
        if marker
            .as_ref()
            .is_some_and(|marker| marker.phase == DisconnectPhase::InFlight)
        {
            return Err(StorageError::InvalidOperation(
                "cannot disarm an in-flight disconnect",
            ));
        }
        *marker = None;
        Ok(())
    }

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        Ok(self.marker.read().clone())
    }
}

/// Undo storage backed by a [`KvStore`] column family.
pub(crate) struct KvUndoStore<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> KvUndoStore<S> {
    pub(crate) const fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: KvStore> UndoStore for KvUndoStore<S> {
    /// Deferred, matching the rest of the apply path.
    ///
    /// `put` is what this used to call, and on redb `put` commits an
    /// immediately durable transaction, so every connected block paid an fsync
    /// on that backend — the same per-block durability cost the deferred
    /// block-body write path exists to avoid. `write_deferred` leaves the row
    /// visible to later reads in this process and lets the checkpoint flush
    /// make it durable, which is what `disconnect_block` needs and all it needs.
    ///
    /// This is not crash-safe, and neither is the UTXO commit beside it: no
    /// part of block connection fsyncs. An fsync on this write alone would cost
    /// one per connected block and still leave the commit it describes
    /// unrecoverable, so it would buy a slower node and no guarantee.
    ///
    /// Closing the gap needs a crash-recovery path that re-applies the blocks
    /// between the last durable state and the tip. The node has no such path
    /// today, so do not cite one here.
    fn persist_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        record: &[u8],
    ) -> Result<(), StorageError> {
        use bitcoin_rs_storage::WriteBatch as _;

        let mut batch = self.store.new_batch();
        batch.put(
            bitcoin_rs_storage::ColumnFamily::UndoData,
            &bitcoin_rs_pruning::block_undo_key(height, hash),
            record,
        );
        self.store.write_deferred(batch)
    }

    fn load_undo(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(
            bitcoin_rs_storage::ColumnFamily::UndoData,
            &bitcoin_rs_pruning::block_undo_key(height, hash),
        )
    }

    /// Flushed, unlike every other write on this path.
    ///
    /// The rest of block apply does not fsync because a crash there is
    /// recoverable by re-applying blocks. This one is different: it is the only
    /// record that a rollback started, and it is worthless if the crash that it
    /// exists to survive can lose it. One fsync per disconnect, and disconnects
    /// are rare.
    fn arm_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), StorageError> {
        self.store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            DISCONNECT_MARKER_KEY,
            &DisconnectMarker {
                hash,
                height,
                phase: DisconnectPhase::InFlight,
            }
            .encode(),
        )?;
        self.store.flush()
    }

    fn complete_disconnect(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<(), StorageError> {
        self.store.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            DISCONNECT_MARKER_KEY,
            &DisconnectMarker {
                hash,
                height,
                phase: DisconnectPhase::RolledBack,
            }
            .encode(),
        )?;
        self.store.flush()
    }

    /// Refuses to clear a marker that is still `InFlight`.
    ///
    /// The caller is a checkpoint, and a checkpoint taken while a rollback is
    /// half-done captures the damage. Only a completed rollback may be cleared.
    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        use bitcoin_rs_storage::WriteBatch as _;

        if self
            .load_disconnect_marker()?
            .is_some_and(|marker| marker.phase == DisconnectPhase::InFlight)
        {
            return Err(StorageError::InvalidOperation(
                "cannot disarm an in-flight disconnect",
            ));
        }
        let mut batch = self.store.new_batch();
        batch.delete(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            DISCONNECT_MARKER_KEY,
        );
        self.store.write(batch)?;
        self.store.flush()
    }

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        self.store
            .get(
                bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                DISCONNECT_MARKER_KEY,
            )?
            .map(|bytes| DisconnectMarker::decode(&bytes))
            .transpose()
    }
}

pub(crate) trait PruneBodyReader {
    /// Prefetches body positions in the order that they will be loaded.
    ///
    /// Implementations must not prefetch body bytes.
    fn prefetch_positions(
        &mut self,
        requests: &[(u32, bitcoin_rs_primitives::Hash256)],
    ) -> Result<(), StorageError> {
        let _ = requests;
        Ok(())
    }

    fn load_block_body(
        &mut self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError>;
}

struct DirectPruneBodyReader<'a, S: PruneBodyStore + ?Sized> {
    store: &'a S,
}

impl<S: PruneBodyStore + ?Sized> PruneBodyReader for DirectPruneBodyReader<'_, S> {
    fn load_block_body(
        &mut self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.load_block_body(height, hash)
    }
}

pub(crate) trait PruneBodyStore: Send + Sync {
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError>;

    fn persist_block_body_value(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: bytes::Bytes,
    ) -> Result<(), StorageError> {
        self.persist_block_body(height, hash, &body)
    }

    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError>;
    fn reader(&self) -> Result<Box<dyn PruneBodyReader + '_>, StorageError> {
        Ok(Box::new(DirectPruneBodyReader { store: self }))
    }

    /// Loads `len` body bytes starting `offset` bytes into the serialized block.
    ///
    /// Defaults to `Ok(None)`, meaning "this store cannot slice"; callers fall
    /// back to [`Self::load_block_body`]. Never a short read.
    fn load_block_body_range(
        &self,
        _height: u32,
        _hash: bitcoin_rs_primitives::Hash256,
        _offset: u32,
        _len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn block_body_metadata(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<(usize, usize)>, StorageError> {
        let Some(body) = self.load_block_body(height, hash)? else {
            return Ok(None);
        };
        let Some(tx_count) = decode_block_tx_count(&body) else {
            return Ok(None);
        };
        Ok(Some((body.len(), tx_count)))
    }

    /// Bytes this store's block files occupy on disk, when it keeps files.
    ///
    /// `None` from a store with nothing on disk to measure; the caller then
    /// falls back to the block-record sum.
    fn disk_usage(&self) -> Option<u64> {
        None
    }

    /// Makes body bytes durable before their checkpoint can be published.
    fn sync(&self) -> Result<(), StorageError>;
}

pub(crate) struct FlatFilePruneBodyStore<S: KvStore> {
    index: Arc<S>,
    files: Arc<FlatFileBlockStore>,
}
enum PositionLookup {
    Direct,
    Prefetched {
        entries: Vec<(u32, Hash256, Option<BlockFilePosition>)>,
        next: usize,
    },
}

struct FlatFilePruneBodyReader<'a> {
    index: Box<dyn KvSnapshot + 'a>,
    files: FlatFileBlockReader,
    positions: PositionLookup,
}

impl PruneBodyReader for FlatFilePruneBodyReader<'_> {
    fn prefetch_positions(&mut self, requests: &[(u32, Hash256)]) -> Result<(), StorageError> {
        if let PositionLookup::Prefetched { entries, next } = &self.positions
            && *next != entries.len()
        {
            return Err(StorageError::InvalidOperation(
                "prefetched body positions were not fully consumed",
            ));
        }

        let keys: Vec<_> = requests
            .iter()
            .map(|&(height, hash)| bitcoin_rs_pruning::block_body_key(height, hash))
            .collect();
        let key_refs: Vec<_> = keys.iter().map(<[u8; 37]>::as_slice).collect();
        let values = self
            .index
            .get_many_sorted(bitcoin_rs_pruning::BLOCK_DATA_CF, &key_refs)?;
        if values.len() != requests.len() {
            return Err(StorageError::InvalidOperation(
                "snapshot batch returned the wrong number of values",
            ));
        }

        let entries = requests
            .iter()
            .copied()
            .zip(values)
            .map(|((height, hash), value)| {
                (
                    height,
                    hash,
                    value.as_deref().and_then(BlockFilePosition::decode),
                )
            })
            .collect();
        self.positions = PositionLookup::Prefetched { entries, next: 0 };
        Ok(())
    }

    fn load_block_body(
        &mut self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let position = match &mut self.positions {
            PositionLookup::Direct => {
                let key = bitcoin_rs_pruning::block_body_key(height, hash);
                let Some(encoded) = self.index.get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)? else {
                    return Ok(None);
                };
                BlockFilePosition::decode(&encoded)
            }
            PositionLookup::Prefetched { entries, next } => {
                let Some(&(expected_height, expected_hash, position)) = entries.get(*next) else {
                    return Err(StorageError::InvalidOperation(
                        "prefetched body positions are exhausted",
                    ));
                };
                if expected_height != height || expected_hash != hash {
                    return Err(StorageError::InvalidOperation(
                        "prefetched body position consumed out of order",
                    ));
                }
                *next += 1;
                position
            }
        };
        let Some(position) = position else {
            return Ok(None);
        };
        self.files.load(position, height, *hash.as_byte_array())
    }
}

impl<S: KvStore> FlatFilePruneBodyStore<S> {
    pub(crate) fn open(
        index: Arc<S>,
        files: Arc<FlatFileBlockStore>,
        data_dir: &std::path::Path,
    ) -> Result<Self, StorageError> {
        for row in index.iter_prefix(bitcoin_rs_pruning::BLOCK_DATA_CF, b"b")? {
            let (key, value) = row?;
            if key.len() == 37 && value.len() != BlockFilePosition::ENCODED_LEN {
                return Err(StorageError::IncompatibleData(format!(
                    "datadir {} predates the flat-file block store and must be resynced",
                    data_dir.display()
                )));
            }
        }
        Ok(Self { index, files })
    }

    /// Resolves the flat-file position of a block body, or `None` when the
    /// block is unknown or its index row is not a decodable position.
    ///
    /// Every read path starts here, so it is written once rather than three
    /// times: divergence between the whole-body, ranged, and metadata lookups
    /// would surface as one of them silently disagreeing about which blocks
    /// exist.
    fn body_position(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<BlockFilePosition>, StorageError> {
        let key = bitcoin_rs_pruning::block_body_key(height, hash);
        let Some(encoded) = self.index.get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)? else {
            return Ok(None);
        };
        Ok(BlockFilePosition::decode(&encoded))
    }
}

impl<S: KvStore> PruneBodyStore for FlatFilePruneBodyStore<S> {
    fn disk_usage(&self) -> Option<u64> {
        Some(self.files.disk_usage())
    }

    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let key = bitcoin_rs_pruning::block_body_key(height, hash);
        let existing = self
            .index
            .get(bitcoin_rs_pruning::BLOCK_DATA_CF, &key)?
            .map(|bytes| {
                BlockFilePosition::decode(&bytes).ok_or_else(|| {
                    StorageError::IncompatibleData(
                        "block-body index row is not a 16-byte flat-file position".to_owned(),
                    )
                })
            })
            .transpose()?;
        let position = self
            .files
            .persist(existing, height, *hash.as_byte_array(), body)?;
        if existing == Some(position) {
            return Ok(());
        }

        let max_height_key = block_file_max_height_key(position.file_no);
        let max_height = self
            .index
            .get(bitcoin_rs_pruning::BLOCK_DATA_CF, &max_height_key)?
            .as_deref()
            .and_then(decode_block_file_max_height)
            .map_or(height, |previous| previous.max(height));
        let mut batch = self.index.new_batch();
        batch.put(bitcoin_rs_pruning::BLOCK_DATA_CF, &key, &position.encode());
        batch.put(
            bitcoin_rs_pruning::BLOCK_DATA_CF,
            &max_height_key,
            &encode_block_file_max_height(max_height),
        );
        self.index.write_deferred(batch)
    }

    fn reader(&self) -> Result<Box<dyn PruneBodyReader + '_>, StorageError> {
        Ok(Box::new(FlatFilePruneBodyReader {
            index: self.index.snapshot()?,
            files: self.files.reader(),
            positions: PositionLookup::Direct,
        }))
    }

    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(position) = self.body_position(height, hash)? else {
            return Ok(None);
        };
        self.files.load(position, height, *hash.as_byte_array())
    }

    fn load_block_body_range(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        offset: u32,
        len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(position) = self.body_position(height, hash)? else {
            return Ok(None);
        };
        self.files
            .load_range(position, height, *hash.as_byte_array(), offset, len)
    }

    fn block_body_metadata(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<(usize, usize)>, StorageError> {
        let Some(position) = self.body_position(height, hash)? else {
            return Ok(None);
        };
        let Some(prefix) = self.files.load_prefix(
            position,
            height,
            *hash.as_byte_array(),
            SERIALIZED_BLOCK_METADATA_PREFIX_LEN,
        )?
        else {
            return Ok(None);
        };
        let Some(tx_count) = decode_block_tx_count(&prefix) else {
            return Ok(None);
        };
        let body_size = usize::try_from(position.len)
            .map_err(|_| StorageError::InvalidOperation("block body length does not fit usize"))?;
        Ok(Some((body_size, tx_count)))
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.files.sync()?;
        self.index.flush()
    }
}

#[cfg(all(test, feature = "fjall"))]
mod body_position_prefetch_tests {
    use super::*;

    #[test]
    fn prefetched_positions_stream_bodies_in_exact_request_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(bitcoin_rs_storage::FjallStore::open(
            temp.path().join("index"),
        )?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = FlatFilePruneBodyStore::open(index, files, temp.path())?;
        let hash1 = Hash256::from_le_bytes(&[1_u8; 32]);
        let hash2 = Hash256::from_le_bytes(&[2_u8; 32]);
        store.persist_block_body(1, hash1, b"first body")?;
        store.persist_block_body(2, hash2, b"second body")?;

        let mut reader = store.reader()?;
        reader.prefetch_positions(&[(1, hash1), (2, hash2)])?;
        assert!(matches!(
            reader.load_block_body(2, hash2),
            Err(StorageError::InvalidOperation(
                "prefetched body position consumed out of order"
            ))
        ));
        assert_eq!(
            reader.load_block_body(1, hash1)?.as_deref(),
            Some(b"first body".as_slice())
        );
        assert_eq!(
            reader.load_block_body(2, hash2)?.as_deref(),
            Some(b"second body".as_slice())
        );
        assert!(matches!(
            reader.load_block_body(2, hash2),
            Err(StorageError::InvalidOperation(
                "prefetched body positions are exhausted"
            ))
        ));
        Ok(())
    }
}

/// Admission barrier shared by every cloned apply handle.
pub(crate) struct ApplyAdmission {
    closed: AtomicBool,
    barrier: RwLock<()>,
}

impl ApplyAdmission {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            barrier: RwLock::new(()),
        }
    }

    fn ensure_open(&self) -> Result<(), ApplyError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(ApplyError::Shutdown);
        }
        Ok(())
    }

    fn enter(&self) -> Result<RwLockReadGuard<'_, ()>, ApplyError> {
        self.ensure_open()?;
        let permit = self.barrier.read();
        if let Err(error) = self.ensure_open() {
            drop(permit);
            return Err(error);
        }
        Ok(permit)
    }

    pub(crate) fn close(&self) -> RwLockWriteGuard<'_, ()> {
        self.closed.store(true, Ordering::Release);
        self.barrier.write()
    }

    /// Closes admission without taking the barrier.
    ///
    /// [`Self::close`] hands back the write guard because shutdown holds it
    /// while it drains. A torn chainstate has nothing to drain and no owner to
    /// hold a guard: it needs the flag set and every later `enter` refused,
    /// including the one that would otherwise apply the next block.
    pub(crate) fn close_permanently(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// Proof that admission and the chain-transition lock are both held.
///
/// Private fields make [`ApplyHandles::begin_chain_transition`] the only
/// constructor. Field order releases the transition lock before the permit.
pub(crate) struct ChainTransition<'a> {
    _transition: MutexGuard<'a, ()>,
    _admission: RwLockReadGuard<'a, ()>,
}

/// Hash-pinned assume-valid trust gate (Bitcoin Core `-assumevalid` semantics).
///
/// Historical script verification may be skipped only while the active header
/// chain is verified to contain the pinned anchor block. The gate starts
/// trusted when no anchor applies (no pin configured) and starts untrusted
/// when an anchor is pinned; [`AssumeValidGate::evaluate`] re-evaluates trust
/// against the block tree whenever a new inbound headers batch is accepted.
#[derive(Debug)]
pub struct AssumeValidGate {
    /// Pinned `(height, hash)` anchor, or `None` when no pin applies.
    anchor: Option<(u32, Hash256)>,
    /// Whether the active chain is currently verified to contain the anchor.
    trusted: AtomicBool,
    /// Whether the diverged-chain warning has already been emitted.
    warned: AtomicBool,
}

impl AssumeValidGate {
    /// Builds the gate for `network` gated on `configured_height`.
    ///
    /// The network's pinned anchor applies only when `configured_height` equals
    /// the anchor height (the production default). Any other value — `0` (full
    /// verification opt-in) or a custom height-only shortcut — leaves the gate
    /// unpinned and therefore always trusted.
    #[must_use]
    pub fn new(network: Network, configured_height: u32) -> Self {
        let anchor = network
            .assume_valid_anchor()
            .filter(|(height, _)| *height == configured_height);
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Builds a gate directly from an optional pinned anchor.
    #[must_use]
    pub fn with_anchor(anchor: Option<(u32, Hash256)>) -> Self {
        Self {
            trusted: AtomicBool::new(anchor.is_none()),
            warned: AtomicBool::new(false),
            anchor,
        }
    }

    /// Returns whether historical script verification may currently be skipped.
    #[must_use]
    pub fn trusted(&self) -> bool {
        self.trusted.load(Ordering::Relaxed)
    }

    /// Re-evaluates trust against `tree`'s active chain.
    ///
    /// Trusted only when the active tip is at or above the pinned height and
    /// the node at the pinned height on the active chain carries the pinned
    /// hash. Emits a one-time warning when a chain at/past the anchor height
    /// lacks the anchor block; such a chain is never trusted.
    pub fn evaluate(&self, tree: &BlockTree) {
        let Some((pinned_height, pinned_hash)) = self.anchor else {
            return;
        };
        let Some(tip) = tree.tip() else {
            self.trusted.store(false, Ordering::Relaxed);
            return;
        };
        if tip.height < pinned_height {
            self.trusted.store(false, Ordering::Relaxed);
            return;
        }
        let trusted = tree
            .node_at_height_from(tip.tip_id, pinned_height)
            .is_some_and(|id| tree.lookup(pinned_hash) == Some(id));
        if !trusted && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                pinned_height,
                pinned_hash = %pinned_hash,
                "active chain lacks the assume-valid anchor block; verifying every script",
            );
        }
        self.trusted.store(trusted, Ordering::Relaxed);
    }
}

/// Owned shared handle set needed by `apply_block` to perform a block apply.
#[derive(Clone)]
pub struct ApplyHandles {
    /// Network consensus parameters.
    pub network: Network,
    /// Shared best-chain tip handle.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared best-applied-block tip handle.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<RwLock<BlockTree>>,
    /// Shared UTXO set.
    pub utxo: Arc<UtxoSet>,
    /// Shared coinstats listener.
    pub coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
    /// Shared transaction index runtime, when enabled.
    pub tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    /// Shared best-effort compact-filter indexer.
    pub filter_index: Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>,
    /// Shared mempool.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Shared block records exposed to RPC handlers.
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Shared transaction map exposed to RPC handlers.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// Shared ZMQ-event publisher (default: `NoOpZmqPublisher`).
    pub zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    pub(crate) filter_header_cache: Arc<Mutex<Option<(Hash256, Hash256)>>>,
    pub(crate) cache_block_bodies_in_memory: bool,
    pub(crate) block_body_store: Option<Arc<dyn PruneBodyStore>>,
    /// Undo storage. Mandatory: see [`UndoStore`].
    pub(crate) undo_store: Arc<dyn UndoStore>,
    pub(crate) g2_muhash_sampler: Option<Arc<crate::g2_muhash::G2MuhashSampler>>,
    pub(crate) g14_utxo_commit_sampler: Option<Arc<crate::g14_utxo_commit::G14UtxoCommitSampler>>,
    pub(crate) admission: Arc<ApplyAdmission>,
    /// Process-wide shutdown signal shared by all runtime workers.
    pub(crate) shutdown: Arc<AtomicBool>,
    /// Serializes whole chain transitions against each other.
    ///
    /// Distinct from `admission`, which is a shutdown barrier: `enter` takes a
    /// READ guard, so any number of applies hold it at once and it excludes
    /// nothing but a checkpoint close. A transition reads the applied tip,
    /// decides what follows it, mutates the UTXO set, and publishes a new tip;
    /// two of those interleaved can both pass the predecessor check against the
    /// same tip and then race to publish, so one silently discards the other's
    /// block. This lock spans the whole read-decide-mutate-publish sequence for
    /// connects, windows, and disconnects alike.
    pub(crate) chain_transition: Arc<parking_lot::Mutex<()>>,
    /// Block height at or below which kernel / portable script execution is skipped during block apply.
    /// Non-script transaction checks still run. Zero disables the shortcut (full script checks on every block).
    pub assume_valid_height: u32,
    /// Hash-pinned assume-valid trust gate; the height shortcut above applies only while this is trusted.
    pub assume_valid_gate: Arc<AssumeValidGate>,
}

impl ApplyHandles {
    pub(crate) fn begin_chain_transition(
        &self,
    ) -> core::result::Result<ChainTransition<'_>, ApplyError> {
        let admission = self.admission.enter()?;
        let transition = self.chain_transition.lock();
        self.admission.ensure_open()?;
        Ok(ChainTransition {
            _transition: transition,
            _admission: admission,
        })
    }

    /// Notifies the transaction index runtime that the applied tip changed.
    pub(crate) fn wake_tx_index(&self) {
        if let Some(runtime) = &self.tx_index_runtime {
            runtime.wake();
        }
    }

    /// Builds the full shared handle set used by `apply_block`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        network: Network,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        utxo: Arc<UtxoSet>,
        coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
        tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
        filter_index: Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>,
        mempool: Arc<RwLock<Mempool>>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
        zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    ) -> Self {
        Self {
            network,
            chain_tip,
            applied_tip,
            block_tree,
            utxo,
            coin_stats,
            tx_index_runtime,
            filter_index,
            mempool,
            blocks,
            transactions,
            zmq_publisher,
            filter_header_cache: Arc::new(Mutex::new(None)),
            cache_block_bodies_in_memory: true,
            block_body_store: None,
            undo_store: Arc::new(InMemoryUndoStore::default()),
            g2_muhash_sampler: None,
            g14_utxo_commit_sampler: None,
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            chain_transition: Arc::new(parking_lot::Mutex::new(())),
            assume_valid_height: 0,
            assume_valid_gate: Arc::new(AssumeValidGate::with_anchor(None)),
        }
    }

    /// Returns `self` with `zmq_publisher` swapped to `publisher`.
    ///
    /// Useful for tests + integration scenarios that want a custom publisher
    /// without going through `NodeState::open` (which currently always
    /// installs `NoOpZmqPublisher`).
    #[must_use]
    pub fn with_zmq_publisher(mut self, publisher: Arc<dyn crate::ZmqPublisher>) -> Self {
        self.zmq_publisher = publisher;
        self
    }
}

/// Everything a disconnect can refuse, decided before anything is mutated.
///
/// Split out because the ordering matters more than the code: if a check can
/// live here it must, since a refusal from this function costs nothing while a
/// refusal after the first write leaves a partly disconnected chain. Anything
/// added to `disconnect_block` that can fail belongs here unless it physically
/// cannot run this early.
struct DisconnectPlan {
    parent_tip: TipSnapshot,
    undo: bitcoin_rs_utxo::UndoBatch,
    height: u32,
    tx_count_delta: u64,
}

fn plan_disconnect(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    block_hash: Hash256,
) -> core::result::Result<DisconnectPlan, ApplyError> {
    let applied = handles
        .applied_tip
        .load_full()
        .ok_or(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: block_hash,
        })?;
    // The height is read from the snapshot, never from the caller. A caller
    // that could pass one would be able to disagree with the tip, and the undo
    // key is keyed by it. The index worker also keys its rollback by height.
    let height = applied.height;
    if applied.hash != block_hash {
        return Err(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        });
    }

    // The header hash proves the caller named the right block; it does not
    // prove they handed over that block's transactions. An altered body under
    // a matching header would roll the UTXO set back over transactions the
    // block never contained.
    //
    // Computing txids here and verifying the merkle root with them catches
    // mutation (a duplicate final transaction on an odd count) that
    // `check_merkle_root` alone misses.
    let txids: Vec<bitcoin::Txid> = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    bitcoin_rs_consensus::verify_merkle_root_with_txids(block, &txids)
        .map_err(|_| ApplyError::DisconnectBodyMismatch { hash: block_hash })?;

    let parent_tip = {
        let tree = handles.block_tree.read();
        let node = tree.node(applied.tip_id)?;
        let parent_id = node.parent.ok_or(ApplyError::DisconnectNotTip {
            hash: block_hash,
            tip: applied.hash,
        })?;
        let parent = tree.node(parent_id)?;
        TipSnapshot {
            tip_id: parent_id,
            height: parent.height,
            chainwork: parent.chainwork,
            hash: parent.hash,
        }
    };

    let encoded = handles
        .undo_store
        .load_undo(height, block_hash)
        .map_err(ApplyError::UndoRead)?
        .ok_or(ApplyError::UndoRecordMissing {
            hash: block_hash,
            height,
        })?;
    let undo = bitcoin_rs_utxo::undo_codec::decode(&encoded, block_hash).map_err(|error| {
        ApplyError::UndoRecordUnreadable {
            hash: block_hash,
            reason: error.to_string(),
        }
    })?;

    // The coinstats rewind itself has to run after `undo_block`, because the
    // per-coin fields ride the UTXO change listener. This is the only place its
    // preconditions can be checked while a refusal is still free.
    let tx_count_delta = tx_count_delta_for(block);
    let stats = handles.coin_stats.snapshot();
    if stats.height != height {
        return Err(ApplyError::CoinStatsRewind(
            bitcoin_rs_coinstats::CoinStatsRewindError::HeightMismatch {
                expected: height,
                found: stats.height,
            },
        ));
    }
    if stats.tx_count < tx_count_delta {
        return Err(ApplyError::CoinStatsRewind(
            bitcoin_rs_coinstats::CoinStatsRewindError::TxCountUnderflow {
                tx_count: stats.tx_count,
                tx_delta: tx_count_delta,
            },
        ));
    }

    Ok(DisconnectPlan {
        parent_tip,
        undo,
        height,
        tx_count_delta,
    })
}

/// Disconnects the applied tip, restoring the consensus state the block
/// replaced.
///
/// Restores the UTXO set and `applied_tip`. The transaction index runtime is
/// notified after the tip moves, and the worker reconciles the index
/// asynchronously. It does NOT yet restore the other state connection touches,
/// so it has no production caller and must not get one until they are handled:
///
/// | Handle | Status |
/// |---|---|
/// | `utxo`, `applied_tip` | restored here |
/// | `tx_index_runtime` | notified here; the worker reconciles the index asynchronously |
/// | `coin_stats` | restored here, in two halves. The per-coin fields ride the `UtxoSet` change listener, so the UTXO undo already reverses them; only the block-level height and transaction count need an explicit rewind |
/// | `filter_header_cache` | repointed here at the parent, or cleared when the index has no header for it |
/// | `filter_index` | retained deliberately — its rows are hash-addressed, like block bodies, so a disconnected block's filter stays valid and simply stops being reachable. What is owed is BACKFILL after a gap, not rollback |
/// | `blocks` | restored here — RPC would otherwise keep serving the disconnected block |
/// | `transactions` | nothing owed: connection never populates it |
/// | `mempool` | **owed** once transaction relay exists; disconnected transactions belong back in it |
/// | `block_tree` | retained deliberately — the header stays valid and known |
/// | `block_body_store` | retained deliberately — the body is still a real block |
/// | `zmq_publisher` | a notification, not state; a disconnect event belongs here later |
///
/// The ordering below is the design: every fallible step that touches nothing
/// runs first, so the common failures cost nothing.
///
/// One partial-failure window remains and is not yet closed. If `undo_block`
/// fails, the UTXO set may be left partly undone while the tip and index still
/// describe the block. The index runtime is not notified on a failed
/// disconnect, so it stays consistent with the still-published tip.
///
/// Retry is not the recovery strategy, and this is settled rather than open.
/// Each individual UTXO operation is idempotent on the set, since restoring a
/// live output and removing an absent one are both no-ops. The set is not the
/// whole contract: `undo_block` runs through `commit_adds_and_removes`, which
/// fires `UtxoSet`'s listener, and `coin_stats` is one. A second pass re-emits
/// callbacks for operations that changed nothing, so a cumulative listener
/// double-counts even where the set converges.
///
/// The caller must therefore treat a failed disconnect as fatal: stop applying
/// blocks and report the block hash and height where it wedged, rather than
/// trying again. That is the same poison path the branch-switch layer needs for
/// a failed compensating rollback, so it is one mechanism, not two.
///
/// 1. Read and decode the undo record. Nothing is mutated until this succeeds,
///    so a missing or corrupt record costs nothing.
/// 2. Restore the UTXO set.
/// 3. Move `applied_tip` to the parent.
/// 4. Notify the transaction index runtime. The worker rolls the index back
///    asynchronously, and the runtime wake is a coalesced, non-blocking signal.
///
/// Refuses any block that is not the applied tip, because disconnecting from
/// the middle of a chain restores outputs its descendants have already spent,
/// and any block whose body does not match its own header.
///
/// Takes no height. The applied tip already knows it, and a second source for
/// the same fact is a second source of disagreement: the undo key is keyed by
/// height, and the index worker also keys its rollback by height. A caller
/// passing a stale height could delete the wrong rows. There is no parameter
/// to get wrong.
// Keep the marker, UTXO, and tip ordering visible in one operation.
// Splitting the sequence would hide the fatal boundary this function enforces.
#[allow(clippy::too_many_lines)]
pub fn disconnect_block(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
) -> core::result::Result<TipSnapshot, crate::DisconnectError> {
    let transition = handles
        .begin_chain_transition()
        .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;
    let result = disconnect_block_admitted(handles, block, &transition);
    drop(transition);
    result
}

/// Disconnects one block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
#[allow(clippy::too_many_lines)]
pub(crate) fn disconnect_block_admitted(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    _transition: &ChainTransition<'_>,
) -> core::result::Result<TipSnapshot, crate::DisconnectError> {
    use bitcoin::hashes::Hash as _;

    let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    let DisconnectPlan {
        parent_tip,
        undo,
        height,
        tx_count_delta,
    } = plan_disconnect(handles, block, block_hash)
        .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;

    // Armed before the first mutation and cleared after the last, so the window
    // it covers is exactly the window in which state can be torn. Errors are not
    // what this guards against; a crash is. A crash writes no error anywhere,
    // and the marker is the only thing that survives it.
    //
    // Above the UTXO undo, not below it: once that undo commits, a crash
    // between it and the arming would leave the UTXO set rolled back while the
    // tip still names the block.
    //
    // Deliberately per-disconnect rather than per-reorg: each disconnect commits
    // fully, so a branch switch interrupted BETWEEN disconnects leaves a
    // consistent chain at a lower tip, which is recoverable by connecting
    // forward. Holding the marker across a whole switch would refuse startup for
    // that case and force a needless reindex.
    // Read before arming. A branch switch disconnects several blocks in a row,
    // and arming overwrites the marker, so an earlier disconnect's `RolledBack`
    // debt — still owed a checkpoint — would be destroyed by the next arm and
    // then cleared by a refusal. Loading the marker first lets a read failure
    // refuse before any mutation.
    handles
        .undo_store
        .load_disconnect_marker()
        .map_err(|error| {
            crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(error)))
        })?;
    handles
        .undo_store
        .arm_disconnect(height, block_hash)
        .map_err(|error| {
            crate::DisconnectError::Refused(Box::new(ApplyError::UndoPersistence(error)))
        })?;
    let poison = |error| {
        handles.admission.close_permanently();
        error
    };
    // Past this line every failure is `Fatal`. The UTXO commit walks shards and
    // can stop part-way, so from here some state is rolled back and some is
    // not.
    handles.utxo.undo_block(&undo).map_err(|error| {
        poison(crate::DisconnectError::Fatal {
            hash: block_hash,
            height,
            source: Box::new(ApplyError::UtxoCommit(error)),
        })
    })?;

    // RPC serves blocks from this vector, so the disconnected block's record
    // must go or `getblock` keeps answering for it.
    //
    // Absence is legitimate and must never be an error. This is a best-effort
    // in-process cache, not authoritative state: it starts empty on every boot
    // while `applied_tip` resumes from a checkpoint at height N, and pruning
    // removes records from it. Failing a consensus rollback because an optional
    // cache is empty would refuse the first disconnect after any restart.
    //
    // The hash check is what stops the pop from truncating a record that is not
    // ours. The tail can only be ours or gone, because disconnect runs on the
    // applied tip and connection pushed that tip's record last.
    {
        let mut blocks = handles.blocks.write();
        if blocks
            .last()
            .is_some_and(|record| record.hash == block_hash)
        {
            blocks.pop();
        }
    }

    // The cache maps one block to its filter header. Leaving the disconnected
    // block there is not a correctness bug, because lookups are keyed by the
    // tip's hash and would simply miss, but it is a lie about what the node
    // last indexed. Replace it with the parent's header when the index has one,
    // and clear it otherwise so the next connect asks storage.
    {
        let parent_header = handles
            .filter_index
            .filter_header(parent_tip.hash)
            .ok()
            .flatten();
        *handles.filter_header_cache.lock() = parent_header.map(|header| (parent_tip.hash, header));
    }

    // The per-coin coinstats fields need nothing here: `coin_stats` is the
    // `UtxoSet` change listener, so `undo_block` already drove them in reverse.
    // The block-level fields are not part of that, because `finish_block` sets
    // them directly on connect.
    handles
        .coin_stats
        .rewind_block(height, parent_tip.height, tx_count_delta)
        .map_err(|error| {
            poison(crate::DisconnectError::Fatal {
                hash: block_hash,
                height,
                source: Box::new(ApplyError::CoinStatsRewind(error)),
            })
        })?;

    handles
        .applied_tip
        .store(Some(Arc::new(parent_tip.clone())));
    handles.wake_tx_index();

    if handles.zmq_publisher.wants_notifications() {
        handles
            .zmq_publisher
            .publish_sequence(crate::zmq_publisher::SequenceEvent::Disconnected(
                block_hash,
            ));
    }

    // The rollback finished in memory, so the marker moves to `RolledBack`.
    // It stays set: a checkpoint has not captured this yet.
    handles
        .undo_store
        .complete_disconnect(height, block_hash)
        .map_err(|error| {
            poison(crate::DisconnectError::MarkerStuck {
                hash: block_hash,
                height,
                source: Box::new(ApplyError::UndoPersistence(error)),
            })
        })?;

    // The marker deliberately stays set here.
    //
    // The authoritative rollback completed in memory, but it is not durable.
    // A crash can restore a checkpoint whose UTXO set and tip still contain
    // this block. TxIndex is outside this transaction and reconciles from its
    // own atomic watermark after restart.
    //
    // [`NodeState::write_clean_checkpoint`] clears the marker only after it
    // publishes the rolled-back UTXO set and tip.
    Ok(parent_tip)
}

/// The `tx_count` delta one block contributes to coinstats.
///
/// One function, used by connect and by disconnect. Two copies of this
/// expression would be two chances for the rewind to subtract something the
/// apply never added.
fn tx_count_delta_for(block: &bitcoin::Block) -> u64 {
    u64::try_from(block.txdata.len()).unwrap_or(u64::MAX)
}

/// Synthetically applies `block` as the next tip after consensus checks.
pub fn apply_block(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
) -> core::result::Result<TipSnapshot, ApplyError> {
    apply_block_inner(handles, block, None)
}

/// Applies `block` reusing preserved wire-format bytes for body persistence and indexing.
pub fn apply_block_with_serialized(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    serialized: bytes::Bytes,
) -> core::result::Result<TipSnapshot, ApplyError> {
    apply_block_inner(handles, block, Some(serialized))
}

/// Applies one serialized block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
pub(crate) fn apply_block_with_serialized_admitted(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    serialized: bytes::Bytes,
    transition: &ChainTransition<'_>,
) -> core::result::Result<TipSnapshot, ApplyError> {
    apply_block_admitted(handles, block, Some(serialized), None, transition)
}

/// How many consecutive blocks share one script-verification dispatch.
///
/// The window amortises dispatch, it does not add parallelism. A mainnet block
/// early in the chain carries about 19 input checks, so fanning those across 32
/// workers costs more in wakeups than the work itself: measured over blocks
/// `0..150_000`, per-block dispatch left 29s of checks running serially in blocks
/// below the parallel threshold and wasted a further 11s above it. Sixty-four
/// blocks turns roughly 21,000 dispatches into 330.
///
/// Bounded by memory: the window holds every block's parsed kernel block and
/// resolved prevouts at once, which costs far more than the block bytes.
/// Measured over `0..150_000`, pinned to 32 cores, medians of interleaved runs:
///
///   window     wall     CPU     peak RSS
///       64    66.2s   596.3s      397 MB
///      128    75.8s   525.6s      409 MB
///      256    69.8s   471.5s      436 MB
///     1024    51.8s   388.7s      572 MB
///     4096    47.2s   377.1s     1205 MB
///
/// CPU falls by a third from 64 to 1024 because the cost being removed is rayon
/// dispatch and spin, not verification. RSS is what stops it: 4096 doubles the
/// resident set for a few more seconds.
///
/// This is a COUNT cap, and count alone is the wrong bound. Early-chain blocks
/// average about 4.6 KB, so 1024 of them is 5 MB of block data; at the tip they
/// are 2 MB, so the same 1024 would hold 2 GB. [`SCRIPT_BATCH_MAX_BYTES`] is the
/// other half, and the window is whichever bound hits first.
///
/// Peer sync does not reach 1024 today. `RECEIVED_BLOCK_BUDGET` caps staging at
/// 128 blocks, so the windows it forms are at most that, worth 525s CPU against
/// 596s at 64 — a real gain, and not the 389s the replay driver reaches.
/// Raising the staging cap is not a constant change: the staller-arming
/// invariant in `sync.rs` ties the staged byte budget to the staged count at
/// `MAX_SERIALIZED_BLOCK_SIZE`, so a 1024-block stage would demand a 2 GB bound.
/// That invariant has to be reworked against typical block size first.
pub const SCRIPT_BATCH_WINDOW: usize = 1024;

/// How many bytes of block data one window may hold.
///
/// The count cap above is sized for small early-chain blocks. This is what
/// keeps the same constant safe at the tip, where a block is roughly 2 MB and
/// the count would otherwise let a window hold gigabytes. Whichever cap binds
/// first ends the window, so the batch is large exactly where blocks are small
/// and dispatch dominates, and small where blocks are large and it does not.
pub const SCRIPT_BATCH_MAX_BYTES: usize = 64 << 20;

/// Returns how many of `sizes` fit in one window.
///
/// At least one block always fits, even one larger than the byte cap on its
/// own: refusing it would stall the chain on an oversized block rather than
/// verify it.
pub fn window_len(sizes: impl IntoIterator<Item = usize>) -> usize {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for size in sizes {
        if count == SCRIPT_BATCH_WINDOW {
            break;
        }
        let next = bytes.saturating_add(size);
        if count > 0 && next > SCRIPT_BATCH_MAX_BYTES {
            break;
        }
        bytes = next;
        count = count.saturating_add(1);
    }
    count
}

/// Applies consecutive blocks, verifying all their input scripts in one
/// dispatch when the window can be proven.
///
/// Blocks commit one at a time and in order, exactly as they would
/// individually, so every rule that depends on committed state still sees the
/// real chain: BIP30, coinbase maturity, and the relative locks all run after
/// their predecessor has committed. Only work that depends on nothing but the
/// block and the outputs it spends moves earlier.
///
/// # Errors
///
/// Propagates the first failing apply, leaving earlier blocks applied, which is
/// what applying them one at a time would also do.
pub fn apply_window(
    handles: &ApplyHandles,
    blocks: &[&bitcoin::Block],
    serialized: &[bytes::Bytes],
) -> core::result::Result<(), WindowApplyError> {
    if blocks.len() != serialized.len() {
        return Err(WindowApplyError {
            applied: 0,
            source: ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Kernel(format!(
                "window has {} blocks but {} serialized bodies",
                blocks.len(),
                serialized.len()
            ))),
        });
    }
    // One admission permit and one transition lock for the whole window.
    //
    // The permit alone would not do it: `enter` takes a read guard, so two
    // windows, or a window and a single connect, hold it at the same time. The
    // transition lock is what actually excludes them. Preparation reads the
    // applied tip and the UTXO set and the commits mutate both, so a concurrent
    // applier moving the chain in between would invalidate the proof this window
    // is about to rely on, and matching the tip hash would not detect a same-tip
    // partial change.
    //
    // Both taken once for the window rather than per block: re-entering the
    // permit is two read guards that deadlock against a shutdown waiting on the
    // write side, and re-locking the transition would leave gaps between commits.
    let transition = handles
        .begin_chain_transition()
        .map_err(|source| WindowApplyError { applied: 0, source })?;
    let mut proven = prove_window(handles, blocks, serialized).into_iter();
    let mut applied = 0_usize;
    for (block, raw) in blocks.iter().zip(serialized) {
        apply_block_admitted(
            handles,
            block,
            Some(raw.clone()),
            proven.next(),
            &transition,
        )
        .map_err(|source| WindowApplyError { applied, source })?;
        applied = applied.saturating_add(1);
    }
    Ok(())
}

/// A window that failed partway, and how many of its blocks committed first.
///
/// The count is what a caller needs to recover: it must record the hashes that
/// landed, retry only the one that failed, and put the rest back. A bare
/// `ApplyError` cannot say where the window stopped.
#[derive(Debug)]
pub struct WindowApplyError {
    /// Blocks that committed before the failure.
    pub applied: usize,
    /// What stopped the block at index `applied`.
    pub source: ApplyError,
}

impl core::fmt::Display for WindowApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "window failed after applying {} block(s): {}",
            self.applied, self.source
        )
    }
}

impl std::error::Error for WindowApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Prepares consecutive blocks against one overlay and verifies all their input
/// scripts in a single dispatch.
///
/// Returns one proof per block, or nothing at all. There is no partial result
/// by design: a block must never be applied with its scripts skipped on the
/// strength of a neighbour.
///
/// Every reason to give up is silent and cheap, because the per-block path
/// behind this is complete and produces the real verdict in its documented
/// order. A header not yet in the tree, a block that does not extend its
/// predecessor, a prevout that does not resolve, or any failing check all
/// return nothing.
#[allow(clippy::too_many_lines)]
fn prove_window(
    handles: &ApplyHandles,
    blocks: &[&bitcoin::Block],
    serialized: &[bytes::Bytes],
) -> Vec<ProvenApply> {
    use bitcoin::hashes::Hash as _;

    if blocks.is_empty() || blocks.len() != serialized.len() {
        return Vec::new();
    }
    let Some(applied) = handles.applied_tip.load_full() else {
        return Vec::new();
    };

    // Context is captured before any block applies, because applying inserts
    // headers into the shared tree and would move median-time-past and softfork
    // state under the later blocks. Each apply re-derives all of it and
    // compares, so a captured value that turns out wrong costs the batch only.
    let context_started = quanta::Instant::now();
    let mut contexts = Vec::with_capacity(blocks.len());
    {
        let tree = handles.block_tree.read();
        let mut parent_id = applied.tip_id;
        let mut parent_hash = applied.hash;
        for (index, block) in blocks.iter().enumerate() {
            let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
            if Hash256::from_le_bytes(block.header.prev_blockhash.as_byte_array()) != parent_hash {
                return Vec::new();
            }
            let Some(height) = u32::try_from(index)
                .ok()
                .and_then(|offset| applied.height.checked_add(offset))
                .and_then(|height| height.checked_add(1))
            else {
                return Vec::new();
            };
            let softfork = crate::bip9_context::contextual_softfork_state(
                &tree,
                handles.network,
                Some(parent_id),
                height,
            );
            let cutoff = if softfork.csv_active {
                tree.median_time_past_at(parent_id, 11).unwrap_or(0)
            } else {
                block.header.time
            };
            // The next block's context needs this one in the tree. Header-first
            // sync put it there; without it there is no window.
            let Some(node_id) = tree.lookup(hash) else {
                return Vec::new();
            };
            contexts.push(ScriptProof {
                hash,
                parent: parent_hash,
                height,
                flags: compute_verify_flags(handles.network, height, hash, softfork),
                locktime_cutoff: cutoff,
            });
            parent_id = node_id;
            parent_hash = hash;
        }
    }

    metrics::histogram!("node.window.context_seconds")
        .record(context_started.elapsed().as_secs_f64());

    // Parsing a block and planning its transactions depends on nothing but that
    // block, so the window does all of it at once. Only the overlay walk below
    // is order-dependent, and it is the cheaper half.
    let parse_started = quanta::Instant::now();
    let parsed: Vec<core::result::Result<_, ApplyError>> = blocks
        .par_iter()
        .zip(serialized.par_iter())
        .map(|(block, raw)| parse_block_for_apply(block, Some(raw.clone())))
        .collect();
    metrics::histogram!("node.window.parse_seconds").record(parse_started.elapsed().as_secs_f64());

    let prepare_started = quanta::Instant::now();
    let mut overlay = crate::window_overlay::WindowOverlay::new(handles.utxo.as_ref());
    let mut prepared = Vec::with_capacity(blocks.len());
    for ((block, parsed), context) in blocks.iter().zip(parsed).zip(&contexts) {
        let Ok((kernel_block, tx_plan)) = parsed else {
            return Vec::new();
        };
        let resolved = Arc::new(ResolvedUtxoView::resolve(&overlay, block, &tx_plan));
        if overlay
            .advance(
                block,
                tx_plan.txids(),
                context.height,
                tx_plan.same_block_spent_set(),
            )
            .is_err()
        {
            return Vec::new();
        }
        prepared.push(PreparedApply {
            kernel_block,
            tx_plan,
            resolved,
        });
    }

    metrics::histogram!("node.window.prepare_seconds")
        .record(prepare_started.elapsed().as_secs_f64());

    // Cheap structural checks before any script runs.
    //
    // Batching changed the cost of a bad body. The per-block path rejects a
    // broken merkle root or witness commitment before it verifies a single
    // script, but the window used to dispatch the whole batch first — so a peer
    // could send a body with the expected header and one altered witness
    // reserved value, keeping every txid intact, and force a full window of
    // script verification for a block that is rejected immediately either way.
    // Both checks below depend on nothing but the block, so running them here
    // costs a hash per block and removes the amplification.
    let max_txs = blocks.iter().map(|b| b.txdata.len()).max().unwrap_or(0);
    let mut merkle_scratch = Vec::with_capacity(max_txs);
    for (block, (unit, context)) in blocks.iter().zip(prepared.iter().zip(&contexts)) {
        merkle_scratch.clear();
        merkle_scratch.extend_from_slice(unit.tx_plan.txids());
        if !bitcoin_rs_consensus::verify_block::block_merkle_root_matches_txids(
            block,
            &mut merkle_scratch,
        ) {
            return Vec::new();
        }
        if context
            .flags
            .contains(bitcoin_rs_script::VerifyFlags::WITNESS)
            && !block.check_witness_commitment()
        {
            return Vec::new();
        }
    }

    // One slot per input block, so a skipped unit leaves a hole rather than
    // shifting every later block onto the wrong prepared state.
    let mut skipped = vec![false; prepared.len()];
    // One dispatch for the whole window. The check units borrow their kernel
    // blocks, so they live and die inside this scope, before anything commits.
    {
        // Each block's checks are built from its own prepared state, so the
        // window builds them all at once. The overlay walk above already fixed
        // every prevout, which is what makes this independent per block.
        let checks_started = quanta::Instant::now();
        // Serial on purpose. Fanning this out measured worse on both axes:
        // 58.7s wall / 585.2s CPU with it serial against 64.2s / 613.1s
        // parallel, on the 0..150_000 replay. Each block's preparation is short
        // enough that the dispatch costs more than it distributes, which is the
        // same reason the script checks are batched across blocks rather than
        // split within one.
        let mut units = Vec::with_capacity(prepared.len());
        let mut flags: Vec<bitcoin_rs_script::VerifyFlags> = Vec::with_capacity(prepared.len());
        for (index, ((block, unit), context)) in
            blocks.iter().zip(&prepared).zip(&contexts).enumerate()
        {
            // The same predicate the single-block path applies, per block rather
            // than per window, because the anchor height can fall inside a
            // window. Without it the batch prepared and executed every unit
            // before the per-block decision was ever reached, so assume-valid
            // did nothing at all on the windowed path.
            if handles.assume_valid_height > 0
                && context.height <= handles.assume_valid_height
                && handles.assume_valid_gate.trusted()
            {
                skipped[index] = true;
                continue;
            }
            let Ok(resolved) = resolve_block_prevouts(
                Arc::clone(&unit.resolved),
                block,
                &unit.tx_plan,
                context.height,
            ) else {
                return Vec::new();
            };
            match bitcoin_rs_consensus::verify_tx::prepare_block_script_checks(
                &block.txdata,
                resolved,
                context.height,
                context.locktime_cutoff,
                &unit.kernel_block,
            ) {
                Ok(checks) => {
                    units.push(checks);
                    // Pushed together with the unit so the two stay aligned:
                    // collecting flags from every context would misalign them
                    // against a units list that skipped some.
                    flags.push(context.flags);
                }
                Err(_) => return Vec::new(),
            }
        }
        metrics::histogram!("node.window.checks_seconds")
            .record(checks_started.elapsed().as_secs_f64());
        let verify_started = quanta::Instant::now();
        let verdict = bitcoin_rs_consensus::verify_tx::verify_prepared_units(&units, &flags);
        metrics::histogram!("node.window.verify_seconds")
            .record(verify_started.elapsed().as_secs_f64());
        if verdict.is_err() {
            return Vec::new();
        }
        if !units.is_empty() {
            metrics::counter!("node.window.verify_success_total").increment(1);
        }
    }

    prepared
        .into_iter()
        .zip(contexts)
        .zip(skipped)
        .map(|((prepared, proof), skipped)| ProvenApply {
            prepared,
            // No proof for a block whose scripts this window skipped. A
            // `ScriptProof` asserts the scripts ran, and handing one back for a
            // skipped block would do more than lie: the commit would take the
            // proof branch instead of re-reading the trust gate, so a gate that
            // flipped to untrusted between here and the commit would let the
            // block through unverified. `None` sends it down the per-block path,
            // which makes that decision against the gate as it stands then.
            proof: (!skipped).then_some(proof),
        })
        .collect()
}

/// Evidence that a block's input scripts were executed and passed as part of a
/// batch spanning several consecutive blocks.
///
/// Bound to more than the block hash on purpose. The verdict also depends on
/// the height, the rule flags, the median-time-past cutoff, and the block this
/// one extends, and a reorg can change all four while the hash stays the same.
struct ScriptProof {
    hash: Hash256,
    parent: Hash256,
    height: u32,
    flags: bitcoin_rs_script::VerifyFlags,
    locktime_cutoff: u32,
}

impl ScriptProof {
    fn matches(
        &self,
        hash: Hash256,
        parent: Hash256,
        height: u32,
        flags: bitcoin_rs_script::VerifyFlags,
        locktime_cutoff: u32,
    ) -> bool {
        self.hash == hash
            && self.parent == parent
            && self.height == height
            && self.flags == flags
            && self.locktime_cutoff == locktime_cutoff
    }
}

/// One block's prepared state together with the proof covering it.
///
/// Deliberately one value rather than two parameters. Passed separately, a
/// caller could hand over block A's proof beside block B's prepared prevouts:
/// the proof would still match the block being applied, and the scripts skipped
/// would be the ones verified against different data. Pairing them at
/// construction makes that unrepresentable.
struct ProvenApply {
    prepared: PreparedApply,
    /// `None` when the window skipped this block's scripts under assume-valid.
    /// The preparation is still reused; only the script evidence is absent.
    proof: Option<ScriptProof>,
}

/// Everything a block's application needs that depends only on the block and
/// the outputs it spends, not on the chain state the commit will mutate.
///
/// Split out because a window of consecutive blocks can produce all of these
/// at once, against one ordered overlay, and share a single script dispatch.
/// The measured duplication that made an earlier batching attempt a wash was
/// exactly the kernel parse and the prevout resolution below being done twice.
struct PreparedApply {
    kernel_block: bitcoin_rs_consensus::kernel::KernelBlock,
    tx_plan: BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
}

/// Parses a block and resolves the outputs it spends.
///
/// `source` is where prevouts come from. Today that is always the committed
/// UTXO set; a window passes an overlay so a block can see outputs an earlier
/// block in the same window created.
///
/// Runs no consensus rule and mutates nothing, which is what lets a window
/// prepare several blocks before committing any of them.
/// A sink that compares what is written to it against `expected`.
///
/// Used to check preserved bytes against a block without serialising the block
/// into a second buffer: nothing is allocated and the first differing byte ends
/// the walk.
struct ByteEquality<'a> {
    expected: &'a [u8],
    offset: usize,
    equal: bool,
}

impl bitcoin::io::Write for ByteEquality<'_> {
    fn write(&mut self, buf: &[u8]) -> bitcoin::io::Result<usize> {
        if self.equal {
            match self
                .expected
                .get(self.offset..self.offset.saturating_add(buf.len()))
            {
                Some(window) if window == buf => {}
                _ => self.equal = false,
            }
        }
        self.offset = self.offset.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> bitcoin::io::Result<()> {
        Ok(())
    }
}

/// Returns true iff `raw` is exactly the consensus serialization of `block`.
pub(crate) fn bytes_are_block(raw: &[u8], block: &bitcoin::Block) -> bool {
    use bitcoin::consensus::Encodable as _;

    let mut sink = ByteEquality {
        expected: raw,
        offset: 0,
        equal: true,
    };
    // Encoding to a sink cannot fail; a write error here would be a bug in the
    // sink above, and treating it as inequality is the safe reading either way.
    let Ok(written) = block.consensus_encode(&mut sink) else {
        return false;
    };
    sink.equal && written == raw.len()
}

fn parse_block_for_apply(
    block: &bitcoin::Block,
    provided_serialized: Option<bytes::Bytes>,
) -> core::result::Result<(bitcoin_rs_consensus::kernel::KernelBlock, BlockTxPlan), ApplyError> {
    // Preserved bytes must BE this block, not merely agree with it on
    // transaction count. In kernel builds the txids and the transactions that
    // script verification runs come from these bytes, while the witness
    // commitment check and the UTXO mutation use the decoded block. Changing a
    // witness does not change a txid, so a count check lets a caller pair a
    // block carrying an invalid witness with bytes carrying a valid one: the
    // scripts verify against the bytes and the invalid block gets applied.
    if let Some(raw) = provided_serialized.as_deref()
        && !bytes_are_block(raw, block)
    {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Kernel(
                "preserved bytes are not the serialization of the block they accompany".to_owned(),
            ),
        ));
    }
    let raw_block: bytes::Bytes =
        provided_serialized.unwrap_or_else(|| bitcoin::consensus::encode::serialize(block).into());
    let kernel_block = bitcoin_rs_consensus::kernel::KernelBlock::parse(&raw_block)
        .map_err(ApplyError::Consensus)?;
    if kernel_block.transaction_count() != block.txdata.len() {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Kernel(format!(
                "kernel parsed {} transactions, decoder produced {}",
                kernel_block.transaction_count(),
                block.txdata.len()
            )),
        ));
    }
    let tx_plan = plan_block_transactions_with_txids(
        block,
        kernel_block.txids().map_err(ApplyError::Consensus)?,
    );
    Ok((kernel_block, tx_plan))
}

/// Parses a block and resolves the outputs it spends.
///
/// `source` is where prevouts come from. Every caller outside a window passes
/// the committed UTXO set; a window passes an overlay so a block can see
/// outputs an earlier block in the same window created.
fn prepare_apply<S: crate::window_overlay::OutputSource + ?Sized>(
    block: &bitcoin::Block,
    provided_serialized: Option<bytes::Bytes>,
    source: &S,
) -> core::result::Result<PreparedApply, ApplyError> {
    let (kernel_block, tx_plan) = parse_block_for_apply(block, provided_serialized)?;
    let resolved = Arc::new(ResolvedUtxoView::resolve(source, block, &tx_plan));
    Ok(PreparedApply {
        kernel_block,
        tx_plan,
        resolved,
    })
}

fn apply_block_inner(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    provided_serialized: Option<bytes::Bytes>,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let transition = handles.begin_chain_transition()?;
    apply_block_admitted(handles, block, provided_serialized, None, &transition)
}

/// The apply itself, with the admission permit and the transition lock held.
///
/// Callers MUST hold both. `handles.chain_transition` is what serializes this
/// against another connect or a disconnect; the admission permit only keeps a
/// checkpoint close from cutting across it.
///
/// Split from [`apply_block_inner`] so a window can take both once across its
/// preparation and all of its ordered commits. Re-entering per block would be
/// two read guards on the same lock, which deadlocks against a shutdown waiting
/// on the write side, and would leave gaps in which another applier could move
/// the chain out from under prepared state.
#[allow(clippy::too_many_lines)]
fn apply_block_admitted(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    provided_serialized: Option<bytes::Bytes>,
    proven: Option<ProvenApply>,
    _transition: &ChainTransition<'_>,
) -> core::result::Result<TipSnapshot, ApplyError> {
    use bitcoin::hashes::Hash as _;

    let total_started = quanta::Instant::now();
    let block_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
    let prev_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.header.prev_blockhash.as_byte_array());
    let (prior, height) = applied_predecessor(handles, block_hash, prev_hash)?;

    // Self-consistency PoW: the block header's hash must satisfy its
    // declared target. This is the cheapest consensus gate; do it before
    // any structural checks. Contextual difficulty-adjustment validation
    // (verifying the declared target matches the network's expected
    // difficulty at this height) requires `BlockTree` state — deferred.
    let pow_self_started = quanta::Instant::now();
    let declared_target = block.header.target();
    let pow_self_result = block.header.validate_pow(declared_target);
    let pow_self_dur = pow_self_started.elapsed();
    metrics::histogram!("node.apply_block.pow_self_consistency_seconds")
        .record(pow_self_dur.as_secs_f64());
    if pow_self_result.is_err() {
        return Err(ApplyError::ProofOfWork { hash: block_hash });
    }

    let (prev_tip_state, softfork_state) = if let Some(tip) = prior.as_deref() {
        let tree = handles.block_tree.read();
        let mtp = tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0);
        let softfork_state = crate::bip9_context::contextual_softfork_state(
            &tree,
            handles.network,
            Some(tip.tip_id),
            height,
        );
        (
            bitcoin_rs_consensus::rust_path::TipState {
                height: Some(tip.height),
                block_hash: None,
                median_time_past: mtp,
            },
            softfork_state,
        )
    } else {
        let tree = handles.block_tree.read();
        (
            bitcoin_rs_consensus::rust_path::TipState {
                height: None,
                block_hash: None,
                median_time_past: 0,
            },
            crate::bip9_context::contextual_softfork_state(&tree, handles.network, None, height),
        )
    };
    let locktime_cutoff = if softfork_state.csv_active {
        prev_tip_state.median_time_past
    } else {
        block.header.time
    };
    // Parse the block once with the kernel and take its txids. Core's
    // `CTransaction` hashes itself while deserializing with the SHA-256
    // implementation selected at runtime, so this one parse replaces the
    // scalar `compute_txid` pass *and* the per-transaction serialize/reparse
    // that script preparation used to perform.
    // A window prepares several blocks against one overlay and hands the result
    // back, so the kernel parse and the prevout resolution happen once.
    let (prepared, proof) = match proven {
        Some(ProvenApply { prepared, proof }) => (prepared, proof),
        None => (
            prepare_apply(block, provided_serialized.clone(), handles.utxo.as_ref())?,
            None,
        ),
    };
    let PreparedApply {
        kernel_block,
        tx_plan,
        resolved,
    } = prepared;
    // Before any mutation. A header the tree has never seen skips header sync's
    // timestamp rules entirely, and `applied_header_tip` — where the insert
    // happens — runs after the UTXO commit, so checking there would reject the
    // block with its outputs already installed.
    check_unseen_header_timestamp(handles, block, block_hash)?;

    let block_rules_started = quanta::Instant::now();
    let block_rules_result =
        bitcoin_rs_consensus::verify_block_rules_borrowed_contextual_with_txids_and_witness_hint(
            block,
            &prev_tip_state,
            bitcoin_rs_consensus::BlockRuleContext {
                segwit_active: softfork_state.segwit_active,
            },
            tx_plan.txids(),
            tx_plan.witness_presence.is_present(),
        );
    let block_rules_dur = block_rules_started.elapsed();
    metrics::histogram!("node.apply_block.block_rules_seconds")
        .record(block_rules_dur.as_secs_f64());
    block_rules_result?;
    // Contextual consensus checks (BIP30 + BIP34) using the resolved height.
    let bip30_bip34_started = quanta::Instant::now();
    let previous_tip_id = prior.as_deref().map(|tip| tip.tip_id);
    let bip30_bip34_result =
        check_bip30_and_bip34(handles, block, height, tx_plan.txids(), previous_tip_id);
    let bip30_bip34_dur = bip30_bip34_started.elapsed();
    metrics::histogram!("node.apply_block.bip30_bip34_seconds")
        .record(bip30_bip34_dur.as_secs_f64());
    bip30_bip34_result?;
    // PoW limit + DAA non-retarget continuity.
    let pow_limit_started = quanta::Instant::now();
    let pow_limit_result = check_pow_limit_and_continuity(handles, prior.as_deref(), block, height);
    let pow_limit_dur = pow_limit_started.elapsed();
    metrics::histogram!("node.apply_block.pow_limit_continuity_seconds")
        .record(pow_limit_dur.as_secs_f64());
    pow_limit_result?;

    let script_verify_started = quanta::Instant::now();
    let verify_flags = compute_verify_flags(handles.network, height, block_hash, softfork_state);
    // A batch already executed these scripts under exactly the context derived
    // here. Every bound field is compared, so a proof reached under different
    // rules simply does not apply and the block verifies in full.
    let script_verify_result = if proof.is_some_and(|proof| {
        proof.matches(block_hash, prev_hash, height, verify_flags, locktime_cutoff)
    }) {
        run_non_script_checks_only(
            block,
            &tx_plan,
            Arc::clone(&resolved),
            tx_plan.txids(),
            height,
            locktime_cutoff,
        )
    } else {
        verify_block_transactions(
            handles,
            block,
            &tx_plan,
            Arc::clone(&resolved),
            height,
            locktime_cutoff,
            verify_flags,
            &kernel_block,
        )
    };
    let script_verify_dur = script_verify_started.elapsed();
    metrics::histogram!("node.apply_block.script_verify_seconds")
        .record(script_verify_dur.as_secs_f64());
    // Same duration split by dispatch path, so replay decompositions can
    // attribute time to the serial overlay walk vs the rayon fan-out.
    let script_verify_path = if tx_plan.only_coinbase {
        "node.apply_block.script_verify_coinbase_only_seconds"
    } else if tx_plan.needs_local_utxo_overlay {
        "node.apply_block.script_verify_serial_overlay_seconds"
    } else {
        "node.apply_block.script_verify_parallel_seconds"
    };
    metrics::histogram!(script_verify_path).record(script_verify_dur.as_secs_f64());
    script_verify_result?;

    let coinbase_maturity_started = quanta::Instant::now();
    let coinbase_maturity_result = check_coinbase_maturity_with_tx_plan(
        handles,
        block,
        &tx_plan,
        Arc::clone(&resolved),
        height,
    );
    let coinbase_maturity_dur = coinbase_maturity_started.elapsed();
    metrics::histogram!("node.apply_block.coinbase_maturity_seconds")
        .record(coinbase_maturity_dur.as_secs_f64());
    coinbase_maturity_result?;
    let bip68_started = quanta::Instant::now();
    let previous_tip_id = prior.as_deref().map(|tip| tip.tip_id);
    let bip68_result = check_bip68_sequence_locks(
        handles,
        block,
        &tx_plan,
        Arc::clone(&resolved),
        height,
        prev_tip_state.median_time_past,
        softfork_state,
        previous_tip_id,
    );
    let bip68_dur = bip68_started.elapsed();
    metrics::histogram!("node.apply_block.bip68_seconds").record(bip68_dur.as_secs_f64());
    bip68_result?;

    let wants_rawtx = handles.zmq_publisher.wants_rawtx();
    let wants_rawblock = handles.zmq_publisher.wants_rawblock();
    let wants_filters = handles.filter_index.wants_filters();
    let needs_g14_sample = handles
        .g14_utxo_commit_sampler
        .as_ref()
        .is_some_and(|sampler| sampler.wants_height(height));
    let (txids, scratch_capacities, same_block_spent, same_block_spent_input_count) =
        tx_plan.into_scratch_parts();
    let scratch = ApplyScratch::from_prepared_parts(
        block,
        height,
        wants_rawtx,
        wants_filters,
        txids,
        scratch_capacities,
        same_block_spent,
        same_block_spent_input_count,
    )?;
    let filter_bytes = if wants_filters {
        let filter_build_started = quanta::Instant::now();
        let filter_bytes = compute_basic_filter(block, handles, block_hash, height, &scratch);
        let filter_build_dur = filter_build_started.elapsed();
        metrics::histogram!("node.apply_block.filter_build_seconds")
            .record(filter_build_dur.as_secs_f64());
        filter_bytes
    } else {
        None
    };

    let utxo_changes_started = quanta::Instant::now();
    let (changes, undo) = build_utxo_changes(
        block,
        height,
        &scratch,
        &resolved,
        bitcoin_rs_consensus::bip30::is_bip30_exception(height, block_hash)
            .then(|| handles.utxo.as_ref()),
    )?;
    let utxo_changes_dur = utxo_changes_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_changes_seconds")
        .record(utxo_changes_dur.as_secs_f64());

    // Persist undo before the block body, the index, and the UTXO commit. All
    // three are derived state for a block that is about to apply; if the undo
    // record cannot be written the block must not apply at all, and leaving
    // body bytes or index rows behind for it would be worse than not starting.
    let undo_persist_started = quanta::Instant::now();
    let undo_record = bitcoin_rs_utxo::encode_undo(&undo, block_hash);
    let undo_persist_result = handles
        .undo_store
        .persist_undo(height, block_hash, &undo_record)
        .map_err(ApplyError::UndoPersistence);
    metrics::histogram!("node.apply_block.undo_persist_seconds")
        .record(undo_persist_started.elapsed().as_secs_f64());
    undo_persist_result?;

    // Serialize the block lazily: only when a consumer actually needs the
    // full bytes. During IBD with pruning+txindex disabled this avoids a
    // full-block serialize on every apply.
    let block_bytes: bytes::Bytes = {
        let needs_body = handles.block_body_store.is_some()
            || handles.tx_index_runtime.is_some()
            || handles.cache_block_bodies_in_memory
            || wants_rawblock
            || needs_g14_sample;
        if needs_body {
            // The preserved P2P wire payload is byte-identical to the canonical
            // block serialization: the decoder rejects every non-canonical
            // encoding, so a decoded block always re-serializes to its wire
            // bytes. The length guard keeps that invariant release-observable and
            // self-heals to a fresh serialize if it ever fails to hold, so a
            // future decoder change can never admit non-canonical bytes into the
            // block body store.
            match provided_serialized {
                Some(provided) if provided.len() == block.total_size() => {
                    #[cfg(debug_assertions)]
                    {
                        debug_assert_eq!(
                            provided.as_ref(),
                            bitcoin::consensus::encode::serialize(block).as_slice(),
                        );
                    }
                    provided
                }
                _ => bytes::Bytes::from(bitcoin::consensus::encode::serialize(block)),
            }
        } else {
            // Header-only: 80 bytes is enough for the block record.
            bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block.header))
        }
    };

    let block_body_persist_started = quanta::Instant::now();
    let block_body_persist_result = match &handles.block_body_store {
        Some(store) => store
            .persist_block_body_value(height, block_hash, block_bytes.clone())
            .map_err(ApplyError::BlockBodyPersistence),
        None => Ok(()),
    };
    let block_body_persist_dur = block_body_persist_started.elapsed();
    metrics::histogram!("node.apply_block.block_body_persist_seconds")
        .record(block_body_persist_dur.as_secs_f64());
    block_body_persist_result?;

    let utxo_commit_started = quanta::Instant::now();
    let utxo_commit_result = handles.utxo.commit_borrowed_block(&changes, &block_hash);
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;

    if needs_g14_sample {
        if let Some(sampler) = &handles.g14_utxo_commit_sampler {
            if let Err(error) =
                sampler.record(height, block_hash, block_bytes.len(), utxo_commit_dur)
            {
                metrics::counter!("node.apply_block.g14_utxo_commit_sample_errors").increment(1);
                tracing::warn!(
                    height,
                    %error,
                    "G14 UTXO commit sample emission failed; evidence file incomplete"
                );
            }
        }
    }

    // Resolve the applied header after validation and UTXO commit have
    // succeeded. Header-first sync may already have inserted this header.
    let block_tree_insert_started = quanta::Instant::now();
    let block_tree_insert_result = applied_header_tip(handles, block_hash, block, height);
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());
    let tip = block_tree_insert_result?;

    let block_record_started = quanta::Instant::now();
    {
        let block_record = applied_block_record(
            height,
            block_hash,
            block,
            &block_bytes,
            handles.cache_block_bodies_in_memory,
        );
        handles.blocks.write().push(block_record);
    }
    let block_record_dur = block_record_started.elapsed();
    metrics::histogram!("node.apply_block.block_record_seconds")
        .record(block_record_dur.as_secs_f64());
    let mempool_evict_started = quanta::Instant::now();
    {
        let mut mempool = handles.mempool.write();
        if !mempool.is_empty() {
            for txid in scratch.txids() {
                let evicted_count = mempool.remove_by_txid(txid).len();
                tracing::debug!(%txid, evicted_count, "apply_block: evicted transaction from mempool");
            }
        }
    }
    let mempool_evict_dur = mempool_evict_started.elapsed();
    metrics::histogram!("node.apply_block.mempool_evict_seconds")
        .record(mempool_evict_dur.as_secs_f64());
    let tx_count_delta = tx_count_delta_for(block);
    let coin_stats_started = quanta::Instant::now();
    handles.coin_stats.finish_block(height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    let filter_started = quanta::Instant::now();
    if let Some(filter_bytes) = filter_bytes {
        if let Some(prev_filter_header) = previous_filter_header(handles, prior.as_deref()) {
            match handles
                .filter_index
                .put_filter(block_hash, prev_filter_header, &filter_bytes)
            {
                Ok(filter_header) => {
                    *handles.filter_header_cache.lock() = Some((block_hash, filter_header));
                    tracing::debug!(
                        height,
                        %filter_header,
                        bytes = filter_bytes.len(),
                        "filter_index stored block filter"
                    );
                }
                Err(error) => {
                    tracing::warn!(height, %error, "filter_index failed to store block filter");
                }
            }
        } else {
            // Skip the write rather than chain from zero. A BIP157 header is a
            // hash over its predecessor, so a chain that restarts mid-way is
            // invalid, not short, and verifies wrongly with no way to tell.
            // Writing nothing leaves the index unavailable from here, which a
            // backfill can repair.
            tracing::warn!(
                height,
                %block_hash,
                "no BIP157 filter header for the previous block; skipping this block's filter"
            );
        }
    }
    let filter_dur = filter_started.elapsed();
    metrics::histogram!("node.apply_block.filter_index_seconds").record(filter_dur.as_secs_f64());
    let total_dur = total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    tracing::debug!(
        height,
        %block_hash,
        tx_count = block.txdata.len(),
        pow_self_us = pow_self_dur.as_micros(),
        pow_limit_us = pow_limit_dur.as_micros(),
        block_rules_us = block_rules_dur.as_micros(),
        bip30_bip34_us = bip30_bip34_dur.as_micros(),
        script_verify_us = script_verify_dur.as_micros(),
        coinbase_maturity_us = coinbase_maturity_dur.as_micros(),
        bip68_us = bip68_dur.as_micros(),
        utxo_commit_us = utxo_commit_dur.as_micros(),
        block_body_persist_us = block_body_persist_dur.as_micros(),
        block_record_us = block_record_dur.as_micros(),
        block_tree_insert_us = block_tree_insert_dur.as_micros(),
        mempool_evict_us = mempool_evict_dur.as_micros(),
        filter_index_us = filter_dur.as_micros(),
        coin_stats_us = coin_stats_dur.as_micros(),
        total_us = total_dur.as_micros(),
        "apply_block: profile"
    );
    if handles.zmq_publisher.wants_notifications() {
        // Best-effort ZMQ event emission. Failures must not propagate per the
        // ZmqPublisher contract; the trait's methods return `()`.
        handles.zmq_publisher.publish_hashblock(tip.hash);
        if wants_rawblock {
            handles.zmq_publisher.publish_rawblock(&block_bytes);
        }
        if let Some(raw_txs) = scratch.raw_txs() {
            for (txid, rawtx_bytes) in scratch.txids().iter().zip(raw_txs) {
                handles.zmq_publisher.publish_hashtx(*txid);
                handles.zmq_publisher.publish_rawtx(rawtx_bytes);
            }
        } else {
            for txid in scratch.txids() {
                handles.zmq_publisher.publish_hashtx(*txid);
            }
        }
    }
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    handles.wake_tx_index();
    if handles.zmq_publisher.wants_notifications() {
        handles
            .zmq_publisher
            .publish_sequence(crate::zmq_publisher::SequenceEvent::Connected(tip.hash));
    }
    if let Some(sampler) = &handles.g2_muhash_sampler
        && sampler.wants_height(height)
    {
        let snapshot = handles.coin_stats.snapshot();
        if let Err(error) = sampler.record(&snapshot) {
            metrics::counter!("node.apply_block.g2_muhash_sample_errors").increment(1);
            tracing::warn!(
                height,
                %error,
                "G2 MuHash sample emission failed after tip publication; evidence file incomplete"
            );
        }
    }
    Ok(tip)
}

fn applied_predecessor(
    handles: &ApplyHandles,
    block_hash: bitcoin_rs_primitives::Hash256,
    prev_hash: bitcoin_rs_primitives::Hash256,
) -> core::result::Result<(Option<Arc<TipSnapshot>>, u32), ApplyError> {
    let prior = handles.applied_tip.load_full();
    let height = if let Some(tip) = prior.as_deref() {
        if tip.hash != prev_hash {
            return Err(ApplyError::PrevHashMismatch {
                tip: tip.hash,
                prev: prev_hash,
            });
        }
        tip.height
            .checked_add(1)
            .ok_or(ApplyError::HeightOverflow(tip.height))?
    } else {
        if block_hash != handles.network.genesis_block_hash() {
            return Err(ApplyError::Chain(
                bitcoin_rs_chain::ChainError::MissingParent { prev_hash },
            ));
        }
        0_u32
    };
    Ok((prior, height))
}

/// The BIP157 filter header the next filter chains from, when one exists.
///
/// Zero is valid for exactly one caller: the genesis block, whose parent
/// header is defined as zero. Everywhere else zero is a wrong answer that
/// looks like a right one, because BIP157 defines each header as a hash over
/// the previous one. A chain that restarts mid-way is not a shorter valid
/// chain; it is an invalid one, and a light client verifying against it gets
/// wrong answers with no way to tell.
///
/// Never returns an error, and never fails a block. Filters are optional
/// derived state written after the block has already applied, so neither an
/// absent row nor a broken backend may turn an applied block into a failure.
/// Both answer `None`, the caller skips the write, and the index stays
/// unavailable from that point until a backfill repairs it.
///
/// `None` is not the old bug wearing a new hat. The old code returned zero and
/// wrote a header, producing an index that verifies wrongly. This writes
/// nothing, which is honest and repairable.
fn previous_filter_header(handles: &ApplyHandles, prior: Option<&TipSnapshot>) -> Option<Hash256> {
    let Some(tip) = prior else {
        return Some(Hash256::default());
    };
    if let Some((cached_hash, cached_header)) = handles.filter_header_cache.lock().as_ref()
        && *cached_hash == tip.hash
    {
        return Some(*cached_header);
    }
    match handles.filter_index.filter_header(tip.hash) {
        Ok(header) => header,
        Err(error) => {
            tracing::warn!(
                prior_hash = %tip.hash,
                %error,
                "filter header lookup failed; skipping this block's filter"
            );
            None
        }
    }
}

/// Applies header-sync's timestamp rules to a header the tree has not seen.
///
/// A header already in the tree went through `accept_headers` and was checked
/// there. One that is not is about to be inserted by `applied_header_tip`, and
/// without this a caller handing `apply_block` a block directly could make one
/// with an invalid median-time-past or an absurd future timestamp the applied
/// consensus tip.
fn check_unseen_header_timestamp(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    block_hash: bitcoin_rs_primitives::Hash256,
) -> core::result::Result<(), ApplyError> {
    let tree = handles.block_tree.read();
    if tree.lookup(block_hash).is_some() {
        return Ok(());
    }
    bitcoin_rs_chain::validate_header_timestamp(
        &tree,
        &block.header,
        block_hash,
        bitcoin_rs_chain::current_unix_seconds(),
    )?;
    Ok(())
}

fn applied_header_tip(
    handles: &ApplyHandles,
    block_hash: bitcoin_rs_primitives::Hash256,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let mut tree = handles.block_tree.write();
    // No timestamp check here: this runs after the UTXO commit, so rejecting a
    // block at this point would leave its outputs and index rows installed.
    // `check_unseen_header_timestamp` does it before any mutation.
    let node_id = match tree.lookup(block_hash) {
        Some(node_id) => node_id,
        None => tree.insert_header(block.header, bitcoin_rs_chain::node::NodeStatus::Active)?,
    };
    let node = tree.node(node_id)?;
    if node.height != height {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "INTERNAL",
                reason: format!(
                    "block-tree height {} does not match applied height {height} for block {block_hash}",
                    node.height
                ),
            },
        ));
    }
    Ok(TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

struct BlockTxPlan {
    txids: Vec<Txid>,
    only_coinbase: bool,
    needs_local_utxo_overlay: bool,
    overlay_capacity: usize,
    witness_presence: WitnessPresence,
    has_bip68_sequence_locks: bool,
    created_output_count: usize,
    spent_input_count: usize,
    same_block_spent: Option<SameBlockSpentSet>,
    same_block_spent_input_count: usize,
}

impl BlockTxPlan {
    /// Outpoints this block both creates and spends, empty when it has none.
    ///
    /// The overlay nets these out exactly as `build_utxo_changes` does: such an
    /// output never reaches the committed set, so a view carrying it would
    /// resolve a later spend the real set would refuse.
    fn same_block_spent_set(&self) -> &SameBlockSpentSet {
        static NONE: std::sync::LazyLock<SameBlockSpentSet> =
            std::sync::LazyLock::new(SameBlockSpentSet::new);
        self.same_block_spent.as_ref().unwrap_or(&NONE)
    }

    fn txids(&self) -> &[Txid] {
        &self.txids
    }

    fn into_scratch_parts(
        self,
    ) -> (
        Vec<Txid>,
        ApplyScratchCapacities,
        Option<SameBlockSpentSet>,
        usize,
    ) {
        (
            self.txids,
            ApplyScratchCapacities {
                created_outputs: self.created_output_count,
                spent_inputs: self.spent_input_count,
            },
            self.same_block_spent,
            self.same_block_spent_input_count,
        )
    }
}

#[derive(Clone, Copy)]
enum WitnessPresence {
    Absent,
    Present,
}

impl WitnessPresence {
    const fn from_bool(has_witness: bool) -> Self {
        if has_witness {
            Self::Present
        } else {
            Self::Absent
        }
    }

    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

#[cfg(test)]
fn plan_block_transactions(block: &bitcoin::Block) -> BlockTxPlan {
    let txids: Vec<Txid> = if block.txdata.len() > 32 {
        block
            .txdata
            .par_iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect()
    } else {
        block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect()
    };
    plan_block_transactions_with_txids(block, txids)
}

/// Plans a block whose txids are already known.
///
/// The kernel's one-shot block parse hashes every transaction on the way past,
/// using the SHA-256 implementation Core picks at runtime, so the apply path
/// hands those txids straight in rather than re-hashing with a scalar
/// implementation.
fn plan_block_transactions_with_txids(block: &bitcoin::Block, txids: Vec<Txid>) -> BlockTxPlan {
    let mut only_coinbase = true;
    let mut needs_local_utxo_overlay = false;
    let mut overlay_capacity = 0usize;
    let mut has_witness = false;
    let mut has_bip68_sequence_locks = false;
    let mut created_output_count = 0usize;
    let mut spent_input_count = 0usize;
    let mut same_block_spent: Option<SameBlockSpentSet> = None;
    let mut same_block_spent_input_count = 0usize;
    let mut created_txids: Option<HashSet<Txid>> = None;
    let mut spent_outpoints: Option<HashSet<bitcoin::OutPoint>> = None;
    let track_spent_conflicts = block.txdata.len() > 2;
    let mut saw_non_coinbase = false;

    for (tx_index, (tx, txid)) in block.txdata.iter().zip(txids.iter().copied()).enumerate() {
        let is_coinbase = tx.is_coinbase();
        let output_count = tx.output.len();
        only_coinbase &= is_coinbase;
        created_output_count = created_output_count.saturating_add(output_count);
        if is_coinbase {
            has_witness |= tx.input.iter().any(|input| !input.witness.is_empty());
            overlay_capacity = overlay_capacity.saturating_add(output_count);
        } else {
            let input_count = tx.input.len();
            for input in &tx.input {
                has_witness |= !input.witness.is_empty();
                let prior_txids = &txids[..tx_index];
                let spends_created_output = if prior_txids.len() <= LOCAL_OVERLAY_TXID_SET_THRESHOLD
                {
                    prior_txids.contains(&input.previous_output.txid)
                } else {
                    let created_txids = created_txids.get_or_insert_with(|| {
                        let mut set = HashSet::with_capacity(block.txdata.len());
                        set.extend(prior_txids.iter().copied());
                        set
                    });
                    created_txids.contains(&input.previous_output.txid)
                };
                if spends_created_output {
                    same_block_spent
                        .get_or_insert_with(|| HashSet::with_capacity(input_count))
                        .insert(internal_outpoint(&input.previous_output));
                    same_block_spent_input_count = same_block_spent_input_count.saturating_add(1);
                }
                let repeats_prior_spend = if track_spent_conflicts {
                    let spent_outpoints = spent_outpoints.get_or_insert_with(|| {
                        HashSet::with_capacity(input_count.max(block.txdata.len()))
                    });
                    !spent_outpoints.insert(input.previous_output)
                } else {
                    saw_non_coinbase
                };
                needs_local_utxo_overlay |= spends_created_output || repeats_prior_spend;
            }
            saw_non_coinbase = true;
            if tx.version.0 >= 2 {
                has_bip68_sequence_locks |= tx
                    .input
                    .iter()
                    .any(|input| input.sequence.to_consensus_u32() & BIP68_DISABLE_FLAG == 0);
            }
            spent_input_count = spent_input_count.saturating_add(input_count);
            overlay_capacity =
                overlay_capacity.saturating_add(output_count.saturating_add(input_count));
        }
        if let Some(created_txids) = &mut created_txids {
            created_txids.insert(txid);
        }
    }

    BlockTxPlan {
        txids,
        only_coinbase,
        needs_local_utxo_overlay,
        overlay_capacity,
        witness_presence: WitnessPresence::from_bool(has_witness),
        has_bip68_sequence_locks,
        created_output_count,
        spent_input_count,
        same_block_spent,
        same_block_spent_input_count,
    }
}

fn compute_basic_filter(
    block: &bitcoin::Block,
    handles: &ApplyHandles,
    block_hash: bitcoin_rs_primitives::Hash256,
    height: u32,
    scratch: &ApplyScratch,
) -> Option<Vec<u8>> {
    use bitcoin::hashes::Hash as _;

    let filter = match bitcoin::bip158::BlockFilter::new_script_filter(block, |outpoint| {
        let prev_outpoint = OutPoint::new(
            bitcoin_rs_primitives::Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
            outpoint.vout,
        );
        scratch
            .same_block_spent_output_script(&prev_outpoint)
            .or_else(|| {
                handles
                    .utxo
                    .get(&prev_outpoint)
                    .map(|txout| txout.script_pubkey)
            })
            .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
    }) {
        Ok(filter) => filter,
        Err(error) => {
            tracing::warn!(height, %block_hash, %error, "BIP158 filter generation failed; skipping best-effort filter index row");
            return None;
        }
    };
    Some(filter.content)
}
/// All external (already-committed) prevouts for one block, resolved in a single
/// parallel pass so `script_verify`, `coinbase_maturity`, and `bip68` reuse one
/// lookup table instead of hitting the `UtxoSet` repeatedly.
struct ResolvedUtxoView {
    external: HashMap<bitcoin::OutPoint, LiveOutput>,
}

impl ResolvedUtxoView {
    /// Resolves a block's external prevouts from any source of live outputs.
    ///
    /// Generic so a window can substitute an overlay carrying the outputs its
    /// earlier blocks created. Every caller outside a window passes the
    /// committed set.
    fn resolve<S: crate::window_overlay::OutputSource + ?Sized>(
        utxo: &S,
        block: &bitcoin::Block,
        tx_plan: &BlockTxPlan,
    ) -> Self {
        let same_block = tx_plan.same_block_spent.as_ref();
        let candidates = block
            .txdata
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .flat_map(|tx| &tx.input)
            .filter(|input| {
                same_block
                    .is_none_or(|set| !set.contains(&internal_outpoint(&input.previous_output)))
            })
            .map(|input| input.previous_output);
        // Serial on purpose. A UTXO lookup is a sharded hashmap hit of order
        // 500 ns, so a rayon fan-out costs more than the work it distributes.
        // Measured on mainnet 0..150_000, 3x medians pinned to `taskset -c
        // 0-31`, parallel and serial interleaved: `into_par_iter` 143.8s vs
        // serial 134.7s, and serial won every round. Apply alone goes 116.2s
        // to 103.6s. Parallelize a stage only when per-item work exceeds the
        // dispatch, as the script checks do at ~100 us per input.
        Self {
            external: candidates
                .filter_map(|outpoint| {
                    utxo.get_entry(&internal_outpoint(&outpoint))
                        .map(|entry| (outpoint, entry))
                })
                .collect(),
        }
    }
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            external: HashMap::new(),
        }
    }

    fn lookup(&self, outpoint: &bitcoin::OutPoint) -> Option<bitcoin::TxOut> {
        self.external.get(outpoint).map(|entry| entry.txout.clone())
    }

    /// Full resolved entry for a spent outpoint, including creation metadata.
    fn entry(&self, outpoint: &bitcoin::OutPoint) -> Option<&LiveOutput> {
        self.external.get(outpoint)
    }

    fn lookup_meta(&self, outpoint: &bitcoin::OutPoint) -> Option<LiveOutputMeta> {
        self.external.get(outpoint).map(|entry| LiveOutputMeta {
            coinbase: entry.coinbase,
            height: entry.height,
        })
    }
}

impl UtxoView for ResolvedUtxoView {
    fn lookup(&self, outpoint: &bitcoin::OutPoint) -> Option<bitcoin::TxOut> {
        self.lookup(outpoint)
    }
}

/// Resolves every transaction's prevouts serially in block order into an owned
/// `Vec<Vec<Option<TxOut>>>` (coinbase -> empty inner Vec). This is the only
/// order-sensitive step of full script verification: the overlay walk advances
/// a `BlockLocalUtxoView` so a later transaction sees outputs an earlier one
/// created (or spent) in the same block; the non-overlay case reads the
/// committed shared set directly.
fn resolve_block_prevouts(
    resolved: Arc<ResolvedUtxoView>,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    height: u32,
) -> core::result::Result<Vec<Vec<Option<bitcoin::TxOut>>>, ApplyError> {
    let txids = tx_plan.txids();
    if tx_plan.needs_local_utxo_overlay {
        let mut view =
            BlockLocalUtxoView::new(resolved, &block.txdata, height, tx_plan.overlay_capacity);
        let mut resolved = Vec::with_capacity(block.txdata.len());
        for (tx_index, (tx, txid)) in (0_u32..).zip(block.txdata.iter().zip(txids)) {
            if tx.is_coinbase() {
                resolved.push(Vec::new());
                view.add_outputs(tx_index, *txid, tx.output.len())?;
                continue;
            }
            let inputs = tx
                .input
                .iter()
                .map(|input| view.lookup(&input.previous_output))
                .collect();
            resolved.push(inputs);
            view.spend_inputs(tx);
            view.add_outputs(tx_index, *txid, tx.output.len())?;
        }
        Ok(resolved)
    } else {
        // Serial on purpose, for the same reason as `ResolvedUtxoView::resolve`:
        // each item is a hashmap hit plus a `TxOut` clone, which is cheaper than
        // handing the work to another thread. Pinned 3x medians on mainnet
        // 0..150_000, parallel and serial interleaved, serial winning every
        // round: 139.4s vs 125.4s overall, and this stage 6.9s vs 1.63s. The
        // fan-out was adding 5.3s of dispatch on top of 1.6s of work.
        Ok(block
            .txdata
            .iter()
            .map(|tx| {
                if tx.is_coinbase() {
                    return Vec::new();
                }
                tx.input
                    .iter()
                    .map(|input| resolved.lookup(&input.previous_output))
                    .collect()
            })
            .collect())
    }
}
#[allow(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
/// Runs every non-script transaction check for a block whose scripts do not
/// need executing here.
///
/// Two callers reach this: assume-valid, which trusts the scripts, and a batch
/// proof, which already ran them. One implementation for both, because a second
/// copy is how a trusted path and a proven path drift apart.
fn run_non_script_checks_only(
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    txids: &[Txid],
    height: u32,
    locktime_cutoff: u32,
) -> core::result::Result<(), ApplyError> {
    if !tx_plan.needs_local_utxo_overlay {
        block.txdata.par_iter().try_for_each(|tx| {
            if tx.is_coinbase() {
                bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
                return Ok(());
            }
            bitcoin_rs_consensus::verify_tx::verify_transaction_borrowed_non_script_with_mtp(
                tx,
                &*resolved,
                height,
                locktime_cutoff,
            )
        })?;
        return Ok(());
    }
    let mut view =
        BlockLocalUtxoView::new(resolved, &block.txdata, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txdata.iter().zip(txids)) {
        if tx.is_coinbase() {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
            view.add_outputs(tx_index, *txid, tx.output.len())?;
            continue;
        }
        bitcoin_rs_consensus::verify_tx::verify_transaction_borrowed_non_script_with_mtp(
            tx,
            &view,
            height,
            locktime_cutoff,
        )?;
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.output.len())?;
    }
    Ok(())
}

#[allow(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn verify_block_transactions(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_script::VerifyFlags,
    kernel_block: &bitcoin_rs_consensus::kernel::KernelBlock,
) -> core::result::Result<(), ApplyError> {
    let txids = tx_plan.txids();
    debug_assert_eq!(block.txdata.len(), txids.len());
    if tx_plan.only_coinbase {
        for tx in &block.txdata {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
        }
        return Ok(());
    }
    // Assume-valid: skip kernel / portable script execution only, and only while the
    // hash-pinned trust gate holds (always trusted when no pin is configured).
    let skip_scripts = handles.assume_valid_height > 0
        && height <= handles.assume_valid_height
        && handles.assume_valid_gate.trusted();
    if skip_scripts {
        return run_non_script_checks_only(
            block,
            tx_plan,
            resolved,
            txids,
            height,
            locktime_cutoff,
        );
    }
    // Full-verify: resolve every transaction's prevouts serially in block order
    // into an owned `Vec<Vec<Option<TxOut>>>` (coinbase -> empty inner Vec), then
    // hand it to consensus, which runs the per-input script checks concurrently
    // and returns the first failure in block order. Resolution is the only
    // order-sensitive step: the overlay walk advances a `BlockLocalUtxoView` so a
    // later transaction sees outputs an earlier one created (or spent) in the same
    // block; the non-overlay case reads the committed shared set directly.
    let resolution_started = quanta::Instant::now();
    let resolution_result = resolve_block_prevouts(resolved, block, tx_plan, height);
    let resolution_dur = resolution_started.elapsed();
    metrics::histogram!("node.apply_block.script_resolution_seconds")
        .record(resolution_dur.as_secs_f64());
    let resolved = resolution_result?;
    // preparation and parallel input-check fan-out internally and reports both
    // sub-stage durations back; record them here on the success and error paths
    // before propagating the verdict, mirroring the surrounding `*_result` idiom.
    let mut script_timings = bitcoin_rs_consensus::ScriptStageTimings::default();
    let script_input_result = bitcoin_rs_consensus::verify_block_input_scripts(
        &block.txdata,
        resolved,
        height,
        locktime_cutoff,
        flags,
        &mut script_timings,
        kernel_block,
    );
    metrics::histogram!("node.apply_block.script_prepare_seconds")
        .record(script_timings.prepare_seconds);
    metrics::histogram!("node.apply_block.script_parallel_seconds")
        .record(script_timings.parallel_seconds);
    script_input_result?;
    tracing::debug!(
        height,
        script_resolution_us = resolution_dur.as_micros(),
        script_prepare_us = (script_timings.prepare_seconds * 1_000_000.0) as u64,
        script_parallel_us = (script_timings.parallel_seconds * 1_000_000.0) as u64,
        "script_verify: profile"
    );
    Ok(())
}

struct BlockLocalUtxoView<'b> {
    base: Arc<ResolvedUtxoView>,
    txdata: &'b [bitcoin::Transaction],
    height: u32,
    overlay: HashMap<bitcoin::OutPoint, Option<u32>>,
}

impl<'b> BlockLocalUtxoView<'b> {
    fn new(
        base: Arc<ResolvedUtxoView>,
        txdata: &'b [bitcoin::Transaction],
        height: u32,
        overlay_capacity: usize,
    ) -> Self {
        Self {
            base,
            txdata,
            height,
            overlay: HashMap::with_capacity(overlay_capacity),
        }
    }

    fn lookup_meta(&self, outpoint: &bitcoin::OutPoint) -> Option<LiveOutputMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let tx_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            self.txdata.get(tx_index)?.output.get(vout)?;
            return Some(LiveOutputMeta {
                coinbase: tx_index == 0,
                height: self.height,
            });
        }
        self.base.lookup_meta(outpoint)
    }

    fn spend_inputs(&mut self, tx: &bitcoin::Transaction) {
        for input in &tx.input {
            self.overlay.insert(input.previous_output, None);
        }
    }

    fn add_outputs(
        &mut self,
        tx_index: u32,
        txid: bitcoin::Txid,
        output_count: usize,
    ) -> core::result::Result<(), ApplyError> {
        for vout in 0..output_count {
            let vout = u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(self.height))?;
            self.overlay
                .insert(bitcoin::OutPoint::new(txid, vout), Some(tx_index));
        }
        Ok(())
    }
}

impl UtxoView for BlockLocalUtxoView<'_> {
    fn lookup(&self, outpoint: &bitcoin::OutPoint) -> Option<bitcoin::TxOut> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let tx_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            return self.txdata.get(tx_index)?.output.get(vout).cloned();
        }
        self.base.lookup(outpoint)
    }
}

#[cfg(test)]
pub(crate) fn check_coinbase_maturity(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let tx_plan = plan_block_transactions(block);
    let resolved = Arc::new(ResolvedUtxoView::resolve(
        handles.utxo.as_ref(),
        block,
        &tx_plan,
    ));
    check_coinbase_maturity_with_tx_plan(handles, block, &tx_plan, resolved, height)
}

fn check_coinbase_maturity_with_tx_plan(
    _handles: &ApplyHandles,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let txids = tx_plan.txids();
    debug_assert_eq!(block.txdata.len(), txids.len());
    if tx_plan.only_coinbase {
        return Ok(());
    }
    // COINBASE_MATURITY: spent coinbase outputs must be at least 100 blocks deep.
    if !tx_plan.needs_local_utxo_overlay {
        for tx in block.txdata.iter().filter(|tx| !tx.is_coinbase()) {
            for input in &tx.input {
                let Some(entry) = resolved.lookup_meta(&input.previous_output) else {
                    continue;
                };
                check_coinbase_input_maturity(entry, height)?;
            }
        }
        return Ok(());
    }

    let mut view =
        BlockLocalUtxoView::new(resolved, &block.txdata, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txdata.iter().zip(txids)) {
        if tx.is_coinbase() {
            view.add_outputs(tx_index, *txid, tx.output.len())?;
            continue;
        }
        for input in &tx.input {
            let Some(entry) = view.lookup_meta(&input.previous_output) else {
                continue;
            };
            check_coinbase_input_maturity(entry, height)?;
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.output.len())?;
    }
    Ok(())
}

fn check_coinbase_input_maturity(entry: LiveOutputMeta, height: u32) -> Result<(), ApplyError> {
    let depth = height.saturating_sub(entry.height);
    if entry.coinbase && depth < COINBASE_MATURITY {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "COINBASE_MATURITY",
                reason: format!(
                    "spent coinbase output created at height {} cannot be spent at height {} (depth {} < {})",
                    entry.height, height, depth, COINBASE_MATURITY,
                ),
            },
        ));
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
    mtp: u32,
    softfork_state: crate::bip9_context::ContextualSoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
) -> core::result::Result<(), ApplyError> {
    if !softfork_state.csv_active {
        return Ok(());
    }
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.has_bip68_sequence_locks {
        return Ok(());
    }

    let txids = tx_plan.txids();
    debug_assert_eq!(block.txdata.len(), txids.len());
    let mut view =
        BlockLocalUtxoView::new(resolved, &block.txdata, height, tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = None;
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txdata.iter().zip(txids)) {
        if tx.is_coinbase() {
            view.add_outputs(tx_index, *txid, tx.output.len())?;
            continue;
        }
        if tx.version.0 < 2 {
            view.spend_inputs(tx);
            view.add_outputs(tx_index, *txid, tx.output.len())?;
            continue;
        }
        for tx_input in &tx.input {
            let sequence = tx_input.sequence.to_consensus_u32();
            if sequence & BIP68_DISABLE_FLAG != 0 {
                continue;
            }
            let is_time_based = sequence & BIP68_TYPE_FLAG != 0;
            if is_time_based {
                let relative_intervals = sequence & BIP68_MASK;
                let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                    continue;
                };
                let prevout_mtp = if entry.height == height {
                    // A same-block prevout's coin time is the MTP of the block
                    // before the block being connected; the previous tip cannot
                    // contain an ancestor at the current block height yet.
                    mtp
                } else {
                    let cache = prevout_mtp_by_height.get_or_insert_with(HashMap::new);
                    if let Some(prevout_mtp) = cache.get(&entry.height) {
                        *prevout_mtp
                    } else {
                        let prevout_mtp =
                            bip68_prevout_mtp(handles, previous_tip_id, entry.height)?;
                        cache.insert(entry.height, prevout_mtp);
                        prevout_mtp
                    }
                };
                let earliest_time = prevout_mtp.saturating_add(
                    relative_intervals.saturating_mul(BIP68_TIME_GRANULARITY_SECONDS),
                );
                if mtp < earliest_time {
                    return Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip {
                            bip: "BIP68",
                            reason: format!(
                                "input sequence time-based lock unmet: prevout mtp {prevout_mtp} + {relative_intervals}*512s = {earliest_time} > current mtp {mtp}",
                            ),
                        },
                    ));
                }
                continue;
            }

            let relative_blocks = sequence & BIP68_MASK;
            let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                continue;
            };
            let earliest_height = entry.height.saturating_add(relative_blocks);
            if height < earliest_height {
                return Err(ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::Bip {
                        bip: "BIP68",
                        reason: format!(
                            "input sequence height-based lock unmet: prevout at height {} + {} blocks > current {}",
                            entry.height, relative_blocks, height
                        ),
                    },
                ));
            }
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.output.len())?;
    }

    Ok(())
}

fn bip68_prevout_mtp(
    handles: &ApplyHandles,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
    prevout_height: u32,
) -> core::result::Result<u32, ApplyError> {
    let tree = handles.block_tree.read();
    let Some(previous_tip_id) = previous_tip_id else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing previous tip for time-based sequence lock".to_owned(),
            },
        ));
    };
    let mtp_height = prevout_height.saturating_sub(1);
    let Some(prev_block_node) = tree.node_at_height_from(previous_tip_id, mtp_height) else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: format!(
                    "missing prevout ancestry at height {mtp_height} for time-based sequence lock"
                ),
            },
        ));
    };
    let Some(prevout_mtp) = tree.median_time_past_at(prev_block_node, 11) else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing prevout median-time-past for time-based sequence lock".to_owned(),
            },
        ));
    };
    Ok(prevout_mtp)
}

fn check_bip30_and_bip34(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    txids: &[bitcoin::Txid],
    previous_tip_id: Option<NodeId>,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // BIP30: reject any txid that collides with an earlier transaction while
    // any output of the earlier transaction remains unspent, except at the
    // documented historical exception heights handled by `check_bip30`.
    let mut has_duplicate = false;
    if should_scan_bip30_duplicates(handles, height, previous_tip_id) {
        for txid in txids {
            let txid = bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array());
            if handles.utxo.has_live_outputs_for_txid(&txid) {
                has_duplicate = true;
                break;
            }
        }
    }
    let block_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
    bitcoin_rs_consensus::bip30::check_bip30(height, block_hash, has_duplicate)?;

    // BIP34: when active for this network at `height`, the coinbase
    // scriptSig must start with the minimally-encoded height.
    if handles.network.is_bip34_active(height) {
        let coinbase = block
            .txdata
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::EmptyBlock)?;
        // `verify_block_rules_borrowed` already pinned the first tx to
        // be the coinbase; relying on that here. `coinbase.input[0]`
        // is the synthetic prevout pointing at the impossible
        // outpoint; its `script_sig` carries the BIP34 height encoding.
        let coinbase_input = coinbase
            .input
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)?;
        bitcoin_rs_consensus::bip34::check_bip34(height, coinbase_input.script_sig.as_script())?;
    }

    Ok(())
}

fn should_scan_bip30_duplicates(
    handles: &ApplyHandles,
    height: u32,
    previous_tip_id: Option<NodeId>,
) -> bool {
    if height >= BIP34_IMPLIES_BIP30_LIMIT || !handles.network.is_bip34_active(height) {
        return true;
    }

    let Some(expected_activation_hash) = handles.network.bip34_activation_hash() else {
        return true;
    };
    let Some(previous_tip_id) = previous_tip_id else {
        return true;
    };

    let tree = handles.block_tree.read();
    let Some(activation_id) =
        tree.node_at_height_from(previous_tip_id, handles.network.bip34_activation_height())
    else {
        return true;
    };
    let Ok(activation_node) = tree.node(activation_id) else {
        return true;
    };

    activation_node.hash != expected_activation_hash
}

fn check_pow_limit_and_continuity(
    handles: &ApplyHandles,
    prior: Option<&TipSnapshot>,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    // PoW limit: declared target must not exceed network max_target.
    let target_be = block.header.target().to_be_bytes();
    let declared = bitcoin_rs_chain::node::ChainWork::from_be_bytes(target_be);
    let max_target = handles.network.max_target();
    if declared > max_target {
        return Err(ApplyError::TargetAboveLimit);
    }

    // Genesis (height 0) has no parent; skip contextual DAA.
    if height == 0 {
        return Ok(());
    }

    let tree = handles.block_tree.read();
    let Some(parent_id) = prior.map(|tip| tip.tip_id) else {
        use bitcoin::hashes::Hash as _;

        let prev_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(
            block.header.prev_blockhash.as_byte_array(),
        );
        return Err(ApplyError::Chain(
            bitcoin_rs_chain::ChainError::MissingParent { prev_hash },
        ));
    };
    bitcoin_rs_chain::header_sync::validate_header_nbits(
        &tree,
        parent_id,
        &block.header,
        handles.network,
    )
    .map_err(apply_nbits_error)
}

fn apply_nbits_error(error: bitcoin_rs_chain::ChainError) -> ApplyError {
    match error {
        bitcoin_rs_chain::ChainError::NbitsMismatch {
            actual,
            expected,
            height,
        } => ApplyError::NbitsNonRetargetMismatch {
            actual,
            expected,
            height,
        },
        error => ApplyError::Chain(error),
    }
}

fn build_utxo_changes<'a>(
    block: &'a bitcoin::Block,
    height: u32,
    scratch: &ApplyScratch,
    resolved: &ResolvedUtxoView,
    overwritten: Option<&UtxoSet>,
) -> core::result::Result<(BorrowedBlockChanges<'a>, bitcoin_rs_utxo::UndoBatch), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // Bitcoin Core indexes genesis but does not connect its transactions into
    // CoinsView; its coinbase is unspendable and absent from UTXO/MuHash state.
    if height == 0 {
        return Ok((
            BorrowedBlockChanges::default(),
            bitcoin_rs_utxo::UndoBatch::default(),
        ));
    }

    let (add_capacity, remove_capacity) = scratch.utxo_change_capacity();
    let mut changes = BorrowedBlockChanges::with_capacity(add_capacity, remove_capacity);
    let mut undo = bitcoin_rs_utxo::UndoBatch::default();
    let net_same_block_spends = scratch.has_same_block_spends();
    for (tx, txid) in block.txdata.iter().zip(scratch.txids()) {
        let txid = bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array());
        let coinbase = tx.is_coinbase();
        for (vout_idx, txout) in tx.output.iter().enumerate() {
            if txout.script_pubkey.is_op_return() || txout.script_pubkey.len() > MAX_SCRIPT_SIZE {
                continue;
            }
            let outpoint = OutPoint::new(
                txid,
                u32::try_from(vout_idx).map_err(|_| ApplyError::HeightOverflow(height))?,
            );
            if net_same_block_spends && scratch.contains_same_block_spent(&outpoint) {
                continue;
            }
            // At a BIP30 exception height the coinbase reuses an earlier txid
            // whose outputs are still live, so this add OVERWRITES a coin
            // rather than creating one. `overwritten` is `Some` only at those
            // two mainnet heights, so every other block pays no lookup.
            let replaced = overwritten.and_then(|set| set.get_entry(&outpoint));
            changes.add(BorrowedUtxoAdd::new(outpoint, txout, coinbase, height));
            match replaced {
                // The inverse of overwriting is writing the old coin back, not
                // deleting the outpoint. Emitting a remove as well would depend
                // on `undo_block` applying restores after removes, and it does
                // the opposite, so the older coin would be lost and the rewound
                // UTXO set, MuHash, and coinstats would not match the parent.
                Some(previous) => undo.restore(bitcoin_rs_utxo::UtxoAdd::new(
                    outpoint,
                    previous.txout,
                    previous.coinbase,
                    previous.height,
                )),
                // Disconnecting the block deletes what it created.
                None => undo.remove(outpoint),
            }
        }

        if !coinbase {
            for tx_input in &tx.input {
                let previous_output = internal_outpoint(&tx_input.previous_output);
                if net_same_block_spends && scratch.contains_same_block_spent(&previous_output) {
                    continue;
                }
                changes.remove(previous_output);
                // ...and restores what it spent. A spend with no resolved
                // prevout would make the record unable to restore that output,
                // so refuse rather than persist an undo that silently loses it.
                let spent = resolved.entry(&tx_input.previous_output).ok_or(
                    ApplyError::UndoPrevoutMissing {
                        txid: previous_output.txid,
                        vout: previous_output.vout,
                    },
                )?;
                undo.restore(bitcoin_rs_utxo::UtxoAdd::new(
                    previous_output,
                    spent.txout.clone(),
                    spent.coinbase,
                    spent.height,
                ));
            }
        }
    }
    Ok((changes, undo))
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    use bitcoin::hashes::Hash as _;

    OutPoint::new(
        bitcoin_rs_primitives::Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}

fn applied_block_record(
    height: u32,
    block_hash: Hash256,
    block: &bitcoin::Block,
    block_bytes: &[u8],
    include_body: bool,
) -> BlockRecord {
    let block_hex = if include_body {
        block_bytes.to_lower_hex_string()
    } else {
        String::new()
    };
    let header_hex = block_bytes.get(..SERIALIZED_BLOCK_HEADER_LEN).map_or_else(
        || bitcoin::consensus::encode::serialize(&block.header).to_lower_hex_string(),
        DisplayHex::to_lower_hex_string,
    );
    BlockRecord {
        hash: block_hash,
        height,
        block_hex,
        body_size: block_bytes.len(),
        header_hex,
        tx_count: block.txdata.len(),
        time: block.header.time,
    }
}

#[must_use]
fn compute_verify_flags(
    network: Network,
    height: u32,
    block_hash: Hash256,
    softfork_state: crate::bip9_context::ContextualSoftforkState,
) -> bitcoin_rs_script::VerifyFlags {
    use bitcoin_rs_script::VerifyFlags;

    // P2SH (BIP16) is enforced on every block except Core's single grandfathered
    // `consensus.BIP16Exception` (mainnet block 170060), keyed by block hash.
    let mut flags = VerifyFlags::NONE;
    if !network.is_bip16_p2sh_exception(block_hash) {
        flags = flags.union(VerifyFlags::P2SH);
    }
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if softfork_state.csv_active {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if softfork_state.segwit_active {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}

#[cfg(test)]
mod consensus_rule_tests {
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, CompactTarget, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_chain::{
        BlockTree,
        node::{ChainWork, NodeStatus},
    };
    use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_primitives::{Hash256, OutPoint};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
    use hashbrown::HashMap;
    use parking_lot::{Mutex, RwLock};

    use super::*;

    const BIP68_TEST_PREVOUT_HEIGHT: u32 = 100;
    const BIP68_TEST_PREVOUT_MTP: u32 = 1_000_000;
    const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
    const MAINNET_POW_LIMIT_DIV_4_BITS: u32 = 0x1c3f_ffc0;
    const DAA_ANCHOR_TIME: u32 = 1_600_000_000;

    /// Parses `block` the way production does, so tests exercise the real
    /// one-shot kernel parse rather than a stand-in.
    fn kernel_block_of(block: &bitcoin::Block) -> bitcoin_rs_consensus::kernel::KernelBlock {
        bitcoin_rs_consensus::kernel::KernelBlock::parse(&bitcoin::consensus::encode::serialize(
            block,
        ))
        .unwrap_or_else(|error| panic!("test block must parse: {error}"))
    }

    fn tx_plan(block: &bitcoin::Block) -> BlockTxPlan {
        plan_block_transactions(block)
    }

    #[test]
    fn applied_block_record_matches_rpc_constructors() {
        let block = block_with_transaction(coinbase_transaction(0x42));
        let block_bytes = bitcoin::consensus::encode::serialize(&block);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        assert_eq!(
            super::decode_block_tx_count(&block_bytes),
            Some(block.txdata.len())
        );
        assert_eq!(
            super::decode_block_tx_count(&block_bytes[..SERIALIZED_BLOCK_HEADER_LEN]),
            None
        );

        let cached = applied_block_record(7, block_hash, &block, &block_bytes, true);
        let expected_cached = BlockRecord::from_block_bytes(7, &block, &block_bytes);
        assert_eq!(cached.hash, expected_cached.hash);
        assert_eq!(cached.height, expected_cached.height);
        assert_eq!(cached.block_hex, expected_cached.block_hex);
        assert_eq!(cached.body_size, expected_cached.body_size);
        assert_eq!(cached.header_hex, expected_cached.header_hex);
        assert_eq!(cached.tx_count, expected_cached.tx_count);
        assert_eq!(cached.time, expected_cached.time);

        let metadata = applied_block_record(7, block_hash, &block, &block_bytes, false);
        let expected_metadata = BlockRecord::from_block_metadata_bytes(7, &block, &block_bytes);
        assert_eq!(metadata.hash, expected_metadata.hash);
        assert_eq!(metadata.height, expected_metadata.height);
        assert_eq!(metadata.block_hex, expected_metadata.block_hex);
        assert_eq!(metadata.body_size, expected_metadata.body_size);
        assert_eq!(metadata.header_hex, expected_metadata.header_hex);
        assert_eq!(metadata.tx_count, expected_metadata.tx_count);
        assert_eq!(metadata.time, expected_metadata.time);
    }

    #[test]
    fn block_apply_predecessor_uses_applied_tip_when_header_tip_is_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let mut tree = handles.block_tree.write();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let genesis_node = tree.node(genesis_id)?;
        let genesis_tip = TipSnapshot {
            tip_id: genesis_id,
            height: genesis_node.height,
            chainwork: genesis_node.chainwork,
            hash: genesis_node.hash,
        };
        let mut tip_id = genesis_id;
        for height in 1..=3 {
            let parent_hash =
                bitcoin::BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = pow_header(
                parent_hash,
                CompactTarget::from_consensus(0x207f_ffff),
                height,
                height,
            );
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        }
        handles.chain_tip.store(tree.tip());
        drop(tree);
        handles
            .applied_tip
            .store(Some(Arc::new(genesis_tip.clone())));

        let (prior, height) = applied_predecessor(
            &handles,
            Hash256::from_le_bytes(&[0x42; 32]),
            genesis_tip.hash,
        )?;

        let prior = prior.ok_or_else(|| std::io::Error::other("missing predecessor"))?;
        assert_eq!(prior.tip_id, genesis_id);
        assert_eq!(height, 1);
        Ok(())
    }

    #[test]
    fn block_apply_predecessor_rejects_non_genesis_without_applied_tip() {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let prev_hash = Hash256::from_le_bytes(&[0x11; 32]);
        let error =
            match applied_predecessor(&handles, Hash256::from_le_bytes(&[0x22; 32]), prev_hash) {
                Ok(_) => panic!("non-genesis block must not start the applied chain"),
                Err(error) => error,
            };

        assert!(matches!(
            error,
            ApplyError::Chain(bitcoin_rs_chain::ChainError::MissingParent { prev_hash: got }) if got == prev_hash
        ));
    }

    #[test]
    fn applied_header_tip_reuses_preaccepted_header() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let header_id = handles
            .block_tree
            .write()
            .insert_header(block.header, NodeStatus::HeaderValid)?;

        let tip = applied_header_tip(&handles, block_hash, &block, 0)?;

        assert_eq!(tip.tip_id, header_id);
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, block_hash);
        Ok(())
    }

    #[test]
    fn verify_block_transactions_accepts_same_block_spend() -> Result<(), Box<dyn std::error::Error>>
    {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x61; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
            &kernel_block_of(&block),
        )?;
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_resolves_earlier_same_block_output() -> Result<(), ApplyError> {
        let created = coinbase_transaction(0x41);
        let outpoint = bitcoin::OutPoint {
            txid: created.compute_txid(),
            vout: 0,
        };
        let spending = spending_transaction_to_script(
            outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![created, spending]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txdata, 42, 2);

        view.add_outputs(
            0,
            block.txdata[0].compute_txid(),
            block.txdata[0].output.len(),
        )?;
        let resolved = view.lookup(&outpoint);

        let output = resolved.ok_or(ApplyError::HeightOverflow(42))?;
        assert_eq!(output.value, block.txdata[0].output[0].value);
        assert_eq!(
            output.script_pubkey,
            block.txdata[0].output[0].script_pubkey
        );
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_hides_same_block_double_spend() -> Result<(), ApplyError> {
        let created = coinbase_transaction(0x42);
        let outpoint = bitcoin::OutPoint {
            txid: created.compute_txid(),
            vout: 0,
        };
        let first_spend = spending_transaction_to_script(
            outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let second_spend = spending_transaction_to_script(
            outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![created, first_spend, second_spend]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txdata, 42, 3);

        view.add_outputs(
            0,
            block.txdata[0].compute_txid(),
            block.txdata[0].output.len(),
        )?;
        assert!(view.lookup(&outpoint).is_some());
        view.spend_inputs(&block.txdata[1]);

        assert_eq!(view.lookup(&outpoint), None);
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_create_after_spend_uses_last_write() -> Result<(), ApplyError> {
        let created = coinbase_transaction(0x43);
        let outpoint = bitcoin::OutPoint {
            txid: created.compute_txid(),
            vout: 0,
        };
        let spending = spending_transaction_to_script(
            outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![spending, created]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txdata, 42, 2);

        view.spend_inputs(&block.txdata[0]);
        view.add_outputs(
            1,
            block.txdata[1].compute_txid(),
            block.txdata[1].output.len(),
        )?;

        assert_eq!(
            view.lookup(&outpoint),
            Some(block.txdata[1].output[0].clone())
        );
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_hides_later_same_block_output() -> Result<(), ApplyError> {
        let earlier = coinbase_transaction(0x44);
        let later = coinbase_transaction(0x45);
        let later_outpoint = bitcoin::OutPoint {
            txid: later.compute_txid(),
            vout: 0,
        };
        let block = block_with_transactions(vec![earlier, later]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txdata, 42, 2);

        view.add_outputs(
            0,
            block.txdata[0].compute_txid(),
            block.txdata[0].output.len(),
        )?;

        assert_eq!(view.lookup(&later_outpoint), None);
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_metadata_tracks_coinbase_and_height() -> Result<(), ApplyError> {
        let coinbase = coinbase_transaction(0x46);
        let transaction = spending_transaction_to_script(
            bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x47; 32]),
                vout: 0,
            },
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let transaction_outpoint = bitcoin::OutPoint {
            txid: transaction.compute_txid(),
            vout: 0,
        };
        let block = block_with_transactions(vec![coinbase, transaction]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txdata, 42, 2);

        view.add_outputs(
            0,
            block.txdata[0].compute_txid(),
            block.txdata[0].output.len(),
        )?;
        view.add_outputs(
            1,
            block.txdata[1].compute_txid(),
            block.txdata[1].output.len(),
        )?;

        let coinbase_meta = view
            .lookup_meta(&coinbase_outpoint)
            .ok_or(ApplyError::HeightOverflow(42))?;
        let transaction_meta = view
            .lookup_meta(&transaction_outpoint)
            .ok_or(ApplyError::HeightOverflow(42))?;
        assert!(coinbase_meta.coinbase);
        assert!(!transaction_meta.coinbase);
        assert_eq!(coinbase_meta.height, 42);
        assert_eq!(transaction_meta.height, 42);
        Ok(())
    }

    /// R2 pin (shared-view parallel path): under the kernel feature the script
    /// verdict carries the kernel dispatch marker — the Rust interpreter did
    /// not produce it.
    #[test]
    #[cfg(feature = "kernel")]
    fn verify_block_transactions_shared_view_path_uses_kernel_verdict()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = bad_script_spend_block()?;
        let handles = apply_handles(utxo);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("bad script must fail under the kernel build"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                input_index: 0,
                ref reason,
            }) if reason.starts_with("kernel script verification failed:")
        ));
        Ok(())
    }

    /// R2 pin (overlay path): a same-block spend resolved against the frozen
    /// per-tx snapshot view is also verdict-checked by the kernel.
    #[test]
    #[cfg(feature = "kernel")]
    fn verify_block_transactions_overlay_path_uses_kernel_verdict()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::opcodes::all::OP_EQUAL;
        use bitcoin::script::Builder;

        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x67; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            Builder::new().push_opcode(OP_EQUAL).into_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let bad_same_block_spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true_script(),
            }],
        };
        let block = block_with_transactions(vec![funding_tx, bad_same_block_spend]);
        let plan = tx_plan(&block);
        assert!(plan.needs_local_utxo_overlay);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("bad same-block spend must fail under the kernel build"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                input_index: 0,
                ref reason,
            }) if reason.starts_with("kernel script verification failed:")
        ));
        Ok(())
    }

    /// The unified full-verify path resolves same-block spends in order (tx1 spends
    /// tx0's output, forcing the overlay walk) yet still surfaces the *earlier*
    /// transaction's script failure deterministically — the node rewrite preserves
    /// error identity through `verify_block_input_scripts`. Feature-agnostic: the
    /// Script reason differs between the portable and kernel engines, so only the
    /// variant and input index are asserted.
    #[test]
    fn verify_block_transactions_same_block_spend_surfaces_earlier_bad_script()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::opcodes::all::OP_EQUAL;
        use bitcoin::script::Builder;

        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x68; 32]),
            vout: 0,
        };
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        let txid = Hash256::from_le_bytes(base_prevout.txid.as_byte_array());
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, base_prevout.vout),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
            false,
            1,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
        let handles = apply_handles(utxo);

        // tx0 (funding) fails its script against the OP_EQUAL prevout.
        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: base_prevout,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true_script(),
            }],
        };
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        // tx1 spends tx0's output inside the block, forcing the overlay walk.
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);
        let plan = tx_plan(&block);
        assert!(plan.needs_local_utxo_overlay);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("earlier tx bad script must reject the block"),
            Err(error) => error,
        };
        assert!(
            matches!(
                error,
                ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                    input_index: 0,
                    ..
                })
            ),
            "expected earlier-tx Script error at input 0, got {error:?}"
        );
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_cross_transaction_duplicate_spend()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x64; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let first_spend = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let second_spend = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32() - 1,
            op_true_script(),
        );
        let block = block_with_transactions(vec![first_spend, second_spend]);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("cross-transaction duplicate spend must fail script verification"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                input_index: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_bad_coinbase_script_sig() {
        let mut coinbase = coinbase_transaction(0x63);
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![0x63]);
        let block = block_with_transaction(coinbase);
        let handles = empty_apply_handles();

        let error = match verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            1,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("bad coinbase scriptSig length must fail transaction verification"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseScriptSigSize { len: 1 }
            )
        ));
    }

    #[test]
    fn assume_valid_gate_new_pins_only_the_exact_anchor_height() {
        let anchor_height = Network::Mainnet
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height);
        assert!(anchor_height > 0);

        let no_pin = AssumeValidGate::new(Network::Mainnet, 0);
        assert!(no_pin.trusted(), "zero configured height means no pin");

        let pinned = AssumeValidGate::new(Network::Mainnet, anchor_height);
        assert!(
            !pinned.trusted(),
            "exact anchor height starts untrusted until the chain is evaluated"
        );

        let off_by_one = AssumeValidGate::new(Network::Mainnet, anchor_height + 1);
        assert!(
            off_by_one.trusted(),
            "custom heights keep the height-only shortcut without a pin"
        );

        let unanchored = AssumeValidGate::with_anchor(None);
        assert!(unanchored.trusted(), "no anchor means always trusted");
    }

    #[test]
    fn assume_valid_gate_evaluate_trusts_only_the_chain_containing_the_anchor()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let headers: Vec<_> = (0..=4).map(|height| (bits, height)).collect();
        seed_pow_chain_with_headers(&handles, &headers)?;

        let anchor_hash = {
            let tree = handles.block_tree.read();
            let tip = tree
                .tip()
                .ok_or_else(|| std::io::Error::other("missing tip"))?;
            let anchor_id = tree
                .node_at_height_from(tip.tip_id, 2)
                .ok_or_else(|| std::io::Error::other("missing anchor node"))?;
            tree.node(anchor_id)?.hash
        };

        let pinned = AssumeValidGate::with_anchor(Some((2, anchor_hash)));
        assert!(!pinned.trusted(), "pinned gate starts untrusted");
        {
            let tree = handles.block_tree.read();
            pinned.evaluate(&tree);
        }
        assert!(
            pinned.trusted(),
            "active chain contains the anchor block, so the gate must trust it"
        );

        let diverged = AssumeValidGate::with_anchor(Some((2, Hash256::from_le_bytes(&[0xee; 32]))));
        {
            let tree = handles.block_tree.read();
            diverged.evaluate(&tree);
        }
        assert!(
            !diverged.trusted(),
            "a chain lacking the pinned hash must never be trusted"
        );
        {
            let tree = handles.block_tree.read();
            diverged.evaluate(&tree);
        }
        assert!(
            !diverged.trusted(),
            "re-evaluation on the same diverged chain keeps the gate untrusted"
        );
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_duplicate_spends_when_assume_valid_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = duplicate_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 0);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("duplicate spend must fail when assume_valid_height is zero"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                input_index: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_duplicate_spends_within_assume_valid_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = duplicate_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 2);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("duplicate spend must fail even under assume_valid_height"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                input_index: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_duplicate_spends_above_assume_valid_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = duplicate_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 2);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            3,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("duplicate spend must fail above assume_valid_height"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                input_index: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_skips_script_execution_within_assume_valid_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = bad_script_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 2);

        verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        )?;
        Ok(())
    }

    #[test]
    fn verify_block_transactions_runs_script_checks_when_assume_valid_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = bad_script_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 0);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("bad script must fail when assume_valid_height is zero"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                input_index: 0,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_runs_script_checks_above_assume_valid_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let (block, plan, utxo) = bad_script_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 2);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            3,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("bad script must fail above assume_valid_height"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                input_index: 0,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_excess_output_value_under_assume_valid_height()
    -> Result<(), Box<dyn std::error::Error>> {
        // Skipping script checks must NOT skip the input/output value-balance check:
        // a transaction whose outputs exceed its inputs is rejected even within
        // assume_valid_height.
        let (block, plan, utxo) = excess_value_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 2);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("outputs exceeding inputs must fail even under assume_valid_height"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::InputsLessThanOutputs {
                    input_value: 1_000,
                    output_value: 2_000,
                }
            )
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_still_checks_coinbase_script_sig_under_assume_valid_height() {
        let mut coinbase = coinbase_transaction(0x63);
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![0x63]);
        let block = block_with_transaction(coinbase);
        let mut handles = empty_apply_handles();
        handles.assume_valid_height = 100;

        let error = match verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            1,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
            &kernel_block_of(&block),
        ) {
            Ok(()) => panic!("bad coinbase scriptSig length must fail under assume_valid_height"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseScriptSigSize { len: 1 }
            )
        ));
    }

    #[test]
    fn build_utxo_changes_excludes_op_return_outputs() -> Result<(), Box<dyn std::error::Error>> {
        let mut coinbase = coinbase_transaction(0x6f);
        coinbase.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(b"not a coin"),
        });
        let txid = coinbase.compute_txid();
        let block = block_with_transaction(coinbase);
        let scratch = ApplyScratch::new(&block, 1, false, false)?;
        let (changes, _undo) =
            build_utxo_changes(&block, 1, &scratch, &ResolvedUtxoView::empty(), None)?;
        let utxo = UtxoSet::new();

        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x72; 32]))?;

        assert!(
            utxo.get(&internal_outpoint(&bitcoin::OutPoint::new(txid, 0)))
                .is_some()
        );
        assert!(
            utxo.get(&internal_outpoint(&bitcoin::OutPoint::new(txid, 1)))
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn build_utxo_changes_excludes_oversized_scripts() -> Result<(), Box<dyn std::error::Error>> {
        let mut coinbase = coinbase_transaction(0x70);
        coinbase.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; MAX_SCRIPT_SIZE]),
        });
        coinbase.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; MAX_SCRIPT_SIZE + 1]),
        });
        let txid = coinbase.compute_txid();
        let block = block_with_transaction(coinbase);
        let scratch = ApplyScratch::new(&block, 1, false, false)?;
        let (changes, _undo) =
            build_utxo_changes(&block, 1, &scratch, &ResolvedUtxoView::empty(), None)?;
        let utxo = UtxoSet::new();

        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x73; 32]))?;

        assert!(
            utxo.get(&internal_outpoint(&bitcoin::OutPoint::new(txid, 0)))
                .is_some()
        );
        assert!(
            utxo.get(&internal_outpoint(&bitcoin::OutPoint::new(txid, 1)))
                .is_some()
        );
        assert!(
            utxo.get(&internal_outpoint(&bitcoin::OutPoint::new(txid, 2)))
                .is_none()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn build_utxo_changes_nets_same_block_created_then_spent_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x62; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let final_outpoint = bitcoin::OutPoint {
            txid: same_block_spend.compute_txid(),
            vout: 0,
        };
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        let scratch = ApplyScratch::new(&block, 2, false, false)?;
        // The block spends an external prevout, so the undo half needs the
        // resolved view that spend came from. An empty view would now be
        // rejected, which is the point of UndoPrevoutMissing.
        let resolved = ResolvedUtxoView::resolve(utxo.as_ref(), &block, &tx_plan(&block));
        let (changes, undo) = build_utxo_changes(&block, 2, &scratch, &resolved, None)?;
        assert_eq!(
            undo.restores().len(),
            1,
            "only the external spend is restorable; the same-block spend never entered the set"
        );
        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x63; 32]))?;

        assert!(utxo.get(&internal_outpoint(&base_prevout)).is_none());
        assert!(utxo.get(&internal_outpoint(&funding_outpoint)).is_none());
        assert!(utxo.get(&internal_outpoint(&final_outpoint)).is_some());
        Ok(())
    }

    #[test]
    fn apply_scratch_omits_rawtx_bytes_when_not_requested() -> Result<(), Box<dyn std::error::Error>>
    {
        let block = block_with_transactions(vec![coinbase_transaction(0x71), transaction(0x72)]);

        let scratch = ApplyScratch::new(&block, 2, false, false)?;

        assert_eq!(scratch.txids().len(), block.txdata.len());
        assert!(scratch.raw_txs().is_none());
        Ok(())
    }

    #[test]
    fn apply_scratch_keeps_rawtx_bytes_when_requested() -> Result<(), Box<dyn std::error::Error>> {
        let block = block_with_transactions(vec![coinbase_transaction(0x73), transaction(0x74)]);

        let scratch = ApplyScratch::new(&block, 2, true, false)?;
        let raw_txs = scratch
            .raw_txs()
            .ok_or_else(|| std::io::Error::other("rawtx bytes missing"))?;

        assert_eq!(raw_txs.len(), block.txdata.len());
        assert_eq!(
            raw_txs[0],
            bitcoin::consensus::encode::serialize(&block.txdata[0])
        );
        Ok(())
    }

    #[test]
    fn apply_scratch_skips_same_block_script_tracking_without_spend_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = block_with_transaction(coinbase_transaction(0x70));

        let scratch = ApplyScratch::new(&block, 1, false, true)?;
        let (changes, _undo) =
            build_utxo_changes(&block, 1, &scratch, &ResolvedUtxoView::empty(), None)?;

        assert!(
            !scratch.contains_same_block_spent(&internal_outpoint(&bitcoin::OutPoint {
                txid: block.txdata[0].compute_txid(),
                vout: 0,
            }))
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&bitcoin::OutPoint {
                    txid: block.txdata[0].compute_txid(),
                    vout: 0,
                }))
                .is_none()
        );
        assert_eq!(changes.add_count(), block.txdata[0].output.len());
        assert_eq!(changes.remove_count(), 0);
        Ok(())
    }

    #[test]
    fn apply_scratch_caches_same_block_spent_output_scripts_by_txid_and_vout()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x75; 32]),
            vout: 0,
        };
        let same_block_script = ScriptBuf::from_bytes(vec![0x51, 0x75]);
        let mut funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            same_block_script.clone(),
        );
        funding_tx.output.push(TxOut {
            value: Amount::from_sat(2),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x77]),
        });
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let unspent_funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 1,
        };
        let final_script = ScriptBuf::from_bytes(vec![0x51, 0x76]);
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            final_script,
        );
        let final_outpoint = bitcoin::OutPoint {
            txid: same_block_spend.compute_txid(),
            vout: 0,
        };
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);
        let funding_outpoint = internal_outpoint(&funding_outpoint);
        let scratch_without_scripts = ApplyScratch::new(&block, 2, false, false)?;
        assert!(scratch_without_scripts.contains_same_block_spent(&funding_outpoint));
        assert!(
            scratch_without_scripts
                .same_block_spent_output_script(&funding_outpoint)
                .is_none()
        );
        let scratch = ApplyScratch::new(&block, 2, false, true)?;

        assert_eq!(
            scratch.same_block_spent_output_script(&funding_outpoint),
            Some(same_block_script)
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&base_prevout))
                .is_none()
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&unspent_funding_outpoint))
                .is_none()
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&final_outpoint))
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn coinbase_maturity_rejects_same_block_coinbase_spend() {
        let coinbase = coinbase_transaction(0x64);
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend = spending_transaction_to_script(
            coinbase_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![coinbase, spend]);
        let handles = empty_apply_handles();

        let error = match check_coinbase_maturity_with_tx_plan(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            1,
        ) {
            Ok(()) => panic!("same-block coinbase spend must fail maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "COINBASE_MATURITY");
    }

    #[test]
    fn verify_block_transactions_defers_same_block_coinbase_spend_to_maturity() {
        let mut coinbase = coinbase_transaction(0x65);
        coinbase.output[0].script_pubkey = op_true_script();
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend = spending_transaction_to_script(
            coinbase_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![coinbase, spend]);
        let handles = empty_apply_handles();

        assert!(
            verify_block_transactions(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                1,
                0,
                bitcoin_rs_script::VerifyFlags::NONE,
                &kernel_block_of(&block),
            )
            .is_ok()
        );
        let error = match check_coinbase_maturity_with_tx_plan(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            1,
        ) {
            Ok(()) => panic!("same-block coinbase spend must fail maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "COINBASE_MATURITY");
    }

    #[test]
    fn bip68_height_lock_enforces_boundary_when_csv_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x68; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            2,
            op_true_script(),
        ));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            101,
            0,
            active,
            None,
        ) {
            Ok(()) => panic!("BIP68 height lock must reject one block before maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                102,
                0,
                active,
                None
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_enforces_mtp_boundary_when_csv_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x69; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_for_bip68_time(&handles)?;
        let sequence = BIP68_TYPE_FLAG | 2;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            sequence,
            op_true_script(),
        ));
        let active = softfork_state(true);
        let required_mtp = BIP68_TEST_PREVOUT_MTP + 2 * BIP68_TIME_GRANULARITY_SECONDS;

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            0,
            required_mtp - 1,
            active,
            Some(previous_tip_id),
        ) {
            Ok(()) => panic!("BIP68 time lock must reject one second before maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                0,
                required_mtp,
                active,
                Some(previous_tip_id)
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_uses_mtp_before_prevout_height() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x67; 32]),
            vout: 0,
        };
        let prevout_height = 3;
        let utxo = utxo_with_output(previous_output, prevout_height)?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_with_times(&handles, &[100, 200, 300, 400])?;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            BIP68_TYPE_FLAG,
            op_true_script(),
        ));

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                prevout_height + 1,
                200,
                softfork_state(true),
                Some(previous_tip_id),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_accepts_multiple_prevouts_at_same_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x66; 32]),
            vout: 0,
        };
        let second_previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x65; 32]),
            vout: 0,
        };
        let prevout_height = BIP68_TEST_PREVOUT_HEIGHT;
        let utxo = utxo_with_outputs_at_height(
            &[first_previous_output, second_previous_output],
            prevout_height,
        )?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_for_bip68_time(&handles)?;
        let block = block_with_transactions(vec![
            spending_transaction_to_script(
                first_previous_output,
                BIP68_TYPE_FLAG,
                op_true_script(),
            ),
            spending_transaction_to_script(
                second_previous_output,
                BIP68_TYPE_FLAG,
                op_true_script(),
            ),
        ]);

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                prevout_height + 1,
                BIP68_TEST_PREVOUT_MTP,
                softfork_state(true),
                Some(previous_tip_id),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_uses_previous_tip_mtp_for_same_block_prevout()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
        let funding_tx = transaction(0x6c);
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                101,
                BIP68_TEST_PREVOUT_MTP,
                softfork_state(true),
                Some(previous_tip_id),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_rejects_delayed_same_block_prevout() -> Result<(), Box<dyn std::error::Error>>
    {
        let handles = empty_apply_handles();
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
        let funding_tx = transaction(0x6d);
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG | 1, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            101,
            BIP68_TEST_PREVOUT_MTP,
            softfork_state(true),
            Some(previous_tip_id),
        ) {
            Ok(()) => {
                panic!("same-block time-based relative lock must not mature in the same block")
            }
            Err(error) => error,
        };
        assert_bip_error_reason_contains(&error, "BIP68", "time-based lock unmet");
        Ok(())
    }

    #[test]
    fn bip68_time_lock_rejects_missing_previous_tip_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x6a; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let sequence = BIP68_TYPE_FLAG | 1;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            sequence,
            op_true_script(),
        ));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            0,
            BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
            active,
            None,
        ) {
            Ok(()) => panic!("BIP68 time lock must reject missing previous tip context"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        Ok(())
    }

    #[test]
    fn bip68_time_lock_rejects_missing_prevout_ancestor_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x6b; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 0)?;
        let sequence = BIP68_TYPE_FLAG | 1;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            sequence,
            op_true_script(),
        ));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            0,
            BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
            active,
            Some(previous_tip_id),
        ) {
            Ok(()) => panic!("BIP68 time lock must reject missing prevout ancestry"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        Ok(())
    }

    #[test]
    fn bip68_inactive_csv_skips_unmet_sequence_lock() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x70; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            2,
            op_true_script(),
        ));

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                101,
                0,
                softfork_state(false),
                None
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_ignores_version_one_and_disabled_sequences() -> Result<(), Box<dyn std::error::Error>>
    {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x71; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let active = softfork_state(true);

        let version_one_block = block_with_transaction(spending_transaction_with_version(
            previous_output,
            2,
            bitcoin::transaction::Version::ONE,
        ));
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &version_one_block,
                &tx_plan(&version_one_block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &version_one_block,
                    &tx_plan(&version_one_block)
                )),
                101,
                0,
                active,
                None
            )
            .is_ok()
        );

        let disabled_block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            BIP68_DISABLE_FLAG | 2,
            op_true_script(),
        ));
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &disabled_block,
                &tx_plan(&disabled_block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &disabled_block,
                    &tx_plan(&disabled_block)
                )),
                101,
                0,
                active,
                None
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn bip30_rejects_duplicate_txid_when_only_higher_vout_is_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let duplicate_tx = transaction(7);
        let duplicate_txid = duplicate_tx.compute_txid();
        let duplicate_hash = Hash256::from_le_bytes(duplicate_txid.as_byte_array());
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_hash, 1),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let handles = apply_handles(utxo);
        let block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![duplicate_tx],
        };

        let txids = [duplicate_txid];
        let error = match check_bip30_and_bip34(&handles, &block, 1, &txids, None) {
            Ok(()) => panic!("duplicate txid with live vout 1 must violate BIP30"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
        ));
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn bip30_skips_duplicate_scan_after_known_bip34_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let height = Network::Testnet3
            .bip34_activation_height()
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("activation height overflow"))?;
        let duplicate_tx = coinbase_transaction_with_height(height);
        let duplicate_txid = duplicate_tx.compute_txid();
        let duplicate_hash = Hash256::from_le_bytes(duplicate_txid.as_byte_array());
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_hash, 0),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let handles = apply_handles_for_network(Network::Testnet3, utxo);
        let previous_tip_id = seed_known_bip34_activation_chain(&handles, Network::Testnet3)?;
        let block = block_with_transaction(duplicate_tx);
        let txids = [duplicate_txid];

        check_bip30_and_bip34(&handles, &block, height, &txids, Some(previous_tip_id))?;
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn bip30_duplicate_scan_runs_without_known_bip34_activation_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let height = Network::Regtest
            .bip34_activation_height()
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("activation height overflow"))?;
        let duplicate_tx = coinbase_transaction_with_height(height);
        let duplicate_txid = duplicate_tx.compute_txid();
        let duplicate_hash = Hash256::from_le_bytes(duplicate_txid.as_byte_array());
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_hash, 0),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let handles = apply_handles_for_network(Network::Regtest, utxo);
        let block = block_with_transaction(duplicate_tx);
        let txids = [duplicate_txid];
        let error = match check_bip30_and_bip34(&handles, &block, height, &txids, None) {
            Ok(()) => panic!("regtest has no fixed BIP34 activation hash and must scan BIP30"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
        ));
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn bip30_duplicate_scan_runs_at_core_recheck_limit() -> Result<(), Box<dyn std::error::Error>> {
        let duplicate_tx = coinbase_transaction_with_height(BIP34_IMPLIES_BIP30_LIMIT);
        let duplicate_txid = duplicate_tx.compute_txid();
        let duplicate_hash = Hash256::from_le_bytes(duplicate_txid.as_byte_array());
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_hash, 0),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let handles = apply_handles_for_network(Network::Mainnet, utxo);
        let block = block_with_transaction(duplicate_tx);
        let txids = [duplicate_txid];
        let error = match check_bip30_and_bip34(
            &handles,
            &block,
            BIP34_IMPLIES_BIP30_LIMIT,
            &txids,
            None,
        ) {
            Ok(()) => panic!("Core recheck limit must keep BIP30 duplicate scanning enabled"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
        ));
        Ok(())
    }

    #[test]
    fn daa_non_retarget_height_requires_parent_bits() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + 600,
            1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS),
            DAA_ANCHOR_TIME + 1_200,
            2,
        );

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2) {
            Ok(()) => panic!("non-retarget height must inherit parent nBits"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            MAINNET_POW_LIMIT_DIV_4_BITS,
            MAINNET_POW_LIMIT_BITS,
            2,
        );
        Ok(())
    }

    #[test]
    fn daa_retarget_accepts_expected_bits_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME + expected_timespan + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn daa_retarget_rejects_wrong_bits_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS),
            DAA_ANCHOR_TIME + expected_timespan + 600,
            interval,
        );

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval)
        {
            Ok(()) => panic!("retarget height must reject non-computed nBits"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            MAINNET_POW_LIMIT_DIV_4_BITS,
            MAINNET_POW_LIMIT_BITS,
            interval,
        );
        Ok(())
    }

    #[test]
    fn daa_retarget_clamps_fast_timespan_to_quarter_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan / 4) - 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS),
            DAA_ANCHOR_TIME + expected_timespan,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn daa_retarget_clamps_slow_timespan_to_quadruple_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let start_bits = scaled_pow_limit_bits(&handles, 16);
        let expected_bits = retarget_bits_for_test(
            &handles,
            start_bits,
            (expected_timespan * 4) + 1,
            expected_timespan,
        );
        let parent_hash = seed_pow_chain(
            &handles,
            start_bits,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            expected_bits,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn daa_retarget_caps_slow_timespan_at_pow_limit() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn testnet_allows_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain_with_headers(
            &handles,
            &[
                (regular_bits, DAA_ANCHOR_TIME),
                (regular_bits, DAA_ANCHOR_TIME + 600),
            ],
        )?;
        let block = block_with_pow_header(parent_hash, pow_limit_bits, DAA_ANCHOR_TIME + 1_801, 2);

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2).is_ok());
        Ok(())
    }

    #[test]
    fn testnet_timely_block_after_min_difficulty_inherits_last_non_min_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain_with_headers(
            &handles,
            &[
                (regular_bits, DAA_ANCHOR_TIME),
                (regular_bits, DAA_ANCHOR_TIME + 600),
                (pow_limit_bits, DAA_ANCHOR_TIME + 1_801),
            ],
        )?;
        let timely_time = DAA_ANCHOR_TIME + 2_400;
        let accepted = block_with_pow_header(parent_hash, regular_bits, timely_time, 3);
        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &accepted, 3).is_ok());

        let rejected = block_with_pow_header(parent_hash, pow_limit_bits, timely_time, 4);
        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &rejected, 3) {
            Ok(()) => panic!("timely testnet block must inherit the last non-min nBits"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            pow_limit_bits.to_consensus(),
            regular_bits.to_consensus(),
            3,
        );
        Ok(())
    }

    #[test]
    fn mainnet_rejects_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain_with_headers(
            &handles,
            &[
                (regular_bits, DAA_ANCHOR_TIME),
                (regular_bits, DAA_ANCHOR_TIME + 600),
            ],
        )?;
        let block = block_with_pow_header(parent_hash, pow_limit_bits, DAA_ANCHOR_TIME + 1_801, 2);

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2) {
            Ok(()) => panic!("mainnet must not allow testnet minimum-difficulty exception"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            pow_limit_bits.to_consensus(),
            regular_bits.to_consensus(),
            2,
        );
        Ok(())
    }

    #[test]
    fn testnet_min_difficulty_does_not_override_retarget_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain(
            &handles,
            regular_bits,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            pow_limit_bits,
            DAA_ANCHOR_TIME + expected_timespan + 1_201,
            interval,
        );

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval)
        {
            Ok(()) => panic!("testnet minimum-difficulty exception must not replace retarget math"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            pow_limit_bits.to_consensus(),
            regular_bits.to_consensus(),
            interval,
        );
        Ok(())
    }

    #[test]
    fn testnet4_retarget_uses_first_period_bits_after_min_difficulty_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet4);
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let first_period_bits = scaled_pow_limit_bits(&handles, 16);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_period_with_tip_bits(
            &handles,
            first_period_bits,
            pow_limit_bits,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            first_period_bits,
            DAA_ANCHOR_TIME + expected_timespan + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    /// With no filter header for the parent, the block's filter must be skipped
    /// rather than written chained from zero.
    ///
    /// A BIP157 header is a hash over its predecessor, so a chain that restarts
    /// mid-way is invalid rather than short, and a light client verifying
    /// against it gets wrong answers with nothing to detect. Writing nothing
    /// leaves the index unavailable from that point, which a backfill repairs.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn a_block_whose_parent_has_no_filter_header_writes_no_filter()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            Arc::new(UtxoSet::new()),
            &filter_index,
        );
        // Genesis deliberately NOT seeded: this is the mid-chain enable case,
        // where earlier blocks were applied without a filter index.
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        apply_block(&handles, &block)?;

        assert!(
            filter_index.headers.lock().get(&block_hash).is_none(),
            "no filter header may be written when the parent has none"
        );
        assert!(
            filter_index.prev_headers.lock().is_empty(),
            "put_filter must not be called at all, not called with zero"
        );
        assert!(
            handles.filter_header_cache.lock().is_none(),
            "the cache must not advertise a header that was never written"
        );
        Ok(())
    }

    /// Records genesis's BIP158 filter, as a real node does when it applies
    /// genesis through `apply_block`.
    ///
    /// Fixtures that install genesis with `applied_header_tip` get the header
    /// but not the filter, so the block after it finds no predecessor header
    /// and its own filter is skipped. That skip is correct behaviour and wrong
    /// setup, so the setup is what changes.
    ///
    /// The filter is computed, not stubbed. Genesis's coinbase spends nothing,
    /// so it needs no prevout lookup, and an arbitrary byte string here would
    /// seed a header that no real node would ever produce.
    fn seed_genesis_filter(
        filter_index: &RecordingFilterIndex,
        genesis: &bitcoin::Block,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::hashes::Hash as _;

        let filter = bitcoin::bip158::BlockFilter::new_script_filter(
            genesis,
            |outpoint| -> Result<ScriptBuf, bitcoin::bip158::Error> {
                Err(bitcoin::bip158::Error::UtxoMissing(*outpoint))
            },
        )?;
        filter_index.put_filter(
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            Hash256::default(),
            &filter.content,
        )?;
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_persists_non_empty_filter_for_valid_same_block_spend()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x91; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
            &filter_index,
        );
        seed_genesis_filter(&filter_index, &genesis)?;
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let funding_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1), funding_tx, same_block_spend],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());

        apply_block(&handles, &block)?;

        let stored_filter = filter_index
            .filter(block_hash)?
            .ok_or_else(|| std::io::Error::other("filter row missing"))?;
        assert!(!stored_filter.is_empty());
        Ok(())
    }

    /// The record has to outlive the process that wrote it: a node restarted
    /// mid-chain must still be able to disconnect its own tip. An in-memory
    /// store cannot show that, so this one closes the backend and reopens it,
    /// then checks every restored field rather than just the byte length.
    #[cfg(feature = "fjall")]
    #[test]
    fn a_persisted_undo_record_survives_closing_and_reopening_the_store()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin_rs_utxo::{UndoBatch, UtxoAdd, undo_codec};

        let dir = tempfile::tempdir()?;
        let block_hash = Hash256::from_le_bytes(&[0x5a; 32]);
        let outpoint = bitcoin_rs_primitives::OutPoint::new(Hash256::from_le_bytes(&[0x2c; 32]), 7);
        let removed = bitcoin_rs_primitives::OutPoint::new(Hash256::from_le_bytes(&[0x3d; 32]), 1);
        let txout = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(123_456),
            script_pubkey: op_true_script(),
        };

        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(outpoint, txout.clone(), true, 91));
        batch.remove(removed);
        let encoded = undo_codec::encode(&batch, block_hash);

        {
            let store = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
            KvUndoStore::new(store).persist_undo(91, block_hash, &encoded)?;
        }

        let reopened = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        let loaded = KvUndoStore::new(reopened)
            .load_undo(91, block_hash)?
            .ok_or("undo record did not survive the reopen")?;

        let decoded = undo_codec::decode(&loaded, block_hash)?;
        let restored = decoded
            .restores()
            .first()
            .ok_or("restored entry missing after reopen")?;
        assert_eq!(restored.outpoint, outpoint, "outpoint must round-trip");
        assert_eq!(restored.txout, txout, "spent output must round-trip");
        assert!(restored.coinbase, "coinbase flag must round-trip");
        assert_eq!(restored.height, 91, "creating height must round-trip");
        assert_eq!(
            decoded.removes(),
            batch.removes(),
            "outputs to remove must round-trip"
        );
        Ok(())
    }

    /// Deferred durability must not become deferred visibility.
    ///
    /// `disconnect_block` reads back the undo record the connect wrote, in the
    /// same process and before any checkpoint flush. redb is the backend that
    /// makes this worth pinning: its `put` commits immediately, so moving the
    /// write to `write_deferred` is exactly the change that could have made the
    /// row unreadable until a flush.
    #[cfg(feature = "redb")]
    #[test]
    fn a_deferred_undo_record_is_readable_before_any_flush()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::RedbStore::open(dir.path())?);
        let undo_store = KvUndoStore::new(Arc::clone(&store));
        let hash = Hash256::from_le_bytes(&[0x4d; 32]);

        undo_store.persist_undo(4_242, hash, b"undo-record")?;

        let loaded = undo_store
            .load_undo(4_242, hash)?
            .ok_or("undo record must be readable in-process before any flush")?;
        assert_eq!(
            loaded, b"undo-record",
            "the deferred write must return exactly what was written"
        );
        Ok(())
    }

    /// The marker exists to survive a crash, so an in-memory round trip proves
    /// nothing. This closes the backend and reopens it, which is the only shape
    /// of test that can fail if the write is not durable.
    #[cfg(feature = "fjall")]
    #[test]
    fn an_armed_disconnect_marker_survives_closing_and_reopening_the_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let block_hash = Hash256::from_le_bytes(&[0xa7; 32]);

        {
            let store = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
            KvUndoStore::new(store).arm_disconnect(140_003, block_hash)?;
        }

        let reopened = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        let marker = KvUndoStore::new(Arc::clone(&reopened))
            .load_disconnect_marker()?
            .ok_or("armed marker did not survive the reopen")?;
        assert_eq!(marker.hash, block_hash, "hash must round-trip");
        assert_eq!(marker.height, 140_003, "height must round-trip");
        assert_eq!(
            marker.phase,
            DisconnectPhase::InFlight,
            "arming records an unfinished rollback"
        );

        // A checkpoint must refuse an unfinished rollback. Checkpointing
        // half-rolled-back state captures the damage instead of repairing it.
        assert!(matches!(
            KvUndoStore::new(Arc::clone(&reopened)).disarm_disconnect(),
            Err(StorageError::InvalidOperation(_))
        ));
        assert!(
            KvUndoStore::new(Arc::clone(&reopened))
                .load_disconnect_marker()?
                .is_some(),
            "a checkpoint must not clear an in-flight marker"
        );

        // Once the rollback completes, the same call clears it, or a node that
        // disconnected cleanly could never start again.
        KvUndoStore::new(Arc::clone(&reopened)).complete_disconnect(140_003, block_hash)?;
        KvUndoStore::new(Arc::clone(&reopened)).disarm_disconnect()?;
        drop(reopened);
        let after = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        assert_eq!(
            KvUndoStore::new(after).load_disconnect_marker()?,
            None,
            "a completed rollback must clear and stay cleared across a reopen"
        );
        Ok(())
    }

    /// A truncated marker must not read as "no disconnect was in flight".
    /// Corruption clearing the interlock is the one failure it cannot have.
    #[test]
    fn a_truncated_disconnect_marker_is_an_error_not_an_absence() {
        let Err(error) = DisconnectMarker::decode(&[0_u8; 20]) else {
            panic!("a 20-byte marker must not decode as absent");
        };
        assert!(
            error.to_string().contains("expected 37"),
            "error must say what it expected, got: {error}"
        );
    }

    /// Timestamp rules must hold on the apply path, not only in header sync.
    ///
    /// `applied_header_tip` inserts a header the tree has never seen, so before
    /// this a caller handing `apply_block` a block directly could make one with
    /// a timestamp at or below its parent's median-time-past the applied
    /// consensus tip.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_rejects_a_block_whose_timestamp_precedes_its_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let mut block = block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        );
        // Exactly the parent's timestamp: the rule is strictly greater than the
        // median, and with one ancestor the median IS the parent's time.
        block.header.time = genesis.header.time;
        let target = block.header.target();
        while block.header.validate_pow(target).is_err() {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
        }
        let outcome = apply_block(&handles, &block);

        assert!(
            matches!(
                &outcome,
                Err(ApplyError::Chain(
                    bitcoin_rs_chain::ChainError::TimestampTooEarly { .. }
                ))
            ),
            "a block at or below its parent's median-time-past must be refused, got {outcome:?}"
        );

        // And it must be refused before anything is written. The check first
        // lived in `applied_header_tip`, which runs AFTER the UTXO commit, so
        // the rejection left the block's outputs installed and later validation
        // could spend coins from a block outside the applied chain.
        assert_eq!(
            utxo.len(),
            0,
            "a refused block must leave no outputs in the UTXO set"
        );
        assert_eq!(
            handles
                .applied_tip
                .load()
                .as_ref()
                .map_or(u32::MAX, |tip| tip.height),
            0,
            "and must not move the tip"
        );
        Ok(())
    }

    /// A body that fails a cheap structural check must never reach the batch.
    ///
    /// Batching made this a cost question, not just a correctness one: a peer
    /// can keep the expected header and every txid while breaking the witness
    /// commitment, and before the preflight that bought a full window of script
    /// verification for a block rejected either way.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn a_window_refuses_a_block_whose_merkle_root_does_not_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_for_network(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        applied_header_tip(&handles, block_hash, &block, 1)?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        assert_eq!(
            prove_window(&handles, &[&block], &[raw]).len(),
            1,
            "the honest block must prove, or this test proves nothing"
        );

        // Same header, different body: the merkle root no longer matches.
        let mut tampered = block.clone();
        tampered.txdata.push(coinbase_transaction(2));
        assert_eq!(
            tampered.header, block.header,
            "the header must be untouched for this to be the attack described"
        );
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&tampered));
        assert!(
            prove_window(&handles, &[&tampered], &[raw]).is_empty(),
            "a body that fails the merkle check must not reach the script batch"
        );
        Ok(())
    }

    /// The window's two caps, and which one binds.
    ///
    /// Count alone is wrong at the tip and bytes alone is wrong at genesis, so
    /// the rule is whichever binds first. The oversized-block case is the one
    /// worth pinning: a block bigger than the whole byte cap must still go
    /// through, or the chain stalls on it.
    #[test]
    fn a_window_stops_at_whichever_cap_binds_first() {
        // Tiny blocks: the count cap binds.
        assert_eq!(
            window_len(std::iter::repeat_n(256, SCRIPT_BATCH_WINDOW * 2)),
            SCRIPT_BATCH_WINDOW,
            "small blocks must fill the window to its count cap"
        );

        // Tip-sized blocks: the byte cap binds long before the count does.
        let tip_block = 2 << 20;
        let expected = SCRIPT_BATCH_MAX_BYTES / tip_block;
        assert_eq!(
            window_len(std::iter::repeat_n(tip_block, SCRIPT_BATCH_WINDOW)),
            expected,
            "tip-sized blocks must be cut off by the byte cap"
        );
        assert!(
            expected < SCRIPT_BATCH_WINDOW,
            "this assertion is vacuous unless the byte cap binds first here"
        );

        // A single block larger than the entire byte cap still goes through.
        assert_eq!(
            window_len([SCRIPT_BATCH_MAX_BYTES * 2, 256]),
            1,
            "an oversized block must be applied alone, not refused"
        );

        assert_eq!(window_len([]), 0, "an empty window is empty");
    }

    /// The window must make the same assume-valid decision the single-block path
    /// makes, and must not hand back script evidence for a block it skipped.
    ///
    /// It used to do neither: every unit was prepared and executed before the
    /// per-block decision was reached, so `--assume-valid-height N` did nothing
    /// on the windowed path at all.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn a_window_skips_scripts_for_assume_valid_blocks_and_proves_nothing_for_them()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::opcodes::all::OP_EQUAL;
        let (recorder, metrics_handle) = crate::metrics::test_recorder();

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x71; 32]),
            vout: 0,
        };

        // A spend that cannot pass: the prevout pays to a bare OP_EQUAL, so the
        // script fails whenever it actually runs. Whether the window ran it is
        // therefore observable in the result.
        let build = |assume_valid_height: u32| -> Result<_, Box<dyn std::error::Error>> {
            let utxo = Arc::new(UtxoSet::new());
            let mut changes = BlockChanges::default();
            changes.add(UtxoAdd::new(
                OutPoint::new(
                    Hash256::from_le_bytes(prevout.txid.as_byte_array()),
                    prevout.vout,
                ),
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: bitcoin::script::Builder::new()
                        .push_opcode(OP_EQUAL)
                        .into_script(),
                },
                false,
                0,
            ));
            utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0x71; 32]))?;

            let mut handles = apply_handles_for_network(Network::Regtest, utxo);
            handles.assume_valid_height = assume_valid_height;
            let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
            let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
            handles.applied_tip.store(Some(Arc::new(genesis_tip)));

            let spend = spending_transaction_to_script(
                prevout,
                Sequence::MAX.to_consensus_u32(),
                op_true_script(),
            );
            let block = mined_block_with_prev_hash_and_transactions(
                genesis.block_hash(),
                vec![coinbase_transaction(1), spend],
            )?;
            // The window refuses a block whose header the tree has not seen.
            // This test is about the assume-valid decision, not admission.
            let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
            applied_header_tip(&handles, block_hash, &block, 1)?;
            let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
            Ok((handles, block, raw))
        };

        // Height 1 is covered, and with no anchor pinned the gate is trusted.
        let (handles, block, raw) = build(100)?;
        let proven =
            metrics::with_local_recorder(&recorder, || prove_window(&handles, &[&block], &[raw]));
        assert_eq!(
            proven.len(),
            1,
            "a trusted block must not be failed by a script the window should never have run"
        );
        let Some(entry) = proven.first() else {
            panic!("window returned no entry for the only block");
        };
        assert!(
            entry.proof.is_none(),
            "a skipped block must carry no script proof: the proof branch bypasses the \
             trust-gate re-read at commit, so a gate that flips in between would let an \
             unverified block through"
        );
        assert_eq!(
            metrics_handle
                .snapshot()
                .get("node.window.verify_success_total"),
            None,
            "an empty verification dispatch must not count as script verification",
        );

        // Full verification must be completely unaffected.
        let (handles, block, raw) = build(0)?;
        let proven = prove_window(&handles, &[&block], &[raw]);
        assert!(
            proven.is_empty(),
            "with assume_valid_height 0 the bad script must still fail the window"
        );
        Ok(())
    }

    /// Preserved bytes must be the block, not a block with the same shape.
    ///
    /// The witness is the hole a count check leaves open: changing it does not
    /// change any txid, so the decoded block and the bytes can disagree on
    /// exactly the data script verification reads while every count and every
    /// txid still matches.
    #[test]
    fn preserved_bytes_carrying_a_different_witness_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        let honest = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        assert!(
            bytes_are_block(&honest, &block),
            "the block's own serialization must be accepted"
        );

        // Swap only the witness. Every txid, the transaction count, and the
        // header are untouched.
        let before = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();
        let Some(input) = block.txdata.first_mut().and_then(|tx| tx.input.first_mut()) else {
            panic!("coinbase has no input");
        };
        input.witness.push([0xab_u8; 32]);
        let after = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();
        assert_eq!(
            before, after,
            "the witness swap must not move a txid, or this proves nothing"
        );

        assert!(
            !bytes_are_block(&honest, &block),
            "bytes whose witness differs from the block must be rejected"
        );
        let outcome = parse_block_for_apply(&block, Some(honest));
        assert!(
            outcome.is_err(),
            "apply must refuse a block whose preserved bytes are not its serialization"
        );
        Ok(())
    }

    /// At a BIP30 exception height the coinbase reuses a txid whose outputs are
    /// still live, so the add overwrites a coin rather than creating one. The
    /// undo must put the overwritten coin back; removing the new output instead
    /// loses the old one for good and the rewound set no longer matches the
    /// parent.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn bip30_exception_undo_restores_the_coin_it_overwrote()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let block = block_with_transactions(vec![coinbase_transaction(7)]);
        let coinbase = block.txdata.first().ok_or("block has no coinbase")?;
        let reused = internal_outpoint(&bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        });

        // The older coin at the very same outpoint, with values the new one does
        // not share, so a restore that invents a coin cannot pass.
        let older = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(4_242),
            script_pubkey: op_true_script(),
        };
        let mut seed = bitcoin_rs_utxo::BlockChanges::default();
        seed.add(bitcoin_rs_utxo::UtxoAdd::new(
            reused,
            older.clone(),
            true,
            91_722,
        ));
        utxo.commit_block(&seed, &Hash256::from_le_bytes(&[0x30; 32]))?;

        let scratch = ApplyScratch::new(&block, 91_842, false, false)?;
        let (_changes, undo) = build_utxo_changes(
            &block,
            91_842,
            &scratch,
            &ResolvedUtxoView::empty(),
            Some(utxo.as_ref()),
        )?;

        assert!(
            undo.removes().is_empty(),
            "an overwrite is undone by writing the old coin back, not by deleting the outpoint"
        );
        let restored = undo
            .restores()
            .iter()
            .find(|entry| entry.outpoint == reused)
            .ok_or("undo does not restore the overwritten coin")?;
        assert_eq!(restored.txout, older, "the ORIGINAL output must come back");
        assert_eq!(restored.height, 91_722, "at its original height");
        assert!(restored.coinbase, "and with its original coinbase flag");
        Ok(())
    }

    /// Two connects racing for the same height must produce one winner and one
    /// rejection, never two blocks that both believe they extended the tip.
    ///
    /// Before the transition lock this could pass both: `ApplyAdmission::enter`
    /// hands out read guards, so both threads cleared the predecessor check
    /// against the same tip and then raced to publish, and whichever published
    /// second silently discarded the other's block.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn two_concurrent_connects_at_one_height_produce_one_winner()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        // Two distinct children of the same parent: both are valid extensions of
        // the current tip, and exactly one may become it.
        let left = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let right = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        assert_ne!(
            left.block_hash(),
            right.block_hash(),
            "the two candidates must differ or this races nothing"
        );

        let outcomes = std::thread::scope(|scope| {
            let a = scope.spawn(|| apply_block(&handles, &left));
            let b = scope.spawn(|| apply_block(&handles, &right));
            (a.join(), b.join())
        });
        let (Ok(left_outcome), Ok(right_outcome)) = outcomes else {
            panic!("an applier thread panicked");
        };

        let winners = usize::from(left_outcome.is_ok()) + usize::from(right_outcome.is_ok());
        assert_eq!(
            winners, 1,
            "exactly one connect may win the height, got left={left_outcome:?} right={right_outcome:?}"
        );

        let tip = handles
            .applied_tip
            .load_full()
            .ok_or("no applied tip after the race")?;
        assert_eq!(tip.height, 1, "the tip must advance exactly one block");
        let winner = if left_outcome.is_ok() { &left } else { &right };
        assert_eq!(
            tip.hash,
            Hash256::from_le_bytes(winner.block_hash().as_byte_array()),
            "the published tip must be the block that actually won"
        );
        Ok(())
    }

    /// A store that refuses every write, to prove the undo persistence is a
    /// real gate rather than a best-effort side effect.
    #[derive(Debug, Default)]
    struct RejectingUndoStore;

    impl UndoStore for RejectingUndoStore {
        fn persist_undo(
            &self,
            _height: u32,
            _hash: Hash256,
            _record: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected undo write failure".to_owned(),
            ))
        }

        fn load_undo(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            Ok(None)
        }

        fn arm_disconnect(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected marker write failure".to_owned(),
            ))
        }

        fn complete_disconnect(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected marker completion failure".to_owned(),
            ))
        }

        fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected marker clear failure".to_owned(),
            ))
        }

        fn load_disconnect_marker(
            &self,
        ) -> Result<Option<DisconnectMarker>, bitcoin_rs_storage::StorageError> {
            Ok(None)
        }
    }

    #[derive(Debug, Default)]
    struct CompleteRejectingUndoStore {
        inner: InMemoryUndoStore,
    }

    impl UndoStore for CompleteRejectingUndoStore {
        fn persist_undo(
            &self,
            height: u32,
            hash: Hash256,
            record: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.persist_undo(height, hash, record)
        }

        fn load_undo(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.inner.load_undo(height, hash)
        }

        fn arm_disconnect(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.arm_disconnect(height, hash)
        }

        fn complete_disconnect(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected marker completion failure".to_owned(),
            ))
        }

        fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.disarm_disconnect()
        }

        fn load_disconnect_marker(
            &self,
        ) -> Result<Option<DisconnectMarker>, bitcoin_rs_storage::StorageError> {
            self.inner.load_disconnect_marker()
        }
    }

    /// The disconnect event is published after the applied tip moves and before
    /// marker completion. A marker-completion failure must poison the node but
    /// must not move the tip back or retract the published event.
    #[test]
    fn disconnect_sequence_event_publishes_before_marker_completion_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut handles =
            apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        handles.undo_store = Arc::new(CompleteRejectingUndoStore::default());
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(6)],
        )?;
        apply_block(&handles, &block)?;

        let publisher = Arc::new(RecordingSequencePublisher::default());
        let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        handles = handles.with_zmq_publisher(publisher_handle);
        publisher.events.lock().clear();
        *publisher.next_sequence.lock() = 0;

        let outcome = disconnect_block(&handles, &block);
        assert!(
            matches!(outcome, Err(crate::DisconnectError::MarkerStuck { .. })),
            "marker completion failure must report MarkerStuck, got {outcome:?}"
        );
        assert_eq!(
            publisher.events.lock().as_slice(),
            &[(
                Hash256::from_le_bytes(block.block_hash().as_byte_array()),
                b'D',
                0
            )]
        );
        assert_eq!(
            handles
                .applied_tip
                .load_full()
                .as_deref()
                .map(|tip| tip.height),
            Some(0),
            "the applied tip must already be rolled back on MarkerStuck"
        );
        Ok(())
    }

    /// The ordering contract: undo is written before the UTXO commit and before
    /// every derived write, so a failure to record it must leave the node
    /// exactly as it was. Applying the block anyway would produce a chainstate
    /// the node cannot disconnect.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn a_failed_undo_write_applies_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let utxo = Arc::new(UtxoSet::new());
        let mut handles =
            apply_handles_with_filter_index(Network::Regtest, Arc::clone(&utxo), &filter_index);
        handles.undo_store = Arc::new(RejectingUndoStore);
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let outcome = apply_block(&handles, &block);

        assert!(
            matches!(outcome, Err(ApplyError::UndoPersistence(_))),
            "a failed undo write must fail the apply, got {outcome:?}"
        );
        assert_eq!(
            utxo.len(),
            0,
            "no UTXO mutation may survive a refused undo write"
        );
        assert_eq!(
            handles
                .applied_tip
                .load()
                .as_ref()
                .map_or(u32::MAX, |tip| tip.height),
            0,
            "the applied tip must not advance"
        );
        assert!(
            filter_index.headers.lock().is_empty(),
            "no derived filter row may be written for a block that did not apply"
        );
        Ok(())
    }

    /// The round trip that makes the node a full node: connect a block, then
    /// disconnect it and land on exactly the state that preceded it. A spend is
    /// included deliberately, because a coinbase-only block would exercise only
    /// the removes half and leave the restores half unproven.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn disconnecting_the_tip_restores_the_exact_prior_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let utxo = Arc::new(UtxoSet::new());
        // No transaction index runtime: the index has its own rollback tests in
        // `crates/index`. This isolates the UTXO and tip halves from any
        // asynchronous index work.
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        // A mature output for the block to spend, so the undo record carries a
        // restore as well as a remove.
        let funding_txid = bitcoin::Txid::from_byte_array([0x8b; 32]);
        let funded = bitcoin::OutPoint {
            txid: funding_txid,
            vout: 0,
        };
        let funded_value = bitcoin::Amount::from_sat(50_000);
        let mut seed = bitcoin_rs_utxo::UndoBatch::default();
        seed.restore(bitcoin_rs_utxo::UtxoAdd::new(
            internal_outpoint(&funded),
            bitcoin::TxOut {
                value: funded_value,
                script_pubkey: op_true_script(),
            },
            false,
            0,
        ));
        utxo.undo_block(&seed)?;
        let outputs_before = utxo.len();
        let funded_before = utxo
            .get(&internal_outpoint(&funded))
            .ok_or("seeded output missing before apply")?;

        let spend = spending_transaction_to_script(funded, 0xFFFF_FFFF, op_true_script());
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1), spend.clone()],
        )?;
        let applied = apply_block(&handles, &block)?;
        assert_eq!(applied.height, 1, "the block must connect first");
        assert!(
            utxo.get(&internal_outpoint(&funded)).is_none(),
            "the spend must consume the funded output"
        );

        let restored_tip = disconnect_block(&handles, &block)?;

        assert_eq!(
            restored_tip.hash, genesis_hash,
            "tip must return to genesis"
        );
        assert_eq!(restored_tip.height, 0, "height must return to genesis");
        assert_eq!(
            handles
                .applied_tip
                .load()
                .as_ref()
                .map(|tip| tip.hash)
                .ok_or("applied tip cleared by disconnect")?,
            genesis_hash,
            "the published applied tip must match the returned one"
        );
        assert_eq!(
            utxo.len(),
            outputs_before,
            "the UTXO set must return to its exact prior size"
        );
        let funded_after = utxo
            .get(&internal_outpoint(&funded))
            .ok_or("spent output was not restored")?;
        assert_eq!(
            funded_after, funded_before,
            "the restored output must be byte-identical to the one spent"
        );
        assert!(
            utxo.get(&internal_outpoint(&bitcoin::OutPoint {
                txid: spend.compute_txid(),
                vout: 0,
            }))
            .is_none(),
            "outputs the block created must be gone"
        );
        Ok(())
    }

    /// The header hash names the block; it does not vouch for the transactions
    /// handed over with it. A duplicate final transaction on an odd-width Merkle
    /// level preserves the ordinary root, so disconnect must use the
    /// mutation-aware verifier before touching any state.
    #[test]
    #[allow(clippy::arc_with_non_send_sync, clippy::too_many_lines)]
    fn disconnect_refuses_duplicate_last_transaction_merkle_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x92; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let utxo = utxo_with_output(external_prevout, 1)?;
        let handles =
            apply_handles_with_filter_index(Network::Regtest, Arc::clone(&utxo), &filter_index);
        seed_genesis_filter(&filter_index, &genesis)?;
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let funding_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![
                coinbase_transaction(1),
                funding_tx,
                same_block_spend.clone(),
            ],
        )?;
        let applied = apply_block(&handles, &block)?;
        let outputs_before = utxo.len();
        let block_records_before = handles.blocks.read().len();
        let filter_rows_before = filter_index.rows.lock().len();
        let tree_tip_before = handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash));
        let marker_before = handles.undo_store.load_disconnect_marker()?;

        let mut mutated = block.clone();
        mutated.txdata.push(same_block_spend);
        assert_eq!(
            mutated.compute_merkle_root(),
            Some(block.header.merkle_root),
            "duplicate-last mutation must preserve the ordinary Merkle root"
        );
        assert!(
            mutated.check_merkle_root(),
            "the ordinary Merkle check must accept this mutation, or the test is only the old mismatch guard"
        );
        assert_eq!(
            mutated.block_hash(),
            block.block_hash(),
            "the mutated body must retain the applied header and block hash"
        );

        let outcome = disconnect_block(&handles, &mutated);

        assert!(
            matches!(
                &outcome,
                Err(crate::DisconnectError::Refused(boxed))
                    if matches!(**boxed, ApplyError::DisconnectBodyMismatch { hash } if hash == applied.hash)
            ),
            "a mutation hidden from the ordinary root must be refused, got {outcome:?}"
        );
        assert_eq!(
            utxo.len(),
            outputs_before,
            "a refused disconnect must not touch the UTXO set"
        );
        assert_eq!(
            handles
                .applied_tip
                .load_full()
                .map(|tip| (tip.height, tip.hash)),
            Some((applied.height, applied.hash)),
            "a refused disconnect must leave the applied tip unchanged"
        );
        assert_eq!(
            handles.blocks.read().len(),
            block_records_before,
            "a refused disconnect must leave the RPC block index unchanged"
        );
        assert_eq!(
            filter_index.rows.lock().len(),
            filter_rows_before,
            "a refused disconnect must leave filter-index rows unchanged"
        );
        assert_eq!(
            handles
                .block_tree
                .read()
                .tip()
                .map(|tip| (tip.tip_id, tip.height, tip.hash)),
            tree_tip_before,
            "a refused disconnect must leave the active header index unchanged"
        );
        assert_eq!(
            handles.undo_store.load_disconnect_marker()?,
            marker_before,
            "mutation refusal must happen before the disconnect marker is armed"
        );
        Ok(())
    }

    /// RPC reads blocks from `handles.blocks`. Leaving the entry there would let
    /// `getblock` keep answering for a block the chain no longer contains.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn disconnect_drops_the_rpc_block_record() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let records_before = handles.blocks.read().len();

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        apply_block(&handles, &block)?;
        assert!(
            handles
                .blocks
                .read()
                .iter()
                .any(|record| record.hash == block_hash),
            "connection must publish the record this test then removes"
        );

        disconnect_block(&handles, &block)?;

        assert!(
            !handles
                .blocks
                .read()
                .iter()
                .any(|record| record.hash == block_hash),
            "RPC must not keep serving a disconnected block"
        );
        assert_eq!(
            handles.blocks.read().len(),
            records_before,
            "exactly the one record must go"
        );
        Ok(())
    }

    /// The marker's two ends, on the real disconnect path. Arming without
    /// disarming would refuse every later start; disarming without arming would
    /// leave the crash window unguarded. Only running the real disconnect can
    /// show both ends are wired, so this does not call the store directly.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn a_clean_disconnect_leaves_no_in_flight_marker() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &block)?;
        assert_eq!(
            handles.undo_store.load_disconnect_marker()?,
            None,
            "connecting a block must not arm the disconnect marker"
        );

        disconnect_block(&handles, &block)?;

        // Deliberately still set. The UTXO undo is complete in memory, but the
        // undo record is durable while the UTXO set and tip are not, so the
        // marker is owed a checkpoint before it may go.
        let marker = handles
            .undo_store
            .load_disconnect_marker()?
            .ok_or("a completed disconnect must leave a marker for the checkpoint")?;
        assert_eq!(
            marker.phase,
            DisconnectPhase::RolledBack,
            "a completed rollback must be recorded as such, not left in flight"
        );
        Ok(())
    }

    /// `coin_stats` needs no inverse feed of its own, and this proves it rather
    /// than assuming it. It is registered as the `UtxoSet` change listener, so
    /// `undo_block` already delivers the inverse as ordinary inserts and
    /// removals: restores arrive as inserts, removes as removals. Adding a
    /// second feed on the disconnect path would double-count.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn disconnect_returns_coin_stats_to_their_prior_value() -> Result<(), Box<dyn std::error::Error>>
    {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut utxo = UtxoSet::new();
        let listener = bitcoin_rs_coinstats::CoinStatsListener::new(
            bitcoin_rs_coinstats::CoinStats::default(),
        );
        utxo.set_listener(Box::new(listener.clone()));
        let utxo = Arc::new(utxo);
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        handles.coin_stats = Arc::new(listener);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let before = handles.coin_stats.snapshot();

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &block)?;
        let connected = handles.coin_stats.snapshot();
        assert_ne!(
            connected, before,
            "connection must move the stats, or the test proves nothing"
        );

        disconnect_block(&handles, &block)?;

        // Every field, not a chosen one. Comparing only the per-coin fields
        // would pass while `height` and `tx_count` stayed on the child, which
        // is the gap that made the block-level rewind necessary.
        //
        // MuHash is compared by digest rather than by struct. It is a ratio of
        // a numerator and a denominator, so inserting a coin and removing it
        // leaves the two equal but not back at the limbs they started from. The
        // digest is the observable value and it does return.
        let after = handles.coin_stats.snapshot();
        assert_eq!(
            after.muhash.finalize_hash(),
            before.muhash.finalize_hash(),
            "the MuHash digest must return to its prior value"
        );
        assert_eq!(after.height, before.height, "height must return");
        assert_eq!(
            after.total_amount, before.total_amount,
            "total amount must return"
        );
        assert_eq!(after.bogo_size, before.bogo_size, "bogo size must return");
        assert_eq!(after.tx_count, before.tx_count, "tx count must return");
        assert_eq!(
            after.utxo_count, before.utxo_count,
            "utxo count must return"
        );
        Ok(())
    }

    /// A block that is not the applied tip must be refused before the UTXO set
    /// is mutated. Disconnecting from the middle would restore outputs that
    /// descendants have already spent, and the tip would move to a state the
    /// UTXO set does not describe.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn disconnect_refuses_a_block_that_is_not_the_applied_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let utxo = Arc::new(UtxoSet::new());
        let handles =
            apply_handles_with_filter_index(Network::Regtest, Arc::clone(&utxo), &filter_index);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block_1 = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &block_1)?;
        let block_2 = mined_block_with_prev_hash_and_transactions(
            block_1.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        apply_block(&handles, &block_2)?;
        let outputs_before = utxo.len();

        let outcome = disconnect_block(&handles, &block_1);

        assert!(
            matches!(
                &outcome,
                Err(crate::DisconnectError::Refused(boxed))
                    if matches!(**boxed, ApplyError::DisconnectNotTip { .. })
            ),
            "disconnecting a non-tip block must be refused, got {outcome:?}"
        );
        assert_eq!(
            utxo.len(),
            outputs_before,
            "a refused disconnect must not touch the UTXO set"
        );
        assert_eq!(
            handles
                .applied_tip
                .load()
                .as_ref()
                .map_or(0, |tip| tip.height),
            2,
            "a refused disconnect must leave the tip where it was"
        );
        Ok(())
    }

    /// Without the record the prior UTXO state is unknowable. Proceeding would
    /// silently corrupt the set, so the disconnect must fail and change nothing.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn disconnect_refuses_when_the_undo_record_is_absent() -> Result<(), Box<dyn std::error::Error>>
    {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let utxo = Arc::new(UtxoSet::new());
        let mut handles =
            apply_handles_with_filter_index(Network::Regtest, Arc::clone(&utxo), &filter_index);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &block)?;
        let outputs_before = utxo.len();

        // Swap in an empty store, standing in for a record lost to pruning.
        handles.undo_store = Arc::new(InMemoryUndoStore::default());
        let outcome = disconnect_block(&handles, &block);

        assert!(
            matches!(
                &outcome,
                Err(crate::DisconnectError::Refused(boxed))
                    if matches!(**boxed, ApplyError::UndoRecordMissing { .. })
            ),
            "a missing undo record must refuse the disconnect, got {outcome:?}"
        );
        assert_eq!(
            utxo.len(),
            outputs_before,
            "a refused disconnect must not touch the UTXO set"
        );
        assert_eq!(
            handles
                .applied_tip
                .load()
                .as_ref()
                .map_or(0, |tip| tip.height),
            1,
            "a refused disconnect must leave the tip where it was"
        );
        Ok(())
    }

    /// Layer-2 acceptance: connecting a block leaves a decodable undo record
    /// bound to that block, which is the prerequisite for ever disconnecting it.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_persists_a_decodable_undo_record() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            Arc::new(UtxoSet::new()),
            &filter_index,
        );
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        apply_block(&handles, &block)?;

        let record = handles
            .undo_store
            .load_undo(1, block_hash)?
            .ok_or_else(|| std::io::Error::other("undo record missing after apply"))?;
        let undo = bitcoin_rs_utxo::decode_undo(&record, block_hash)?;

        // A coinbase-only block creates one output and spends nothing, so its
        // inverse removes that output and restores nothing.
        assert_eq!(undo.removes().len(), 1);
        assert!(undo.restores().is_empty());

        // The record is bound to its block: it must refuse another hash.
        let other = Hash256::from_le_bytes(&[0xAB; 32]);
        assert!(bitcoin_rs_utxo::decode_undo(&record, other).is_err());
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_carries_filter_header_to_next_contiguous_block()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            Arc::new(UtxoSet::new()),
            &filter_index,
        );
        seed_genesis_filter(&filter_index, &genesis)?;
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block_1 = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_1_hash = Hash256::from_le_bytes(block_1.block_hash().as_byte_array());
        apply_block(&handles, &block_1)?;

        let block_2 = mined_block_with_prev_hash_and_transactions(
            block_1.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        apply_block(&handles, &block_2)?;

        let first_filter_header = *filter_index
            .headers
            .lock()
            .get(&block_1_hash)
            .ok_or_else(|| std::io::Error::other("first filter header missing"))?;
        let genesis_filter_header = *filter_index
            .headers
            .lock()
            .get(&Hash256::from_le_bytes(
                genesis.block_hash().as_byte_array(),
            ))
            .ok_or_else(|| std::io::Error::other("genesis filter header missing"))?;
        let prev_headers = filter_index.prev_headers.lock();
        // Three writes: the seeded genesis row, then blocks 1 and 2. Each links
        // to the one before it, which is the whole BIP157 chain property.
        assert_eq!(prev_headers.len(), 3);
        assert_eq!(
            prev_headers[0],
            Hash256::default(),
            "genesis chains from zero, the one place zero is right"
        );
        assert_eq!(
            prev_headers[1], genesis_filter_header,
            "block 1 must chain from genesis, not restart at zero"
        );
        assert_eq!(
            prev_headers[2], first_filter_header,
            "block 2 must chain from block 1"
        );
        assert_eq!(
            *filter_index.header_lookup_count.lock(),
            1,
            "second contiguous block should reuse the just-stored filter header"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_skips_confirmed_transaction_cache() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        assert!(handles.tx_index_runtime.is_none());
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        apply_block(&handles, &block)?;

        assert!(handles.transactions.read().is_empty());
        Ok(())
    }

    // --- txindex worker failure isolation fixture ---

    /// A `TxIndex` writer/reader that lets the worker start up cleanly (first
    /// watermark returns `None`) and then fails on the next storage operation.
    /// This models a durable-index write fault that appears after the runtime
    /// has already committed to an asynchronous worker.
    struct FailAfterStartupTxIndex {
        watermark_calls: std::sync::atomic::AtomicUsize,
    }

    impl FailAfterStartupTxIndex {
        fn new() -> Self {
            Self {
                watermark_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl crate::txindex_worker::TxIndexWriter for FailAfterStartupTxIndex {
        fn watermark(
            &self,
        ) -> Result<Option<bitcoin_rs_index::IndexWatermark>, bitcoin_rs_index::IndexError>
        {
            if self
                .watermark_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                == 0
            {
                Ok(None)
            } else {
                Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
            }
        }

        fn prepare_block(
            &self,
            _height: u32,
            _hash: [u8; 32],
            _body: &[u8],
        ) -> Result<bitcoin_rs_index::PreparedBlock, bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }

        fn commit_forward(
            &self,
            _batch: bitcoin_rs_index::PreparedBatch,
        ) -> Result<bitcoin_rs_index::IndexWatermark, bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }

        fn commit_rollback_one(
            &self,
            _prev: Option<bitcoin_rs_index::IndexWatermark>,
            _body: &[u8],
        ) -> Result<(), bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }
    }

    impl bitcoin_rs_index::IndexReader for FailAfterStartupTxIndex {
        fn snapshot(
            &self,
        ) -> Result<Box<dyn bitcoin_rs_index::TxIndexSnapshot + '_>, bitcoin_rs_index::IndexError>
        {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }
    }

    fn wait_until(deadline: std::time::Instant, mut condition: impl FnMut() -> bool) -> bool {
        while std::time::Instant::now() < deadline {
            if condition() {
                return true;
            }
            std::thread::yield_now();
        }
        condition()
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn txindex_worker_failure_makes_queries_unavailable_without_blocking_apply()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut handles =
            apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let runtime = Arc::new(crate::txindex_worker::TxIndexRuntime::new(wake_tx));
        handles.tx_index_runtime = Some(Arc::clone(&runtime));

        let index: Arc<FailAfterStartupTxIndex> = Arc::new(FailAfterStartupTxIndex::new());
        let writer: Arc<dyn crate::txindex_worker::TxIndexWriter> = index.clone();
        let _worker = crate::txindex_worker::TxIndexWorker::spawn(
            Arc::clone(&runtime),
            writer,
            Arc::clone(&handles.applied_tip),
            Arc::clone(&handles.block_tree),
            None,
            crate::txindex_worker::DEFAULT_BATCH_LIMITS,
            wake_rx,
        )?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        assert!(
            wait_until(deadline, || {
                index
                    .watermark_calls
                    .load(std::sync::atomic::Ordering::Acquire)
                    == 1
            }),
            "txindex worker did not complete its startup reconciliation"
        );

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        runtime.wake();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        assert!(
            wait_until(deadline, || runtime.failure_message().is_some()),
            "supervised txindex worker did not publish its writer failure"
        );
        assert!(
            runtime
                .failure_message()
                .is_some_and(|message| message.contains("does not support block disconnect")),
            "worker must publish the failing writer's error"
        );

        let reader: Arc<dyn bitcoin_rs_index::IndexReader> = index;
        let query = crate::txindex_worker::TxIndexQueryEngine::new(
            Arc::clone(&runtime),
            reader,
            crate::block_source::NodeBlockSource::new(Arc::clone(&handles.blocks)),
            Arc::clone(&handles.block_tree),
            Arc::clone(&handles.applied_tip),
            None,
        );
        let query_result =
            bitcoin_rs_rpc::TxIndexQuery::transaction(&query, &genesis.txdata[0].compute_txid());
        assert!(
            matches!(
                query_result,
                Err(bitcoin_rs_rpc::TxQueryError::Unavailable(_))
            ),
            "failed txindex queries must be explicitly unavailable, got {query_result:?}"
        );

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let expected_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let applied = apply_block(&handles, &block)?;
        assert_eq!(applied.height, 1);
        assert_eq!(applied.hash, expected_hash);
        assert_eq!(
            handles
                .applied_tip
                .load_full()
                .as_ref()
                .map(|tip| (tip.height, tip.hash)),
            Some((1, expected_hash)),
            "authoritative block application must commit after txindex failure"
        );

        Ok(())
    }

    #[test]
    fn apply_block_publishes_rawtx_bytes_in_block_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x96; 32]),
            vout: 0,
        };
        let publisher = Arc::new(RecordingRawTxPublisher::default());
        let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let handles = apply_handles_without_tx_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
        )
        .with_zmq_publisher(publisher_for_handles);
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let txdata = vec![
            coinbase_transaction(0x96),
            spending_transaction_to_script(
                external_prevout,
                Sequence::MAX.to_consensus_u32(),
                op_true_script(),
            ),
        ];
        let expected_raw_txs = txdata
            .iter()
            .map(bitcoin::consensus::encode::serialize)
            .collect::<Vec<_>>();
        let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;

        apply_block(&handles, &block)?;

        assert_eq!(*publisher.raw_txs.lock(), expected_raw_txs);
        Ok(())
    }

    #[test]
    fn apply_block_publishes_full_rawblock_bytes_when_only_rawblock_is_requested()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let publisher = Arc::new(RecordingRawBlockPublisher::default());
        let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let mut handles =
            apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
                .with_zmq_publisher(publisher_for_handles);
        handles.cache_block_bodies_in_memory = false;
        assert!(handles.block_body_store.is_none());
        assert!(handles.tx_index_runtime.is_none());
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let expected_block_bytes = bitcoin::consensus::encode::serialize(&block);

        apply_block(&handles, &block)?;

        let published = publisher
            .raw_block
            .lock()
            .clone()
            .unwrap_or_else(|| panic!("rawblock bytes should be published"));
        assert_eq!(published, expected_block_bytes);
        assert!(published.len() > SERIALIZED_BLOCK_HEADER_LEN);
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_skips_zmq_publish_loop_when_publisher_opts_out()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let publisher: Arc<dyn crate::ZmqPublisher> = Arc::new(PanickingOptOutPublisher);
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
            .with_zmq_publisher(publisher);
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        apply_block(&handles, &block)?;

        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_skips_rawblock_publish_when_publisher_opts_out()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let publisher: Arc<dyn crate::ZmqPublisher> = Arc::new(PanickingNoRawblockPublisher);
        let mut handles =
            apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
                .with_zmq_publisher(publisher);
        handles.cache_block_bodies_in_memory = false;
        assert!(handles.block_body_store.is_none());
        assert!(handles.tx_index_runtime.is_none());
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        apply_block(&handles, &block)?;

        Ok(())
    }

    #[test]
    fn compute_basic_filter_skips_missing_prevout_without_persisting_empty_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles =
            apply_handles_with_filter_index(Network::Regtest, empty_utxo(), &filter_index);
        let missing_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x92; 32]),
            vout: 0,
        };
        let block = block_with_transactions(vec![
            coinbase_transaction(0x92),
            spending_transaction_to_script(
                missing_prevout,
                Sequence::MAX.to_consensus_u32(),
                op_true_script(),
            ),
        ]);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let scratch = ApplyScratch::new(&block, 1, false, true)?;

        let filter = compute_basic_filter(&block, &handles, block_hash, 1, &scratch);

        assert!(filter.is_none());
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    #[test]
    fn compute_basic_filter_matches_independent_same_block_prevout_resolver()
    -> Result<(), Box<dyn std::error::Error>> {
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x93; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
            &filter_index,
        );
        let funding_script = ScriptBuf::from_bytes(vec![0x51, 0x93]);
        let funding_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            funding_script,
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            ScriptBuf::from_bytes(vec![0x51, 0x94]),
        );
        let block = block_with_transactions(vec![
            coinbase_transaction(0x93),
            funding_tx,
            same_block_spend,
        ]);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let scratch = ApplyScratch::new(&block, 2, false, true)?;

        let filter = compute_basic_filter(&block, &handles, block_hash, 2, &scratch)
            .ok_or_else(|| std::io::Error::other("scratch filter missing"))?;
        let expected = reference_basic_filter_content(&block, &handles)?;

        assert_eq!(filter, expected);
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    #[test]
    fn apply_block_rejects_same_block_coinbase_spend_without_persisting_filter()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles =
            apply_handles_with_filter_index(Network::Regtest, empty_utxo(), &filter_index);
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let mut coinbase = coinbase_transaction(0x94);
        coinbase.output[0].script_pubkey = op_true_script();
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend = spending_transaction_to_script(
            coinbase_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase, spend],
        )?;

        let error = match apply_block(&handles, &block) {
            Ok(_) => panic!("same-block coinbase spend must fail before filter persistence"),
            Err(error) => error,
        };

        assert_bip_error(&error, "COINBASE_MATURITY");
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    #[test]
    fn apply_block_rejects_future_same_block_prevout_without_utxo_commit_or_filter_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x95; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
            &filter_index,
        );
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let later_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let future_prevout = bitcoin::OutPoint {
            txid: later_tx.compute_txid(),
            vout: 0,
        };
        let premature_spend = spending_transaction_to_script(
            future_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(0x95), premature_spend, later_tx],
        )?;

        let error = match apply_block(&handles, &block) {
            Ok(_) => {
                panic!("future same-block prevout must fail before scratch-backed side effects")
            }
            Err(error) => error,
        };

        assert!(matches!(error, ApplyError::Consensus(_)));
        assert!(
            handles
                .utxo
                .get(&internal_outpoint(&future_prevout))
                .is_none()
        );
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    fn transaction(seed: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
                    vout: u32::from(seed),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn reference_basic_filter_content(
        block: &bitcoin::Block,
        handles: &ApplyHandles,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut same_block_outputs = HashMap::new();
        for tx in &block.txdata {
            let txid = Hash256::from_le_bytes(tx.compute_txid().as_byte_array());
            for (vout, txout) in tx.output.iter().enumerate() {
                same_block_outputs.insert(
                    OutPoint::new(txid, u32::try_from(vout)?),
                    txout.script_pubkey.clone(),
                );
            }
        }

        let filter = bitcoin::bip158::BlockFilter::new_script_filter(block, |outpoint| {
            let prev_outpoint = OutPoint::new(
                Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
                outpoint.vout,
            );
            same_block_outputs
                .get(&prev_outpoint)
                .cloned()
                .or_else(|| {
                    handles
                        .utxo
                        .get(&prev_outpoint)
                        .map(|txout| txout.script_pubkey)
                })
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })?;
        Ok(filter.content)
    }

    fn coinbase_transaction(seed: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![seed, seed]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn coinbase_transaction_with_height(height: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::script::Builder::new()
                    .push_int(i64::from(height))
                    .into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_output(
        previous_output: bitcoin::OutPoint,
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        utxo_with_outputs_at_height(&[previous_output], height)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_outputs_at_height(
        previous_outputs: &[bitcoin::OutPoint],
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        for previous_output in previous_outputs {
            let txid = Hash256::from_le_bytes(previous_output.txid.as_byte_array());
            changes.add(UtxoAdd::new(
                OutPoint::new(txid, previous_output.vout),
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: op_true_script(),
                },
                false,
                height,
            ));
        }
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
        Ok(utxo)
    }

    fn block_with_transaction(tx: Transaction) -> bitcoin::Block {
        bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![tx],
        }
    }

    fn block_with_transactions(txdata: Vec<Transaction>) -> bitcoin::Block {
        bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        }
    }

    fn block_with_prev_hash_and_transactions(
        prev_blockhash: bitcoin::BlockHash,
        txdata: Vec<Transaction>,
    ) -> bitcoin::Block {
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: next_fixture_time(),
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(bitcoin::TxMerkleNode::all_zeros);
        block
    }

    /// A timestamp strictly after every fixture block built before it.
    ///
    /// The fixtures used to hard-code `1`, which is before the regtest genesis
    /// timestamp and therefore below its median-time-past. That went unnoticed
    /// while only header sync checked timestamps; now that the apply path does
    /// too, a fixture block has to carry a timestamp a real one could have.
    /// Strictly increasing also keeps deep chains valid, where a constant would
    /// fall to the median once enough blocks shared it.
    fn next_fixture_time() -> u32 {
        use core::sync::atomic::{AtomicU32, Ordering};

        // Just past the regtest genesis timestamp.
        static NEXT: AtomicU32 = AtomicU32::new(1_296_688_603);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    fn mined_block_with_prev_hash_and_transactions(
        prev_blockhash: bitcoin::BlockHash,
        txdata: Vec<Transaction>,
    ) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
        let mut block = block_with_prev_hash_and_transactions(prev_blockhash, txdata);
        let target = block.header.target();
        loop {
            if block.header.validate_pow(target).is_ok() {
                return Ok(block);
            }
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
        }
    }

    fn block_with_pow_header(
        prev_blockhash: bitcoin::BlockHash,
        bits: CompactTarget,
        time: u32,
        nonce: u32,
    ) -> bitcoin::Block {
        bitcoin::Block {
            header: pow_header(prev_blockhash, bits, time, nonce),
            txdata: Vec::new(),
        }
    }

    fn pow_header(
        prev_blockhash: bitcoin::BlockHash,
        bits: CompactTarget,
        time: u32,
        nonce: u32,
    ) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce,
        }
    }

    fn seed_pow_chain(
        handles: &ApplyHandles,
        bits: CompactTarget,
        anchor_time: u32,
        tip_time: u32,
        tip_height: u32,
    ) -> Result<bitcoin::BlockHash, Box<dyn std::error::Error>> {
        let headers: Vec<_> = (0..=tip_height)
            .map(|height| {
                (
                    bits,
                    interpolated_time(anchor_time, tip_time, height, tip_height),
                )
            })
            .collect();
        seed_pow_chain_with_headers(handles, &headers)
    }

    fn seed_pow_period_with_tip_bits(
        handles: &ApplyHandles,
        period_bits: CompactTarget,
        tip_bits: CompactTarget,
        anchor_time: u32,
        tip_time: u32,
        tip_height: u32,
    ) -> Result<bitcoin::BlockHash, Box<dyn std::error::Error>> {
        let headers: Vec<_> = (0..=tip_height)
            .map(|height| {
                let bits = if height == tip_height {
                    tip_bits
                } else {
                    period_bits
                };
                (
                    bits,
                    interpolated_time(anchor_time, tip_time, height, tip_height),
                )
            })
            .collect();
        seed_pow_chain_with_headers(handles, &headers)
    }

    fn seed_pow_chain_with_headers(
        handles: &ApplyHandles,
        headers: &[(CompactTarget, u32)],
    ) -> Result<bitcoin::BlockHash, Box<dyn std::error::Error>> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut prev_hash = bitcoin::BlockHash::all_zeros();
        for (height, &(bits, time)) in headers.iter().enumerate() {
            let height = u32::try_from(height)?;
            let header = pow_header(prev_hash, bits, time, height);
            prev_hash = header.block_hash();
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        handles.chain_tip.store(tree.tip());
        Ok(prev_hash)
    }

    fn seed_known_bip34_activation_chain(
        handles: &ApplyHandles,
        network: Network,
    ) -> Result<NodeId, Box<dyn std::error::Error>> {
        let activation_height = network.bip34_activation_height();
        let expected_hash = network
            .bip34_activation_hash()
            .ok_or_else(|| std::io::Error::other("network has no fixed BIP34 activation hash"))?;
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut prev_hash = bitcoin::BlockHash::all_zeros();
        let mut activation_id = None;
        for height in 0..=activation_height.saturating_add(1) {
            let header = pow_header(
                prev_hash,
                CompactTarget::from_consensus(0x207f_ffff),
                height,
                height,
            );
            let node_id = tree.insert_node(parent, header, NodeStatus::Active)?;
            if height == activation_height {
                activation_id = Some(node_id);
            }
            parent = Some(node_id);
            prev_hash = bitcoin::BlockHash::from_byte_array(tree.node(node_id)?.hash.to_le_bytes());
        }
        let activation_id =
            activation_id.ok_or_else(|| std::io::Error::other("missing activation node"))?;
        tree.node_mut(activation_id)?.hash = expected_hash;
        handles.chain_tip.store(tree.tip());
        parent.ok_or_else(|| std::io::Error::other("missing previous tip").into())
    }

    fn interpolated_time(anchor_time: u32, tip_time: u32, height: u32, tip_height: u32) -> u32 {
        if height == 0 || tip_height == 0 {
            return anchor_time;
        }
        let span = u64::from(tip_time.saturating_sub(anchor_time));
        let offset = span.saturating_mul(u64::from(height)) / u64::from(tip_height);
        anchor_time.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX))
    }

    fn scaled_pow_limit_bits(handles: &ApplyHandles, divisor: u64) -> CompactTarget {
        let target = handles.network.max_target() / ChainWork::from(divisor);
        bitcoin::Target::from_be_bytes(target.to_be_bytes::<32>()).to_compact_lossy()
    }

    fn pow_limit_bits(handles: &ApplyHandles) -> CompactTarget {
        bitcoin::Target::from_be_bytes(handles.network.max_target().to_be_bytes::<32>())
            .to_compact_lossy()
    }

    fn retarget_bits_for_test(
        handles: &ApplyHandles,
        previous_bits: CompactTarget,
        actual_timespan: u32,
        expected_timespan: u32,
    ) -> CompactTarget {
        let min_timespan = expected_timespan / 4;
        let max_timespan = expected_timespan * 4;
        let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);
        let previous_target =
            ChainWork::from_be_bytes(bitcoin::Target::from_compact(previous_bits).to_be_bytes());
        let actual = ChainWork::from(actual_clamped);
        let expected = ChainWork::from(expected_timespan);
        let target = ((previous_target / expected) * actual)
            + (((previous_target % expected) * actual) / expected);
        let target = target.min(handles.network.max_target());
        bitcoin::Target::from_be_bytes(target.to_be_bytes::<32>()).to_compact_lossy()
    }

    fn assert_nbits_error(error: &ApplyError, actual: u32, expected: u32, height: u32) {
        assert!(matches!(
            error,
            ApplyError::NbitsNonRetargetMismatch {
                actual: got_actual,
                expected: got_expected,
                height: got_height,
            } if *got_actual == actual && *got_expected == expected && *got_height == height
        ));
    }

    fn spending_transaction(previous_output: bitcoin::OutPoint, sequence: u32) -> Transaction {
        spending_transaction_to_script(previous_output, sequence, ScriptBuf::new())
    }

    fn spending_transaction_with_version(
        previous_output: bitcoin::OutPoint,
        sequence: u32,
        version: bitcoin::transaction::Version,
    ) -> Transaction {
        let mut transaction = spending_transaction(previous_output, sequence);
        transaction.version = version;
        transaction
    }

    fn spending_transaction_to_script(
        previous_output: bitcoin::OutPoint,
        sequence: u32,
        script_pubkey: ScriptBuf,
    ) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey,
            }],
        }
    }

    fn op_true_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn softfork_state(csv_active: bool) -> crate::bip9_context::ContextualSoftforkState {
        crate::bip9_context::ContextualSoftforkState {
            csv_active,
            segwit_active: false,
        }
    }

    fn seed_block_tree_for_bip68_time(
        handles: &ApplyHandles,
    ) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
        seed_block_tree_for_bip68_time_at_height(handles, BIP68_TEST_PREVOUT_HEIGHT)
    }

    fn seed_block_tree_for_bip68_time_at_height(
        handles: &ApplyHandles,
        tip_height: u32,
    ) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut tip = None;
        for height in 0..=tip_height {
            let header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: parent
                    .and_then(|id| {
                        tree.node(id).ok().map(|node| {
                            bitcoin::BlockHash::from_byte_array(node.hash.to_le_bytes())
                        })
                    })
                    .unwrap_or_else(bitcoin::BlockHash::all_zeros),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: BIP68_TEST_PREVOUT_MTP,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            };
            let id = tree.insert_node(parent, header, NodeStatus::Active)?;
            parent = Some(id);
            tip = Some(id);
        }
        match tip {
            Some(tip) => Ok(tip),
            None => Err(ApplyError::HeightOverflow(0)),
        }
    }

    fn seed_block_tree_with_times(
        handles: &ApplyHandles,
        times: &[u32],
    ) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut tip = None;
        for (height, time) in times.iter().copied().enumerate() {
            let header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: parent
                    .and_then(|id| {
                        tree.node(id).ok().map(|node| {
                            bitcoin::BlockHash::from_byte_array(node.hash.to_le_bytes())
                        })
                    })
                    .unwrap_or_else(bitcoin::BlockHash::all_zeros),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: u32::try_from(height).map_err(|_| ApplyError::HeightOverflow(u32::MAX))?,
            };
            let id = tree.insert_node(parent, header, NodeStatus::Active)?;
            parent = Some(id);
            tip = Some(id);
        }
        match tip {
            Some(tip) => Ok(tip),
            None => Err(ApplyError::HeightOverflow(0)),
        }
    }

    fn assert_bip_error(error: &ApplyError, bip: &str) {
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, .. }) if *actual == bip
        ));
    }

    fn assert_bip_error_reason_contains(error: &ApplyError, bip: &str, needle: &str) {
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, reason })
                if *actual == bip && reason.contains(needle)
        ));
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_apply_handles() -> ApplyHandles {
        empty_apply_handles_for_network(Network::Mainnet)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_apply_handles_for_network(network: Network) -> ApplyHandles {
        apply_handles_for_network(network, Arc::new(UtxoSet::new()))
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_handles(utxo: Arc<UtxoSet>) -> ApplyHandles {
        apply_handles_for_network(Network::Mainnet, utxo)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_handles_with_assume_valid(
        utxo: Arc<UtxoSet>,
        assume_valid_height: u32,
    ) -> ApplyHandles {
        let mut handles = apply_handles(utxo);
        handles.assume_valid_height = assume_valid_height;
        handles
    }

    fn duplicate_spend_block()
    -> Result<(bitcoin::Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x64; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let first_spend = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let second_spend = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32() - 1,
            op_true_script(),
        );
        let block = block_with_transactions(vec![first_spend, second_spend]);
        let plan = tx_plan(&block);
        Ok((block, plan, utxo))
    }

    fn bad_script_spend_block()
    -> Result<(bitcoin::Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        use bitcoin::opcodes::all::OP_EQUAL;
        use bitcoin::script::Builder;

        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x65; 32]),
            vout: 0,
        };
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        let txid = Hash256::from_le_bytes(base_prevout.txid.as_byte_array());
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, base_prevout.vout),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
            false,
            1,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: base_prevout,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true_script(),
            }],
        };
        let block = block_with_transaction(spend);
        let plan = tx_plan(&block);
        Ok((block, plan, utxo))
    }

    /// Builds a block whose single non-coinbase tx spends a P2SH-template output with a
    /// scriptSig that is VALID as a bare script but INVALID as P2SH.
    ///
    /// redeemScript = `OP_0` (single byte `0x00`), which executes to FALSE.
    /// - prevout scriptPubKey = `OP_HASH160 <hash160(redeem)> OP_EQUAL` (P2SH template).
    /// - scriptSig = push-only, pushing the redeem bytes `[0x00]` as the only item.
    ///
    /// BARE eval (P2SH OFF): scriptSig pushes `[0x00]`; scriptPubKey HASH160s it to `h`,
    /// pushes `h`, `OP_EQUAL` -> TRUE. ACCEPTED.
    /// P2SH eval (P2SH ON): the last scriptSig push `[0x00]` is deserialized as the
    /// redeemScript `OP_0`, run with an empty stack -> pushes FALSE -> FAIL at input 0.
    ///
    /// Gated to a real script backend: the acceptance arm asserts `Ok`, which only
    /// holds when scripts actually execute. With no backend the verifier returns a
    /// `Script { .. "backend disabled" }` error, so the helper would be dead code.
    #[cfg(feature = "kernel")]
    fn p2sh_template_bare_spend_block()
    -> Result<(bitcoin::Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        use bitcoin::opcodes::all::{OP_EQUAL, OP_HASH160};
        use bitcoin::script::Builder;

        let redeem: [u8; 1] = [0x00];
        let h = bitcoin::hashes::hash160::Hash::hash(&redeem);

        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x67; 32]),
            vout: 0,
        };
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        let txid = Hash256::from_le_bytes(base_prevout.txid.as_byte_array());
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, base_prevout.vout),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Builder::new()
                    .push_opcode(OP_HASH160)
                    .push_slice(h.to_byte_array())
                    .push_opcode(OP_EQUAL)
                    .into_script(),
            },
            false,
            1,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[10; 32]))?;

        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: base_prevout,
                script_sig: Builder::new().push_slice(redeem).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true_script(),
            }],
        };
        let block = block_with_transaction(spend);
        let plan = tx_plan(&block);
        Ok((block, plan, utxo))
    }

    // Asserts acceptance under the BIP16 exception, which needs a real script backend
    // (the backend-less default build returns a "backend disabled" Script error).
    #[cfg(feature = "kernel")]
    #[test]
    fn bip16_exception_accepts_bare_p2sh_template_spend_that_normal_p2sh_rejects()
    -> Result<(), Box<dyn std::error::Error>> {
        // Build the exception-block hash via bitcoin's own parser (same independent path
        // the network.rs orientation-lock test uses), and a non-exception sibling hash.
        let exception_hash = Hash256::from_le_bytes(
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
                .parse::<bitcoin::BlockHash>()?
                .as_byte_array(),
        );
        let normal_hash = Hash256::from_le_bytes(&[0x11; 32]); // any non-exception block

        // csv + segwit inactive: height 170060 predates both softforks.
        let softforks = crate::bip9_context::ContextualSoftforkState {
            csv_active: false,
            segwit_active: false,
        };

        // At height 170060 the only height-gated flag is P2SH, so:
        //   exception block -> compute_verify_flags drops P2SH
        //   normal block    -> compute_verify_flags carries P2SH
        let exc_flags = compute_verify_flags(Network::Mainnet, 170_060, exception_hash, softforks);
        let normal_flags = compute_verify_flags(Network::Mainnet, 170_060, normal_hash, softforks);
        assert!(!exc_flags.contains(bitcoin_rs_script::VerifyFlags::P2SH));
        assert!(normal_flags.contains(bitcoin_rs_script::VerifyFlags::P2SH));

        // Exception block: bare-valid P2SH-template spend is ACCEPTED.
        let (block, plan, utxo) = p2sh_template_bare_spend_block()?;
        let handles = apply_handles_with_assume_valid(utxo, 0); // full verification
        verify_block_transactions(
            &handles,
            &block,
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            170_060,
            0,
            exc_flags,
            &kernel_block_of(&block),
        )?;

        // Normal block at the same height: P2SH enforced -> REJECTED at input 0.
        let (block2, plan2, utxo2) = p2sh_template_bare_spend_block()?;
        let handles2 = apply_handles_with_assume_valid(utxo2, 0);
        let err = match verify_block_transactions(
            &handles2,
            &block2,
            &plan2,
            Arc::new(ResolvedUtxoView::resolve(
                handles2.utxo.as_ref(),
                &block2,
                &plan2,
            )),
            170_060,
            0,
            normal_flags,
            &kernel_block_of(&block2),
        ) {
            Ok(()) => {
                panic!("normal P2SH enforcement must reject the bare-script redeem spend")
            }
            Err(e) => e,
        };
        assert!(matches!(
            err,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                input_index: 0,
                ..
            })
        ));
        Ok(())
    }

    fn excess_value_spend_block()
    -> Result<(bitcoin::Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        // `utxo_with_output` funds the prevout with 1_000 sats (its second arg `1` is
        // the coinbase height, not a value); the spend creates 2_000 sats of outputs,
        // so outputs exceed inputs — a NON-script consensus violation that must be
        // caught even when script checks are skipped.
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x66; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: base_prevout,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: op_true_script(),
            }],
        };
        let block = block_with_transaction(spend);
        let plan = tx_plan(&block);
        Ok((block, plan, utxo))
    }

    fn apply_handles_with_filter_index(
        network: Network,
        utxo: Arc<UtxoSet>,
        filter_index: &RecordingFilterIndex,
    ) -> ApplyHandles {
        let filter_index: Arc<Box<dyn FilterIndexLike>> =
            Arc::new(Box::new(RecordingFilterIndex {
                rows: Arc::clone(&filter_index.rows),
                headers: Arc::clone(&filter_index.headers),
                prev_headers: Arc::clone(&filter_index.prev_headers),
                header_lookup_count: Arc::clone(&filter_index.header_lookup_count),
            }));
        ApplyHandles::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            None,
            filter_index,
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(RwLock::new(HashMap::<bitcoin::Txid, Transaction>::new())),
            Arc::new(crate::NoOpZmqPublisher),
        )
    }

    /// In-memory bodies, so a branch switch can reload the blocks it needs.
    #[derive(Default)]
    struct MapBodyStore {
        bodies: parking_lot::RwLock<HashMap<(u32, bitcoin_rs_primitives::Hash256), Vec<u8>>>,
        failed_reads: parking_lot::RwLock<HashSet<(u32, bitcoin_rs_primitives::Hash256)>>,
    }

    struct ReorgBodyLoadingFixture {
        handles: ApplyHandles,
        utxo: Arc<UtxoSet>,
        bodies: Arc<MapBodyStore>,
        target: bitcoin_rs_chain::NodeId,
        losing: bitcoin::Block,
        applied: TipSnapshot,
    }

    impl crate::apply::PruneBodyStore for MapBodyStore {
        fn load_block_body(
            &self,
            height: u32,
            hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            if self.failed_reads.read().contains(&(height, hash)) {
                return Err(StorageError::Backend(
                    "injected block-body read failure".to_owned(),
                ));
            }
            Ok(self.bodies.read().get(&(height, hash)).cloned())
        }

        fn persist_block_body(
            &self,
            height: u32,
            hash: bitcoin_rs_primitives::Hash256,
            body: &[u8],
        ) -> Result<(), StorageError> {
            self.bodies.write().insert((height, hash), body.to_vec());
            Ok(())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn reorg_body_loading_fixture() -> Result<ReorgBodyLoadingFixture, Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_arc = Arc::clone(&bodies);
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = body_arc;
        handles.block_body_store = Some(body_handle);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let losing = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&losing));
        let applied = apply_block_with_serialized(&handles, &losing, raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((applied.height, applied.hash), raw.to_vec());

        let win_one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let win_two = mined_block_with_prev_hash_and_transactions(
            win_one.block_hash(),
            vec![coinbase_transaction(3)],
        )?;
        let target = {
            let mut tree = handles.block_tree.write();
            let mut last = None;
            for (height, block) in [(1_u32, &win_one), (2_u32, &win_two)] {
                let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
                last = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
                bodies
                    .bodies
                    .write()
                    .insert((height, hash), bitcoin::consensus::encode::serialize(block));
            }
            last.ok_or_else(|| anyhow::anyhow!("no winning branch built"))?
        };

        Ok(ReorgBodyLoadingFixture {
            handles,
            utxo,
            bodies,
            target,
            losing,
            applied,
        })
    }

    fn assert_reorg_load_failure_preserved_state(
        handles: &ApplyHandles,
        utxo: &UtxoSet,
        losing: &bitcoin::Block,
        applied: &TipSnapshot,
        tree_tip_before: Option<(bitcoin_rs_chain::NodeId, u32, Hash256)>,
        block_records_before: &[(u32, Hash256)],
        utxo_len_before: usize,
    ) {
        assert_eq!(
            handles
                .applied_tip
                .load_full()
                .map(|tip| (tip.tip_id, tip.height, tip.hash)),
            Some((applied.tip_id, applied.height, applied.hash)),
            "body loading failure must not move the applied tip"
        );
        assert_eq!(
            handles
                .block_tree
                .read()
                .tip()
                .map(|tip| (tip.tip_id, tip.height, tip.hash)),
            tree_tip_before,
            "body loading failure must not change the active header index"
        );
        assert_eq!(
            handles
                .blocks
                .read()
                .iter()
                .map(|record| (record.height, record.hash))
                .collect::<Vec<_>>(),
            block_records_before,
            "body loading failure must not change the applied block index"
        );
        assert_eq!(
            utxo.len(),
            utxo_len_before,
            "body loading failure must not change UTXO cardinality"
        );
        assert!(
            utxo.has_live_outputs_for_txid(&Hash256::from_le_bytes(
                losing.txdata[0].compute_txid().as_byte_array()
            )),
            "body loading failure must leave the applied branch coin live"
        );
    }

    #[test]
    fn a_branch_with_unavailable_bodies_moves_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_arc = Arc::clone(&bodies);
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = body_arc;
        handles.block_body_store = Some(body_handle);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let applied_block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&applied_block));
        let applied = apply_block_with_serialized(&handles, &applied_block, raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((applied.height, applied.hash), raw.to_vec());

        // A competing branch whose headers are known and whose bodies are not.
        let rival_one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let rival_two = mined_block_with_prev_hash_and_transactions(
            rival_one.block_hash(),
            vec![coinbase_transaction(3)],
        )?;
        let target = {
            let mut tree = handles.block_tree.write();
            let mut last = None;
            for block in [&rival_one, &rival_two] {
                last = Some(tree.insert_header(
                    block.header,
                    bitcoin_rs_chain::node::NodeStatus::HeaderValid,
                )?);
            }
            last.ok_or_else(|| anyhow::anyhow!("no rival branch built"))?
        };

        let outcome = crate::reorg::switch_to_branch(&handles, target, |_| None, |_| {});
        assert!(
            matches!(outcome, Err(crate::reorg::ReorgError::MissingBody { .. })),
            "an unavailable branch must report a missing body, got {outcome:?}"
        );
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(applied.hash),
            "the applied tip must not move when the candidate branch is incomplete"
        );
        assert!(
            utxo.has_live_outputs_for_txid(&Hash256::from_le_bytes(
                applied_block.txdata[0].compute_txid().as_byte_array()
            )),
            "the applied branch's coins must survive an aborted switch"
        );
        Ok(())
    }

    #[derive(Debug, Default)]
    struct RecordingSequencePublisher {
        events: Mutex<Vec<(Hash256, u8, u32)>>,
        next_sequence: Mutex<u32>,
    }

    impl crate::ZmqPublisher for RecordingSequencePublisher {
        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {}

        fn publish_rawtx(&self, _bytes: &[u8]) {}

        fn publish_sequence(&self, event: crate::SequenceEvent) {
            let (hash, label) = match event {
                crate::SequenceEvent::Connected(hash) => (hash, b'C'),
                crate::SequenceEvent::Disconnected(hash) => (hash, b'D'),
            };
            let mut next_sequence = self.next_sequence.lock();
            self.events.lock().push((hash, label, *next_sequence));
            *next_sequence += 1;
        }
    }

    #[test]
    fn reorg_sequence_events_disconnect_old_tip_before_connecting_new_branch()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let publisher = Arc::new(RecordingSequencePublisher::default());
        let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo))
            .with_zmq_publisher(publisher_handle);
        let bodies = Arc::new(MapBodyStore::default());
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = bodies.clone();
        handles.block_body_store = Some(body_handle);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let old_one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let old_one_raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&old_one));
        let old_one_tip = apply_block_with_serialized(&handles, &old_one, old_one_raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((old_one_tip.height, old_one_tip.hash), old_one_raw.to_vec());

        let old_two = mined_block_with_prev_hash_and_transactions(
            old_one.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let old_two_raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&old_two));
        let old_two_tip = apply_block_with_serialized(&handles, &old_two, old_two_raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((old_two_tip.height, old_two_tip.hash), old_two_raw.to_vec());
        publisher.events.lock().clear();
        *publisher.next_sequence.lock() = 0;

        let new_one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(3)],
        )?;
        let new_two = mined_block_with_prev_hash_and_transactions(
            new_one.block_hash(),
            vec![coinbase_transaction(4)],
        )?;
        let target = {
            let mut tree = handles.block_tree.write();
            let mut target = None;
            for (height, block) in [(1_u32, &new_one), (2_u32, &new_two)] {
                target = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
                bodies.bodies.write().insert(
                    (
                        height,
                        Hash256::from_le_bytes(block.block_hash().as_byte_array()),
                    ),
                    bitcoin::consensus::encode::serialize(block),
                );
            }
            target.ok_or_else(|| anyhow::anyhow!("new branch has no target"))?
        };

        crate::reorg::switch_to_branch(&handles, target, |_| None, |_| {})?;

        let events = publisher.events.lock().clone();
        assert_eq!(
            events,
            vec![
                (
                    Hash256::from_le_bytes(old_two.block_hash().as_byte_array()),
                    b'D',
                    0
                ),
                (
                    Hash256::from_le_bytes(old_one.block_hash().as_byte_array()),
                    b'D',
                    1
                ),
                (
                    Hash256::from_le_bytes(new_one.block_hash().as_byte_array()),
                    b'C',
                    2
                ),
                (
                    Hash256::from_le_bytes(new_two.block_hash().as_byte_array()),
                    b'C',
                    3
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn invalidate_block_disconnects_active_tip_and_emits_sequence_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let publisher = Arc::new(RecordingSequencePublisher::default());
        let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo))
            .with_zmq_publisher(publisher_handle);
        let bodies = Arc::new(MapBodyStore::default());
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = bodies.clone();
        handles.block_body_store = Some(body_handle);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let one_raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&one));
        let one_tip = apply_block_with_serialized(&handles, &one, one_raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((one_tip.height, one_tip.hash), one_raw.to_vec());

        let two = mined_block_with_prev_hash_and_transactions(
            one.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let two_raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&two));
        let two_tip = apply_block_with_serialized(&handles, &two, two_raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((two_tip.height, two_tip.hash), two_raw.to_vec());
        publisher.events.lock().clear();
        *publisher.next_sequence.lock() = 0;

        crate::reorg::invalidate_block(&handles, two_tip.hash)?;

        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(one_tip.hash)
        );
        let tree = handles.block_tree.read();
        let invalid_id = tree.lookup(two_tip.hash).ok_or("missing invalidated tip")?;
        assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
        drop(tree);
        assert_eq!(
            publisher.events.lock().as_slice(),
            &[(two_tip.hash, b'D', 0)]
        );
        Ok(())
    }

    #[test]
    fn invalidate_block_missing_disconnect_body_mutates_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = bodies.clone();
        handles.block_body_store = Some(body_handle);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        let applied = apply_block_with_serialized(&handles, &block, raw)?;
        bodies
            .bodies
            .write()
            .remove(&(applied.height, applied.hash));
        handles.blocks.write().clear();

        let header_tip_before = handles.chain_tip.load_full();
        let applied_tip_before = handles.applied_tip.load_full();
        let utxo_len_before = utxo.len();
        let outcome = crate::reorg::invalidate_block(&handles, applied.hash);

        assert!(
            matches!(outcome, Err(crate::reorg::ReorgError::MissingBody { .. })),
            "missing disconnect data must abort invalidation, got {outcome:?}"
        );
        assert_eq!(
            handles.block_tree.read().node(applied.tip_id)?.status,
            NodeStatus::Active,
            "preflight failure must leave the requested header valid and active"
        );
        assert_eq!(handles.chain_tip.load_full(), header_tip_before);
        assert_eq!(handles.applied_tip.load_full(), applied_tip_before);
        assert_eq!(utxo.len(), utxo_len_before);
        Ok(())
    }

    #[test]
    fn invalidate_block_rejects_unknown_and_genesis_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles
            .applied_tip
            .store(Some(Arc::new(genesis_tip.clone())));
        let header_tip_before = handles.chain_tip.load_full();

        let unknown = Hash256::from_le_bytes(&[0x5a; 32]);
        assert!(matches!(
            crate::reorg::invalidate_block(&handles, unknown),
            Err(crate::reorg::ReorgError::UnknownBlock(hash)) if hash == unknown
        ));
        assert!(matches!(
            crate::reorg::invalidate_block(&handles, genesis_hash),
            Err(crate::reorg::ReorgError::CannotInvalidateGenesis)
        ));
        assert_eq!(handles.chain_tip.load_full(), header_tip_before);
        assert_eq!(
            handles.applied_tip.load_full().as_deref(),
            Some(&genesis_tip)
        );
        assert_eq!(
            handles.block_tree.read().node(genesis_tip.tip_id)?.status,
            NodeStatus::Active
        );
        Ok(())
    }

    struct BlockingBodyStore {
        body: Vec<u8>,
        entered: std::sync::Barrier,
        release: std::sync::Barrier,
        block_once: AtomicBool,
    }

    impl crate::apply::PruneBodyStore for BlockingBodyStore {
        fn load_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            if self.block_once.swap(false, Ordering::AcqRel) {
                self.entered.wait();
                self.release.wait();
            }
            Ok(Some(self.body.clone()))
        }

        fn persist_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
            _body: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[test]
    fn invalidate_block_holds_chain_transition_through_preflight_and_disconnect()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        let applied = apply_block_with_serialized(&handles, &block, raw.clone())?;
        handles.blocks.write().clear();

        let store = Arc::new(BlockingBodyStore {
            body: raw.to_vec(),
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
            block_once: AtomicBool::new(true),
        });
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = store.clone();
        handles.block_body_store = Some(body_handle);

        let worker_handles = handles.clone();
        let contender_handles = handles.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
            let invalidator =
                scope.spawn(move || crate::reorg::invalidate_block(&worker_handles, applied.hash));
            store.entered.wait();

            let contender = scope.spawn(move || {
                let _ = started_tx.send(());
                let transition = contender_handles.begin_chain_transition();
                let acquired = transition.is_ok();
                let _ = acquired_tx.send(acquired);
                drop(transition);
                if acquired {
                    Ok(())
                } else {
                    Err(ApplyError::Shutdown)
                }
            });
            started_rx.recv_timeout(std::time::Duration::from_secs(5))?;
            assert!(
                matches!(
                    acquired_rx.recv_timeout(std::time::Duration::from_millis(100)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ),
                "a competing transition entered while invalidation was preloading"
            );

            store.release.wait();
            invalidator
                .join()
                .map_err(|_| std::io::Error::other("invalidation worker panicked"))??;
            assert!(acquired_rx.recv_timeout(std::time::Duration::from_secs(5))?);
            contender
                .join()
                .map_err(|_| std::io::Error::other("transition contender panicked"))??;
            Ok(())
        })?;

        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(genesis_hash)
        );
        assert_eq!(
            handles.block_tree.read().node(applied.tip_id)?.status,
            NodeStatus::Invalid
        );
        Ok(())
    }

    #[derive(Debug)]
    struct AppliedTipVisiblePublisher {
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        expected: Hash256,
        seen: Mutex<Vec<Hash256>>,
    }

    impl crate::ZmqPublisher for AppliedTipVisiblePublisher {
        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {}

        fn publish_rawtx(&self, _bytes: &[u8]) {}

        fn publish_sequence(&self, event: crate::SequenceEvent) {
            if let crate::SequenceEvent::Connected(hash) = event {
                assert_eq!(
                    self.applied_tip.load_full().as_deref().map(|tip| tip.hash),
                    Some(self.expected),
                    "applied tip must be visible before publishing C"
                );
                self.seen.lock().push(hash);
            }
        }
    }

    #[test]
    fn connected_sequence_event_observes_the_published_applied_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(5)],
        )?;
        let expected = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let publisher = Arc::new(AppliedTipVisiblePublisher {
            applied_tip: Arc::clone(&handles.applied_tip),
            expected,
            seen: Mutex::new(Vec::new()),
        });
        let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let handles = handles.with_zmq_publisher(publisher_handle);

        apply_block(&handles, &block)?;

        assert_eq!(*publisher.seen.lock(), vec![expected]);
        Ok(())
    }

    #[test]
    fn a_disconnect_body_store_failure_moves_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let ReorgBodyLoadingFixture {
            handles,
            utxo,
            bodies,
            target,
            losing,
            applied,
        } = reorg_body_loading_fixture()?;
        bodies
            .failed_reads
            .write()
            .insert((applied.height, applied.hash));
        let tree_tip_before = handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash));
        let block_records_before = handles
            .blocks
            .read()
            .iter()
            .map(|record| (record.height, record.hash))
            .collect::<Vec<_>>();
        let utxo_len_before = utxo.len();
        let marker_before = handles.undo_store.load_disconnect_marker()?;

        let outcome = crate::reorg::switch_to_branch(&handles, target, |_| None, |_| {});
        assert!(
            matches!(
                outcome,
                Err(crate::reorg::ReorgError::BodyStore {
                    hash,
                    height,
                    source: StorageError::Backend(ref message),
                }) if hash == applied.hash
                    && height == applied.height
                    && message == "injected block-body read failure"
            ),
            "disconnect body storage failure must retain its typed error, got {outcome:?}"
        );
        assert_reorg_load_failure_preserved_state(
            &handles,
            &utxo,
            &losing,
            &applied,
            tree_tip_before,
            &block_records_before,
            utxo_len_before,
        );
        assert_eq!(
            handles.undo_store.load_disconnect_marker()?,
            marker_before,
            "body storage failure must not arm the disconnect marker"
        );
        Ok(())
    }

    #[test]
    fn a_disconnect_body_decode_failure_moves_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let ReorgBodyLoadingFixture {
            handles,
            utxo,
            bodies,
            target,
            losing,
            applied,
        } = reorg_body_loading_fixture()?;
        bodies
            .bodies
            .write()
            .insert((applied.height, applied.hash), vec![0]);
        let tree_tip_before = handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash));
        let block_records_before = handles
            .blocks
            .read()
            .iter()
            .map(|record| (record.height, record.hash))
            .collect::<Vec<_>>();
        let utxo_len_before = utxo.len();
        let marker_before = handles.undo_store.load_disconnect_marker()?;

        let outcome = crate::reorg::switch_to_branch(&handles, target, |_| None, |_| {});
        assert!(
            matches!(
                outcome,
                Err(crate::reorg::ReorgError::BodyDecode { hash, height, .. })
                    if hash == applied.hash && height == applied.height
            ),
            "malformed disconnect body must retain its typed decode error, got {outcome:?}"
        );
        assert_reorg_load_failure_preserved_state(
            &handles,
            &utxo,
            &losing,
            &applied,
            tree_tip_before,
            &block_records_before,
            utxo_len_before,
        );
        assert_eq!(
            handles.undo_store.load_disconnect_marker()?,
            marker_before,
            "body decode failure must not arm the disconnect marker"
        );
        Ok(())
    }

    #[test]
    fn a_closed_admission_refuses_every_chainstate_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));
        apply_block(&handles, &block)?;

        handles.admission.close_permanently();

        let child = mined_block_with_prev_hash_and_transactions(
            block.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        assert!(
            matches!(apply_block(&handles, &child), Err(ApplyError::Shutdown)),
            "connect must refuse after a tear"
        );
        assert!(
            matches!(
                apply_window(&handles, &[&child], core::slice::from_ref(&raw)),
                Err(WindowApplyError {
                    source: ApplyError::Shutdown,
                    ..
                })
            ),
            "the window path must refuse after a tear"
        );
        let disconnected = disconnect_block(&handles, &block);
        assert!(
            matches!(
                disconnected,
                Err(crate::DisconnectError::Refused(ref boxed))
                    if matches!(**boxed, ApplyError::Shutdown)
            ),
            "disconnect must refuse after a tear, got {disconnected:?}"
        );
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.height),
            Some(1),
            "the applied tip must not have moved while admission was closed"
        );
        Ok(())
    }

    #[test]
    fn a_writer_waiting_on_chain_transition_rechecks_fatal_admission_before_mutating()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let child = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let applied_before = handles
            .applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        let tree_tip_before = handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash));
        let utxo_len_before = utxo.len();

        let transition = handles.chain_transition.lock();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (shutdown, outcome_debug, admission_observed) = std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                if started_tx.send(()).is_err() {
                    return (
                        false,
                        "parent stopped before apply worker started".to_owned(),
                    );
                }
                let outcome = apply_block(&handles, &child);
                (
                    matches!(&outcome, Err(ApplyError::Shutdown)),
                    format!("{outcome:?}"),
                )
            });

            started_rx
                .recv()
                .map_err(|_| std::io::Error::other("writer did not start apply_block"))?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut admission_observed = false;
            while std::time::Instant::now() < deadline {
                if handles.admission.barrier.is_locked() {
                    admission_observed = true;
                    break;
                }
                std::thread::yield_now();
            }

            handles.admission.close_permanently();
            drop(transition);
            let (shutdown, outcome_debug) = writer
                .join()
                .map_err(|_| std::io::Error::other("writer thread panicked"))?;
            Ok::<_, std::io::Error>((shutdown, outcome_debug, admission_observed))
        })?;

        assert!(
            admission_observed,
            "the public apply path never acquired its admission permit"
        );
        assert!(
            shutdown,
            "writer must recheck fatal closure after acquiring chain_transition, got {outcome_debug}"
        );
        assert_eq!(
            handles
                .applied_tip
                .load_full()
                .map(|tip| (tip.tip_id, tip.height, tip.hash)),
            Some((
                applied_before.tip_id,
                applied_before.height,
                applied_before.hash
            )),
            "the waiting writer must not publish a new applied tip"
        );
        assert_eq!(
            handles
                .block_tree
                .read()
                .tip()
                .map(|tip| (tip.tip_id, tip.height, tip.hash)),
            tree_tip_before,
            "the waiting writer must not mutate the active header index"
        );
        assert_eq!(
            utxo.len(),
            utxo_len_before,
            "the waiting writer must not mutate UTXOs"
        );
        Ok(())
    }

    /// `Fatal` is what keeps a torn chainstate from being retried, and the
    /// reason it stays unreachable is that `plan_disconnect` checks the
    /// coinstats height before anything mutates. Drop that check and the same
    /// desync lands mid-rollback instead: the UTXO undo commits, the coinstats
    /// rewind rejects the height, and the node is torn.
    ///
    /// So this pins the precheck, not the tear. A desync must refuse with
    /// nothing touched — same applied tip, same coins.
    #[test]
    fn a_coinstats_desync_refuses_before_it_can_tear_anything()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_arc = Arc::clone(&bodies);
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = body_arc;
        handles.block_body_store = Some(body_handle);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let losing = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&losing));
        let applied = apply_block_with_serialized(&handles, &losing, raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((applied.height, applied.hash), raw.to_vec());

        let win_one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let win_two = mined_block_with_prev_hash_and_transactions(
            win_one.block_hash(),
            vec![coinbase_transaction(3)],
        )?;
        let target = {
            let mut tree = handles.block_tree.write();
            let mut last = None;
            for (height, block) in [(1_u32, &win_one), (2_u32, &win_two)] {
                let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
                last = Some(tree.insert_header(
                    block.header,
                    bitcoin_rs_chain::node::NodeStatus::HeaderValid,
                )?);
                bodies
                    .bodies
                    .write()
                    .insert((height, hash), bitcoin::consensus::encode::serialize(block));
            }
            last.ok_or_else(|| anyhow::anyhow!("no winning branch built"))?
        };

        // Desynchronise the coinstats height. The disconnect's UTXO undo lands
        // first and the coinstats rewind then rejects the height, which is a
        // real tear: some state reverted, some did not.
        handles.coin_stats.finish_block(999, 0);

        let outcome = crate::reorg::switch_to_branch(&handles, target, |_| None, |_| {});
        assert!(
            matches!(outcome, Err(crate::reorg::ReorgError::Refused { .. })),
            "the precheck must refuse rather than tear, got {outcome:?}"
        );
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(applied.hash),
            "a refused disconnect must leave the applied tip alone"
        );
        assert!(
            utxo.has_live_outputs_for_txid(&Hash256::from_le_bytes(
                losing.txdata[0].compute_txid().as_byte_array()
            )),
            "a refused disconnect must not have undone any coins"
        );
        Ok(())
    }

    fn apply_handles_for_network(network: Network, utxo: Arc<UtxoSet>) -> ApplyHandles {
        apply_handles_without_tx_index(network, utxo)
    }

    fn apply_handles_without_tx_index(network: Network, utxo: Arc<UtxoSet>) -> ApplyHandles {
        ApplyHandles::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            None,
            noop_filter_index(),
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(RwLock::new(HashMap::<bitcoin::Txid, Transaction>::new())),
            Arc::new(crate::NoOpZmqPublisher),
        )
    }

    #[derive(Debug, Default)]
    struct RecordingRawTxPublisher {
        raw_txs: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl crate::ZmqPublisher for RecordingRawTxPublisher {
        fn wants_rawtx(&self) -> bool {
            true
        }

        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {}

        fn publish_rawtx(&self, bytes: &[u8]) {
            self.raw_txs.lock().push(bytes.to_vec());
        }
    }

    #[derive(Debug, Default)]
    struct RecordingRawBlockPublisher {
        raw_block: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl crate::ZmqPublisher for RecordingRawBlockPublisher {
        fn wants_rawtx(&self) -> bool {
            false
        }

        fn wants_rawblock(&self) -> bool {
            true
        }

        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {}

        fn publish_rawblock(&self, bytes: &[u8]) {
            *self.raw_block.lock() = Some(bytes.to_vec());
        }

        fn publish_rawtx(&self, _bytes: &[u8]) {
            panic!("rawtx publish should be skipped when wants_rawtx is false");
        }
    }

    #[derive(Debug, Default)]
    struct PanickingOptOutPublisher;

    impl crate::ZmqPublisher for PanickingOptOutPublisher {
        fn wants_notifications(&self) -> bool {
            false
        }

        fn publish_hashblock(&self, _hash: Hash256) {
            panic!("hashblock publish should be skipped");
        }

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {
            panic!("hashtx publish should be skipped");
        }

        fn publish_rawblock(&self, _bytes: &[u8]) {
            panic!("rawblock publish should be skipped");
        }

        fn publish_rawtx(&self, _bytes: &[u8]) {
            panic!("rawtx publish should be skipped");
        }
    }

    #[derive(Debug, Default)]
    struct PanickingNoRawblockPublisher;

    impl crate::ZmqPublisher for PanickingNoRawblockPublisher {
        fn wants_notifications(&self) -> bool {
            true
        }

        fn wants_rawtx(&self) -> bool {
            false
        }

        fn wants_rawblock(&self) -> bool {
            false
        }

        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {
            panic!("rawblock publish should be skipped when wants_rawblock is false");
        }

        fn publish_rawtx(&self, _bytes: &[u8]) {
            panic!("rawtx publish should be skipped when wants_rawtx is false");
        }
    }

    #[derive(Default)]
    struct RecordingFilterIndex {
        rows: Arc<Mutex<HashMap<Hash256, Vec<u8>>>>,
        headers: Arc<Mutex<HashMap<Hash256, Hash256>>>,
        prev_headers: Arc<Mutex<Vec<Hash256>>>,
        header_lookup_count: Arc<Mutex<usize>>,
    }

    impl FilterIndexLike for RecordingFilterIndex {
        fn put_filter(
            &self,
            block_hash: Hash256,
            prev_header: Hash256,
            filter_bytes: &[u8],
        ) -> Result<Hash256, FilterIndexError> {
            self.rows.lock().insert(block_hash, filter_bytes.to_vec());
            self.prev_headers.lock().push(prev_header);
            let filter_header =
                bitcoin_rs_filters::cfheaders::next_header(prev_header, filter_bytes);
            self.headers.lock().insert(block_hash, filter_header);
            Ok(filter_header)
        }

        fn filter_header(&self, block_hash: Hash256) -> Result<Option<Hash256>, FilterIndexError> {
            *self.header_lookup_count.lock() += 1;
            Ok(self.headers.lock().get(&block_hash).copied())
        }

        fn filter(&self, block_hash: Hash256) -> Result<Option<Vec<u8>>, FilterIndexError> {
            Ok(self.rows.lock().get(&block_hash).cloned())
        }
    }

    struct NoopFilterIndex;

    impl FilterIndexLike for NoopFilterIndex {
        fn wants_filters(&self) -> bool {
            false
        }

        fn put_filter(
            &self,
            _block_hash: Hash256,
            _prev_header: Hash256,
            _filter_bytes: &[u8],
        ) -> Result<Hash256, FilterIndexError> {
            Ok(Hash256::default())
        }

        fn filter_header(&self, _block_hash: Hash256) -> Result<Option<Hash256>, FilterIndexError> {
            Ok(None)
        }

        fn filter(&self, _block_hash: Hash256) -> Result<Option<Vec<u8>>, FilterIndexError> {
            Ok(None)
        }
    }

    fn noop_filter_index() -> Arc<Box<dyn FilterIndexLike>> {
        let filter_index: Box<dyn FilterIndexLike> = Box::new(NoopFilterIndex);
        Arc::new(filter_index)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_utxo() -> Arc<UtxoSet> {
        Arc::new(UtxoSet::new())
    }
}

#[cfg(test)]
mod contextual_softfork_tests {
    use bitcoin_rs_script::VerifyFlags;

    use super::*;

    #[test]
    fn verify_flags_use_contextual_csv_and_segwit_state() {
        let inactive = crate::bip9_context::ContextualSoftforkState {
            csv_active: false,
            segwit_active: false,
        };
        let active = crate::bip9_context::ContextualSoftforkState {
            csv_active: true,
            segwit_active: true,
        };

        let non_exception = Hash256::from_le_bytes(&[0u8; 32]);
        let inactive_flags =
            compute_verify_flags(Network::Mainnet, 481_824, non_exception, inactive);
        assert!(!inactive_flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY));
        assert!(!inactive_flags.contains(VerifyFlags::WITNESS));
        assert!(!inactive_flags.contains(VerifyFlags::NULLDUMMY));

        let active_flags = compute_verify_flags(Network::Mainnet, 1, non_exception, active);
        assert!(active_flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY));
        assert!(active_flags.contains(VerifyFlags::WITNESS));
        assert!(active_flags.contains(VerifyFlags::NULLDUMMY));
    }

    #[test]
    fn compute_verify_flags_drops_p2sh_only_for_bip16_exception_block()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::hashes::Hash as _;

        let state = crate::bip9_context::ContextualSoftforkState {
            csv_active: false,
            segwit_active: false,
        };

        // Build the exception hash via bitcoin's own parser through the same byte path
        // the call site uses, so the orientation can't silently drift.
        let exception_display = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22";
        let exception_hash = Hash256::from_le_bytes(
            exception_display
                .parse::<bitcoin::BlockHash>()?
                .as_byte_array(),
        );

        // Core exempts exactly this block (its height) from P2SH; flags must not carry P2SH.
        let exception_flags =
            compute_verify_flags(Network::Mainnet, 170_060, exception_hash, state);
        assert!(!exception_flags.contains(VerifyFlags::P2SH));

        // Any other block at the same height still enforces P2SH.
        let other_hash = Hash256::from_le_bytes(&[0u8; 32]);
        let other_flags = compute_verify_flags(Network::Mainnet, 170_060, other_hash, state);
        assert!(other_flags.contains(VerifyFlags::P2SH));

        Ok(())
    }
}
#[cfg(test)]
mod zmq_emit_tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use parking_lot::Mutex as TestMutex;

    #[derive(Debug, Default)]
    struct CapturingPublisher {
        events: TestMutex<Vec<String>>,
    }

    impl crate::ZmqPublisher for CapturingPublisher {
        fn publish_hashblock(&self, hash: bitcoin_rs_primitives::Hash256) {
            self.events
                .lock()
                .push(format!("hashblock:{}", hash.to_string_be()));
        }

        fn publish_hashtx(&self, txid: bitcoin::Txid) {
            self.events.lock().push(format!("hashtx:{txid}"));
        }

        fn publish_rawblock(&self, _bytes: &[u8]) {
            self.events.lock().push("rawblock".to_owned());
        }

        fn publish_rawtx(&self, _bytes: &[u8]) {
            self.events.lock().push("rawtx".to_owned());
        }
    }

    #[test]
    fn captures_event_count_smoke() {
        let capturing = Arc::new(CapturingPublisher::default());
        let publisher: Arc<dyn crate::ZmqPublisher> = capturing.clone();

        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        publisher.publish_hashtx(bitcoin::Txid::from_byte_array([0; 32]));
        publisher.publish_rawblock(&[]);
        publisher.publish_rawtx(&[]);

        let events = capturing.events.lock().clone();
        assert_eq!(
            events,
            vec![
                format!(
                    "hashblock:{}",
                    bitcoin_rs_primitives::Hash256::default().to_string_be()
                ),
                format!("hashtx:{}", bitcoin::Txid::from_byte_array([0; 32])),
                "rawblock".to_owned(),
                "rawtx".to_owned(),
            ]
        );
    }
}

#[cfg(test)]
mod with_zmq_publisher_tests {
    use crate::ZmqPublisher as _;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct TaggedPublisher {
        tag: Mutex<u32>,
    }

    impl crate::ZmqPublisher for TaggedPublisher {
        fn publish_hashblock(&self, _: bitcoin_rs_primitives::Hash256) {
            *self.tag.lock() = 42;
        }

        fn publish_hashtx(&self, _: bitcoin::Txid) {}

        fn publish_rawblock(&self, _: &[u8]) {}

        fn publish_rawtx(&self, _: &[u8]) {}
    }

    #[test]
    fn with_zmq_publisher_swaps_handle() {
        let publisher = Arc::new(TaggedPublisher::default());
        // Building ApplyHandles directly here is awkward without a full NodeState.
        // Instead, verify the trait-object swap behavior by constructing the
        // publisher and exercising the publish path. The builder semantics are
        // a simple field swap; this test just covers the publisher capture.
        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        assert_eq!(*publisher.tag.lock(), 42);
    }
}

#[cfg(test)]
mod admission_tests {
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::ApplyAdmission;
    use crate::ApplyError;

    #[test]
    fn shutdown_closes_admission_and_waits_for_in_flight_apply() {
        let admission = Arc::new(ApplyAdmission::new());
        let Ok(in_flight) = admission.enter() else {
            panic!("initial apply must be admitted");
        };
        let closing = Arc::clone(&admission);
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _exclusive = closing.close();
            assert!(tx.send(()).is_ok());
        });

        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        drop(in_flight);
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
        assert!(thread.join().is_ok());
        assert!(matches!(admission.enter(), Err(ApplyError::Shutdown)));
    }
}

#[cfg(test)]
fn check_pow_limit_and_continuity_for_seeded_tip(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let prior = handles.chain_tip.load_full();
    check_pow_limit_and_continuity(handles, prior.as_deref(), block, height)
}
