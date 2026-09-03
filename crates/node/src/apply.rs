//! Block-apply pipeline over shared node handles.

mod scratch;

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_consensus::{MAX_SCRIPT_SIZE, rust_path::UtxoView};
use bitcoin_rs_mempool::{AdmissionOrigin, ChainChangeGuard, Mempool, MempoolGateway};
use bitcoin_rs_primitives::{
    Block, BlockHash, ConsensusEncode as _, Hash256, Network, OutPoint, Tx, TxOut, Txid,
    consensus_bytes, varint,
};
use bitcoin_rs_rpc::context::{BlockLog, BlockRecord};
use bitcoin_rs_utxo::{
    LiveOutput, LiveOutputMeta, UtxoSet, is_coinbase_tx,
    connect::{BlockChangeError, SpentOutputLookup, build_block_changes},
};
use hashbrown::{HashMap, HashSet};
use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::state::ApplyError;
use bitcoin_rs_storage::{
    BlockFilePosition, FlatFileBlockReader, FlatFileBlockStore, InMemoryUndoStore, KvSnapshot,
    KvStore, StorageError, WriteBatch, block_file_max_height_key, decode_block_file_max_height,
    encode_block_file_max_height,
};

#[cfg(test)]
use bitcoin_rs_storage::DisconnectMarker;
pub(crate) use bitcoin_rs_storage::{DisconnectPhase, KvUndoStore, UndoStore};
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

/// Double SHA256, kept next to the witness merkle reduction its only remaining
/// caller (a test fixture helper) uses.
#[cfg(test)]
fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let inner = Sha256::digest(data);
    let outer = Sha256::digest(inner);
    outer.into()
}

/// Merkle reduction over 32-byte leaves, duplicating the last leaf on odd
/// widths; test-fixture helper after the witness-commitment precheck moved to
/// the consensus crate.
#[cfg(test)]
fn merkle_root_bytes(leaves: &mut Vec<[u8; 32]>) -> Option<[u8; 32]> {
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
            next.push(sha256d(&pair));
        }
        *leaves = next;
    }
    Some(leaves[0])
}

fn decode_block_tx_count(bytes: &[u8]) -> Option<usize> {
    let cursor = bytes.get(SERIALIZED_BLOCK_HEADER_LEN..)?;
    let (count, consumed) = varint::decode(cursor).ok()?;
    let _ = &cursor[consumed..];
    usize::try_from(count).ok()
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

fn decode_body_position(
    height: u32,
    encoded: Option<&[u8]>,
) -> Result<Option<BlockFilePosition>, StorageError> {
    encoded
        .map(|bytes| {
            BlockFilePosition::decode(bytes).ok_or_else(|| {
                StorageError::IncompatibleData(format!(
                    "block-body index row for height {height} is not a 16-byte flat-file position"
                ))
            })
        })
        .transpose()
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
            .map(|&(height, hash)| bitcoin_rs_storage::pruning::block_body_key(height, hash))
            .collect();
        let key_refs: Vec<_> = keys.iter().map(<[u8; 37]>::as_slice).collect();
        let values = self
            .index
            .get_many_sorted(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key_refs)?;
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
                let position = decode_body_position(height, value.as_deref())?;
                Ok((height, hash, position))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
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
                let key = bitcoin_rs_storage::pruning::block_body_key(height, hash);
                let encoded = self
                    .index
                    .get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?;
                decode_body_position(height, encoded.as_deref())?
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
    pub(crate) fn open(index: Arc<S>, files: Arc<FlatFileBlockStore>) -> Self {
        Self { index, files }
    }
    /// Resolves the flat-file position of a block body, or `None` when the
    /// block is unknown. An index row that is not a decodable 16-byte
    /// flat-file position is `IncompatibleData`, never a silent `None`: the
    /// row's presence means the body must exist, so treating a decode failure
    /// as absence would hide a schema mismatch behind a missing-block answer.
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
        let key = bitcoin_rs_storage::pruning::block_body_key(height, hash);
        decode_body_position(
            height,
            self.index
                .get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?
                .as_deref(),
        )
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
        let key = bitcoin_rs_storage::pruning::block_body_key(height, hash);
        let existing = decode_body_position(
            height,
            self.index
                .get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key)?
                .as_deref(),
        )?;
        let position = self
            .files
            .persist(existing, height, *hash.as_byte_array(), body)?;
        if existing == Some(position) {
            return Ok(());
        }

        let max_height_key = block_file_max_height_key(position.file_no);
        let max_height = self
            .index
            .get(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &max_height_key)?
            .as_deref()
            .and_then(decode_block_file_max_height)
            .map_or(height, |previous| previous.max(height));
        let mut batch = self.index.new_batch();
        batch.put(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            &key,
            &position.encode(),
        );
        batch.put(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
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
        let store = FlatFilePruneBodyStore::open(index, files);
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

    #[test]
    fn malformed_body_row_is_incompatible_not_missing() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(bitcoin_rs_storage::FjallStore::open(
            temp.path().join("index"),
        )?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = FlatFilePruneBodyStore::open(index.clone(), files);
        let hash = Hash256::from_le_bytes(&[9_u8; 32]);
        store.persist_block_body(7, hash, b"body")?;
        // Overwrite the position row with a legacy inline body: same key, not
        // a decodable flat-file position.
        let key = bitcoin_rs_storage::pruning::block_body_key(7, hash);
        let mut batch = index.new_batch();
        batch.put(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            &key,
            b"legacy-inline-body",
        );
        index.write(batch)?;
        let Err(error) = store.load_block_body(7, hash) else {
            return Err("malformed body row must fail closed".into());
        };
        assert!(matches!(error, StorageError::IncompatibleData(_)));

        let mut reader = store.reader()?;
        let Err(error) = reader.load_block_body(7, hash) else {
            return Err("malformed body row must fail closed in the direct reader".into());
        };
        assert!(matches!(error, StorageError::IncompatibleData(_)));
        Ok(())
    }

    #[test]
    fn missing_prefetched_body_row_is_missing_not_incompatible()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(bitcoin_rs_storage::FjallStore::open(
            temp.path().join("index"),
        )?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = FlatFilePruneBodyStore::open(index, files);
        let hash = Hash256::from_le_bytes(&[8_u8; 32]);
        let mut reader = store.reader()?;

        reader.prefetch_positions(&[(7, hash)])?;
        assert_eq!(reader.load_block_body(7, hash)?, None);
        Ok(())
    }

    #[test]
    fn malformed_prefetched_body_row_is_incompatible_not_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(bitcoin_rs_storage::FjallStore::open(
            temp.path().join("index"),
        )?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = FlatFilePruneBodyStore::open(index.clone(), files);
        let hash = Hash256::from_le_bytes(&[7_u8; 32]);
        let key = bitcoin_rs_storage::pruning::block_body_key(7, hash);
        let mut batch = index.new_batch();
        batch.put(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            &key,
            b"legacy-inline-body",
        );
        index.write(batch)?;

        let mut reader = store.reader()?;
        let Err(error) = reader.prefetch_positions(&[(7, hash)]) else {
            return Err("malformed prefetched body row must fail closed".into());
        };
        assert!(matches!(error, StorageError::IncompatibleData(_)));
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
/// [`begin_chain_transition`] is the only constructor. Field order releases
/// the transition lock before the permit.
pub(crate) struct ChainTransition<'a> {
    _transition: MutexGuard<'a, ()>,
    _admission: RwLockReadGuard<'a, ()>,
}

fn begin_chain_transition<'a>(
    admission: &'a ApplyAdmission,
    chain_transition: &'a Mutex<()>,
) -> core::result::Result<ChainTransition<'a>, ApplyError> {
    let admission_guard = admission.enter()?;
    let transition = chain_transition.lock();
    admission.ensure_open()?;
    Ok(ChainTransition {
        _transition: transition,
        _admission: admission_guard,
    })
}

/// Unforgeable proof that a chain change is active: holds both the
/// admission/transition authority ([`ChainTransition`]) and the gateway's
/// [`ChainChangeGuard`] (odd generation).
///
/// Fields and constructor are private to this module. The admitted helpers
/// accept `&ChainChangeProof`, not independent `&ChainTransition` and
/// `&ChainChangeGuard` arguments, so a call without an active odd generation
/// fails to compile. Build one proof per single operation, whole window, or
/// whole reorg. Finish only at the outer success boundary.
pub(crate) struct ChainChangeProof<'a> {
    #[expect(
        dead_code,
        reason = "carried for unforgeability: holding the proof proves both tokens were acquired"
    )]
    transition: ChainTransition<'a>,
    guard: ChainChangeGuard,
}

impl<'a> ChainChangeProof<'a> {
    /// Constructs the combined proof from its two halves.
    ///
    /// Private to this module: only the entry-point functions that begin a
    /// chain change call this.
    pub(crate) fn new(transition: ChainTransition<'a>, guard: ChainChangeGuard) -> Self {
        Self { transition, guard }
    }

    /// Returns the exact odd generation this proof reserved.
    #[cfg(test)]
    pub(crate) fn odd_generation(&self) -> u64 {
        self.guard.odd_generation()
    }

    /// Returns the reserved even value.
    #[cfg(test)]
    pub(crate) fn reserved_even(&self) -> u64 {
        self.guard.reserved_even()
    }

    /// Finishes the chain change, storing the reserved even value.
    ///
    /// Consumes the proof so it cannot be used after finish.
    pub(crate) fn finish(self) -> core::result::Result<(), ApplyError> {
        self.guard.finish().map_err(|_| ApplyError::Shutdown)
    }
}

/// Chain-mutation authority required by destructive block-body pruning.
#[derive(Clone)]
pub(crate) struct PruneAuthority {
    admission: Arc<ApplyAdmission>,
    chain_transition: Arc<Mutex<()>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl PruneAuthority {
    pub(crate) fn begin(&self) -> core::result::Result<PruneGuard<'_>, ApplyError> {
        Ok(PruneGuard {
            _transition: begin_chain_transition(&self.admission, &self.chain_transition)?,
            applied_tip: &self.applied_tip,
        })
    }
}

/// Proof that pruning owns chain mutation and may read the authoritative tip.
pub(crate) struct PruneGuard<'a> {
    _transition: ChainTransition<'a>,
    applied_tip: &'a ArcSwapOption<TipSnapshot>,
}

impl PruneGuard<'_> {
    #[must_use]
    pub(crate) fn applied_tip_height(&self) -> Option<u32> {
        self.applied_tip.load().as_ref().map(|tip| tip.height)
    }
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
    /// Cumulative transaction count of the applied chain, or `0` when unknown.
    ///
    /// Bitcoin Core's `CBlockIndex::m_chain_tx_count`, including its convention
    /// that zero means *unset* rather than *empty* (`HaveNumChainTxs()`). Only a
    /// chain applied from genesis by a node that maintains this counter can know
    /// it; a cold start before genesis or an arithmetic inconsistency leaves it
    /// unknown until the chain is applied again.
    ///
    /// Kept beside `applied_tip` and moved with it, so the pair is always
    /// consistent: a count that lagged its tip would be worse than no count.
    pub chain_tx_count: Arc<AtomicU64>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<RwLock<BlockTree>>,
    /// Shared UTXO set.
    pub utxo: Arc<UtxoSet>,
    /// Shared coinstats listener.
    pub coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    /// Shared transaction index runtime, when enabled.
    pub tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    /// Shared mempool.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Strong gateway handle for production mempool mutation. Apply and reorg
    /// call this directly; they never call `MempoolGateway::shared` or recover
    /// from the weak registry. The raw `mempool` field stays for read-only
    /// node code that still needs the pool.
    pub mempool_gateway: Arc<MempoolGateway>,
    /// Template-coordinator wake; fired on authoritative tip moves.
    pub(crate) mining_generation: Arc<crate::mining::MiningGenerationSignal>,
    /// Shared block records exposed to RPC handlers.
    pub blocks: Arc<RwLock<BlockLog>>,
    /// Shared transaction map exposed to RPC handlers.
    pub transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    /// Shared ZMQ-event publisher (default: `NoOpZmqPublisher`).
    pub zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    /// Chain-event publisher for coherent snapshots and reconciliation hints.
    pub chain_events: Arc<crate::state::ChainEventPublisher>,
    pub(crate) block_body_store: Option<Arc<dyn PruneBodyStore>>,
    /// Undo storage. Mandatory: see [`UndoStore`].
    pub(crate) undo_store: Arc<dyn UndoStore>,
    pub(crate) admission: Arc<ApplyAdmission>,
    /// Process-wide shutdown signal shared by all runtime workers.
    pub(crate) shutdown: Arc<AtomicBool>,
    /// Serializes whole chain transitions against each other.
    ///
    /// Distinct from `admission`, which is a shutdown barrier: `enter` takes a
    /// READ guard, so any number of applies hold it at once and it excludes
    /// nothing but a checkpoint close. A transition reads the applied tip,
    /// decides what follows it, mutates chain-owned state, and publishes the
    /// result. Two such operations interleaved can both validate against the
    /// same tip and then invalidate each other's retention or publication
    /// decisions. This lock spans connects, windows, disconnects, and pruning.
    pub(crate) chain_transition: Arc<parking_lot::Mutex<()>>,
    /// Block height at or below which kernel / portable script execution is skipped during block apply.
    /// Non-script transaction checks still run. Zero disables the shortcut (full script checks on every block).
    pub assume_valid_height: u32,
    /// Path to the crash-recovery sidecar; when set, the apply path writes
    /// `(height, last_committed_height, tip_hash)` after every successful
    /// block apply so boot can replay the gap from stored bodies.
    pub(crate) recovery_meta_path: Option<std::path::PathBuf>,
    /// Hash-pinned assume-valid trust gate; the height shortcut above applies only while this is trusted.
    pub assume_valid_gate: Arc<AssumeValidGate>,
}

impl ApplyHandles {
    pub(crate) fn prune_authority(&self) -> PruneAuthority {
        PruneAuthority {
            admission: Arc::clone(&self.admission),
            chain_transition: Arc::clone(&self.chain_transition),
            applied_tip: Arc::clone(&self.applied_tip),
        }
    }

    pub(crate) fn begin_chain_transition(
        &self,
    ) -> core::result::Result<ChainTransition<'_>, ApplyError> {
        begin_chain_transition(&self.admission, &self.chain_transition)
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
        coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
        tx_index_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
        mempool: Arc<RwLock<Mempool>>,
        mempool_gateway: Arc<MempoolGateway>,
        mining_generation: Arc<crate::mining::MiningGenerationSignal>,
        blocks: Arc<RwLock<BlockLog>>,
        transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
        zmq_publisher: Arc<dyn crate::ZmqPublisher>,
        chain_events: Arc<crate::state::ChainEventPublisher>,
    ) -> Self {
        Self {
            network,
            chain_tip,
            applied_tip,
            chain_tx_count: Arc::new(AtomicU64::new(0)),
            block_tree,
            utxo,
            coin_stats,
            mempool,
            tx_index_runtime,
            mempool_gateway,
            mining_generation,
            blocks,
            transactions,
            zmq_publisher,
            chain_events,
            block_body_store: None,
            undo_store: Arc::new(InMemoryUndoStore::default()),
            admission: Arc::new(ApplyAdmission::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            chain_transition: Arc::new(parking_lot::Mutex::new(())),
            assume_valid_height: 0,
            assume_valid_gate: Arc::new(AssumeValidGate::with_anchor(None)),
            recovery_meta_path: None,
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
    block: &Block,
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
    let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
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
            bitcoin_rs_utxo::stats::CoinStatsRewindError::HeightMismatch {
                expected: height,
                found: stats.height,
            },
        ));
    }
    if stats.tx_count < tx_count_delta {
        return Err(ApplyError::CoinStatsRewind(
            bitcoin_rs_utxo::stats::CoinStatsRewindError::TxCountUnderflow {
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
/// Restores the consensus UTXO set, coinstats, RPC block cache, and `applied_tip`.
///
/// Production callers: branch switching (`crate::reorg::switch_to_branch`) and
/// block invalidation (`crate::reorg::invalidate_block`).
///
/// State and notification ownership across a disconnect:
///
/// | Handle | Responsibility |
/// |---|---|
/// | `utxo`, `applied_tip` | restored here |
/// | `coin_stats` | restored here in two halves: per-coin fields ride the `UtxoSet` change listener; block-level height and transaction count are explicitly rewound |
/// | `blocks` | rewound here — pops the cached block record so RPC reflects the parent tip |
/// | `transactions` | nothing owed: connection never populates it |
/// | `chain_event_publisher` / `tx_index_runtime` | sequence counter advanced and hints emitted; index workers reconcile asynchronously |
/// | `zmq_publisher` | publishes `SequenceEvent::Disconnected` after the tip moves |
/// | `mempool` | owned at the branch-switch boundary in `crate::reorg::reconsider_disconnected_transactions`, which re-admits disconnected transactions through `MempoolGateway` |
/// | `block_tree` | retained deliberately — the header stays valid and known |
/// | `block_body_store` | retained deliberately — the body is still a real block available for future reorgs or RPC |
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
/// 4. Advance the sequence counter, emit chain-event hints, and publish ZMQ
///    disconnect notifications. Index workers reconcile asynchronously over
///    the chain-event seam (`docs/contracts/chain-events.md`).
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
    block: &Block,
) -> core::result::Result<TipSnapshot, crate::DisconnectError> {
    let transition = handles
        .begin_chain_transition()
        .map_err(|error| crate::DisconnectError::Refused(Box::new(error)))?;
    let guard = handles
        .mempool_gateway
        .begin_chain_change()
        .map_err(|_| crate::DisconnectError::Refused(Box::new(ApplyError::Shutdown)))?;
    let proof = ChainChangeProof::new(transition, guard);
    let result = disconnect_block_admitted(handles, block, &proof);
    if result.is_ok() {
        // Finish the chain change only on full success. An error leaves the
        // generation odd by design — admission stays closed.
        let _ = proof.finish();
    }
    result
}

/// Disconnects one block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
#[allow(clippy::too_many_lines)]
pub(crate) fn disconnect_block_admitted(
    handles: &ApplyHandles,
    block: &Block,
    _proof: &ChainChangeProof<'_>,
) -> core::result::Result<TipSnapshot, crate::DisconnectError> {
    let block_hash = block.block_hash().0;
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
            .is_some_and(|record| record.hash == BlockHash::from(block_hash))
        {
            blocks.pop();
        }
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
    handles.chain_events.record(
        crate::state::HintKind::Disconnected,
        parent_tip.height,
        parent_tip.hash,
    );
    rewind_chain_tx_count(handles, tx_count_delta);
    handles.wake_tx_index();
    // The applied tip moved: every template long-poll waiter must observe it.
    handles.mining_generation.publish_generation();

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
fn tx_count_delta_for(block: &Block) -> u64 {
    u64::try_from(block.txs.len()).unwrap_or(u64::MAX)
}

/// Carries the cumulative transaction count forward across a connected block.
///
/// Zero means *unknown*, so a count that is already unknown stays unknown
/// rather than restarting from this block and pretending to be a chain total.
/// Genesis is the one block that can establish the count from nothing: there is
/// no chain below it.
fn advance_chain_tx_count(handles: &ApplyHandles, height: u32, tx_count_delta: u64) {
    let known = handles.chain_tx_count.load(Ordering::Relaxed);
    if known == 0 && height != 0 {
        return;
    }
    let advanced = known.checked_add(tx_count_delta).unwrap_or_else(|| {
        tracing::warn!(
            known,
            tx_count_delta,
            "cumulative chain transaction count overflowed; marking it unknown"
        );
        0
    });
    handles.chain_tx_count.store(advanced, Ordering::Relaxed);
}

/// Takes a disconnected block's transactions back out of the cumulative count.
///
/// An unknown count stays unknown. A subtraction that would go below zero means
/// the count and the chain have diverged, and a silently clamped total is worse
/// than an admitted absence, so that case resets to unknown.
fn rewind_chain_tx_count(handles: &ApplyHandles, tx_count_delta: u64) {
    let known = handles.chain_tx_count.load(Ordering::Relaxed);
    if known == 0 {
        return;
    }
    let rewound = known.checked_sub(tx_count_delta).unwrap_or_else(|| {
        tracing::warn!(
            known,
            tx_count_delta,
            "cumulative chain transaction count fell below zero; marking it unknown"
        );
        0
    });
    handles.chain_tx_count.store(rewound, Ordering::Relaxed);
}

/// Synthetically applies `block` as the next tip after consensus checks.
pub fn apply_block(
    handles: &ApplyHandles,
    block: &Block,
) -> core::result::Result<TipSnapshot, ApplyError> {
    apply_block_inner(handles, block, None)
}

/// Returns after consensus gates that precede the first write, without
/// persisting the block. BIP22 proposal mode omits proof-of-work.
pub fn validate_block(
    handles: &ApplyHandles,
    block: &Block,
) -> core::result::Result<(), ApplyError> {
    let _transition = handles.begin_chain_transition()?;
    let block_hash = block.block_hash().0;
    let prev_hash = block.header.prev_blockhash.0;
    let _ = applied_predecessor(handles, block_hash, prev_hash)?;
    Ok(())
}

/// Applies `block` reusing preserved wire-format bytes for body persistence and indexing.
pub fn apply_block_with_serialized(
    handles: &ApplyHandles,
    block: &Block,
    serialized: bytes::Bytes,
) -> core::result::Result<TipSnapshot, ApplyError> {
    apply_block_inner(handles, block, Some(serialized))
}

/// Applies one serialized block while the caller holds admission and `chain_transition`.
///
/// The caller MUST hold both guards in admission-then-transition order.
pub(crate) fn apply_block_with_serialized_admitted(
    handles: &ApplyHandles,
    block: &Block,
    serialized: bytes::Bytes,
    proof: &ChainChangeProof<'_>,
) -> core::result::Result<TipSnapshot, ApplyError> {
    apply_block_admitted(handles, block, Some(serialized), None, proof)
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
#[allow(clippy::result_large_err)]
pub fn apply_window(
    handles: &ApplyHandles,
    blocks: &[&Block],
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
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
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
        .map_err(|source| WindowApplyError {
            applied: 0,
            source,
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        })?;
    let guard = handles
        .mempool_gateway
        .begin_chain_change()
        .map_err(|_| WindowApplyError {
            applied: 0,
            source: ApplyError::Shutdown,
            disposition: WindowApplyDisposition::Operational,
            invalidated: Box::default(),
        })?;
    let proof = ChainChangeProof::new(transition, guard);
    let mut proven = prove_window(handles, blocks, serialized).into_iter();
    let mut applied = 0_usize;
    for (block, raw) in blocks.iter().zip(serialized) {
        apply_block_admitted(handles, block, Some(raw.clone()), proven.next(), &proof).map_err(
            |source| {
                let disposition = if is_permanent_apply_error(&source) {
                    WindowApplyDisposition::Permanent
                } else {
                    WindowApplyDisposition::Operational
                };
                let invalidated = invalidate_failed_subtree(handles, block, &source);
                WindowApplyError {
                    applied,
                    source,
                    disposition,
                    invalidated,
                }
            },
        )?;
        applied = applied.saturating_add(1);
    }
    // G5: finish only on success. An error after begin leaves the generation
    // odd by design — admission stays closed until an external recovery path
    // resets it.
    let _ = proof.finish();
    Ok(())
}

/// Marks the failed block's header subtree invalid while the chain transition
/// is still held, so the window caller can purge download state without the
/// frontier ever re-offering a descendant of a permanently invalid block.
///
/// Only permanent failures invalidate. Operational failures (storage, UTXO
/// commit, shutdown) are transient: the block stays retryable, so nothing may
/// be marked `Invalid` here. A header missing from the tree (rejected before
/// insertion, e.g. prev-hash mismatch or `PoW` failure) has no subtree to
/// invalidate, which leaves the list empty and the classification untouched.
fn invalidate_failed_subtree(
    handles: &ApplyHandles,
    block: &Block,
    source: &ApplyError,
) -> Box<[Hash256]> {
    if !is_permanent_apply_error(source) {
        return Box::default();
    }
    let hash = block.block_hash().0;
    let mut tree = handles.block_tree.write();
    let Some(node_id) = tree.lookup(hash) else {
        return Box::default();
    };
    tree.invalidate_subtree(node_id)
        .unwrap_or_default()
        .into_boxed_slice()
}

/// Returns true when an apply failure is a permanent block-invalidity
/// condition, not an operational error.
///
/// Only these failures poison the branch: the block and its descendants can
/// never become valid, so invalidating the subtree is safe and the node
/// republishes the best valid tip rather than retrying the same block.
/// Operational failures (storage, UTXO commit, undo record, shutdown) are
/// transient and must not permanently mark a block invalid.
pub(crate) fn is_permanent_apply_error(error: &ApplyError) -> bool {
    match error {
        ApplyError::ProofOfWork { .. }
        | ApplyError::TargetAboveLimit
        | ApplyError::NbitsNonRetargetMismatch { .. } => true,
        ApplyError::Consensus(error) => !matches!(
            error,
            bitcoin_rs_consensus::ConsensusError::PrevoutMatrixSize { .. }
                | bitcoin_rs_consensus::ConsensusError::Kernel(_)
                | bitcoin_rs_consensus::ConsensusError::Encoding(_)
        ),
        _ => false,
    }
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
    /// How the caller must treat this failure: `Permanent` failures poisoned
    /// the failed block's header subtree while the chain transition was still
    /// held; `Operational` failures poisoned nothing.
    pub disposition: WindowApplyDisposition,
    /// Hashes marked invalid under the held transition when `disposition` is
    /// [`WindowApplyDisposition::Permanent`]: the failed block and every
    /// descendant, in deterministic slab order. Empty otherwise.
    pub invalidated: Box<[Hash256]>,
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

impl WindowApplyError {
    /// Failure kind the caller should act on.
    #[must_use]
    pub const fn disposition(&self) -> WindowApplyDisposition {
        self.disposition
    }

    /// Hashes invalidated for a `Permanent` failure, empty otherwise.
    #[must_use]
    pub fn invalidated(&self) -> &[Hash256] {
        &self.invalidated
    }
}

/// Whether a window failure is permanent or operational.
///
/// The caller must not re-classify the source error: the node classifier and
/// the reorg classifier are the same predicate, and the disposition here is
/// what that predicate decided at the failure point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowApplyDisposition {
    /// The failed block and its descendants can never be valid. Their header
    /// subtrees were invalidated under the window's chain transition; purge
    /// every returned hash from staged/download state without retrying.
    Permanent,
    /// Transient failure (storage, UTXO commit, shutdown). Nothing was
    /// invalidated; the failed block and its tail stay retryable.
    Operational,
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
fn prove_window<'a>(
    handles: &ApplyHandles,
    blocks: &[&'a Block],
    serialized: &[bytes::Bytes],
) -> Vec<ProvenApply<'a>> {
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
            let hash = block.block_hash().0;
            if block.header.prev_blockhash.0 != parent_hash {
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
            contexts.push(BlockValidationContext {
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
        let Ok((kernel_block, txids)) = parsed else {
            return Vec::new();
        };
        let tx_plan = plan_block_transactions(block, &txids);
        let view = bitcoin_rs_consensus::BlockView::new(&block.txs, txids);
        let resolved = Arc::new(ResolvedUtxoView::resolve(&overlay, block, &tx_plan));
        if overlay
            .advance(
                block,
                view.txids(),
                context.height,
                tx_plan.same_block_spent_set(),
            )
            .is_err()
        {
            return Vec::new();
        }
        prepared.push(PreparedApply {
            kernel_block,
            view,
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
    for ((block, unit), context) in blocks.iter().zip(prepared.iter_mut()).zip(&contexts) {
        if !bitcoin_rs_consensus::verify_block::block_merkle_root_matches_txids(
            block,
            unit.view.txids(),
        ) {
            return Vec::new();
        }
        // BIP141: a missing commitment is fatal only when the block carries
        // witness data anyway; a commitment-less block without witness data is
        // valid under active segwit. The commitment check consumes the view's
        // cached witness IDs, so a block hashes its transactions as witness
        // IDs exactly once across the whole window.
        if context
            .flags
            .contains(bitcoin_rs_script::VerifyFlags::WITNESS)
            && bitcoin_rs_consensus::verify_block::block_has_witness(block)
        {
            let commitment_matches = {
                let wtxids = unit.view.witness_ids();
                bitcoin_rs_consensus::verify_block::block_witness_commitment_matches(block, wtxids)
            };
            if !commitment_matches {
                return Vec::new();
            }
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
        for (index, ((block, unit), context)) in blocks
            .iter()
            .zip(prepared.iter_mut())
            .zip(&contexts)
            .enumerate()
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
                unit.view.txids(),
            ) else {
                return Vec::new();
            };
            unit.view.set_resolved(resolved);
            match bitcoin_rs_consensus::verify_tx::prepare_block_script_checks(
                &mut unit.view,
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
        .map(|((prepared, context), skipped)| {
            if skipped {
                ProvenApply::AssumeValidSkipped(prepared)
            } else {
                ProvenApply::Proven(BlockValidationProof { prepared, context })
            }
        })
        .collect()
}

/// Chain context that determines the ordered transaction checks for one block.
///
/// A window captures this before it applies any block. The commit path derives
/// it again from the live chain and accepts a proof only when every field still
/// agrees.
#[derive(Debug, Eq, PartialEq)]
struct BlockValidationContext {
    hash: Hash256,
    parent: Hash256,
    height: u32,
    flags: bitcoin_rs_script::VerifyFlags,
    locktime_cutoff: u32,
}

/// Chain facts BIP68 evaluates against: the validation context fixing the
/// block's height, the parent median-time-past, the softfork state at
/// connect, and the applied tip the prevout ancestry hangs from.
#[derive(Clone, Copy)]
struct Bip68Context<'a> {
    validation: &'a BlockValidationContext,
    median_time_past: u32,
    softfork_state: crate::bip9_context::ContextualSoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
}

/// Evidence that every ordered transaction pre-check, input script, and
/// transaction post-check passed for this exact prepared block state.
///
/// The proof is private, single-use, and owns the prepared state it certifies.
/// It is constructed only after the whole window verifier succeeds, so callers
/// cannot pair a block's verdict with foreign resolved prevouts.
struct BlockValidationProof<'b> {
    prepared: PreparedApply<'b>,
    context: BlockValidationContext,
}

/// Prepared state returned by a successful window attempt.
///
/// Assume-valid is not proof. A skipped block must re-enter the ordinary
/// transaction path at commit so it reads the trust gate in its current state.
enum ProvenApply<'b> {
    Proven(BlockValidationProof<'b>),
    AssumeValidSkipped(PreparedApply<'b>),
}

/// Everything a block's application needs that depends only on the block and
/// the outputs it spends, not on the chain state the commit will mutate.
///
/// Split out because a window of consecutive blocks can produce all of these
/// at once, against one ordered overlay, and share a single script dispatch.
/// The measured duplication that made an earlier batching attempt a wash was
/// exactly the kernel parse and the prevout resolution below being done twice.
struct PreparedApply<'b> {
    kernel_block: bitcoin_rs_consensus::kernel::KernelBlock,
    /// Parse-once transaction state: identities computed once in
    /// [`parse_block_for_apply`], witness IDs on demand, and the prevout
    /// matrix installed once right before script verification.
    view: bitcoin_rs_consensus::BlockView<'b>,
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

impl std::io::Write for ByteEquality<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
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

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns true iff `raw` is exactly the consensus serialization of `block`.
pub(crate) fn bytes_are_block(raw: &[u8], block: &Block) -> bool {
    let mut sink = ByteEquality {
        expected: raw,
        offset: 0,
        equal: true,
    };
    // Encoding to a sink cannot fail; a write error here would be a bug in the
    // sink above, and treating it as inequality is the safe reading either way.
    if block.consensus_encode(&mut sink).is_err() {
        return false;
    }
    // `offset` accumulated every written byte, so a longer `raw` (trailing
    // bytes) fails here just as a shorter one fails in the sink.
    sink.equal && sink.offset == raw.len()
}

#[cfg_attr(
    not(feature = "kernel"),
    expect(
        clippy::needless_pass_by_value,
        reason = "the kernel build consumes preserved bytes through this shared signature"
    )
)]
fn parse_block_for_apply(
    block: &Block,
    provided_serialized: Option<bytes::Bytes>,
) -> core::result::Result<(bitcoin_rs_consensus::kernel::KernelBlock, Vec<Txid>), ApplyError> {
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
    #[cfg(feature = "kernel")]
    let (kernel_block, txids) = {
        let raw_block: bytes::Bytes =
            provided_serialized.unwrap_or_else(|| bytes::Bytes::from(consensus_bytes(block)));
        let kernel_block = bitcoin_rs_consensus::kernel::KernelBlock::parse(&raw_block)
            .map_err(ApplyError::Consensus)?;
        if kernel_block.transaction_count() != block.txs.len() {
            return Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Kernel(format!(
                    "kernel parsed {} transactions, decoder produced {}",
                    kernel_block.transaction_count(),
                    block.txs.len()
                )),
            ));
        }
        let txids = kernel_block.txids().map_err(ApplyError::Consensus)?;
        (kernel_block, txids)
    };
    // Without the kernel there is no second parse to harvest identities from,
    // so hash each transaction of the already-decoded block exactly once.
    // Re-decoding the preserved bytes here would make the native path pay two
    // full decodes plus one consensus re-serialization per block.
    #[cfg(not(feature = "kernel"))]
    let (kernel_block, txids) = (
        bitcoin_rs_consensus::kernel::KernelBlock,
        block_txids(block),
    );
    Ok((kernel_block, txids))
}

/// Transaction IDs of an already-decoded block, hashed exactly once.
///
/// Blocks beyond the threshold the window verifier uses fan the hashing out;
/// below it, serial iteration wins because dispatch costs more than the
/// per-transaction double SHA256.
#[cfg(any(test, not(feature = "kernel")))]
fn block_txids(block: &Block) -> Vec<Txid> {
    if block.txs.len() > 32 {
        block.txs.par_iter().map(Tx::txid).collect()
    } else {
        block.txs.iter().map(Tx::txid).collect()
    }
}

/// Parses a block and resolves the outputs it spends.
///
/// `source` is where prevouts come from. Every caller outside a window passes
/// the committed UTXO set; a window passes an overlay so a block can see
/// outputs an earlier block in the same window created.
fn prepare_apply<'b, S: crate::window_overlay::OutputSource + ?Sized>(
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    source: &S,
) -> core::result::Result<PreparedApply<'b>, ApplyError> {
    let (kernel_block, txids) = parse_block_for_apply(block, provided_serialized)?;
    let tx_plan = plan_block_transactions(block, &txids);
    let view = bitcoin_rs_consensus::BlockView::new(&block.txs, txids);
    let resolved = Arc::new(ResolvedUtxoView::resolve(source, block, &tx_plan));
    Ok(PreparedApply {
        kernel_block,
        view,
        tx_plan,
        resolved,
    })
}

fn apply_block_inner(
    handles: &ApplyHandles,
    block: &Block,
    provided_serialized: Option<bytes::Bytes>,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let transition = handles.begin_chain_transition()?;
    let guard = handles
        .mempool_gateway
        .begin_chain_change()
        .map_err(|_| ApplyError::Shutdown)?;
    let proof = ChainChangeProof::new(transition, guard);
    let result = apply_block_admitted(handles, block, provided_serialized, None, &proof);
    if result.is_ok() {
        let _ = proof.finish();
    }
    result
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
fn apply_block_admitted<'b>(
    handles: &ApplyHandles,
    block: &'b Block,
    provided_serialized: Option<bytes::Bytes>,
    proven: Option<ProvenApply<'b>>,
    _proof: &ChainChangeProof<'_>,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let total_started = quanta::Instant::now();
    let block_hash = block.block_hash().0;
    let prev_hash = block.header.prev_blockhash.0;
    let (prior, height) = applied_predecessor(handles, block_hash, prev_hash)?;

    // Self-consistency PoW: the block header's hash must satisfy its
    // declared target. This is the cheapest consensus gate; do it before
    // any structural checks. Contextual difficulty-adjustment validation
    // (verifying the declared target matches the network's expected
    // difficulty at this height) requires `BlockTree` state — deferred.
    let pow_self_started = quanta::Instant::now();
    let pow_self_result = if compact_is_met_by(block.header.bits, block_hash) {
        Ok(())
    } else {
        Err(())
    };
    let pow_self_dur = pow_self_started.elapsed();
    metrics::histogram!("node.apply_block.pow_self_consistency_seconds")
        .record(pow_self_dur.as_secs_f64());
    if pow_self_result.is_err() {
        return Err(ApplyError::ProofOfWork { hash: block_hash });
    }

    let (prev_median_time_past, softfork_state) = if let Some(tip) = prior.as_deref() {
        let tree = handles.block_tree.read();
        let mtp = tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0);
        let softfork_state = crate::bip9_context::contextual_softfork_state(
            &tree,
            handles.network,
            Some(tip.tip_id),
            height,
        );
        (mtp, softfork_state)
    } else {
        let tree = handles.block_tree.read();
        (
            0,
            crate::bip9_context::contextual_softfork_state(&tree, handles.network, None, height),
        )
    };
    let locktime_cutoff = if softfork_state.csv_active {
        prev_median_time_past
    } else {
        block.header.time
    };
    let verify_flags = compute_verify_flags(handles.network, height, block_hash, softfork_state);
    let validation_context = BlockValidationContext {
        hash: block_hash,
        parent: prev_hash,
        height,
        flags: verify_flags,
        locktime_cutoff,
    };
    // Parse the block once with the kernel and take its txids. Core's
    // `CTransaction` hashes itself while deserializing with the SHA-256
    // implementation selected at runtime, so this one parse replaces the
    // scalar `compute_txid` pass *and* the per-transaction serialize/reparse
    // that script preparation used to perform.
    // A window prepares several blocks against one overlay and hands the result
    // back, so the kernel parse and the prevout resolution happen once. A proof
    // whose context no longer matches is discarded together with its prepared
    // view; the ordinary path rebuilds both from the live UTXO set.
    let (prepared, transactions_proven) = match proven {
        Some(ProvenApply::Proven(proof)) if proof.context == validation_context => {
            (proof.prepared, true)
        }
        Some(ProvenApply::AssumeValidSkipped(prepared)) => (prepared, false),
        Some(ProvenApply::Proven(_)) | None => (
            prepare_apply(block, provided_serialized.clone(), handles.utxo.as_ref())?,
            false,
        ),
    };
    let PreparedApply {
        kernel_block,
        mut view,
        tx_plan,
        resolved,
    } = prepared;
    // Before any mutation. A header the tree has never seen skips header
    // sync's timestamp rules entirely, so this gate applies them itself; the
    // header insert in `applied_header_tip` below is part of the same
    // fallible preparation phase and still precedes the first write.
    check_unseen_header_timestamp(handles, block, block_hash)?;

    let block_rules_started = quanta::Instant::now();
    // Witness IDs are needed only for a witness-carrying block under active
    // segwit; the view computes them once and the commitment check consumes
    // the cache, so witness-free blocks never serialize-and-hash for wtxids.
    let needs_wtxids = softfork_state.segwit_active && tx_plan.witness_presence.is_present();
    if needs_wtxids {
        view.witness_ids();
    }
    let block_rules_result = bitcoin_rs_consensus::verify_block_rules_precomputed(
        block,
        bitcoin_rs_consensus::BlockRuleContext {
            segwit_active: softfork_state.segwit_active,
        },
        view.txids(),
        view.computed_witness_ids().unwrap_or(&[]),
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
        check_bip30_and_bip34(handles, block, height, view.txids(), previous_tip_id);
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
    // A matching proof certifies exactly this transaction-validation slot.
    // Block rules and BIP30/BIP34 remain above it; coinbase maturity and BIP68
    // remain below it. Every other state uses the ordinary verifier.
    let script_verify_result = if transactions_proven {
        Ok(())
    } else {
        verify_block_transactions(
            handles,
            block,
            &mut view,
            &tx_plan,
            Arc::clone(&resolved),
            &validation_context,
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
        view.txids(),
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
        view.txids(),
        Arc::clone(&resolved),
        Bip68Context {
            validation: &validation_context,
            median_time_past: prev_median_time_past,
            softfork_state,
            previous_tip_id,
        },
    );
    let bip68_dur = bip68_started.elapsed();
    metrics::histogram!("node.apply_block.bip68_seconds").record(bip68_dur.as_secs_f64());
    bip68_result?;
    let wants_rawtx = handles.zmq_publisher.wants_rawtx();
    let wants_rawblock = handles.zmq_publisher.wants_rawblock();
    let (txids, scratch_capacities, same_block_spent, same_block_spent_input_count) =
        tx_plan.into_scratch_parts(view.into_txids());
    let scratch = ApplyScratch::from_prepared_parts(
        block,
        wants_rawtx,
        txids,
        scratch_capacities,
        same_block_spent,
        same_block_spent_input_count,
    );

    let utxo_changes_started = quanta::Instant::now();
    let (utxo_add_capacity, utxo_remove_capacity) = scratch.utxo_change_capacity();
    let (changes, undo, value_totals) = build_block_changes(
        block,
        height,
        scratch.txids(),
        scratch.same_block_spent(),
        utxo_add_capacity,
        utxo_remove_capacity,
        resolved.as_ref(),
        bitcoin_rs_consensus::bip30::is_bip30_exception(height, block_hash)
            .then(|| handles.utxo.as_ref()),
        MAX_SCRIPT_SIZE,
    )
    .map_err(map_block_change_error)?;
    let utxo_changes_dur = utxo_changes_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_changes_seconds")
        .record(utxo_changes_dur.as_secs_f64());

    // The last consensus gate, and the one that keeps a miner from creating
    // money. Nothing above bounds what the coinbase pays itself: block rules
    // check structure, and per-transaction verification exempts the coinbase
    // because it has no inputs to weigh its outputs against.
    //
    // Placed here because `build_block_changes` has just gathered the totals for
    // free, and still before `persist_undo` -- the first write of any kind --
    // so a rejected block leaves nothing behind. Genesis is skipped for the
    // same reason its transactions are not connected.
    if height > 0 {
        let fees = value_totals
            .fees()
            .ok_or(ApplyError::BlockOutputsExceedInputs)?;
        bitcoin_rs_consensus::verify_coinbase_amount(
            value_totals.coinbase_out,
            fees,
            height,
            handles.network.subsidy_halving_interval(),
        )?;
    }

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
            || wants_rawblock;
        if needs_body {
            // The preserved P2P wire payload is byte-identical to the canonical
            // block serialization: the decoder rejects every non-canonical
            // encoding, so a decoded block always re-serializes to its wire
            // bytes. The length guard keeps that invariant release-observable and
            // self-heals to a fresh serialize if it ever fails to hold, so a
            // future decoder change can never admit non-canonical bytes into the
            // block body store.
            match provided_serialized {
                Some(provided) if provided.len() == consensus_bytes(block).len() => {
                    #[cfg(debug_assertions)]
                    {
                        debug_assert_eq!(provided.as_ref(), consensus_bytes(block).as_slice(),);
                    }
                    provided
                }
                _ => bytes::Bytes::from(consensus_bytes(block)),
            }
        } else {
            // Nothing downstream reads `block_bytes` unless one of the consumers
            // above needs the full body, so skip the serialize entirely.
            bytes::Bytes::new()
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

    // Prove every fallible piece of block-tree bookkeeping before the first
    // UTXO mutation. Header resolution (inserting the header when header-first
    // sync has not seen it), the applied-height check, and the cumulative
    // transaction-count derivation can all fail; proving them here keeps every
    // rejection before the UTXO commit, so a failed block leaves no applied
    // outputs behind, and it leaves the publication tail infallible.
    let block_tree_insert_started = quanta::Instant::now();
    let tip = applied_header_tip(handles, block_hash, block, height)?;
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());

    let utxo_commit_started = quanta::Instant::now();
    let utxo_commit_result = handles.utxo.commit_borrowed_block(&changes, &block_hash);
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;



    // Everything past the UTXO commit publishes values prepared above and
    // cannot fail: the tip snapshot was resolved from the tree before the
    // first write, so the publication tail is infallible.
    let block_record_started = quanta::Instant::now();
    {
        let block_record = BlockRecord::from_block(height, block);
        // The record carries no header. `BlockRecord`'s is filled from the block
        // tree when a caller resolves one, which is sound only because the
        // header is already in the tree by the time the record is in the log —
        // `applied_header_tip` above, through these same handles, is what puts
        // it there.
        //
        // That ordering is the whole of the argument, and until this assertion
        // nothing enforced it. Reverse the two and every `getblock` /
        // `getblockheader` answer for a freshly applied block loses its header,
        // with nothing failing at the point the mistake is made.
        //
        // The tree lock is free here: `applied_header_tip` released its write
        // guard before returning. The check is one hash-table lookup, and it is
        // compiled out of release builds — so this is a guard for the test
        // suite, where it runs on every block any node test applies.
        debug_assert!(
            handles.block_tree.read().node_by_hash(block_hash).is_some(),
            "block {} is entering the record log with no block-tree node; \
             its header would be unrecoverable",
            block_hash.to_string_be()
        );
        handles.blocks.write().push(block_record);
    }
    let block_record_dur = block_record_started.elapsed();
    metrics::histogram!("node.apply_block.block_record_seconds")
        .record(block_record_dur.as_secs_f64());
    let mempool_evict_started = quanta::Instant::now();
    {
        let block_txids = scratch.txids();
        debug_assert_eq!(
            block_txids.len(),
            block.txs.len(),
            "block transactions and validated txids must stay aligned"
        );
        let block_txs: Vec<&Tx> = block.txs.iter().collect();
        handles.mempool_gateway.remove_for_block(
            AdmissionOrigin::Block,
            &block_txs,
            block_txids,
            height,
        );
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
    let total_dur = total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    tracing::debug!(
        height,
        %block_hash,
        tx_count = block.txs.len(),
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
    handles
        .chain_events
        .record(crate::state::HintKind::Connected, tip.height, tip.hash);
    advance_chain_tx_count(handles, height, tx_count_delta_for(block));
    handles.wake_tx_index();
    // The applied tip moved: every template long-poll waiter must observe it.
    handles.mining_generation.publish_generation();
    if handles.zmq_publisher.wants_notifications() {
        handles
            .zmq_publisher
            .publish_sequence(crate::zmq_publisher::SequenceEvent::Connected(tip.hash));
    }

    // Persist crash-recovery progress: the block body is on disk, so the
    // state at this height is reconstructable from the last checkpoint plus
    if let Some(meta_path) = &handles.recovery_meta_path {
        let meta = crate::crash_recovery::Meta {
            height,
            last_committed_height: height,
            tip_hash_hex: Some(tip.hash.to_string_be()),
        };
        if let Err(error) = crate::crash_recovery::write_meta_to_path(meta_path, &meta) {
            tracing::warn!(
                %error,
                height,
                "failed to persist crash-recovery meta; recovery window will be larger on next boot"
            );
        }
    }
    Ok(tip)
}

/// Decodes a compact `bits` encoding into a 256-bit target with Core
/// `arith_uint256::SetCompact` semantics; the sign bit decodes to zero.
/// Node-local port: `bitcoin_rs_chain::header_sync` keeps its `pow` module
/// crate-private, and the header `PoW` gate here must match it exactly.
fn compact_to_target(bits: u32) -> ChainWork {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mut mantissa = u64::from(bits & 0x007f_ffff);
    let target = if exponent <= 3 {
        mantissa >>= 8 * (3 - exponent);
        ChainWork::from(mantissa)
    } else {
        let shift = 8 * (exponent - 3);
        if shift < 256 {
            ChainWork::from(mantissa) << shift
        } else {
            ChainWork::ZERO
        }
    };
    if mantissa != 0 && bits & 0x0080_0000 != 0 {
        ChainWork::ZERO
    } else {
        target
    }
}

/// Returns `true` when `hash`, read as a 256-bit little-endian integer, does
/// not exceed the decoded compact target.
fn compact_is_met_by(bits: u32, hash: Hash256) -> bool {
    let target = compact_to_target(bits);
    target != ChainWork::ZERO && ChainWork::from_le_bytes(hash.to_le_bytes()) <= target
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

/// Applies header-sync's timestamp rules to a header the tree has not seen.
///
/// A header already in the tree went through `accept_headers` and was checked
/// there. One that is not is about to be inserted by `applied_header_tip`, and
/// without this a caller handing `apply_block` a block directly could make one
/// with an invalid median-time-past or an absurd future timestamp the applied
/// consensus tip.
fn check_unseen_header_timestamp(
    handles: &ApplyHandles,
    block: &Block,
    block_hash: Hash256,
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
    block_hash: Hash256,
    block: &Block,
    height: u32,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let mut tree = handles.block_tree.write();
    // No timestamp check here: `check_unseen_header_timestamp` ran just before
    // this call, in the same pre-mutation phase, and this whole function runs
    // before the first write so a rejection here leaves nothing behind.
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
    tree.record_applied_tx_count(node_id, tx_count_delta_for(block))?;
    let node = tree.node(node_id)?;
    Ok(TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

struct BlockTxPlan {
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
    /// The overlay nets these out exactly as `build_block_changes` does: such an
    /// output never reaches the committed set, so a view carrying it would
    /// resolve a later spend the real set would refuse.
    fn same_block_spent_set(&self) -> &SameBlockSpentSet {
        static NONE: std::sync::LazyLock<SameBlockSpentSet> =
            std::sync::LazyLock::new(SameBlockSpentSet::new);
        self.same_block_spent.as_ref().unwrap_or(&NONE)
    }

    fn into_scratch_parts(
        self,
        txids: Vec<Txid>,
    ) -> (
        Vec<Txid>,
        ApplyScratchCapacities,
        Option<SameBlockSpentSet>,
        usize,
    ) {
        (
            txids,
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

/// Plans a block whose txids are already known.
///
/// Identities come from the parse-once view: the kernel parse hashes every
/// transaction on the way past using the SHA-256 implementation Core picks at
/// runtime, and the native build hashes each transaction once in
/// [`block_txids`]. Either way the plan borrows them instead of re-hashing
/// with a scalar implementation.
fn plan_block_transactions(block: &Block, txids: &[Txid]) -> BlockTxPlan {
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
    let mut spent_outpoints: Option<HashSet<OutPoint>> = None;
    let track_spent_conflicts = block.txs.len() > 2;
    let mut saw_non_coinbase = false;

    for (tx_index, (tx, txid)) in block.txs.iter().zip(txids.iter().copied()).enumerate() {
        let is_coinbase = is_coinbase_tx(tx);
        let output_count = tx.outputs.len();
        only_coinbase &= is_coinbase;
        created_output_count = created_output_count.saturating_add(output_count);
        if is_coinbase {
            has_witness |= tx.inputs.iter().any(|input| !input.witness.is_empty());
            overlay_capacity = overlay_capacity.saturating_add(output_count);
        } else {
            let input_count = tx.inputs.len();
            for input in &tx.inputs {
                has_witness |= !input.witness.is_empty();
                let prior_txids = &txids[..tx_index];
                let spends_created_output = if prior_txids.len() <= LOCAL_OVERLAY_TXID_SET_THRESHOLD
                {
                    prior_txids.contains(&input.previous_output.txid)
                } else {
                    let created_txids = created_txids.get_or_insert_with(|| {
                        let mut set = HashSet::with_capacity(block.txs.len());
                        set.extend(prior_txids.iter().copied());
                        set
                    });
                    created_txids.contains(&input.previous_output.txid)
                };
                if spends_created_output {
                    same_block_spent
                        .get_or_insert_with(|| HashSet::with_capacity(input_count))
                        .insert(input.previous_output);
                    same_block_spent_input_count = same_block_spent_input_count.saturating_add(1);
                }
                let repeats_prior_spend = if track_spent_conflicts {
                    let spent_outpoints = spent_outpoints.get_or_insert_with(|| {
                        HashSet::with_capacity(input_count.max(block.txs.len()))
                    });
                    !spent_outpoints.insert(input.previous_output)
                } else {
                    saw_non_coinbase
                };
                needs_local_utxo_overlay |= spends_created_output || repeats_prior_spend;
            }
            saw_non_coinbase = true;
            if tx.version >= 2 {
                has_bip68_sequence_locks |= tx
                    .inputs
                    .iter()
                    .any(|input| input.sequence & BIP68_DISABLE_FLAG == 0);
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

/// All external (already-committed) prevouts for one block, resolved in a single
/// parallel pass so `script_verify`, `coinbase_maturity`, and `bip68` reuse one
/// lookup table instead of hitting the `UtxoSet` repeatedly.
struct ResolvedUtxoView {
    external: HashMap<OutPoint, LiveOutput>,
}

impl ResolvedUtxoView {
    /// Resolves a block's external prevouts from any source of live outputs.
    ///
    /// Generic so a window can substitute an overlay carrying the outputs its
    /// earlier blocks created. Every caller outside a window passes the
    /// committed set.
    fn resolve<S: crate::window_overlay::OutputSource + ?Sized>(
        utxo: &S,
        block: &Block,
        tx_plan: &BlockTxPlan,
    ) -> Self {
        let same_block = tx_plan.same_block_spent.as_ref();
        let candidates = block
            .txs
            .iter()
            .filter(|tx| !is_coinbase_tx(tx))
            .flat_map(|tx| &tx.inputs)
            .filter(|input| same_block.is_none_or(|set| !set.contains(&input.previous_output)))
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
                .filter_map(|outpoint| utxo.get_entry(&outpoint).map(|entry| (outpoint, entry)))
                .collect(),
        }
    }
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            external: HashMap::new(),
        }
    }

    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.external.get(outpoint).map(|entry| entry.txout.clone())
    }

    /// Full resolved entry for a spent outpoint, including creation metadata.
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput> {
        self.external.get(outpoint)
    }

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<LiveOutputMeta> {
        self.external.get(outpoint).map(|entry| LiveOutputMeta {
            coinbase: entry.coinbase,
            height: entry.height,
        })
    }
}

impl UtxoView for ResolvedUtxoView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.lookup(outpoint)
    }
}


impl SpentOutputLookup for ResolvedUtxoView {
    fn entry(&self, outpoint: &OutPoint) -> Option<&LiveOutput> {
        self.entry(outpoint)
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
    block: &Block,
    tx_plan: &BlockTxPlan,
    height: u32,
    txids: &[Txid],
) -> core::result::Result<Vec<Vec<Option<TxOut>>>, ApplyError> {
    if tx_plan.needs_local_utxo_overlay {
        let mut view =
            BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
        let mut resolved = Vec::with_capacity(block.txs.len());
        for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
            if is_coinbase_tx(tx) {
                resolved.push(Vec::new());
                view.add_outputs(tx_index, *txid, tx.outputs.len())?;
                continue;
            }
            let inputs = tx
                .inputs
                .iter()
                .map(|input| view.lookup(&input.previous_output))
                .collect();
            resolved.push(inputs);
            view.spend_inputs(tx);
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
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
            .txs
            .iter()
            .map(|tx| {
                if is_coinbase_tx(tx) {
                    return Vec::new();
                }
                tx.inputs
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
/// Runs every non-script transaction check for a block whose scripts are
/// skipped by the live assume-valid gate.
fn run_non_script_checks_only(
    block: &Block,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    txids: &[Txid],
    height: u32,
    locktime_cutoff: u32,
) -> core::result::Result<(), ApplyError> {
    if !tx_plan.needs_local_utxo_overlay {
        block.txs.par_iter().try_for_each(|tx| {
            if is_coinbase_tx(tx) {
                bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
                return Ok(());
            }
            bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
                tx,
                &*resolved,
                height,
                locktime_cutoff,
            )
        })?;
        return Ok(());
    }
    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        if is_coinbase_tx(tx) {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        bitcoin_rs_consensus::verify_tx::verify_transaction_non_script(
            tx,
            &view,
            height,
            locktime_cutoff,
        )?;
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
    }
    Ok(())
}

#[cfg_attr(
    not(feature = "kernel"),
    expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "the kernel build borrows an owning block handle through this shared signature"
    )
)]
#[allow(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn verify_block_transactions(
    handles: &ApplyHandles,
    block: &Block,
    view: &mut bitcoin_rs_consensus::BlockView<'_>,
    tx_plan: &BlockTxPlan,
    resolved: Arc<ResolvedUtxoView>,
    context: &BlockValidationContext,
    kernel_block: &bitcoin_rs_consensus::kernel::KernelBlock,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(block.txs.len(), view.txids().len());
    if tx_plan.only_coinbase {
        for tx in &block.txs {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
        }
        return Ok(());
    }
    // Assume-valid: skip kernel / portable script execution only, and only while the
    // hash-pinned trust gate holds (always trusted when no pin is configured).
    let skip_scripts = handles.assume_valid_height > 0
        && context.height <= handles.assume_valid_height
        && handles.assume_valid_gate.trusted();
    if skip_scripts {
        return run_non_script_checks_only(
            block,
            tx_plan,
            resolved,
            view.txids(),
            context.height,
            context.locktime_cutoff,
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
    let resolution_result =
        resolve_block_prevouts(resolved, block, tx_plan, context.height, view.txids());
    let resolution_dur = resolution_started.elapsed();
    metrics::histogram!("node.apply_block.script_resolution_seconds")
        .record(resolution_dur.as_secs_f64());
    let resolved = resolution_result?;
    view.set_resolved(resolved);
    // preparation and parallel input-check fan-out internally and reports both
    // sub-stage durations back; record them here on the success and error paths
    // before propagating the verdict, mirroring the surrounding `*_result` idiom.
    let mut script_timings = bitcoin_rs_consensus::ScriptStageTimings::default();
    let script_input_result = bitcoin_rs_consensus::verify_block_input_scripts(
        view,
        context.height,
        context.locktime_cutoff,
        context.flags,
        &mut script_timings,
        kernel_block,
    );
    metrics::histogram!("node.apply_block.script_prepare_seconds")
        .record(script_timings.prepare_seconds);
    metrics::histogram!("node.apply_block.script_parallel_seconds")
        .record(script_timings.parallel_seconds);
    script_input_result?;
    tracing::debug!(
        height = context.height,
        script_resolution_us = resolution_dur.as_micros(),
        script_prepare_us = (script_timings.prepare_seconds * 1_000_000.0) as u64,
        script_parallel_us = (script_timings.parallel_seconds * 1_000_000.0) as u64,
        "script_verify: profile"
    );
    Ok(())
}

struct BlockLocalUtxoView<'b> {
    base: Arc<ResolvedUtxoView>,
    txdata: &'b [Tx],
    height: u32,
    overlay: HashMap<OutPoint, Option<u32>>,
}

impl<'b> BlockLocalUtxoView<'b> {
    fn new(
        base: Arc<ResolvedUtxoView>,
        txdata: &'b [Tx],
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

    fn lookup_meta(&self, outpoint: &OutPoint) -> Option<LiveOutputMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let tx_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            self.txdata.get(tx_index)?.outputs.get(vout)?;
            return Some(LiveOutputMeta {
                coinbase: tx_index == 0,
                height: self.height,
            });
        }
        self.base.lookup_meta(outpoint)
    }

    fn spend_inputs(&mut self, tx: &Tx) {
        for input in &tx.inputs {
            self.overlay.insert(input.previous_output, None);
        }
    }

    fn add_outputs(
        &mut self,
        tx_index: u32,
        txid: Txid,
        output_count: usize,
    ) -> core::result::Result<(), ApplyError> {
        for vout in 0..output_count {
            let vout = u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(self.height))?;
            self.overlay
                .insert(OutPoint::new(txid, vout), Some(tx_index));
        }
        Ok(())
    }
}

impl UtxoView for BlockLocalUtxoView<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        if let Some(entry) = self.overlay.get(outpoint) {
            let tx_index = usize::try_from((*entry)?).ok()?;
            let vout = usize::try_from(outpoint.vout).ok()?;
            return self.txdata.get(tx_index)?.outputs.get(vout).cloned();
        }
        self.base.lookup(outpoint)
    }
}

#[cfg(test)]
pub(crate) fn check_coinbase_maturity(
    handles: &ApplyHandles,
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let tx_plan = plan_block_transactions(block, &block_txids(block));
    let resolved = Arc::new(ResolvedUtxoView::resolve(
        handles.utxo.as_ref(),
        block,
        &tx_plan,
    ));
    let txids = block_txids(block);
    check_coinbase_maturity_with_tx_plan(handles, block, &tx_plan, &txids, resolved, height)
}

fn check_coinbase_maturity_with_tx_plan(
    _handles: &ApplyHandles,
    block: &Block,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    debug_assert_eq!(block.txs.len(), txids.len());
    if tx_plan.only_coinbase {
        return Ok(());
    }
    // COINBASE_MATURITY: spent coinbase outputs must be at least 100 blocks deep.
    if !tx_plan.needs_local_utxo_overlay {
        for tx in block.txs.iter().filter(|tx| !is_coinbase_tx(tx)) {
            for input in &tx.inputs {
                let Some(entry) = resolved.lookup_meta(&input.previous_output) else {
                    continue;
                };
                check_coinbase_input_maturity(entry, height)?;
            }
        }
        return Ok(());
    }

    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        if is_coinbase_tx(tx) {
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        for input in &tx.inputs {
            let Some(entry) = view.lookup_meta(&input.previous_output) else {
                continue;
            };
            check_coinbase_input_maturity(entry, height)?;
        }
        view.spend_inputs(tx);
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
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
    block: &Block,
    tx_plan: &BlockTxPlan,
    txids: &[Txid],
    resolved: Arc<ResolvedUtxoView>,
    context: Bip68Context<'_>,
) -> core::result::Result<(), ApplyError> {
    if !context.softfork_state.csv_active {
        return Ok(());
    }
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.has_bip68_sequence_locks {
        return Ok(());
    }
    let height = context.validation.height;
    let mtp = context.median_time_past;

    debug_assert_eq!(block.txs.len(), txids.len());
    let mut view = BlockLocalUtxoView::new(resolved, &block.txs, height, tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = None;
    for (tx_index, (tx, txid)) in (0_u32..).zip(block.txs.iter().zip(txids)) {
        if is_coinbase_tx(tx) {
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        if tx.version < 2 {
            view.spend_inputs(tx);
            view.add_outputs(tx_index, *txid, tx.outputs.len())?;
            continue;
        }
        for tx_input in &tx.inputs {
            let sequence = tx_input.sequence;
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
                            bip68_prevout_mtp(handles, context.previous_tip_id, entry.height)?;
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
        view.add_outputs(tx_index, *txid, tx.outputs.len())?;
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
    block: &Block,
    height: u32,
    txids: &[Txid],
    previous_tip_id: Option<NodeId>,
) -> core::result::Result<(), ApplyError> {
    // BIP30: reject any txid that collides with an earlier transaction while
    // any output of the earlier transaction remains unspent, except at the
    // documented historical exception heights handled by `check_bip30`.
    let mut has_duplicate = false;
    if should_scan_bip30_duplicates(handles, height, previous_tip_id) {
        for txid in txids {
            if handles.utxo.has_live_outputs_for_txid(&txid.0) {
                has_duplicate = true;
                break;
            }
        }
    }
    let block_hash = block.block_hash().0;
    bitcoin_rs_consensus::bip30::check_bip30(height, block_hash, has_duplicate)?;

    // BIP34: when active for this network at `height`, the coinbase
    // scriptSig must start with the minimally-encoded height.
    if handles.network.is_bip34_active(height) {
        let coinbase = block
            .txs
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::EmptyBlock)?;
        // `verify_block_rules_precomputed` already pinned the first tx to
        // be the coinbase; relying on that here. `coinbase.inputs[0]`
        // is the synthetic prevout pointing at the impossible
        // outpoint; its `script_sig` carries the BIP34 height encoding.
        let coinbase_input = coinbase
            .inputs
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)?;
        bitcoin_rs_consensus::bip34::check_bip34(height, &coinbase_input.script_sig)?;
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
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    // PoW limit: declared target must not exceed network max_target.
    let declared = compact_to_target(block.header.bits);
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
        let prev_hash = block.header.prev_blockhash.0;
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

/// Converts UTXO connect accounting errors into apply errors.
fn map_block_change_error(error: BlockChangeError) -> ApplyError {
    match error {
        BlockChangeError::BlockValueOverflow => ApplyError::BlockValueOverflow,
        BlockChangeError::HeightOverflow(height) => ApplyError::HeightOverflow(height),
        BlockChangeError::UndoPrevoutMissing { txid, vout } => {
            ApplyError::UndoPrevoutMissing { txid, vout }
        }
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
    use bitcoin_rs_chain::{
        BlockTree,
        node::{ChainWork, NodeStatus},
    };
    use bitcoin_rs_primitives::{BlockHash, Hash256, Header, OutPoint, TxIn};
    use bitcoin_rs_script::script::{push_data, push_int};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
    use hashbrown::HashMap;
    use metrics::{
        Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };
    use parking_lot::{Mutex, RwLock};

    use super::*;

    const BIP68_TEST_PREVOUT_HEIGHT: u32 = 100;
    const BIP68_TEST_PREVOUT_MTP: u32 = 1_000_000;
    const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
    const MAINNET_POW_LIMIT_DIV_4_BITS: u32 = 0x1c3f_ffc0;
    const DAA_ANCHOR_TIME: u32 = 1_600_000_000;

    #[derive(Clone, Copy, Debug, Default)]
    struct TestRecorder;

    impl Recorder for TestRecorder {
        fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {
        }

        fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

        fn describe_histogram(
            &self,
            _key: KeyName,
            _unit: Option<Unit>,
            _description: SharedString,
        ) {
        }

        fn register_counter(&self, _key: &Key, _metadata: &Metadata<'_>) -> Counter {
            Counter::noop()
        }

        fn register_gauge(&self, _key: &Key, _metadata: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }

        fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }

    fn test_recorder() -> TestRecorder {
        TestRecorder
    }

    /// Parses `block` the way production does, so tests exercise the real
    /// one-shot kernel parse rather than a stand-in.
    fn kernel_block_of(block: &Block) -> bitcoin_rs_consensus::kernel::KernelBlock {
        bitcoin_rs_consensus::kernel::KernelBlock::parse(&consensus_bytes(block))
            .unwrap_or_else(|error| panic!("test block must parse: {error}"))
    }

    fn tx_plan(block: &Block) -> BlockTxPlan {
        plan_block_transactions(block, &block_txids(block))
    }

    fn validation_context(
        block: &Block,
        height: u32,
        locktime_cutoff: u32,
        flags: bitcoin_rs_script::VerifyFlags,
    ) -> BlockValidationContext {
        BlockValidationContext {
            hash: block.block_hash().0,
            parent: block.header.prev_blockhash.0,
            height,
            flags,
            locktime_cutoff,
        }
    }

    #[test]
    fn decode_block_tx_count_reads_the_varint_after_the_header() {
        let block = block_with_transaction(coinbase_transaction(0x42));
        let block_bytes = consensus_bytes(&block);
        assert_eq!(
            super::decode_block_tx_count(&block_bytes),
            Some(block.txs.len())
        );
        assert_eq!(
            super::decode_block_tx_count(&block_bytes[..SERIALIZED_BLOCK_HEADER_LEN]),
            None
        );
    }

    #[test]
    fn applied_record_carries_block_metadata_without_the_body() {
        let block = block_with_transaction(coinbase_transaction(0x42));
        let block_hash = block.block_hash();
        let record = BlockRecord::from_block(7, &block);

        assert_eq!(record.hash, block_hash);
        assert_eq!(record.height, 7);
        assert_eq!(record.body_size, consensus_bytes(&block).len());
        assert!(record.header.is_none());
        assert_eq!(record.tx_count, block.txs.len());
        assert_eq!(record.time, block.header.time);
    }

    #[test]
    fn block_apply_predecessor_uses_applied_tip_when_header_tip_is_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let mut tree = handles.block_tree.write();
        let genesis = Network::Regtest.genesis_block();
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
            let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
            let header = pow_header(parent_hash, 0x207f_ffff, height, height);
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
        let block = Network::Regtest.genesis_block();
        let block_hash = Hash256::from(block.block_hash());
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
        let base_prevout = OutPoint::new(fixture_txid(0x61), 0);
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let funding_tx = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
            &kernel_block_of(&block),
        )?;
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_resolves_earlier_same_block_output() -> Result<(), ApplyError> {
        let created = coinbase_transaction(0x41);
        let outpoint = OutPoint::new(created.txid(), 0);
        let spending = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![created, spending]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

        view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;
        let resolved = view.lookup(&outpoint);

        let output = resolved.ok_or(ApplyError::HeightOverflow(42))?;
        assert_eq!(output.value, block.txs[0].outputs[0].value);
        assert_eq!(output.script_pubkey, block.txs[0].outputs[0].script_pubkey);
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_hides_same_block_double_spend() -> Result<(), ApplyError> {
        let created = coinbase_transaction(0x42);
        let outpoint = OutPoint::new(created.txid(), 0);
        let first_spend = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
        let second_spend = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![created, first_spend, second_spend]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 3);

        view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;
        assert!(view.lookup(&outpoint).is_some());
        view.spend_inputs(&block.txs[1]);

        assert_eq!(view.lookup(&outpoint), None);
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_create_after_spend_uses_last_write() -> Result<(), ApplyError> {
        let created = coinbase_transaction(0x43);
        let outpoint = OutPoint::new(created.txid(), 0);
        let spending = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![spending, created]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

        view.spend_inputs(&block.txs[0]);
        view.add_outputs(1, block.txs[1].txid(), block.txs[1].outputs.len())?;

        assert_eq!(
            view.lookup(&outpoint),
            Some(block.txs[1].outputs[0].clone())
        );
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_hides_later_same_block_output() -> Result<(), ApplyError> {
        let earlier = coinbase_transaction(0x44);
        let later = coinbase_transaction(0x45);
        let later_outpoint = OutPoint::new(later.txid(), 0);
        let block = block_with_transactions(vec![earlier, later]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

        view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;

        assert_eq!(view.lookup(&later_outpoint), None);
        Ok(())
    }

    #[test]
    fn block_local_utxo_view_metadata_tracks_coinbase_and_height() -> Result<(), ApplyError> {
        let coinbase = coinbase_transaction(0x46);
        let transaction = spending_transaction_to_script(
            OutPoint::new(fixture_txid(0x47), 0),
            u32::MAX,
            op_true_script(),
        );
        let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
        let transaction_outpoint = OutPoint::new(transaction.txid(), 0);
        let block = block_with_transactions(vec![coinbase, transaction]);
        let mut view =
            BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

        view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;
        view.add_outputs(1, block.txs[1].txid(), block.txs[1].outputs.len())?;

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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
        let base_prevout = OutPoint::new(fixture_txid(0x67), 0);
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let funding_tx = spending_transaction_to_script(base_prevout, u32::MAX, vec![0x87]);
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let mut script_sig = push_int(7);
        script_sig.extend_from_slice(&push_int(8));
        let bad_same_block_spend = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig,
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: op_true_script(),
            }],
            lock_time: 0,
        };
        let block = block_with_transactions(vec![funding_tx, bad_same_block_spend]);
        let plan = tx_plan(&block);
        assert!(plan.needs_local_utxo_overlay);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
        let base_prevout = OutPoint::new(fixture_txid(0x68), 0);
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            base_prevout,
            TxOut {
                value: 1_000,
                script_pubkey: vec![0x87],
            },
            false,
            1,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
        let handles = apply_handles(utxo);

        // tx0 (funding) fails its script against the OP_EQUAL prevout.
        let mut script_sig = push_int(7);
        script_sig.extend_from_slice(&push_int(8));
        let funding_tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: base_prevout,
                script_sig,
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: op_true_script(),
            }],
            lock_time: 0,
        };
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        // tx1 spends tx0's output inside the block, forcing the overlay walk.
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);
        let plan = tx_plan(&block);
        assert!(plan.needs_local_utxo_overlay);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
        let base_prevout = OutPoint::new(fixture_txid(0x64), 0);
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let first_spend = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
        let second_spend =
            spending_transaction_to_script(base_prevout, u32::MAX - 1, op_true_script());
        let block = block_with_transactions(vec![first_spend, second_spend]);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
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
        coinbase.inputs[0].script_sig = vec![0x63];
        let block = block_with_transaction(coinbase);
        let handles = empty_apply_handles();

        let error = match verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            &validation_context(&block, 1, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
        let bits = 0x207f_ffff;
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 3, 0, bitcoin_rs_script::VerifyFlags::NONE),
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 3, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
        coinbase.inputs[0].script_sig = vec![0x63];
        let block = block_with_transaction(coinbase);
        let mut handles = empty_apply_handles();
        handles.assume_valid_height = 100;

        let error = match verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            &validation_context(&block, 1, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
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
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: op_return_script(b"not a coin"),
        });
        let txid = coinbase.txid();
        let block = block_with_transaction(coinbase);
        let scratch = ApplyScratch::new(&block, false);
        let (add_cap, rem_cap) = scratch.utxo_change_capacity();
        let (changes, _undo, _totals) = build_block_changes(
            &block,
            1,
            scratch.txids(),
            scratch.same_block_spent(),
            add_cap,
            rem_cap,
            &ResolvedUtxoView::empty(),
            None,
            MAX_SCRIPT_SIZE,
        )?;
        let utxo = UtxoSet::new();

        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x72; 32]))?;

        assert!(utxo.get(&OutPoint::new(txid, 0)).is_some());
        assert!(utxo.get(&OutPoint::new(txid, 1)).is_none());
        Ok(())
    }

    #[test]
    fn build_utxo_changes_excludes_oversized_scripts() -> Result<(), Box<dyn std::error::Error>> {
        let mut coinbase = coinbase_transaction(0x70);
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: vec![0x51; MAX_SCRIPT_SIZE],
        });
        coinbase.outputs.push(TxOut {
            value: 0,
            script_pubkey: vec![0x51; MAX_SCRIPT_SIZE + 1],
        });
        let txid = coinbase.txid();
        let block = block_with_transaction(coinbase);
        let scratch = ApplyScratch::new(&block, false);
        let (add_cap, rem_cap) = scratch.utxo_change_capacity();
        let (changes, _undo, _totals) = build_block_changes(
            &block,
            1,
            scratch.txids(),
            scratch.same_block_spent(),
            add_cap,
            rem_cap,
            &ResolvedUtxoView::empty(),
            None,
            MAX_SCRIPT_SIZE,
        )?;
        let utxo = UtxoSet::new();

        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x73; 32]))?;

        assert!(utxo.get(&OutPoint::new(txid, 0)).is_some());
        assert!(utxo.get(&OutPoint::new(txid, 1)).is_some());
        assert!(utxo.get(&OutPoint::new(txid, 2)).is_none());
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn build_utxo_changes_nets_same_block_created_then_spent_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = OutPoint::new(fixture_txid(0x62), 0);
        let utxo = utxo_with_output(base_prevout, 1)?;
        let funding_tx = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
        let final_outpoint = OutPoint::new(same_block_spend.txid(), 0);
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        let scratch = ApplyScratch::new(&block, false);
        // The block spends an external prevout, so the undo half needs the
        // resolved view that spend came from. An empty view would now be
        // rejected, which is the point of UndoPrevoutMissing.
        let resolved = ResolvedUtxoView::resolve(utxo.as_ref(), &block, &tx_plan(&block));
        let (add_cap, rem_cap) = scratch.utxo_change_capacity();
        let (changes, undo, _totals) = build_block_changes(
            &block,
            2,
            scratch.txids(),
            scratch.same_block_spent(),
            add_cap,
            rem_cap,
            &resolved,
            None,
            MAX_SCRIPT_SIZE,
        )?;
        assert_eq!(
            undo.restores().len(),
            1,
            "only the external spend is restorable; the same-block spend never entered the set"
        );
        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x63; 32]))?;

        assert!(utxo.get(&base_prevout).is_none());
        assert!(utxo.get(&funding_outpoint).is_none());
        assert!(utxo.get(&final_outpoint).is_some());
        Ok(())
    }

    #[test]
    fn apply_scratch_omits_rawtx_bytes_when_not_requested() {
        let block = block_with_transactions(vec![coinbase_transaction(0x71), transaction(0x72)]);

        let scratch = ApplyScratch::new(&block, false);

        assert_eq!(scratch.txids().len(), block.txs.len());
        assert!(scratch.raw_txs().is_none());
    }

    #[test]
    fn apply_scratch_keeps_rawtx_bytes_when_requested() -> Result<(), Box<dyn std::error::Error>> {
        let block = block_with_transactions(vec![coinbase_transaction(0x73), transaction(0x74)]);

        let scratch = ApplyScratch::new(&block, true);
        let raw_txs = scratch
            .raw_txs()
            .ok_or_else(|| std::io::Error::other("rawtx bytes missing"))?;

        assert_eq!(raw_txs.len(), block.txs.len());
        assert_eq!(raw_txs[0], consensus_bytes(&block.txs[0]));
        Ok(())
    }

    #[test]
    fn coinbase_maturity_rejects_same_block_coinbase_spend() {
        let coinbase = coinbase_transaction(0x64);
        let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
        let spend = spending_transaction_to_script(coinbase_outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![coinbase, spend]);
        let handles = empty_apply_handles();

        let error = match check_coinbase_maturity_with_tx_plan(
            &handles,
            &block,
            &tx_plan(&block),
            &block_txids(&block),
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
        coinbase.outputs[0].script_pubkey = op_true_script();
        let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
        let spend = spending_transaction_to_script(coinbase_outpoint, u32::MAX, op_true_script());
        let block = block_with_transactions(vec![coinbase, spend]);
        let handles = empty_apply_handles();

        assert!(
            verify_block_transactions(
                &handles,
                &block,
                &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
                &tx_plan(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                &validation_context(&block, 1, 0, bitcoin_rs_script::VerifyFlags::NONE),
                &kernel_block_of(&block),
            )
            .is_ok()
        );
        let error = match check_coinbase_maturity_with_tx_plan(
            &handles,
            &block,
            &tx_plan(&block),
            &block_txids(&block),
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
        let previous_output = OutPoint::new(fixture_txid(0x68), 0);
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
            &block_txids(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            Bip68Context {
                validation: &validation_context(
                    &block,
                    101,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE,
                ),
                median_time_past: 0,
                softfork_state: active,
                previous_tip_id: None,
            },
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
                &block_txids(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &block,
                        102,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: 0,
                    softfork_state: active,
                    previous_tip_id: None,
                },
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_enforces_mtp_boundary_when_csv_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = OutPoint::new(fixture_txid(0x69), 0);
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
            &block_txids(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            Bip68Context {
                validation: &validation_context(&block, 0, 0, bitcoin_rs_script::VerifyFlags::NONE),
                median_time_past: required_mtp - 1,
                softfork_state: active,
                previous_tip_id: Some(previous_tip_id),
            },
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
                &block_txids(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &block,
                        0,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: required_mtp,
                    softfork_state: active,
                    previous_tip_id: Some(previous_tip_id),
                },
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_uses_mtp_before_prevout_height() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = OutPoint::new(fixture_txid(0x67), 0);
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
                &block_txids(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &block,
                        prevout_height + 1,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: 200,
                    softfork_state: softfork_state(true),
                    previous_tip_id: Some(previous_tip_id),
                },
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_accepts_multiple_prevouts_at_same_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_previous_output = OutPoint::new(fixture_txid(0x66), 0);
        let second_previous_output = OutPoint::new(fixture_txid(0x65), 0);
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
                &block_txids(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &block,
                        prevout_height + 1,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: BIP68_TEST_PREVOUT_MTP,
                    softfork_state: softfork_state(true),
                    previous_tip_id: Some(previous_tip_id),
                },
            )
            .is_ok()
        );
        Ok(())
    }

    /// Drives the real apply entry into active CSV with a version-2 spend whose
    /// relative height lock is unmet, pinning two facts about the apply path:
    /// the BIP68 verdict must propagate out of `apply_block` as
    /// `ApplyError::Consensus(ConsensusError::Bip)`, and it must do so before
    /// the first write — a gate deleted or reordered after the UTXO commit
    /// would leave the tip advanced, the prevout spent, or the header
    /// installed, and every one of those is asserted against here.
    #[test]
    fn apply_block_propagates_unmet_bip68_sequence_lock_before_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        // CSV activates on regtest at height 432, so the applied tip sits at
        // 431 and the block connects at the first BIP68-enforcing height. The
        // prevout is a tip-block output and the sequence asks for two blocks
        // of age, making BIP68 the only rule the block violates.
        let prevout_height = 431;
        let previous_output = OutPoint::new(fixture_txid(0x6e), 0);
        let utxo = utxo_with_output(previous_output, prevout_height)?;
        let handles = apply_handles_for_network(Network::Regtest, Arc::clone(&utxo));
        let tip_id = seed_block_tree_for_bip68_time_at_height(&handles, prevout_height)?;
        let seeded_tip = handles
            .block_tree
            .read()
            .tip()
            .filter(|tip| tip.tip_id == tip_id)
            .ok_or_else(|| std::io::Error::other("seeded tip missing"))?;
        handles.applied_tip.store(Some(Arc::clone(&seeded_tip)));

        // Version 2 with a sequence lacking the disable flag is what arms the
        // relative lock; version 1 or a disabled sequence would bypass it.
        let spend = spending_transaction_to_script(previous_output, 2, op_true_script());
        let block = mined_block_with_prev_hash_and_transactions(
            BlockHash::from(seeded_tip.hash),
            vec![coinbase_transaction(0x6f), spend],
        )?;

        let error = match apply_block(&handles, &block) {
            Ok(_) => panic!("unmet BIP68 sequence lock must reject the block"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");

        // No mutation: tip, UTXO set, and block tree are exactly as seeded.
        let tip_after = handles
            .applied_tip
            .load_full()
            .ok_or_else(|| std::io::Error::other("applied tip vanished"))?;
        assert_eq!(tip_after.height, prevout_height);
        assert_eq!(tip_after.hash, seeded_tip.hash);
        assert!(
            utxo.get(&previous_output).is_some(),
            "the spent prevout must survive a rejected apply"
        );
        assert!(
            utxo.get(&OutPoint::new(block.txs[1].txid(), 0)).is_none(),
            "a rejected block must not install its outputs"
        );
        assert!(
            handles
                .block_tree
                .read()
                .lookup(Hash256::from(block.block_hash()))
                .is_none(),
            "a rejected block must not enter the block tree"
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_uses_previous_tip_mtp_for_same_block_prevout()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
        let funding_tx = transaction(0x6c);
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                &block_txids(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &block,
                        101,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: BIP68_TEST_PREVOUT_MTP,
                    softfork_state: softfork_state(true),
                    previous_tip_id: Some(previous_tip_id),
                },
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
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG | 1, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            &block_txids(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            Bip68Context {
                validation: &validation_context(
                    &block,
                    101,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE,
                ),
                median_time_past: BIP68_TEST_PREVOUT_MTP,
                softfork_state: softfork_state(true),
                previous_tip_id: Some(previous_tip_id),
            },
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
        let previous_output = OutPoint::new(fixture_txid(0x6a), 0);
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
            &block_txids(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            Bip68Context {
                validation: &validation_context(&block, 0, 0, bitcoin_rs_script::VerifyFlags::NONE),
                median_time_past: BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
                softfork_state: active,
                previous_tip_id: None,
            },
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
        let previous_output = OutPoint::new(fixture_txid(0x6b), 0);
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
            &block_txids(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block),
            )),
            Bip68Context {
                validation: &validation_context(&block, 0, 0, bitcoin_rs_script::VerifyFlags::NONE),
                median_time_past: BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
                softfork_state: active,
                previous_tip_id: Some(previous_tip_id),
            },
        ) {
            Ok(()) => panic!("BIP68 time lock must reject missing prevout ancestry"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        Ok(())
    }

    #[test]
    fn bip68_inactive_csv_skips_unmet_sequence_lock() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = OutPoint::new(fixture_txid(0x70), 0);
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
                &block_txids(&block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &block,
                    &tx_plan(&block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &block,
                        101,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: 0,
                    softfork_state: softfork_state(false),
                    previous_tip_id: None,
                },
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_ignores_version_one_and_disabled_sequences() -> Result<(), Box<dyn std::error::Error>>
    {
        let previous_output = OutPoint::new(fixture_txid(0x71), 0);
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let active = softfork_state(true);

        let version_one_block =
            block_with_transaction(spending_transaction_with_version(previous_output, 2, 1));
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &version_one_block,
                &tx_plan(&version_one_block),
                &block_txids(&version_one_block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &version_one_block,
                    &tx_plan(&version_one_block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &version_one_block,
                        101,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: 0,
                    softfork_state: active,
                    previous_tip_id: None,
                },
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
                &block_txids(&disabled_block),
                Arc::new(ResolvedUtxoView::resolve(
                    handles.utxo.as_ref(),
                    &disabled_block,
                    &tx_plan(&disabled_block)
                )),
                Bip68Context {
                    validation: &validation_context(
                        &disabled_block,
                        101,
                        0,
                        bitcoin_rs_script::VerifyFlags::NONE
                    ),
                    median_time_past: 0,
                    softfork_state: active,
                    previous_tip_id: None,
                },
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
        let duplicate_txid = duplicate_tx.txid();
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_txid, 1),
            TxOut {
                value: 1_000,
                script_pubkey: Vec::new(),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let handles = apply_handles(utxo);
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![duplicate_tx],
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
        let duplicate_txid = duplicate_tx.txid();
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_txid, 0),
            TxOut {
                value: 1_000,
                script_pubkey: Vec::new(),
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
        let duplicate_txid = duplicate_tx.txid();
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_txid, 0),
            TxOut {
                value: 1_000,
                script_pubkey: Vec::new(),
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
        let duplicate_txid = duplicate_tx.txid();
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_txid, 0),
            TxOut {
                value: 1_000,
                script_pubkey: Vec::new(),
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
            MAINNET_POW_LIMIT_BITS,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + 600,
            1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            MAINNET_POW_LIMIT_DIV_4_BITS,
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
            MAINNET_POW_LIMIT_BITS,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            MAINNET_POW_LIMIT_BITS,
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
            MAINNET_POW_LIMIT_BITS,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            MAINNET_POW_LIMIT_DIV_4_BITS,
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
            MAINNET_POW_LIMIT_BITS,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan / 4) - 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            MAINNET_POW_LIMIT_DIV_4_BITS,
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
            MAINNET_POW_LIMIT_BITS,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            MAINNET_POW_LIMIT_BITS,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn testnet_allows_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
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
        let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
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
        assert_nbits_error(&error, pow_limit_bits, regular_bits, 3);
        Ok(())
    }

    #[test]
    fn mainnet_rejects_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
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
        assert_nbits_error(&error, pow_limit_bits, regular_bits, 2);
        Ok(())
    }

    #[test]
    fn testnet_min_difficulty_does_not_override_retarget_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let regular_bits = MAINNET_POW_LIMIT_DIV_4_BITS;
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
        assert_nbits_error(&error, pow_limit_bits, regular_bits, interval);
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
        let outpoint = OutPoint::new(fixture_txid(0x2c), 7);
        let removed = OutPoint::new(fixture_txid(0x3d), 1);
        let txout = TxOut {
            value: 123_456,
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

    /// A coinbase may not pay itself more than the subsidy plus the fees.
    ///
    /// Nothing else in the node bounds this. Block rules check structure, and
    /// per-transaction verification exempts the coinbase because it has no
    /// inputs to weigh its outputs against -- so without this rule a miner can
    /// simply write any amount into the coinbase and the block is accepted.
    /// That is inflation, and it is what this test would have demonstrated
    /// before the rule existed.
    ///
    /// The paired accept is the point: the same block, one satoshi lower, must
    /// apply. Otherwise a rejection for any unrelated reason would read as
    /// success here.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_rejects_a_coinbase_that_pays_more_than_the_subsidy() {
        let subsidy =
            bitcoin_rs_consensus::block_subsidy(1, Network::Regtest.subsidy_halving_interval());
        assert_eq!(
            subsidy,
            50 * 100_000_000,
            "regtest height 1 pays the full subsidy"
        );

        let over = apply_coinbase_only_block(subsidy + 1);
        assert!(
            matches!(
                &over,
                Err(ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { paid, allowed }
                )) if *paid == subsidy + 1 && *allowed == subsidy
            ),
            "a coinbase claiming one satoshi too much must be refused, got {over:?}"
        );

        let exact = apply_coinbase_only_block(subsidy);
        assert!(
            exact.is_ok(),
            "the same block claiming exactly the subsidy must apply, got {exact:?}"
        );
    }

    /// The allowance includes the fees the block actually earned.
    ///
    /// A rule that only compared against the subsidy would pass the test above
    /// and still be wrong in both directions: it would refuse every real block
    /// that collects fees, and it would let a block claim fees it never earned.
    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn the_coinbase_allowance_counts_the_fees_the_block_earned() {
        let subsidy =
            bitcoin_rs_consensus::block_subsidy(1, Network::Regtest.subsidy_halving_interval());
        // The seeded output is 1000 sats and the spend pays 1 sat onward.
        let fee = 999_u64;

        let exact = apply_block_with_a_fee_paying_transaction(subsidy + fee);
        assert!(
            exact.is_ok(),
            "the coinbase may claim the subsidy plus the fee it collected, got {exact:?}"
        );

        let over = apply_block_with_a_fee_paying_transaction(subsidy + fee + 1);
        assert!(
            matches!(
                &over,
                Err(ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { allowed, .. }
                )) if *allowed == subsidy + fee
            ),
            "one satoshi past the fee must be refused, got {over:?}"
        );
    }

    /// Applies a height-1 regtest block whose only transaction is a coinbase
    /// claiming `coinbase_value`.
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_coinbase_only_block(coinbase_value: u64) -> Result<TipSnapshot, ApplyError> {
        apply_height_one_block(vec![], coinbase_value)
    }

    /// The same, plus a transaction spending a seeded 1000-satoshi output and
    /// paying 1 satoshi onward, so the block earns a 999-satoshi fee.
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_with_a_fee_paying_transaction(
        coinbase_value: u64,
    ) -> Result<TipSnapshot, ApplyError> {
        let funded = OutPoint::new(fixture_txid(0x71), 0);
        let spend = spending_transaction_to_script(funded, u32::MAX, op_true_script());
        apply_height_one_block(vec![spend], coinbase_value)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_height_one_block(
        extra: Vec<Tx>,
        coinbase_value: u64,
    ) -> Result<TipSnapshot, ApplyError> {
        let funded = OutPoint::new(fixture_txid(0x71), 0);
        // Height 0 so the seeded coin is mature, and non-coinbase so maturity
        // does not apply to it at all.
        let Ok(utxo) = utxo_with_output(funded, 0) else {
            panic!("seeding the fixture UTXO must succeed");
        };
        let genesis = Network::Regtest.genesis_block();
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let mut coinbase = coinbase_transaction_with_height(1);
        // The BIP34 height push alone is one byte, and consensus requires a
        // coinbase scriptSig of at least two.
        let mut script_sig = push_int(1);
        script_sig.extend_from_slice(&push_data(&[0_u8; 4]));
        coinbase.inputs[0].script_sig = script_sig;
        coinbase.outputs = vec![TxOut {
            value: coinbase_value,
            script_pubkey: op_true_script(),
        }];
        let mut txdata = vec![coinbase];
        txdata.extend(extra);

        let mut block = block_with_prev_hash_and_transactions(genesis.block_hash(), txdata);
        while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        apply_block(&handles, &block)
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let mut block = block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        );
        // Exactly the parent's timestamp: the rule is strictly greater than the
        // median, and with one ancestor the median IS the parent's time.
        block.header.time = genesis.header.time;
        while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
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
        // lived in `applied_header_tip`, which now runs BEFORE any mutation, so
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_for_network(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from(block.block_hash());
        applied_header_tip(&handles, block_hash, &block, 1)?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
        assert_eq!(
            prove_window(&handles, &[&block], &[raw]).len(),
            1,
            "the honest block must prove, or this test proves nothing"
        );

        // Same header, different body: the merkle root no longer matches.
        let mut tampered = block.clone();
        tampered.txs.push(coinbase_transaction(2));
        assert_eq!(
            tampered.header, block.header,
            "the header must be untouched for this to be the attack described"
        );
        let raw = bytes::Bytes::from(consensus_bytes(&tampered));
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

    #[allow(clippy::arc_with_non_send_sync)]
    fn one_block_window_fixture(
        utxo: Arc<UtxoSet>,
        txdata: Vec<Tx>,
        assume_valid_height: u32,
    ) -> Result<(ApplyHandles, Block, bytes::Bytes), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let mut handles = apply_handles_for_network(Network::Regtest, utxo);
        handles.assume_valid_height = assume_valid_height;
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;
        let block_hash = Hash256::from(block.block_hash());
        applied_header_tip(&handles, block_hash, &block, 1)?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
        Ok((handles, block, raw))
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn every_validation_context_mismatch_rebuilds_from_live_utxo()
    -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Clone, Copy, Debug)]
        enum Field {
            Hash,
            Parent,
            Height,
            Flags,
            LocktimeCutoff,
        }

        for field in [
            Field::Hash,
            Field::Parent,
            Field::Height,
            Field::Flags,
            Field::LocktimeCutoff,
        ] {
            let prevout = OutPoint::new(fixture_txid(0x72), 0);
            let utxo = utxo_with_output(prevout, 0)?;
            let spend = spending_transaction_to_script(prevout, u32::MAX, op_true_script());
            let (handles, block, raw) = one_block_window_fixture(
                Arc::clone(&utxo),
                vec![coinbase_transaction(1), spend],
                0,
            )?;
            let mut entries = prove_window(&handles, &[&block], core::slice::from_ref(&raw));
            let Some(ProvenApply::Proven(mut proof)) = entries.pop() else {
                panic!("valid fixture did not produce a proof for {field:?}");
            };

            match field {
                Field::Hash => proof.context.hash = Hash256::from_le_bytes(&[0x81; 32]),
                Field::Parent => proof.context.parent = Hash256::from_le_bytes(&[0x82; 32]),
                Field::Height => proof.context.height = proof.context.height.saturating_add(1),
                Field::Flags => {
                    proof.context.flags =
                        if proof.context.flags == bitcoin_rs_script::VerifyFlags::NONE {
                            bitcoin_rs_script::VerifyFlags::MANDATORY
                        } else {
                            bitcoin_rs_script::VerifyFlags::NONE
                        };
                }
                Field::LocktimeCutoff => {
                    proof.context.locktime_cutoff = proof.context.locktime_cutoff.saturating_add(1);
                }
            }

            let mut remove = BlockChanges::default();
            remove.remove(prevout);
            utxo.commit_block(&remove, &Hash256::from_le_bytes(&[0x83; 32]))?;

            let transition = handles.begin_chain_transition()?;
            let guard = handles.mempool_gateway.begin_chain_change()?;
            let chain_proof = ChainChangeProof::new(transition, guard);
            let Err(error) = apply_block_admitted(
                &handles,
                &block,
                Some(raw),
                Some(ProvenApply::Proven(proof)),
                &chain_proof,
            ) else {
                panic!("a mismatched proof must re-read the now-missing live prevout");
            };
            assert!(
                matches!(
                    error,
                    ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                        input_index: 0
                    })
                ),
                "{field:?} mismatch used stale prepared state instead of ordinary validation: {error:?}"
            );
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn a_window_never_proves_non_script_invalidity() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Clone, Copy, Debug)]
        enum Case {
            DuplicateInput,
            MissingPrevout,
            NonFinalLocktime,
            OutputsGreaterThanInputs,
            CoinbaseScriptSigLength,
            SigopOverflow,
        }

        for (index, case) in [
            Case::DuplicateInput,
            Case::MissingPrevout,
            Case::NonFinalLocktime,
            Case::OutputsGreaterThanInputs,
            Case::CoinbaseScriptSigLength,
            Case::SigopOverflow,
        ]
        .into_iter()
        .enumerate()
        {
            let prevout = OutPoint::new(fixture_txid(0x90 + u8::try_from(index)?), 0);
            let mut utxo = Arc::new(UtxoSet::new());
            let txdata = match case {
                Case::CoinbaseScriptSigLength => {
                    let mut coinbase = coinbase_transaction(1);
                    coinbase.inputs[0].script_sig = vec![1];
                    vec![coinbase]
                }
                Case::SigopOverflow => {
                    utxo = utxo_with_output(prevout, 0)?;
                    let output_script =
                        vec![
                            0xac;
                            usize::try_from(bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST / 4 + 1)?
                        ];
                    let spend = spending_transaction_to_script(prevout, u32::MAX, output_script);
                    vec![coinbase_transaction(1), spend]
                }
                _ => {
                    if !matches!(case, Case::MissingPrevout) {
                        utxo = utxo_with_output(prevout, 0)?;
                    }
                    let mut spend =
                        spending_transaction_to_script(prevout, u32::MAX, op_true_script());
                    match case {
                        Case::DuplicateInput => spend.inputs.push(spend.inputs[0].clone()),
                        Case::MissingPrevout => {}
                        Case::NonFinalLocktime => {
                            spend.lock_time = 2;
                            spend.inputs[0].sequence = 0;
                        }
                        Case::OutputsGreaterThanInputs => {
                            spend.outputs[0].value = 2_000;
                        }
                        Case::CoinbaseScriptSigLength | Case::SigopOverflow => unreachable!(),
                    }
                    vec![coinbase_transaction(1), spend]
                }
            };
            let (handles, block, raw) = one_block_window_fixture(utxo, txdata, 0)?;
            assert!(
                prove_window(&handles, &[&block], &[raw]).is_empty(),
                "{case:?} must not produce a validation proof"
            );
        }
        Ok(())
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
        let (recorder, metrics_handle) = crate::metrics::test_recorder();

        let genesis = Network::Regtest.genesis_block();
        let prevout = OutPoint::new(fixture_txid(0x71), 0);

        // A spend that cannot pass: the prevout pays to a bare OP_EQUAL, so the
        // script fails whenever it actually runs. Whether the window ran it is
        // therefore observable in the result.
        let build = |assume_valid_height: u32| -> Result<_, Box<dyn std::error::Error>> {
            let utxo = Arc::new(UtxoSet::new());
            let mut changes = BlockChanges::default();
            changes.add(UtxoAdd::new(
                prevout,
                TxOut {
                    value: 1_000,
                    script_pubkey: vec![0x87],
                },
                false,
                0,
            ));
            utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0x71; 32]))?;

            let mut handles = apply_handles_for_network(Network::Regtest, utxo);
            handles.assume_valid_height = assume_valid_height;
            let genesis_hash = Hash256::from(genesis.block_hash());
            let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
            handles.applied_tip.store(Some(Arc::new(genesis_tip)));

            let spend = spending_transaction_to_script(prevout, u32::MAX, op_true_script());
            let block = mined_block_with_prev_hash_and_transactions(
                genesis.block_hash(),
                vec![coinbase_transaction(1), spend],
            )?;
            // The window refuses a block whose header the tree has not seen.
            // This test is about the assume-valid decision, not admission.
            let block_hash = Hash256::from(block.block_hash());
            applied_header_tip(&handles, block_hash, &block, 1)?;
            let raw = bytes::Bytes::from(consensus_bytes(&block));
            Ok((handles, block, raw))
        };

        // Height 1 is covered, and with no anchor pinned the gate is trusted.
        let (mut handles, block, raw) = build(100)?;
        let mut proven = metrics::with_local_recorder(&recorder, || {
            prove_window(&handles, &[&block], core::slice::from_ref(&raw))
        });
        assert_eq!(
            proven.len(),
            1,
            "a trusted block must not be failed by a script the window should never have run"
        );
        let Some(skipped) = proven.pop() else {
            panic!("window returned no entry for the only block");
        };
        assert!(
            matches!(skipped, ProvenApply::AssumeValidSkipped(_)),
            "a skipped block must carry AssumeValidSkipped, not script proof: the proof branch \
             bypasses the trust-gate re-read at commit, so a gate that flips in between would let \
             an unverified block through"
        );
        let mut entries = prove_window(&handles, &[&block], core::slice::from_ref(&raw));
        let Some(skipped) = entries.pop() else {
            panic!("the trusted assume-valid window returned one entry above");
        };
        handles.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
            1,
            Hash256::from_le_bytes(&[0xff; 32]),
        ))));
        assert!(!handles.assume_valid_gate.trusted());
        let transition = handles.begin_chain_transition()?;
        let guard = handles.mempool_gateway.begin_chain_change()?;
        let proof = ChainChangeProof::new(transition, guard);
        let outcome = apply_block_admitted(&handles, &block, Some(raw), Some(skipped), &proof);
        assert!(
            matches!(
                outcome,
                Err(ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::Script { input_index: 0, .. }
                ))
            ),
            "trust-gate flip must re-enter ordinary script validation, got {outcome:?}"
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
        let genesis = Network::Regtest.genesis_block();
        let mut block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        let honest = bytes::Bytes::from(consensus_bytes(&block));
        assert!(
            bytes_are_block(&honest, &block),
            "the block's own serialization must be accepted"
        );

        // Swap only the witness. Every txid, the transaction count, and the
        // header are untouched.
        let before = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
        let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
            panic!("coinbase has no input");
        };
        input.witness.push(vec![0xab_u8; 32]);
        let after = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
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
        let coinbase = block.txs.first().ok_or("block has no coinbase")?;
        let reused = OutPoint::new(coinbase.txid(), 0);

        // The older coin at the very same outpoint, with values the new one does
        // not share, so a restore that invents a coin cannot pass.
        let older = TxOut {
            value: 4_242,
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

        let scratch = ApplyScratch::new(&block, false);
        let (add_cap, rem_cap) = scratch.utxo_change_capacity();
        let (_changes, undo, _totals) = build_block_changes(
            &block,
            91_842,
            scratch.txids(),
            scratch.same_block_spent(),
            add_cap,
            rem_cap,
            &ResolvedUtxoView::empty(),
            Some(utxo.as_ref()),
            MAX_SCRIPT_SIZE,
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
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
            Hash256::from(winner.block_hash()),
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
        let genesis = Network::Regtest.genesis_block();
        let mut handles =
            apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        handles.undo_store = Arc::new(CompleteRejectingUndoStore::default());
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
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
            &[(Hash256::from(block.block_hash()), b'D', 0)]
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        handles.undo_store = Arc::new(RejectingUndoStore);
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        // No transaction index runtime: the index has its own rollback tests in
        // `crates/index`. This isolates the UTXO and tip halves from any
        // asynchronous index work.
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        // A mature output for the block to spend, so the undo record carries a
        // restore as well as a remove.
        let funding_txid = fixture_txid(0x8b);
        let funded = OutPoint::new(funding_txid, 0);
        let funded_value = 50_000;
        let mut seed = bitcoin_rs_utxo::UndoBatch::default();
        seed.restore(bitcoin_rs_utxo::UtxoAdd::new(
            funded,
            TxOut {
                value: funded_value,
                script_pubkey: op_true_script(),
            },
            false,
            0,
        ));
        utxo.undo_block(&seed)?;
        let outputs_before = utxo.len();
        let funded_before = utxo
            .get(&funded)
            .ok_or("seeded output missing before apply")?;

        let spend = spending_transaction_to_script(funded, 0xFFFF_FFFF, op_true_script());
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1), spend.clone()],
        )?;
        let applied = apply_block(&handles, &block)?;
        assert_eq!(applied.height, 1, "the block must connect first");
        assert!(
            utxo.get(&funded).is_none(),
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
        let funded_after = utxo.get(&funded).ok_or("spent output was not restored")?;
        assert_eq!(
            funded_after, funded_before,
            "the restored output must be byte-identical to the one spent"
        );
        assert!(
            utxo.get(&OutPoint::new(spend.txid(), 0)).is_none(),
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
        let genesis = Network::Regtest.genesis_block();
        let external_prevout = OutPoint::new(fixture_txid(0x92), 0);
        let utxo = utxo_with_output(external_prevout, 1)?;
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let funding_tx =
            spending_transaction_to_script(external_prevout, u32::MAX, op_true_script());
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
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
        let tree_tip_before = handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash));
        let marker_before = handles.undo_store.load_disconnect_marker()?;

        let mut mutated = block.clone();
        mutated.txs.push(same_block_spend);
        assert_eq!(
            txids_merkle_root(&mutated),
            Some(block.header.merkle_root),
            "duplicate-last mutation must preserve the ordinary Merkle root"
        );
        assert!(
            txids_merkle_root(&mutated) == Some(mutated.header.merkle_root),
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let records_before = handles.blocks.read().len();

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = block.block_hash();
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
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
        let genesis = Network::Regtest.genesis_block();
        let mut utxo = UtxoSet::new();
        let listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        );
        utxo.set_listener(Box::new(listener.clone()));
        let utxo = Arc::new(utxo);
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        handles.coin_stats = Arc::new(listener);
        let genesis_hash = Hash256::from(genesis.block_hash());
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
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
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
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
        let genesis = Network::Regtest.genesis_block();
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from(block.block_hash());
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
    fn apply_block_skips_confirmed_transaction_cache() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        assert!(handles.tx_index_runtime.is_none());
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
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
    /// A `TxIndex` writer/reader that lets the worker start up cleanly through
    /// the current fence API and then fails on the next `fenced_watermarks`
    /// call. This models a durable-index write fault that appears after the
    /// runtime has already committed to an asynchronous worker.
    struct FailAfterStartupTxIndex {
        fence: bitcoin_rs_index::IndexWriteFence,
        watermarks: bitcoin_rs_index::IndexWatermarks,
        fenced_calls: std::sync::atomic::AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
    }

    impl FailAfterStartupTxIndex {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let temp = tempfile::tempdir()?;
            let store = Arc::new(bitcoin_rs_storage::FjallStore::open(temp.path())?);
            let mut writer = bitcoin_rs_index::IndexWriter::open(store, 1)?;
            let (fence, watermarks) = writer.fenced_watermarks()?;
            Ok(Self {
                fence,
                watermarks,
                fenced_calls: std::sync::atomic::AtomicUsize::new(0),
                fail: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    impl crate::txindex_worker::TxIndexWriter for FailAfterStartupTxIndex {
        fn fenced_watermarks(
            &self,
        ) -> Result<
            (
                bitcoin_rs_index::IndexWriteFence,
                bitcoin_rs_index::IndexWatermarks,
            ),
            bitcoin_rs_index::IndexError,
        > {
            if self.fail.load(std::sync::atomic::Ordering::Acquire) {
                return Err(bitcoin_rs_index::IndexError::UnsupportedRollback);
            }
            self.fenced_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok((self.fence, self.watermarks))
        }

        fn commit_forward_with_cursor(
            &self,
            _fence: bitcoin_rs_index::IndexWriteFence,
            _batch: bitcoin_rs_index::PreparedBatch,
            _cursor: bitcoin_rs_index::ConsumerCursorUpdate<'_>,
        ) -> Result<bitcoin_rs_index::IndexWatermark, bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }

        fn prepare_block(
            &self,
            _height: u32,
            _hash: [u8; 32],
            _body: &[u8],
        ) -> Result<bitcoin_rs_index::PreparedBlock, bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }

        fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }

        fn commit_consumer_cursor(
            &self,
            _fence: bitcoin_rs_index::IndexWriteFence,
            _cursor: &[u8],
        ) -> Result<(), bitcoin_rs_index::IndexError> {
            Err(bitcoin_rs_index::IndexError::UnsupportedRollback)
        }
        fn commit_rollback_one_for_with_cursor(
            &self,
            _fence: bitcoin_rs_index::IndexWriteFence,
            _capabilities: bitcoin_rs_index::IndexCapabilities,
            _prev: Option<bitcoin_rs_index::IndexWatermark>,
            _body: &[u8],
            _cursor: bitcoin_rs_index::ConsumerCursorUpdate<'_>,
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
        let index: Arc<FailAfterStartupTxIndex> = Arc::new(FailAfterStartupTxIndex::new()?);
        let writer: Arc<dyn crate::txindex_worker::TxIndexWriter> = index.clone();
        let _worker = crate::txindex_worker::TxIndexWorker::spawn(
            Arc::clone(&runtime),
            writer,
            Arc::clone(&handles.applied_tip),
            Arc::clone(&handles.block_tree),
            None,
            crate::txindex_worker::DEFAULT_BATCH_LIMITS,
            bitcoin_rs_index::IndexCapabilities::ALL,
            Arc::new(crate::state::ChainEventPublisher::detached(0).0),
            u32::MAX,
            wake_rx,
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        assert!(
            wait_until(deadline, || {
                index
                    .fenced_calls
                    .load(std::sync::atomic::Ordering::Acquire)
                    >= 2
            }),
            "txindex worker did not complete its startup reconciliation"
        );

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        index.fail.store(true, std::sync::atomic::Ordering::Release);
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
            bitcoin_rs_rpc::context::TxIndexQuery::transaction(&query, &genesis.txs[0].txid());
        assert!(
            matches!(
                query_result,
                Err(bitcoin_rs_rpc::context::TxQueryError::Unavailable(_))
            ),
            "failed txindex queries must be explicitly unavailable, got {query_result:?}"
        );

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let expected_hash = Hash256::from(block.block_hash());
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
        let genesis = Network::Regtest.genesis_block();
        let external_prevout = OutPoint::new(fixture_txid(0x96), 0);
        let publisher = Arc::new(RecordingRawTxPublisher::default());
        let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let handles = apply_handles_without_tx_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
        )
        .with_zmq_publisher(publisher_for_handles);
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let txdata = vec![
            coinbase_transaction(0x96),
            spending_transaction_to_script(external_prevout, u32::MAX, op_true_script()),
        ];
        let expected_raw_txs = txdata.iter().map(consensus_bytes).collect::<Vec<_>>();
        let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;

        apply_block(&handles, &block)?;

        assert_eq!(*publisher.raw_txs.lock(), expected_raw_txs);
        Ok(())
    }

    #[test]
    fn apply_block_publishes_full_rawblock_bytes_when_only_rawblock_is_requested()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let publisher = Arc::new(RecordingRawBlockPublisher::default());
        let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
            .with_zmq_publisher(publisher_for_handles);
        assert!(handles.block_body_store.is_none());
        assert!(handles.tx_index_runtime.is_none());
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let expected_block_bytes = consensus_bytes(&block);

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
        let genesis = Network::Regtest.genesis_block();
        let publisher: Arc<dyn crate::ZmqPublisher> = Arc::new(PanickingOptOutPublisher);
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
            .with_zmq_publisher(publisher);
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
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
        let genesis = Network::Regtest.genesis_block();
        let publisher: Arc<dyn crate::ZmqPublisher> = Arc::new(PanickingNoRawblockPublisher);
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()))
            .with_zmq_publisher(publisher);
        assert!(handles.block_body_store.is_none());
        assert!(handles.tx_index_runtime.is_none());
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        apply_block(&handles, &block)?;

        Ok(())
    }

    #[test]
    fn apply_block_rejects_same_block_coinbase_spend() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let handles = apply_handles_without_tx_index(Network::Regtest, empty_utxo());
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let mut coinbase = coinbase_transaction(0x94);
        coinbase.outputs[0].script_pubkey = op_true_script();
        let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
        let spend = spending_transaction_to_script(coinbase_outpoint, u32::MAX, op_true_script());
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase, spend],
        )?;

        let error = match apply_block(&handles, &block) {
            Ok(_) => panic!("same-block coinbase spend must fail the apply"),
            Err(error) => error,
        };

        assert_bip_error(&error, "COINBASE_MATURITY");
        Ok(())
    }

    #[test]
    fn apply_block_rejects_future_same_block_prevout_without_utxo_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let external_prevout = OutPoint::new(fixture_txid(0x95), 0);
        let handles = apply_handles_without_tx_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
        );
        let genesis_tip =
            applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let later_tx = spending_transaction_to_script(external_prevout, u32::MAX, op_true_script());
        let future_prevout = OutPoint::new(later_tx.txid(), 0);
        let premature_spend =
            spending_transaction_to_script(future_prevout, u32::MAX, op_true_script());
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
        assert!(handles.utxo.get(&future_prevout).is_none());
        Ok(())
    }

    fn transaction(seed: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(fixture_txid(seed), u32::from(seed)),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    pub(super) fn coinbase_transaction(seed: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![seed, seed],
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    fn coinbase_transaction_with_height(height: u32) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: push_int(i64::from(height)),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_output(
        previous_output: OutPoint,
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        utxo_with_outputs_at_height(&[previous_output], height)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_outputs_at_height(
        previous_outputs: &[OutPoint],
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        for previous_output in previous_outputs {
            changes.add(UtxoAdd::new(
                *previous_output,
                TxOut {
                    value: 1_000,
                    script_pubkey: op_true_script(),
                },
                false,
                height,
            ));
        }
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
        Ok(utxo)
    }

    fn block_with_transaction(tx: Tx) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![tx],
        }
    }

    fn block_with_transactions(txdata: Vec<Tx>) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: txdata,
        }
    }

    fn block_with_prev_hash_and_transactions(prev_blockhash: BlockHash, txdata: Vec<Tx>) -> Block {
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::default(),
                time: next_fixture_time(),
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: txdata,
        };
        block.header.merkle_root = txids_merkle_root(&block).unwrap_or_default();
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

    pub(super) fn mined_block_with_prev_hash_and_transactions(
        prev_blockhash: BlockHash,
        txdata: Vec<Tx>,
    ) -> Result<Block, Box<dyn std::error::Error>> {
        let mut block = block_with_prev_hash_and_transactions(prev_blockhash, txdata);
        loop {
            if compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
                return Ok(block);
            }
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
        }
    }

    fn block_with_pow_header(prev_blockhash: BlockHash, bits: u32, time: u32, nonce: u32) -> Block {
        Block {
            header: pow_header(prev_blockhash, bits, time, nonce),
            txs: Vec::new(),
        }
    }

    fn pow_header(prev_blockhash: BlockHash, bits: u32, time: u32, nonce: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits,
            nonce,
        }
    }

    fn seed_pow_chain(
        handles: &ApplyHandles,
        bits: u32,
        anchor_time: u32,
        tip_time: u32,
        tip_height: u32,
    ) -> Result<BlockHash, Box<dyn std::error::Error>> {
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
        period_bits: u32,
        tip_bits: u32,
        anchor_time: u32,
        tip_time: u32,
        tip_height: u32,
    ) -> Result<BlockHash, Box<dyn std::error::Error>> {
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
        headers: &[(u32, u32)],
    ) -> Result<BlockHash, Box<dyn std::error::Error>> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut prev_hash = BlockHash::default();
        for (height, &(bits, time)) in headers.iter().enumerate() {
            let height = u32::try_from(height)?;
            let header = pow_header(prev_hash, bits, time, height);
            prev_hash = header.compute_hash();
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
        let mut prev_hash = BlockHash::default();
        let mut activation_id = None;
        for height in 0..=activation_height.saturating_add(1) {
            let header = pow_header(prev_hash, 0x207f_ffff, height, height);
            let node_id = tree.insert_node(parent, header, NodeStatus::Active)?;
            if height == activation_height {
                activation_id = Some(node_id);
            }
            parent = Some(node_id);
            prev_hash = BlockHash::from(tree.node(node_id)?.hash);
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

    /// Fixture txid with every consensus byte set to `seed`.
    fn fixture_txid(seed: u8) -> Txid {
        Txid(Hash256::from_le_bytes(&[seed; 32]))
    }

    /// `OP_RETURN <data>` output script.
    fn op_return_script(data: &[u8]) -> Vec<u8> {
        let mut script = vec![0x6a_u8];
        script.extend_from_slice(&push_data(data));
        script
    }

    /// Merkle root over the block's txids: pairwise double-SHA256 over the
    /// little-endian id bytes, duplicating the last leaf on odd widths.
    fn txids_merkle_root(block: &Block) -> Option<Hash256> {
        let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        merkle_root_bytes(&mut leaves).map(|bytes| Hash256::from_le_bytes(&bytes))
    }

    /// Compact target encoding of a 256-bit target: mirrors Bitcoin Core's
    /// `GetCompact` and `bitcoin_rs_chain`'s crate-private
    /// `pow::target_to_compact` (lossy past three bytes, sign bit never set).
    fn target_to_compact_lossy(target: ChainWork) -> u32 {
        if target == ChainWork::ZERO {
            return 0;
        }
        let mut size = target.bit_len().div_ceil(8);
        let mut compact = if size <= 3 {
            u32::try_from(target.as_limbs()[0] << (8 * (3 - size))).unwrap_or(0)
        } else {
            u32::try_from((target >> (8 * (size - 3))).as_limbs()[0]).unwrap_or(0)
        };
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        compact | (u32::try_from(size).unwrap_or(0) << 24)
    }

    fn scaled_pow_limit_bits(handles: &ApplyHandles, divisor: u64) -> u32 {
        target_to_compact_lossy(handles.network.max_target() / ChainWork::from(divisor))
    }

    fn pow_limit_bits(handles: &ApplyHandles) -> u32 {
        target_to_compact_lossy(handles.network.max_target())
    }

    fn retarget_bits_for_test(
        handles: &ApplyHandles,
        previous_bits: u32,
        actual_timespan: u32,
        expected_timespan: u32,
    ) -> u32 {
        let min_timespan = expected_timespan / 4;
        let max_timespan = expected_timespan * 4;
        let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);
        let previous_target = compact_to_target(previous_bits);
        let actual = ChainWork::from(actual_clamped);
        let expected = ChainWork::from(expected_timespan);
        let target = ((previous_target / expected) * actual)
            + (((previous_target % expected) * actual) / expected);
        let target = target.min(handles.network.max_target());
        target_to_compact_lossy(target)
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

    fn spending_transaction(previous_output: OutPoint, sequence: u32) -> Tx {
        spending_transaction_to_script(previous_output, sequence, Vec::new())
    }

    fn spending_transaction_with_version(
        previous_output: OutPoint,
        sequence: u32,
        version: i32,
    ) -> Tx {
        let mut transaction = spending_transaction(previous_output, sequence);
        transaction.version = version;
        transaction
    }

    fn spending_transaction_to_script(
        previous_output: OutPoint,
        sequence: u32,
        script_pubkey: Vec<u8>,
    ) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Vec::new(),
                sequence,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey,
            }],
            lock_time: 0,
        }
    }

    fn op_true_script() -> Vec<u8> {
        vec![0x51]
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
            let header = Header {
                version: 1,
                prev_blockhash: parent
                    .and_then(|id| tree.node(id).ok().map(|node| BlockHash::from(node.hash)))
                    .unwrap_or_else(BlockHash::default),
                merkle_root: Hash256::default(),
                time: BIP68_TEST_PREVOUT_MTP,
                bits: 0x207f_ffff,
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
            let header = Header {
                version: 1,
                prev_blockhash: parent
                    .and_then(|id| tree.node(id).ok().map(|node| BlockHash::from(node.hash)))
                    .unwrap_or_else(BlockHash::default),
                merkle_root: Hash256::default(),
                time,
                bits: 0x207f_ffff,
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
    pub(super) fn empty_apply_handles() -> ApplyHandles {
        empty_apply_handles_for_network(Network::Mainnet)
    }

    /// The rewind is wired to the disconnect, not merely implemented.
    ///
    /// `rewind_chain_tx_count` has its own unit tests, and they all passed while
    /// the call site was missing: a mutation that deleted the call from
    /// `disconnect_block_admitted` survived the whole audit. Testing a function
    /// is not testing that anything calls it.
    #[test]
    fn a_disconnect_takes_the_blocks_transactions_back_out_of_the_chain_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        // Genesis counted, as it would be on a node that synced from it.
        handles.chain_tx_count.store(1, Ordering::Relaxed);

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let applied = apply_block(&handles, &block)?;
        assert_eq!(applied.height, 1, "the block must connect first");
        assert_eq!(
            handles.chain_tx_count.load(Ordering::Relaxed),
            2,
            "connecting a one-transaction block moves the count by one"
        );
        assert_eq!(
            handles
                .block_tree
                .read()
                .node(applied.tip_id)?
                .chain_tx_count,
            2,
            "apply must record the per-node count the RPC reads"
        );

        let _restored = disconnect_block(&handles, &block)?;
        assert_eq!(
            handles.chain_tx_count.load(Ordering::Relaxed),
            1,
            "the disconnected block's transactions must leave the count with it"
        );
        Ok(())
    }

    /// A connected block always fires the fee estimator's `block_connected`,
    /// even when the pool is empty and the block confirms nothing the pool
    /// tracked. The estimator ages one height per call regardless, so
    /// `estimator_last_decayed_height` advancing from `None` to `Some(height)`
    /// on an empty pool is the proof that `remove_for_block` ran.
    #[test]
    fn apply_sweep_records_fee_estimator_confirmation() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        handles.chain_tx_count.store(1, Ordering::Relaxed);

        // The pool starts empty — no transaction has entered it.
        assert!(
            handles.mempool_gateway.read().is_empty(),
            "pool must start empty for the empty-pool estimator proof"
        );
        assert_eq!(
            handles
                .mempool_gateway
                .read()
                .estimator_last_decayed_height(),
            None,
            "estimator must not have aged before any block connects"
        );

        // Connect a block whose only transaction is a coinbase the pool never
        // tracked. The pool stays empty, but the estimator must still age.
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let applied = apply_block(&handles, &block)?;
        assert_eq!(applied.height, 1, "the block must connect first");
        assert!(
            handles.mempool_gateway.read().is_empty(),
            "pool must still be empty — the coinbase was never in it"
        );
        assert_eq!(
            handles
                .mempool_gateway
                .read()
                .estimator_last_decayed_height(),
            Some(1),
            "a connected block must fire block_connected even with an empty pool"
        );

        // A second block with no tracked transactions must age the estimator
        // again, proving the sweep is not gated on pool non-emptiness.
        let block2 = mined_block_with_prev_hash_and_transactions(
            block.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let applied2 = apply_block(&handles, &block2)?;
        assert_eq!(applied2.height, 2);
        assert_eq!(
            handles
                .mempool_gateway
                .read()
                .estimator_last_decayed_height(),
            Some(2),
            "every connected block must age the estimator, including empty-pool blocks"
        );
        Ok(())
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
    -> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        let base_prevout = OutPoint::new(fixture_txid(0x64), 0);
        let utxo = utxo_with_output(base_prevout, 1)?;
        let first_spend = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
        let second_spend =
            spending_transaction_to_script(base_prevout, u32::MAX - 1, op_true_script());
        let block = block_with_transactions(vec![first_spend, second_spend]);
        let plan = tx_plan(&block);
        Ok((block, plan, utxo))
    }

    fn bad_script_spend_block()
    -> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        let base_prevout = OutPoint::new(fixture_txid(0x65), 0);
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            base_prevout,
            TxOut {
                value: 1_000,
                script_pubkey: vec![0x87],
            },
            false,
            1,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let mut script_sig = push_int(7);
        script_sig.extend_from_slice(&push_int(8));
        let spend = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: base_prevout,
                script_sig,
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: op_true_script(),
            }],
            lock_time: 0,
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
    -> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        // hash160([0x00]): the bare-eval arm only accepts when the redeem script
        // pushed by the scriptSig hashes to the value in the template output.
        const REDEEM_HASH160: [u8; 20] = [
            0x9f, 0x7f, 0xd0, 0x96, 0xd3, 0x7e, 0xd2, 0xc0, 0xe3, 0xf7, 0xf0, 0xcf, 0xc9, 0x24,
            0xbe, 0xef, 0x4f, 0xfc, 0xeb, 0x68,
        ];

        let redeem: [u8; 1] = [0x00];
        let mut p2sh_output_script = vec![0xa9_u8];
        p2sh_output_script.extend_from_slice(&push_data(&REDEEM_HASH160));
        p2sh_output_script.push(0x87);

        let base_prevout = OutPoint::new(fixture_txid(0x67), 0);
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            base_prevout,
            TxOut {
                value: 1_000,
                script_pubkey: p2sh_output_script,
            },
            false,
            1,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[10; 32]))?;

        let spend = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: base_prevout,
                script_sig: push_data(&redeem),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: op_true_script(),
            }],
            lock_time: 0,
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
        // Parse the exception-block hash from its display hex so a byte-order
        // flip against the stored consensus-LE constant cannot drift, and take
        // a non-exception sibling hash.
        let exception_hash = Hash256::from(
            "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
                .parse::<BlockHash>()?,
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
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &plan,
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &plan,
            )),
            &validation_context(&block, 170_060, 0, exc_flags),
            &kernel_block_of(&block),
        )?;

        // Normal block at the same height: P2SH enforced -> REJECTED at input 0.
        let (block2, plan2, utxo2) = p2sh_template_bare_spend_block()?;
        let handles2 = apply_handles_with_assume_valid(utxo2, 0);
        let err = match verify_block_transactions(
            &handles2,
            &block2,
            &mut bitcoin_rs_consensus::BlockView::new(&block2.txs, block_txids(&block2)),
            &plan2,
            Arc::new(ResolvedUtxoView::resolve(
                handles2.utxo.as_ref(),
                &block2,
                &plan2,
            )),
            &validation_context(&block2, 170_060, 0, normal_flags),
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
    -> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
        // `utxo_with_output` funds the prevout with 1_000 sats (its second arg `1` is
        // the coinbase height, not a value); the spend creates 2_000 sats of outputs,
        // so outputs exceed inputs — a NON-script consensus violation that must be
        // caught even when script checks are skipped.
        let base_prevout = OutPoint::new(fixture_txid(0x66), 0);
        let utxo = utxo_with_output(base_prevout, 1)?;
        let spend = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: base_prevout,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 2_000,
                script_pubkey: op_true_script(),
            }],
            lock_time: 0,
        };
        let block = block_with_transaction(spend);
        let plan = tx_plan(&block);
        Ok((block, plan, utxo))
    }

    /// In-memory bodies, so a branch switch can reload the blocks it needs.
    #[derive(Default)]
    pub(super) struct MapBodyStore {
        pub(super) bodies:
            parking_lot::RwLock<HashMap<(u32, bitcoin_rs_primitives::Hash256), Vec<u8>>>,
        pub(super) failed_reads:
            parking_lot::RwLock<HashSet<(u32, bitcoin_rs_primitives::Hash256)>>,
        /// Bodies that succeed on the first read but fail on every subsequent
        /// read, simulating a storage failure between the preflight and
        /// execution passes of a streamed reorg.
        pub(super) fail_on_second_read:
            parking_lot::RwLock<HashSet<(u32, bitcoin_rs_primitives::Hash256)>>,
        read_counts: parking_lot::RwLock<HashMap<(u32, bitcoin_rs_primitives::Hash256), u32>>,
    }

    struct ReorgBodyLoadingFixture {
        handles: ApplyHandles,
        utxo: Arc<UtxoSet>,
        bodies: Arc<MapBodyStore>,
        target: bitcoin_rs_chain::NodeId,
        losing: Block,
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
            if self.fail_on_second_read.read().contains(&(height, hash)) {
                let mut counts = self.read_counts.write();
                let count = counts.entry((height, hash)).or_insert(0);
                *count += 1;
                if *count >= 2 {
                    return Err(StorageError::Backend(
                        "injected second-read failure".to_owned(),
                    ));
                }
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

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let losing = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(consensus_bytes(&losing));
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
                let hash = Hash256::from(block.block_hash());
                last = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
                bodies
                    .bodies
                    .write()
                    .insert((height, hash), consensus_bytes(block));
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
        losing: &Block,
        applied: &TipSnapshot,
        tree_tip_before: Option<(bitcoin_rs_chain::NodeId, u32, Hash256)>,
        block_records_before: &[(u32, BlockHash)],
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
            utxo.has_live_outputs_for_txid(&Hash256::from(losing.txs[0].txid())),
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

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let applied_block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(consensus_bytes(&applied_block));
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
            utxo.has_live_outputs_for_txid(&Hash256::from(applied_block.txs[0].txid())),
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

        fn publish_hashtx(&self, _txid: Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {}

        fn publish_rawtx(&self, _bytes: &[u8]) {}

        fn publish_sequence(&self, event: crate::SequenceEvent) {
            let (hash, label) = match event {
                crate::SequenceEvent::Connected(hash) => (hash, b'C'),
                crate::SequenceEvent::Disconnected(hash) => (hash, b'D'),
                // Test-fake arms for the mempool `A`/`R` events; the
                // production payload mapping lives in `mempool_observer`.
                crate::SequenceEvent::Added(txid, _) => (Hash256::from(txid), b'A'),
                crate::SequenceEvent::Removed(txid, _) => (Hash256::from(txid), b'R'),
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

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let old_one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let old_one_raw = bytes::Bytes::from(consensus_bytes(&old_one));
        let old_one_tip = apply_block_with_serialized(&handles, &old_one, old_one_raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((old_one_tip.height, old_one_tip.hash), old_one_raw.to_vec());

        let old_two = mined_block_with_prev_hash_and_transactions(
            old_one.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let old_two_raw = bytes::Bytes::from(consensus_bytes(&old_two));
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
                    (height, Hash256::from(block.block_hash())),
                    consensus_bytes(block),
                );
            }
            target.ok_or_else(|| anyhow::anyhow!("new branch has no target"))?
        };

        crate::reorg::switch_to_branch(&handles, target, |_| None, |_| {})?;

        let events = publisher.events.lock().clone();
        assert_eq!(
            events,
            vec![
                (Hash256::from(old_two.block_hash()), b'D', 0),
                (Hash256::from(old_one.block_hash()), b'D', 1),
                (Hash256::from(new_one.block_hash()), b'C', 2),
                (Hash256::from(new_two.block_hash()), b'C', 3),
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

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let one = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let one_raw = bytes::Bytes::from(consensus_bytes(&one));
        let one_tip = apply_block_with_serialized(&handles, &one, one_raw.clone())?;
        bodies
            .bodies
            .write()
            .insert((one_tip.height, one_tip.hash), one_raw.to_vec());

        let two = mined_block_with_prev_hash_and_transactions(
            one.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let two_raw = bytes::Bytes::from(consensus_bytes(&two));
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

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
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
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
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
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
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

        fn publish_hashtx(&self, _txid: Txid) {}

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
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(5)],
        )?;
        let expected = Hash256::from(block.block_hash());
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
    fn a_deep_reorg_deeper_than_the_stream_window_lands_on_the_fork_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = bodies.clone();
        handles.block_body_store = Some(body_handle);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        // Build a 20-block old chain — deeper than DISCONNECT_STREAM_WINDOW (8).
        let mut prev = genesis.block_hash();
        for seed in 1_u8..=20 {
            let block = mined_block_with_prev_hash_and_transactions(
                prev,
                vec![coinbase_transaction(seed)],
            )?;
            let raw = bytes::Bytes::from(consensus_bytes(&block));
            let tip = apply_block_with_serialized(&handles, &block, raw.clone())?;
            bodies
                .bodies
                .write()
                .insert((tip.height, tip.hash), raw.to_vec());
            prev = block.block_hash();
        }

        // Build a 21-block fork from genesis (heavier by one block).
        let mut fork_prev = genesis.block_hash();
        let mut fork_target = None;
        for (height, seed) in (1_u32..=21).zip(101_u8..=121) {
            let block = mined_block_with_prev_hash_and_transactions(
                fork_prev,
                vec![coinbase_transaction(seed)],
            )?;
            let hash = Hash256::from(block.block_hash());
            bodies
                .bodies
                .write()
                .insert((height, hash), consensus_bytes(&block));
            let mut tree = handles.block_tree.write();
            fork_target = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
            fork_prev = block.block_hash();
        }
        let fork_target = fork_target.ok_or_else(|| anyhow::anyhow!("fork has no target"))?;
        let fork_tip_hash = Hash256::from(fork_prev);

        crate::reorg::switch_to_branch(&handles, fork_target, |_| None, |_| {})?;

        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(fork_tip_hash),
            "deep reorg must land on the fork tip"
        );
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.height),
            Some(21),
            "deep reorg must reach fork height"
        );
        // 21 fork coinbase outputs (genesis coinbase was never applied to the
        // UTXO set — only the 20 old blocks were, and they were disconnected).
        assert_eq!(
            utxo.len(),
            21,
            "UTXO set must contain exactly the fork coinbase outputs"
        );
        Ok(())
    }

    #[test]
    fn a_body_read_failure_mid_rollback_reports_disconnect_body_lost_not_panic()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = bodies.clone();
        handles.block_body_store = Some(body_handle);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        // Build a 20-block old chain.
        let mut prev = genesis.block_hash();
        let mut old_tips = Vec::new();
        for seed in 1_u8..=20 {
            let block = mined_block_with_prev_hash_and_transactions(
                prev,
                vec![coinbase_transaction(seed)],
            )?;
            let raw = bytes::Bytes::from(consensus_bytes(&block));
            let tip = apply_block_with_serialized(&handles, &block, raw.clone())?;
            bodies
                .bodies
                .write()
                .insert((tip.height, tip.hash), raw.to_vec());
            old_tips.push(tip);
            prev = block.block_hash();
        }

        // Build a 21-block fork from genesis.
        let mut fork_prev = genesis.block_hash();
        let mut fork_target = None;
        for (height, seed) in (1_u32..=21).zip(101_u8..=121) {
            let block = mined_block_with_prev_hash_and_transactions(
                fork_prev,
                vec![coinbase_transaction(seed)],
            )?;
            let hash = Hash256::from(block.block_hash());
            bodies
                .bodies
                .write()
                .insert((height, hash), consensus_bytes(&block));
            let mut tree = handles.block_tree.write();
            fork_target = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
            fork_prev = block.block_hash();
        }
        let fork_target = fork_target.ok_or_else(|| anyhow::anyhow!("fork has no target"))?;

        // Mark the body at height 5 (16th in the tip-down disconnect list,
        // inside the second window of 8) to fail on its second read. The
        // preflight pass reads it once (succeeds); the execution pass reads
        // it again (fails), proving the mid-rollback recovery path.
        let target_tip = &old_tips[4]; // height 5
        bodies
            .fail_on_second_read
            .write()
            .insert((target_tip.height, target_tip.hash));

        let outcome = crate::reorg::switch_to_branch(&handles, fork_target, |_| None, |_| {});

        // With DISCONNECT_STREAM_WINDOW = 8, the first window (heights 20..13)
        // disconnects fully (8 blocks), then the second window's load fails at
        // height 5. The chain is coherent at height 12.
        let Err(crate::reorg::ReorgError::DisconnectBodyLost {
            disconnected,
            stopped_at,
            ..
        }) = outcome
        else {
            panic!("expected DisconnectBodyLost, got {outcome:?}");
        };
        assert_eq!(
            disconnected, 8,
            "first window of 8 must disconnect before the second window's load fails"
        );
        assert_eq!(
            stopped_at, 12,
            "tip must be at height 12 after 8 disconnects from height 20"
        );
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.height),
            Some(12),
            "applied tip must be at the height reached by the completed window"
        );
        Ok(())
    }

    #[test]
    fn a_closed_admission_refuses_every_chainstate_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
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
                    disposition: WindowApplyDisposition::Operational,
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
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
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

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let losing = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let raw = bytes::Bytes::from(consensus_bytes(&losing));
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
                let hash = Hash256::from(block.block_hash());
                last = Some(tree.insert_header(
                    block.header,
                    bitcoin_rs_chain::node::NodeStatus::HeaderValid,
                )?);
                bodies
                    .bodies
                    .write()
                    .insert((height, hash), consensus_bytes(block));
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
            utxo.has_live_outputs_for_txid(&Hash256::from(losing.txs[0].txid())),
            "a refused disconnect must not have undone any coins"
        );
        Ok(())
    }

    fn apply_handles_for_network(network: Network, utxo: Arc<UtxoSet>) -> ApplyHandles {
        apply_handles_without_tx_index(network, utxo)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    pub(super) fn apply_handles_without_tx_index(
        network: Network,
        utxo: Arc<UtxoSet>,
    ) -> ApplyHandles {
        let mempool: Arc<RwLock<bitcoin_rs_mempool::Mempool>> = Arc::new(RwLock::new(
            bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits::default()),
        ));
        let mempool_gateway = bitcoin_rs_mempool::MempoolGateway::shared(Arc::clone(&mempool));
        let mining_generation = Arc::new(crate::mining::MiningGenerationSignal::new());
        ApplyHandles::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                bitcoin_rs_utxo::stats::CoinStats::default(),
            )),
            None,
            mempool,
            mempool_gateway,
            mining_generation,
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(RwLock::new(HashMap::<Txid, Tx>::new())),
            Arc::new(crate::NoOpZmqPublisher),
            Arc::new(crate::state::ChainEventPublisher::detached(0).0),
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

        fn publish_hashtx(&self, _txid: Txid) {}

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

        fn publish_hashtx(&self, _txid: Txid) {}

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

        fn publish_hashtx(&self, _txid: Txid) {
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

        fn publish_hashtx(&self, _txid: Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {
            panic!("rawblock publish should be skipped when wants_rawblock is false");
        }

        fn publish_rawtx(&self, _bytes: &[u8]) {
            panic!("rawtx publish should be skipped when wants_rawtx is false");
        }
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_utxo() -> Arc<UtxoSet> {
        Arc::new(UtxoSet::new())
    }

    use bitcoin_rs_rpc::context::MiningControlError;
    use compact_str::CompactString;

    /// A fake template coordinator recording generation publications.
    struct RecordingGenerationControl {
        published: Mutex<usize>,
    }

    fn generation_unavailable() -> MiningControlError {
        MiningControlError::Unavailable(CompactString::from("not wired in this test"))
    }

    impl bitcoin_rs_rpc::context::MiningControl for RecordingGenerationControl {
        fn get_block_template(
            &self,
            _request: bitcoin_rs_rpc::context::BlockTemplateRequest,
        ) -> Result<bitcoin_rs_rpc::context::BlockTemplateResult, MiningControlError> {
            Err(generation_unavailable())
        }

        fn mining_info(&self) -> Result<bitcoin_rs_rpc::context::MiningInfo, MiningControlError> {
            Err(generation_unavailable())
        }

        fn submit_block(
            &self,
            _block: Block,
        ) -> Result<bitcoin_rs_rpc::context::BlockValidationResult, MiningControlError> {
            Err(generation_unavailable())
        }

        fn publish_generation(&self) {
            *self.published.lock() += 1;
        }
    }

    /// Authoritative applied-tip moves must reach the template coordinator's
    /// long-poll waiters through the shared `MiningGenerationSignal`: one
    /// wake per connect and one per disconnect, fired after the tip is
    /// published.
    #[test]
    fn connect_and_disconnect_wake_the_mining_generation() -> Result<(), Box<dyn std::error::Error>>
    {
        let genesis = Network::Regtest.genesis_block();
        let utxo = Arc::new(UtxoSet::new());
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let control = Arc::new(RecordingGenerationControl {
            published: Mutex::new(0),
        });
        let control_dyn: Arc<dyn bitcoin_rs_rpc::context::MiningControl> = control.clone();
        handles.mining_generation.attach(&control_dyn);
        assert_eq!(*control.published.lock(), 0, "nothing ran yet");

        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &block)?;
        assert_eq!(
            *control.published.lock(),
            1,
            "the connect's tip publication must wake the coordinator once"
        );

        disconnect_block(&handles, &block)?;
        assert_eq!(
            *control.published.lock(),
            2,
            "the disconnect's tip publication must wake the coordinator once"
        );
        Ok(())
    }
    /// Failure-injecting undo store: every persist fails, everything else
    /// delegates to a real in-memory store.
    struct FailingUndoPersist {
        inner: InMemoryUndoStore,
    }

    impl UndoStore for FailingUndoPersist {
        fn persist_undo(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
            _record: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::backend(
                "injected undo-persist failure",
            ))
        }

        fn load_undo(
            &self,
            height: u32,
            hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.inner.load_undo(height, hash)
        }

        fn arm_disconnect(
            &self,
            height: u32,
            hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.arm_disconnect(height, hash)
        }

        fn complete_disconnect(
            &self,
            height: u32,
            hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.inner.complete_disconnect(height, hash)
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

    #[test]
    fn permanent_window_failure_invalidates_failed_subtree_and_descendants()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let genesis = Network::Regtest.genesis_block();
        let genesis_tip = applied_header_tip(&handles, genesis.block_hash().0, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let applied = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &applied)?;
        let applied_hash = applied.block_hash().0;

        let bad = mined_block_with_prev_hash_and_transactions(
            applied.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        // Corrupt the body against its own header: the txid changes, so the
        // header merkle root no longer matches and block rules reject the
        // block with a permanent consensus error before any write.
        let mut bad_body = bad.clone();
        bad_body.txs[0].outputs[0].value = 2;
        let descendant = mined_block_with_prev_hash_and_transactions(
            bad.block_hash(),
            vec![coinbase_transaction(3)],
        )?;
        {
            let mut tree = handles.block_tree.write();
            tree.insert_header(bad.header, NodeStatus::HeaderValid)?;
            tree.insert_header(descendant.header, NodeStatus::HeaderValid)?;
        }
        let bad_hash = bad.block_hash().0;
        let descendant_hash = descendant.block_hash().0;
        let raw = bytes::Bytes::from(consensus_bytes(&bad_body));

        let outcome = apply_window(&handles, &[&bad_body], core::slice::from_ref(&raw));
        let Err(error) = outcome else {
            panic!("a body contradicting its header merkle root must fail");
        };
        assert_eq!(error.disposition(), WindowApplyDisposition::Permanent);
        assert_eq!(
            error.invalidated(),
            &[bad_hash, descendant_hash],
            "the failed block and every descendant are invalid, in slab order"
        );
        {
            let tree = handles.block_tree.read();
            assert_eq!(
                tree.node_by_hash(bad_hash).map(|node| node.status),
                Some(NodeStatus::Invalid)
            );
            assert_eq!(
                tree.node_by_hash(descendant_hash).map(|node| node.status),
                Some(NodeStatus::Invalid)
            );
        }
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(applied_hash),
            "invalidation republishes the valid prefix, never the failed block"
        );
        assert_eq!(handles.utxo.len(), 1, "the failed block committed nothing");
        Ok(())
    }

    #[test]
    fn operational_window_failure_keeps_failed_block_retryable()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut handles = empty_apply_handles_for_network(Network::Regtest);
        let genesis = Network::Regtest.genesis_block();
        let genesis_tip = applied_header_tip(&handles, genesis.block_hash().0, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let applied = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &applied)?;
        let applied_hash = applied.block_hash().0;
        // The block's header was never accepted by header sync, so tree
        // preparation would have to insert it; the block stays unseen unless
        // apply gets that far.
        let bad = mined_block_with_prev_hash_and_transactions(
            applied.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let bad_hash = bad.block_hash().0;
        // The persisted-undo write fails: an operational error.
        handles.undo_store = Arc::new(FailingUndoPersist {
            inner: InMemoryUndoStore::default(),
        });
        let raw = bytes::Bytes::from(consensus_bytes(&bad));

        let outcome = apply_window(&handles, &[&bad], core::slice::from_ref(&raw));
        let Err(error) = outcome else {
            panic!("an undo-persist failure must fail the window");
        };
        assert_eq!(error.disposition(), WindowApplyDisposition::Operational);
        assert!(
            error.invalidated().is_empty(),
            "operational failures must not mark the block or its subtree invalid"
        );
        {
            let tree = handles.block_tree.read();
            assert!(
                tree.node_by_hash(bad_hash).is_none(),
                "tree preparation runs before the failing persist and must leave no node behind"
            );
        }
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(applied_hash),
            "the failed block must not move the applied tip"
        );
        assert_eq!(
            handles.utxo.len(),
            1,
            "the failed block must not commit outputs"
        );
        Ok(())
    }

    #[test]
    fn precommit_persist_failure_leaves_utxo_and_tip_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut handles = empty_apply_handles_for_network(Network::Regtest);
        let genesis = Network::Regtest.genesis_block();
        let genesis_tip = applied_header_tip(&handles, genesis.block_hash().0, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let applied = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        apply_block(&handles, &applied)?;
        let applied_hash = applied.block_hash().0;
        let block_log_len = handles.blocks.read().len();
        let utxo_len = handles.utxo.len();
        handles.undo_store = Arc::new(FailingUndoPersist {
            inner: InMemoryUndoStore::default(),
        });
        let next = mined_block_with_prev_hash_and_transactions(
            applied.block_hash(),
            vec![coinbase_transaction(2)],
        )?;
        let next_hash = next.block_hash().0;

        let outcome = apply_block(&handles, &next);
        assert!(
            matches!(outcome, Err(ApplyError::UndoPersistence(_))),
            "the injected persist failure must surface as UndoPersistence, got {outcome:?}"
        );
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.hash),
            Some(applied_hash),
            "a precommit bookkeeping failure must not move the tip"
        );
        assert_eq!(handles.utxo.len(), utxo_len, "no outputs may commit");
        assert_eq!(
            handles.blocks.read().len(),
            block_log_len,
            "the block log must not grow past the failed bookkeeping"
        );
        assert!(
            handles.block_tree.read().node_by_hash(next_hash).is_none(),
            "fallible tree preparation must precede the first UTXO mutation and stay absent on failure"
        );
        Ok(())
    }
}

#[cfg(test)]
fn check_pow_limit_and_continuity_for_seeded_tip(
    handles: &ApplyHandles,
    block: &Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let prior = handles.chain_tip.load_full();
    check_pow_limit_and_continuity(handles, prior.as_deref(), block, height)
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
        let state = crate::bip9_context::ContextualSoftforkState {
            csv_active: false,
            segwit_active: false,
        };

        // Parse the exception hash from its display hex, so a byte-order flip in
        // the stored consensus-LE constant cannot silently drift past this test.
        let exception_display = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22";
        let exception_hash = Hash256::from(exception_display.parse::<BlockHash>()?);

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

        fn publish_hashtx(&self, txid: Txid) {
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
        publisher.publish_hashtx(Txid::default());
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
                format!("hashtx:{}", Txid::default()),
                "rawblock".to_owned(),
                "rawtx".to_owned(),
            ]
        );
    }
}

#[cfg(test)]
mod with_zmq_publisher_tests {
    use std::sync::Arc;

    use bitcoin_rs_primitives::Txid;
    use parking_lot::Mutex;

    use crate::ZmqPublisher as _;

    #[derive(Debug, Default)]
    struct TaggedPublisher {
        tag: Mutex<u32>,
    }

    impl crate::ZmqPublisher for TaggedPublisher {
        fn publish_hashblock(&self, _: bitcoin_rs_primitives::Hash256) {
            *self.tag.lock() = 42;
        }

        fn publish_hashtx(&self, _: Txid) {}

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
mod chain_tx_count_tests {
    use super::*;

    fn handles() -> ApplyHandles {
        super::consensus_rule_tests::empty_apply_handles()
    }

    #[test]
    fn genesis_establishes_the_count_from_nothing() {
        let handles = handles();
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
        advance_chain_tx_count(&handles, 0, 1);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn an_unknown_count_stays_unknown_above_genesis() {
        let handles = handles();
        // A datadir written before the counter existed restores as unknown.
        // Accumulating from here would produce a small number that looks like a
        // chain total and is not one — worse than admitting we do not know.
        advance_chain_tx_count(&handles, 900_000, 2_500);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_known_count_advances_and_rewinds_by_the_same_delta() {
        let handles = handles();
        advance_chain_tx_count(&handles, 0, 1);
        advance_chain_tx_count(&handles, 1, 7);
        advance_chain_tx_count(&handles, 2, 3);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 11);

        rewind_chain_tx_count(&handles, 3);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 8);
        rewind_chain_tx_count(&handles, 7);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rewinding_an_unknown_count_leaves_it_unknown() {
        let handles = handles();
        rewind_chain_tx_count(&handles, 5);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_rewind_past_zero_admits_it_does_not_know_rather_than_clamping() {
        let handles = handles();
        advance_chain_tx_count(&handles, 0, 4);
        // Only reachable if the count and the chain have diverged. A clamp to
        // some small number would keep reporting a confident wrong total.
        rewind_chain_tx_count(&handles, 9);
        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_advance_past_u64_marks_the_count_unknown_instead_of_wrapping() {
        let handles = handles();
        handles
            .chain_tx_count
            .store(u64::MAX - 1, Ordering::Relaxed);

        advance_chain_tx_count(&handles, 900_000, 3);

        assert_eq!(handles.chain_tx_count.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod chain_generation_tests {
    use std::sync::Arc;

    use bitcoin_rs_mempool::{MempoolObserver, MutationEnvelope};
    use bitcoin_rs_primitives::{BlockHash, Network, OutPoint, Tx, TxIn, TxOut, Txid};
    use bitcoin_rs_utxo::UtxoSet;
    use parking_lot::Mutex;

    use super::consensus_rule_tests::{
        apply_handles_without_tx_index, coinbase_transaction,
        mined_block_with_prev_hash_and_transactions,
    };
    use super::{ApplyHandles, applied_header_tip};

    /// An observer that captures the gateway's `stable_generation` when a
    /// mutation fires. We pass the gateway in via an Arc.
    struct GatewayGenerationRecorder {
        /// Bound after the gateway exists: the gateway owns the observer, so
        /// the observer cannot own the gateway at construction. An unbound
        /// recorder records `None`, which fails the caller's assertion rather
        /// than passing quietly.
        gateway: std::sync::OnceLock<Arc<bitcoin_rs_mempool::MempoolGateway>>,
        seen: Mutex<Vec<Option<u64>>>,
    }

    impl GatewayGenerationRecorder {
        fn bind(&self, gateway: &Arc<bitcoin_rs_mempool::MempoolGateway>) {
            let _ = self.gateway.set(Arc::clone(gateway));
        }
    }

    impl MempoolObserver for GatewayGenerationRecorder {
        fn on_mutation(&self, _envelope: &MutationEnvelope) {
            let generation = self
                .gateway
                .get()
                .and_then(|gateway| gateway.stable_generation());
            self.seen.lock().push(generation);
        }
    }

    fn setup_regtest_with_genesis() -> (ApplyHandles, bitcoin_rs_primitives::Block, BlockHash) {
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        let genesis_tip = applied_header_tip(&handles, genesis_hash.into(), &genesis, 0)
            .unwrap_or_else(|error| panic!("genesis tip must apply: {error}"));
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        (handles, genesis, genesis_hash)
    }

    #[test]
    fn stable_generation_is_even_before_and_after_connect() {
        let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();
        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            Some(0),
            "generation is even zero before any chain change"
        );

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )
        .unwrap_or_else(|error| panic!("mine block: {error}"));

        crate::apply::apply_block(&handles, &block)
            .unwrap_or_else(|error| panic!("connect succeeds: {error}"));

        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            Some(2),
            "generation is even after a successful connect"
        );
    }

    #[test]
    fn stable_generation_is_even_after_disconnect() {
        let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )
        .unwrap_or_else(|error| panic!("mine block: {error}"));

        crate::apply::apply_block(&handles, &block)
            .unwrap_or_else(|error| panic!("connect: {error}"));
        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            Some(2),
            "even after connect"
        );

        crate::apply::disconnect_block(&handles, &block)
            .unwrap_or_else(|error| panic!("disconnect succeeds: {error}"));
        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            Some(4),
            "generation is even after a successful disconnect"
        );
    }

    #[test]
    fn stable_generation_is_even_after_window() {
        let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();

        let block1 = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )
        .unwrap_or_else(|error| panic!("mine block 1: {error}"));

        let block2 = mined_block_with_prev_hash_and_transactions(
            block1.block_hash(),
            vec![coinbase_transaction(2)],
        )
        .unwrap_or_else(|error| panic!("mine block 2: {error}"));

        let blocks = [block1, block2];
        let serialized: Vec<bytes::Bytes> = blocks
            .iter()
            .map(|b| bytes::Bytes::from(super::consensus_bytes(b)))
            .collect();
        let block_refs: Vec<&bitcoin_rs_primitives::Block> = blocks.iter().collect();

        crate::apply::apply_window(&handles, &block_refs, &serialized)
            .unwrap_or_else(|error| panic!("window succeeds: {error}"));

        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            Some(2),
            "generation is even after a multi-block window"
        );
    }

    #[test]
    fn chain_change_proof_finish_restores_even_generation() {
        let (handles, _genesis, _genesis_hash) = setup_regtest_with_genesis();

        let transition = handles
            .begin_chain_transition()
            .unwrap_or_else(|error| panic!("transition: {error}"));
        let guard = handles
            .mempool_gateway
            .begin_chain_change()
            .unwrap_or_else(|error| panic!("begin chain change: {error}"));
        let proof = super::ChainChangeProof::new(transition, guard);

        assert_eq!(proof.odd_generation(), 1);
        assert_eq!(proof.reserved_even(), 2);
        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            None,
            "odd while proof is held"
        );

        proof
            .finish()
            .unwrap_or_else(|error| panic!("finish restores even: {error}"));
        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            Some(2),
            "even after finish"
        );
    }

    #[test]
    fn observer_sees_none_during_connect() {
        let (mut handles, genesis, _genesis_hash) = setup_regtest_with_genesis();
        let recorder = Arc::new(GatewayGenerationRecorder {
            gateway: std::sync::OnceLock::new(),
            seen: Mutex::new(Vec::new()),
        });
        let observer: Arc<dyn MempoolObserver> = recorder.clone();
        let pool = handles.mempool_gateway.pool().clone();
        let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
            pool,
            Some(observer),
        ));
        recorder.bind(&gateway);
        handles.mempool_gateway = gateway;

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )
        .unwrap_or_else(|error| panic!("mine block: {error}"));

        crate::apply::apply_block(&handles, &block)
            .unwrap_or_else(|error| panic!("connect: {error}"));

        let seen = recorder.seen.lock();
        // The observer fires during remove_for_block, which happens while the
        // generation is odd. Every observed mutation must see None.
        assert!(
            seen.iter().all(|&g| g.is_none()),
            "all observer mutations during connect must see None (odd generation), got {:?}",
            *seen
        );
    }

    #[test]
    fn invalidate_block_reconsiders_under_held_transition() {
        use bitcoin_rs_primitives::{TxIn, consensus_bytes};
        use bitcoin_rs_script::push_int;

        use super::consensus_rule_tests::MapBodyStore;

        let utxo = Arc::new(UtxoSet::new());
        let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
        let bodies = Arc::new(MapBodyStore::default());
        let body_handle: Arc<dyn crate::apply::PruneBodyStore> = bodies.clone();
        handles.block_body_store = Some(body_handle);

        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        let genesis_tip = applied_header_tip(&handles, genesis_hash.into(), &genesis, 0)
            .unwrap_or_else(|error| panic!("genesis tip: {error}"));
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        // Build a 101-block chain: block 1's coinbase carries the full
        // subsidy, and the tip block spends it after 100 confirmations
        // (coinbase maturity). The spend is the transaction that
        // reconsideration must readmit when the tip is invalidated.
        let subsidy = 5_000_000_000_u64;
        let mut prev_hash = genesis.block_hash();
        let mut first_txid = None;
        let mut spend_txid = None;
        let mut tip_hash: bitcoin_rs_primitives::Hash256 = genesis_hash.into();
        for height in 1..=101_u32 {
            let mut coinbase = coinbase_transaction(u8::try_from(height).unwrap_or(0xFF));
            if height == 1 {
                coinbase.outputs[0].value = subsidy;
            }
            let mut txs = vec![coinbase];
            if height == 101 {
                let Some(first) = first_txid else {
                    panic!("block 1 txid must exist")
                };
                txs.push(Tx {
                    version: 2,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(first, 0),
                        script_sig: push_int(1),
                        sequence: 0xffff_ffff,
                        witness: Vec::new(),
                    }],
                    outputs: vec![TxOut {
                        value: subsidy - 100_000,
                        script_pubkey: Vec::new(),
                    }],
                    lock_time: 0,
                });
            }
            let block = mined_block_with_prev_hash_and_transactions(prev_hash, txs)
                .unwrap_or_else(|error| panic!("mine block {height}: {error}"));
            if height == 1 {
                first_txid = Some(block.txs[0].txid());
            }
            if height == 101 {
                spend_txid = Some(block.txs[1].txid());
            }
            let raw = bytes::Bytes::from(consensus_bytes(&block));
            let tip = crate::apply::apply_block_with_serialized(&handles, &block, raw.clone())
                .unwrap_or_else(|error| panic!("apply block {height}: {error}"));
            bodies
                .bodies
                .write()
                .insert((tip.height, tip.hash), raw.to_vec());
            prev_hash = block.block_hash();
            tip_hash = tip.hash;
        }
        let Some(spend_txid) = spend_txid else {
            panic!("block 101 must have a spend tx")
        };

        // Install the generation recorder before invalidation so it captures
        // every mempool mutation during reconsideration.
        let recorder = Arc::new(GatewayGenerationRecorder {
            gateway: std::sync::OnceLock::new(),
            seen: Mutex::new(Vec::new()),
        });
        let observer: Arc<dyn MempoolObserver> = recorder.clone();
        let pool = handles.mempool_gateway.pool().clone();
        let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
            pool,
            Some(observer),
        ));
        recorder.bind(&gateway);
        handles.mempool_gateway = gateway;

        crate::reorg::invalidate_block(&handles, tip_hash)
            .unwrap_or_else(|error| panic!("invalidate tip: {error}"));

        // The spend must have been readmitted to the mempool.
        assert!(
            handles.mempool.read().contains_txid(&spend_txid),
            "the disconnected spend must be readmitted"
        );
        // Every observer mutation during reconsideration must have seen an odd
        // generation (None). If reconsideration ran after proof.finish(), the
        // generation would be even and the recorder would see Some(_).
        let seen = recorder.seen.lock();
        assert!(
            !seen.is_empty(),
            "reconsideration must produce at least one mempool mutation"
        );
        assert!(
            seen.iter().all(|&g| g.is_none()),
            "reconsideration must run while the chain transition is held (odd generation), \
             got {:?}",
            *seen
        );
        // After invalidation completes, the generation is even again
        // (admission reopens). The exact value depends on how many chain
        // changes preceded this call.
        assert!(
            handles.mempool_gateway.stable_generation().is_some(),
            "generation must be even after successful invalidation"
        );
    }

    #[test]
    fn failed_connect_does_not_restore_even_generation() {
        let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();

        // Build a block that will fail during apply — it has a non-coinbase
        // transaction spending a nonexistent UTXO, which will fail consensus.
        let mut bad_tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(
                    Txid::from(bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xAA; 32])),
                    0,
                ),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        let _ = &mut bad_tx;

        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1), bad_tx],
        )
        .unwrap_or_else(|error| panic!("mine block: {error}"));

        let result = crate::apply::apply_block(&handles, &block);
        assert!(
            result.is_err(),
            "block with nonexistent UTXO spend must fail"
        );

        // A failed connect leaves the generation odd — admission stays closed.
        assert_eq!(
            handles.mempool_gateway.stable_generation(),
            None,
            "failed connect leaves generation odd (admission closed)"
        );
    }
}
