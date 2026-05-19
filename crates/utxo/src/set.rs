use std::io;

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use parking_lot::Mutex;
use thiserror::Error;

use crate::{
    UtxoKey,
    record::{OwnedUtxoOut, validate_bitmap_vout},
    shard::Shard,
};

/// Errors returned by UTXO mutation and snapshot operations.
#[derive(Debug, Error)]
pub enum UtxoError {
    /// The record bitmap only represents vouts `0..64`.
    #[error("vout {vout} exceeds the UTXO record bitmap range 0..64")]
    VoutOutOfRange {
        /// Invalid vout.
        vout: u32,
    },
    /// A script does not fit the snapshot and record `u16` length field.
    #[error("script_pubkey is too large for a u16 length: {len} bytes")]
    ScriptTooLarge {
        /// Script length in bytes.
        len: usize,
    },
    /// The shard script slab exceeded the record `u32` offset field.
    #[error("script arena offset exceeded u32 range at {len} bytes")]
    ArenaOffsetOverflow {
        /// Current script slab byte length.
        len: usize,
    },
    /// Internal record offsets no longer point into the shard script slab.
    #[error("UTXO record points outside its shard script arena")]
    CorruptArena,
    /// Snapshot I/O failed.
    #[error("snapshot I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Snapshot magic did not match `UTXO`.
    #[error("invalid snapshot magic {actual:#010x}")]
    InvalidSnapshotMagic {
        /// Observed magic.
        actual: u32,
    },
    /// Snapshot version is not supported by this crate.
    #[error("unsupported snapshot version {version}")]
    UnsupportedSnapshotVersion {
        /// Observed version.
        version: u32,
    },
    /// Snapshot record count does not fit the local platform.
    #[error("snapshot record count {count} does not fit usize")]
    SnapshotRecordCountTooLarge {
        /// Record count from the header.
        count: u64,
    },
    /// Snapshot output count does not fit the record header.
    #[error("snapshot record has too many live outputs: {count}")]
    SnapshotOutputCountTooLarge {
        /// Live output count in one transaction-level record.
        count: usize,
    },
    /// Snapshot vout count does not match the bitmap.
    #[error("snapshot record vout count {vout_count} does not match bitmap {bitmap:#018x}")]
    SnapshotVoutCountMismatch {
        /// Vout bitmap from the record.
        bitmap: u64,
        /// Vout count from the record.
        vout_count: u8,
    },
    /// Snapshot shard byte does not match the key's first byte.
    #[error("snapshot shard {shard} does not match key shard {key_shard}")]
    SnapshotShardMismatch {
        /// Shard index serialized in the record.
        shard: u8,
        /// Shard implied by the key prefix.
        key_shard: u8,
    },
}

/// One UTXO output to add to the set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoAdd {
    /// Outpoint being created.
    pub outpoint: OutPoint,
    /// Output payload.
    pub txout: TxOut,
    /// Whether the creating transaction is coinbase.
    pub coinbase: bool,
    /// Creating block height.
    pub height: u32,
}

impl UtxoAdd {
    /// Constructs an add operation.
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: TxOut, coinbase: bool, height: u32) -> Self {
        Self {
            outpoint,
            txout,
            coinbase,
            height,
        }
    }

    pub(crate) const fn payload(&self) -> BuildPayload<'_> {
        BuildPayload {
            vout: self.outpoint.vout,
            txout: &self.txout,
            coinbase: self.coinbase,
            height: self.height,
        }
    }
}

/// UTXO mutations produced by one connected block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockChanges {
    adds: Vec<UtxoAdd>,
    removes: Vec<OutPoint>,
}

impl BlockChanges {
    /// Appends an output creation.
    pub fn add(&mut self, add: UtxoAdd) {
        self.adds.push(add);
    }

    /// Appends an output spend.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns true when there are no additions or removals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.removes.is_empty()
    }

    /// Returns the number of add operations.
    #[must_use]
    pub fn add_count(&self) -> usize {
        self.adds.len()
    }

    /// Returns the number of remove operations.
    #[must_use]
    pub fn remove_count(&self) -> usize {
        self.removes.len()
    }
}

/// Inverse mutations needed to disconnect one block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UndoBatch {
    restores: Vec<UtxoAdd>,
    removes: Vec<OutPoint>,
}

impl UndoBatch {
    /// Restores an output spent by the disconnected block.
    pub fn restore(&mut self, add: UtxoAdd) {
        self.restores.push(add);
    }

    /// Removes an output created by the disconnected block.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns true when the undo batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.restores.is_empty() && self.removes.is_empty()
    }
}

#[derive(Copy, Clone)]
pub(crate) struct BuildPayload<'a> {
    pub(crate) vout: u32,
    pub(crate) txout: &'a TxOut,
    pub(crate) coinbase: bool,
    pub(crate) height: u32,
}

#[derive(Copy, Clone)]
pub(crate) struct SpendPayload {
    pub(crate) key: UtxoKey,
    pub(crate) vout: u32,
}

/// In-memory 256-shard UTXO set.
pub struct UtxoSet {
    pub(crate) shards: [Shard; UtxoKey::SHARD_COUNT],
    pub(crate) last_defragged_shard: Mutex<u8>,
}

impl UtxoSet {
    /// Creates an empty UTXO set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: [(); UtxoKey::SHARD_COUNT].map(|()| Shard::new()),
            last_defragged_shard: Mutex::new(0),
        }
    }

    /// Applies all UTXO changes for a connected block.
    pub fn commit_block(
        &self,
        changes: &BlockChanges,
        block_hash: &Hash256,
    ) -> Result<(), UtxoError> {
        tracing::trace!(%block_hash, adds = changes.adds.len(), removes = changes.removes.len(), "commit utxo block");
        self.commit_adds_and_removes(&changes.adds, &changes.removes)
    }

    /// Returns an owned transaction output if the outpoint is live.
    #[must_use]
    pub fn get(&self, op: &OutPoint) -> Option<TxOut> {
        let key = UtxoKey::from_txid(&op.txid);
        self.shards[usize::from(key.shard())].get(&key, op.vout)
    }

    /// Reverses one connected block using its undo data.
    pub fn undo_block(&self, undo: &UndoBatch) -> Result<(), UtxoError> {
        self.commit_adds_and_removes(&undo.restores, &undo.removes)
    }

    /// Returns the number of live outpoint entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(Shard::output_count).sum()
    }

    /// Returns true when the set has no live outpoint entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of transaction-level records.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.shards.iter().map(Shard::record_count).sum()
    }

    /// Returns each shard's script-slab high-water mark.
    #[must_use]
    pub fn arena_high_water_by_shard(&self) -> [usize; UtxoKey::SHARD_COUNT] {
        core::array::from_fn(|idx| self.shards[idx].arena_high_water())
    }

    pub(crate) const fn shard(&self, idx: usize) -> &Shard {
        &self.shards[idx]
    }

    pub(crate) fn insert_snapshot_record(
        &self,
        key: UtxoKey,
        outputs: &[OwnedUtxoOut],
    ) -> Result<(), UtxoError> {
        self.shards[usize::from(key.shard())].insert_owned_record(key, outputs)
    }

    fn commit_adds_and_removes(
        &self,
        adds: &[UtxoAdd],
        removes: &[OutPoint],
    ) -> Result<(), UtxoError> {
        let mut adds_by_shard = empty_add_buckets();
        let mut removes_by_shard = empty_remove_buckets();

        for add in adds {
            validate_add(add)?;
            let key = UtxoKey::from_txid(&add.outpoint.txid);
            adds_by_shard[usize::from(key.shard())].push((key, add.payload()));
        }
        for remove in removes {
            validate_bitmap_vout(remove.vout)?;
            let key = UtxoKey::from_txid(&remove.txid);
            removes_by_shard[usize::from(key.shard())].push(SpendPayload {
                key,
                vout: remove.vout,
            });
        }

        let errors = Mutex::new(Vec::new());
        rayon::scope(|scope| {
            for shard_idx in 0..UtxoKey::SHARD_COUNT {
                let shard_adds = &adds_by_shard[shard_idx];
                let shard_removes = &removes_by_shard[shard_idx];
                if shard_adds.is_empty() && shard_removes.is_empty() {
                    continue;
                }
                let shard = &self.shards[shard_idx];
                let errors = &errors;
                scope.spawn(move |_| {
                    if let Err(error) = shard.commit_batch(shard_adds, shard_removes) {
                        errors.lock().push(error);
                    }
                });
            }
        });

        let mut errors = errors.into_inner();
        if let Some(error) = errors.pop() {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_add(add: &UtxoAdd) -> Result<(), UtxoError> {
    validate_bitmap_vout(add.outpoint.vout)?;
    let script_len = add.txout.script_pubkey.as_bytes().len();
    let _fits =
        u16::try_from(script_len).map_err(|_| UtxoError::ScriptTooLarge { len: script_len })?;
    Ok(())
}

fn empty_add_buckets<'a>() -> Vec<Vec<(UtxoKey, BuildPayload<'a>)>> {
    (0..UtxoKey::SHARD_COUNT).map(|_| Vec::new()).collect()
}

fn empty_remove_buckets() -> Vec<Vec<SpendPayload>> {
    (0..UtxoKey::SHARD_COUNT).map(|_| Vec::new()).collect()
}
