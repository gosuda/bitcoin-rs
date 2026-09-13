//! Durable chain head record and its atomic commit boundary.
//!
//! `RCV-02` orders every connect or disconnect as: reserve, append, sync, one
//! atomic durable batch, publish. This module owns the record that batch
//! commits: one versioned, CRC32C-framed row in the `UtxoMeta` family naming
//! the committed chain tip, its strictly monotonic `commit_id`, the chain
//! transaction count, and the committed body/undo extents (`INV-06`: the head
//! never names a byte range that was not made durable before the batch).
//!
//! The framing imitates the chainstate journal's `HeadMarker` (magic, version
//! byte, checksum over the payload) but is not a second copy of it: the
//! journal head stays a derived recovery accelerator, while this row is the
//! commit point the apply path advances before it publishes the tip. A head
//! whose bytes do not decode fails closed, exactly like a torn `head.json`.

use bitcoin_rs_primitives::Hash256;

use crate::pruning::{BLOCK_DATA_CF, block_body_key, block_undo_key};
use crate::{ColumnFamily, KvStore, StorageError, WriteBatch as _, WriteCondition};

/// Key of the durable-head row in the `UtxoMeta` family.
///
/// One key, like the disconnect marker: the chain-transition lock admits one
/// writer at a time, so a per-head key would only force readers to scan.
pub const DURABLE_HEAD_KEY: &[u8] = b"node:durable-head";

/// Current durable-head row format version.
///
/// Owner-local to this row. A bump is a breaking change for every datadir
/// that ever wrote the row, so decode treats an unknown version as corruption
/// and refuses, rather than guessing around it.
pub const DURABLE_HEAD_FORMAT_VERSION: u8 = 1;

/// Magic prefix of the durable-head row bytes.
const DURABLE_HEAD_MAGIC: [u8; 4] = *b"BRSD";

/// Fixed payload width: commit id, height, tip, chain tx count, body extent,
/// undo extent.
const DURABLE_HEAD_PAYLOAD_LEN: usize = 8 + 4 + 32 + 8 + 1 + 4 + 8 + 1 + 4 + 32;

/// Frame width: magic, version, CRC32C, payload.
const DURABLE_HEAD_FRAME_LEN: usize = DURABLE_HEAD_MAGIC.len() + 1 + 4 + DURABLE_HEAD_PAYLOAD_LEN;

/// Byte range of the flat-file block store this head certifies.
///
/// Every block body the head references lives in a block file numbered at or
/// below `file_no`, at an offset below `offset`. The bound is a floor for
/// recovery (bytes outside it are orphan tails), not an index: individual
/// bodies are addressed by their locator rows, which land in the same batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyExtent {
    /// Highest block file number the head names.
    pub file_no: u32,
    /// First byte at or after the last frame the head names.
    pub offset: u64,
}

/// The chain's durable commit point.
///
/// Written by exactly one caller at a time under the chain-transition lock,
/// and always through [`DurableHeadStore::commit`], whose single
/// `write_durable_if` receipt covers the head row and every record row named
/// in the same batch. `commit_id` is strictly monotonic across connects and
/// disconnects alike: a reorg may lower `height`, never `commit_id` (`P3`),
/// which is what makes an ambiguous durable completion resolvable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableHead {
    /// Strictly monotonic commit counter; advances on disconnect too.
    pub commit_id: u64,
    /// Height of `tip`.
    pub height: u32,
    /// Committed chain tip.
    pub tip: Hash256,
    /// Cumulative applied-chain transaction count at `tip`.
    pub chain_tx_count: u64,
    /// Body-byte range certified durable before this batch.
    pub body_extent: Option<BodyExtent>,
    /// The newest undo record `(height, hash)` this head certifies durable.
    pub undo_extent: Option<(u32, Hash256)>,
}

impl DurableHead {
    /// Serializes the versioned, CRC32C-framed row.
    ///
    /// Layout: `magic | version u8 | crc32c(payload) u32 LE | payload`, the
    /// payload all big-endian. The checksum covers the payload so a torn
    /// backend row or a bit flip fails closed at load.
    #[must_use]
    pub fn encode(&self) -> [u8; DURABLE_HEAD_FRAME_LEN] {
        let mut payload = [0_u8; DURABLE_HEAD_PAYLOAD_LEN];
        payload[0..8].copy_from_slice(&self.commit_id.to_be_bytes());
        payload[8..12].copy_from_slice(&self.height.to_be_bytes());
        payload[12..44].copy_from_slice(self.tip.as_byte_array());
        payload[44..52].copy_from_slice(&self.chain_tx_count.to_be_bytes());
        payload[52] = u8::from(self.body_extent.is_some());
        if let Some(extent) = self.body_extent {
            payload[53..57].copy_from_slice(&extent.file_no.to_be_bytes());
            payload[57..65].copy_from_slice(&extent.offset.to_be_bytes());
        }
        payload[65] = u8::from(self.undo_extent.is_some());
        if let Some((height, hash)) = self.undo_extent {
            payload[66..70].copy_from_slice(&height.to_be_bytes());
            payload[70..102].copy_from_slice(hash.as_byte_array());
        }

        let mut frame = [0_u8; DURABLE_HEAD_FRAME_LEN];
        frame[..DURABLE_HEAD_MAGIC.len()].copy_from_slice(&DURABLE_HEAD_MAGIC);
        frame[DURABLE_HEAD_MAGIC.len()] = DURABLE_HEAD_FORMAT_VERSION;
        let checksum = crc32c(&payload);
        frame[5..9].copy_from_slice(&checksum.to_le_bytes());
        frame[9..].copy_from_slice(&payload);
        frame
    }

    /// Decodes a framed row, refusing every malformed byte.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let header = DURABLE_HEAD_MAGIC.len() + 1 + 4;
        if bytes.len() != DURABLE_HEAD_FRAME_LEN
            || bytes[..DURABLE_HEAD_MAGIC.len()] != DURABLE_HEAD_MAGIC
            || bytes[DURABLE_HEAD_MAGIC.len()] != DURABLE_HEAD_FORMAT_VERSION
        {
            return None;
        }
        let checksum = u32::from_le_bytes(
            bytes[DURABLE_HEAD_MAGIC.len() + 1..header]
                .try_into()
                .ok()?,
        );
        let payload = &bytes[header..];
        if crc32c(payload) != checksum {
            return None;
        }
        parse_payload(payload)
    }
}

/// Parses the checksum-verified payload into a head.
fn parse_payload(payload: &[u8]) -> Option<DurableHead> {
    if payload.len() != DURABLE_HEAD_PAYLOAD_LEN {
        return None;
    }
    let commit_id = u64::from_be_bytes(payload[0..8].try_into().ok()?);
    let height = u32::from_be_bytes(payload[8..12].try_into().ok()?);
    let tip = Hash256::from_le_bytes(&payload[12..44].try_into().ok()?);
    let chain_tx_count = u64::from_be_bytes(payload[44..52].try_into().ok()?);
    let body_present = payload[52];
    let undo_present = payload[65];
    if body_present > 1 || undo_present > 1 {
        return None;
    }
    let body_extent = if body_present == 1 {
        Some(BodyExtent {
            file_no: u32::from_be_bytes(payload[53..57].try_into().ok()?),
            offset: u64::from_be_bytes(payload[57..65].try_into().ok()?),
        })
    } else {
        None
    };
    let undo_extent = if undo_present == 1 {
        let height = u32::from_be_bytes(payload[66..70].try_into().ok()?);
        let hash = Hash256::from_le_bytes(&payload[70..102].try_into().ok()?);
        Some((height, hash))
    } else {
        None
    };
    Some(DurableHead {
        commit_id,
        height,
        tip,
        chain_tx_count,
        body_extent,
        undo_extent,
    })
}

/// Record rows that land atomically beside a durable-head advance.
///
/// The apply path fills only the legs a commit needs: a connect lands the
/// block's undo row and body locator row, a disconnect lands the `RolledBack`
/// marker phase. Everything here must already be *written* (deferred is fine)
/// and *synced* where it lives outside the key-value store before the batch
/// runs, because `Ok(())` from [`DurableHeadStore::commit`] is the durability
/// receipt for the head and all of these rows together.
#[derive(Debug, Default)]
pub struct CommitRecords<'a> {
    /// Undo rows (`UndoData`) to land with the head: `(height, hash, record)`.
    pub undo_rows: Vec<(u32, Hash256, &'a [u8])>,
    /// Body locator rows (`BlockBodies`): `(height, hash, position)`.
    pub body_rows: Vec<(u32, Hash256, crate::block_file::BlockFilePosition)>,
}

/// Owner of the durable-head row and its atomic commit boundary.
///
/// Implementations must keep the whole [`CommitRecords`] set and the head row
/// in one atomic, durable write: after `Ok(())`, a reopened store sees the
/// new head and every record row, or the old head and none of them.
pub trait DurableHeadStore: Send + Sync + 'static {
    /// Loads the current durable head, if any has ever been committed.
    ///
    /// An unreadable row is an error, never `None`: treating corruption as
    /// "no head" would let a silent bit flip turn the chain's commit point
    /// back into a checkpoint-and-journal node.
    fn load(&self) -> Result<Option<DurableHead>, StorageError>;

    /// Durably advances the head to `next` iff the stored head still encodes
    /// `expected`.
    ///
    /// `expected` is the fence: the empty store must be named with `None`.
    /// A mismatch returns [`StorageError::InvalidOperation`] and applies
    /// nothing, mirroring a lost `write_durable_if` claim. `Ok(())` is the
    /// durability receipt for `next` and every row in `records`; `Err` is not
    /// a rollback receipt — the batch may already be durable, and the caller
    /// must reconcile instead of retrying blindly.
    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError>;

    /// Clears a committed head during authenticated full revalidation.
    fn reset(&self, expected: &DurableHead) -> Result<(), StorageError>;
}

/// Durable-head storage backed by a [`KvStore`].
///
/// The row lands in the `UtxoMeta` family beside the disconnect marker and
/// the index watermark keys, which is where chainstate metadata already
/// lives; no new column family and no datadir-wide schema bump.
pub struct KvDurableHeadStore<S: KvStore> {
    store: std::sync::Arc<S>,
}

impl<S: KvStore> KvDurableHeadStore<S> {
    /// Binds the head store to `store`.
    #[must_use]
    pub const fn new(store: std::sync::Arc<S>) -> Self {
        Self { store }
    }

    fn load_bytes(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.get(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY)
    }
}

impl<S: KvStore> DurableHeadStore for KvDurableHeadStore<S> {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.load_bytes()?
            .map(|bytes| {
                DurableHead::decode(&bytes).ok_or_else(|| {
                    StorageError::IncompatibleData(
                        "durable head row is unreadable; refusing to treat it as absent".to_owned(),
                    )
                })
            })
            .transpose()
    }

    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        for (height, hash, record) in &records.undo_rows {
            batch.put(
                ColumnFamily::UndoData,
                &block_undo_key(*height, *hash),
                record,
            );
        }
        for (height, hash, position) in &records.body_rows {
            batch.put(
                BLOCK_DATA_CF,
                &block_body_key(*height, *hash),
                &position.encode(),
            );
        }
        let condition = match expected {
            Some(current) => WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: DURABLE_HEAD_KEY,
                expected: &current.encode(),
            },
            None => WriteCondition::Absent {
                cf: ColumnFamily::UtxoMeta,
                key: DURABLE_HEAD_KEY,
            },
        };
        batch.put(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY, &next.encode());
        if !self.store.write_durable_if(&[condition], batch)? {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        Ok(())
    }

    fn reset(&self, expected: &DurableHead) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        batch.delete(ColumnFamily::UtxoMeta, DURABLE_HEAD_KEY);
        let condition = WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: DURABLE_HEAD_KEY,
            expected: &expected.encode(),
        };
        if !self.store.write_durable_if(&[condition], batch)? {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        Ok(())
    }
}

/// Process-local durable-head storage.
///
/// A real implementation for tests: what is committed can be loaded back and
/// the fence is honored, but nothing survives a restart because there is no
/// restart to survive. Production wiring uses [`KvDurableHeadStore`].
#[derive(Debug, Default)]
pub struct InMemoryDurableHeadStore {
    head: parking_lot::RwLock<Option<DurableHead>>,
}

impl InMemoryDurableHeadStore {
    /// Creates an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: parking_lot::RwLock::new(None),
        }
    }
}

impl DurableHeadStore for InMemoryDurableHeadStore {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        Ok(*self.head.read())
    }

    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        _records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        let mut head = self.head.write();
        if head.as_ref() != expected {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        *head = Some(*next);
        Ok(())
    }

    fn reset(&self, expected: &DurableHead) -> Result<(), StorageError> {
        let mut head = self.head.write();
        if head.as_ref() != Some(expected) {
            return Err(StorageError::InvalidOperation(
                "durable head moved since it was read",
            ));
        }
        *head = None;
        Ok(())
    }
}

/// CRC32C (Castagnoli), matching the chainstate journal's framing checksum.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82_F6_3B_78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(commit_id: u64) -> DurableHead {
        DurableHead {
            commit_id,
            height: 41,
            tip: Hash256::from_le_bytes(&[0x5A_u8; 32]),
            chain_tx_count: 123_456,
            body_extent: Some(BodyExtent {
                file_no: 1,
                offset: 9_876,
            }),
            undo_extent: Some((41, Hash256::from_le_bytes(&[0x5A_u8; 32]))),
        }
    }

    #[test]
    fn frame_round_trips_extents() {
        let head = sample(7);
        assert_eq!(DurableHead::decode(&head.encode()), Some(head));

        let bare = DurableHead {
            body_extent: None,
            undo_extent: None,
            ..sample(1)
        };
        assert_eq!(DurableHead::decode(&bare.encode()), Some(bare));
    }

    #[test]
    fn frame_fails_closed_on_corruption() {
        let mut frame = sample(7).encode();
        // Wrong version byte.
        frame[DURABLE_HEAD_MAGIC.len()] = DURABLE_HEAD_FORMAT_VERSION + 1;
        assert_eq!(DurableHead::decode(&frame), None);

        let mut frame = sample(7).encode();
        // Bit flip inside the payload.
        let last = frame.len() - 1;
        frame[last] ^= 0x80;
        assert_eq!(DurableHead::decode(&frame), None);

        let mut frame = sample(7).encode();
        // Bad magic.
        frame[0] = b'X';
        assert_eq!(DurableHead::decode(&frame), None);

        // Truncated frame.
        let frame = sample(7).encode();
        assert_eq!(DurableHead::decode(&frame[..frame.len() - 1]), None);
    }

    #[test]
    fn memory_store_honors_the_fence() -> Result<(), StorageError> {
        let store = InMemoryDurableHeadStore::new();
        let first = sample(1);
        store.commit(None, &first, &CommitRecords::default())?;
        let second = DurableHead {
            commit_id: 2,
            ..sample(2)
        };
        // A stale expectation applies nothing and reports the fence.
        let stale = DurableHead {
            commit_id: 9,
            ..first
        };
        assert!(
            store
                .commit(Some(&stale), &second, &CommitRecords::default())
                .is_err()
        );
        assert_eq!(store.load()?, Some(first));
        store.commit(Some(&first), &second, &CommitRecords::default())?;
        assert_eq!(store.load()?, Some(second));
        Ok(())
    }
}
