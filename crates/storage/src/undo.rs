//! Durable per-block UTXO undo records and the in-flight disconnect marker.

use hashbrown::HashMap;
use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;

use crate::{ColumnFamily, KvStore, StorageError};

pub(crate) const BLOCK_UNDO_PREFIX: u8 = b'u';
pub(crate) const BLOCK_UNDO_PREFIX_BYTES: &[u8] = b"u";
const HEIGHT_START: usize = 1;
const HEIGHT_END: usize = 5;
const KEY_LEN: usize = 37;

/// Builds the canonical pruning key for stored undo data for one block.
#[must_use]
pub fn block_undo_key(height: u32, hash: Hash256) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    key[0] = BLOCK_UNDO_PREFIX;
    key[HEIGHT_START..HEIGHT_END].copy_from_slice(&height.to_be_bytes());
    key[HEIGHT_END..].copy_from_slice(hash.as_byte_array());
    key
}

/// Storage for per-block UTXO undo records.
/// Records survive an orderly restart. They are not crash-safe: see
/// [`KvUndoStore::persist_undo`] for why no fsync sits here.
///
/// Records are keyed by height AND block hash. Keying by height alone would let
/// a stale record from an abandoned branch be replayed against a different
/// block at the same height.
pub trait UndoStore: Send + Sync {
    fn persist_undo(&self, height: u32, hash: Hash256, record: &[u8]) -> Result<(), StorageError>;

    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError>;

    /// Reads undo only when its borrowed/pinned value fits the owned-copy bound.
    ///
    /// Engine-internal allocation is outside this bound; unsupported stores refuse
    /// rather than falling back to the unbounded consensus read.
    fn load_undo_bounded(
        &self,
        _height: u32,
        _hash: Hash256,
        _max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        Err(crate::BoundedReadError::Unsupported)
    }

    /// Records that a disconnect is about to mutate state, durably.
    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError>;

    /// Records that the rollback finished, in memory, and is owed a checkpoint.
    /// `RolledBack` marker — a checkpoint taken over a half-finished rollback
    /// would be a checkpoint of the damage.
    fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError>;

    /// Clears the marker once a disconnect has finished cleanly.
    /// The marker covers authoritative UTXO and tip state between checkpoints.
    fn disarm_disconnect(&self) -> Result<(), StorageError>;

    /// Clears the marker unconditionally after disconnect recovery.
    ///
    /// The recovery transaction has reconstructed a coherent chainstate to the durable
    /// head and published the clean checkpoint that makes it durable, so the marker's
    /// evidence is spent even when its phase is `InFlight`.
    fn retire_disconnect_marker(&self) -> Result<(), StorageError>;

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError>;
}

/// A disconnect that started and never reported finishing through a clean
/// checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectMarker {
    /// Block being disconnected.
    pub hash: Hash256,
    /// Height it was applied at.
    pub height: u32,
    /// How far the disconnect got.
    pub phase: DisconnectPhase,
}

/// How far a disconnect got before the marker was last written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectPhase {
    InFlight,
    /// The rollback completed in memory and is waiting for a checkpoint to make
    /// it durable. Only this phase may be cleared, and only by that checkpoint.
    RolledBack,
}

/// Key for the in-flight disconnect marker.
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
            hash: Hash256::from_le_bytes(&hash),
            height: u32::from_be_bytes(height),
            phase,
        })
    }
}

/// Process-local undo storage.
#[derive(Debug, Default)]
pub struct InMemoryUndoStore {
    records: parking_lot::RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
    marker: parking_lot::RwLock<Option<DisconnectMarker>>,
}

impl InMemoryUndoStore {
    /// Retires a transient record after its owner durably archives it. Used by
    /// forward-only historical validation, which cannot roll back this store.
    pub fn remove_archived(&self, height: u32, hash: Hash256) {
        self.records.write().remove(&(height, hash));
    }
}

impl UndoStore for InMemoryUndoStore {
    fn load_undo_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        self.records
            .read()
            .get(&(height, hash))
            .map(|value| crate::error::copy_bounded(value, max_bytes))
            .transpose()
    }

    fn persist_undo(&self, height: u32, hash: Hash256, record: &[u8]) -> Result<(), StorageError> {
        self.records.write().insert((height, hash), record.to_vec());
        Ok(())
    }

    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.records.read().get(&(height, hash)).cloned())
    }

    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        *self.marker.write() = Some(DisconnectMarker {
            hash,
            height,
            phase: DisconnectPhase::InFlight,
        });
        Ok(())
    }

    fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
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

    fn retire_disconnect_marker(&self) -> Result<(), StorageError> {
        *self.marker.write() = None;
        Ok(())
    }

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        Ok(self.marker.read().clone())
    }
}

/// Undo storage backed by a [`KvStore`] column family.
pub struct KvUndoStore<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> KvUndoStore<S> {
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: KvStore> UndoStore for KvUndoStore<S> {
    fn load_undo_bounded(
        &self,
        height: u32,
        hash: Hash256,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, crate::BoundedReadError> {
        self.store.get_bounded(
            ColumnFamily::UndoData,
            &block_undo_key(height, hash),
            max_bytes,
        )
    }

    /// Deferred, matching the rest of the apply path.
    ///
    /// Deferred is correct because the durable-head commit is the receipt that makes
    /// this row authoritative: the apply path flushes it together with the head row in
    /// one atomic batch (`RCV-02`), and the head's `undo_extent` names it only from
    /// that receipt on. Writing it earlier keeps it readable for planning; it is an
    /// orphan tail, safely discarded, until the head names it.
    fn persist_undo(&self, height: u32, hash: Hash256, record: &[u8]) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UndoData,
            &block_undo_key(height, hash),
            record,
        );
        self.store.write_deferred(batch)
    }

    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        self.store
            .get(ColumnFamily::UndoData, &block_undo_key(height, hash))
    }

    /// Flushed, unlike every other write on this path.
    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.store.put(
            ColumnFamily::UtxoMeta,
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

    fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
        self.store.put(
            ColumnFamily::UtxoMeta,
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
    /// The caller is a checkpoint, and a checkpoint taken while a rollback is
    /// half-done captures the damage. Only a completed rollback may be cleared.
    fn disarm_disconnect(&self) -> Result<(), StorageError> {
        if self
            .load_disconnect_marker()?
            .is_some_and(|marker| marker.phase == DisconnectPhase::InFlight)
        {
            return Err(StorageError::InvalidOperation(
                "cannot disarm an in-flight disconnect",
            ));
        }
        let mut batch = self.store.new_batch();
        batch.delete(ColumnFamily::UtxoMeta, DISCONNECT_MARKER_KEY);
        self.store.write(batch)?;
        self.store.flush()
    }

    fn retire_disconnect_marker(&self) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        batch.delete(ColumnFamily::UtxoMeta, DISCONNECT_MARKER_KEY);
        self.store.write(batch)?;
        self.store.flush()
    }

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        self.store
            .get(ColumnFamily::UtxoMeta, DISCONNECT_MARKER_KEY)?
            .map(|bytes| DisconnectMarker::decode(&bytes))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "redb")]
    #[test]
    fn a_deferred_undo_record_is_readable_before_any_flush()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(crate::RedbStore::open(dir.path())?);
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

    #[cfg(feature = "fjall")]
    #[test]
    fn an_armed_disconnect_marker_survives_closing_and_reopening_the_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let block_hash = Hash256::from_le_bytes(&[0xa7; 32]);

        {
            let store = Arc::new(crate::FjallStore::open(dir.path())?);
            KvUndoStore::new(store).arm_disconnect(140_003, block_hash)?;
        }

        let reopened = Arc::new(crate::FjallStore::open(dir.path())?);
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

        KvUndoStore::new(Arc::clone(&reopened)).complete_disconnect(140_003, block_hash)?;
        KvUndoStore::new(Arc::clone(&reopened)).disarm_disconnect()?;
        drop(reopened);
        let after = Arc::new(crate::FjallStore::open(dir.path())?);
        assert_eq!(
            KvUndoStore::new(after).load_disconnect_marker()?,
            None,
            "a completed rollback must clear and stay cleared across a reopen"
        );
        Ok(())
    }

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
}
