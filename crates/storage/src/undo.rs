//! Durable per-block UTXO undo records and the in-flight disconnect marker.

use hashbrown::HashMap;
use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;

use crate::pruning::block_undo_key;
use crate::{ColumnFamily, KvStore, StorageError, WriteBatch as _};

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
pub trait UndoStore: Send + Sync {
    /// Writes the undo record for one block.
    fn persist_undo(&self, height: u32, hash: Hash256, record: &[u8]) -> Result<(), StorageError>;

    /// Reads the undo record for one block, if present.
    fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError>;

    /// Records that a disconnect is about to mutate state, durably.
    ///
    /// Armed BEFORE the first mutation, not after a failure. A marker written
    /// on the error path cannot exist for the case that needs it most: the
    /// process dying mid-rollback writes nothing at all. Armed first, both a
    /// crash and a returned `Fatal` leave the same evidence behind.
    fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError>;

    /// Records that the rollback finished, in memory, and is owed a checkpoint.
    ///
    /// Distinct from clearing. Both phases refuse a startup, because both mean
    /// the durable state is torn. What the phase decides is whether a
    /// checkpoint may clear the marker: only a rollback that ran to completion
    /// may, and a checkpoint taken over a half-finished or failed one would be
    /// a checkpoint of the damage.
    fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError>;

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
    pub hash: Hash256,
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
pub(crate) const DISCONNECT_MARKER_KEY: &[u8] = b"node:disconnect-in-flight";

impl DisconnectMarker {
    pub(crate) fn encode(&self) -> [u8; 37] {
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
            hash: Hash256::from_le_bytes(&hash),
            height: u32::from_be_bytes(height),
            phase,
        })
    }
}

/// Serializes a disconnect marker for a caller outside this module.
///
/// The durable-head commit writes the marker row in the same atomic batch as
/// the head advance, so the marker codec is shared crate-internally while
/// decoding stays behind [`UndoStore::load_disconnect_marker`].
pub(crate) fn encode_disconnect_marker(marker: &DisconnectMarker) -> [u8; 37] {
    marker.encode()
}

/// Process-local undo storage.
///
/// A real implementation: what is written can be read back. Suitable wherever
/// durability across a restart is not required, such as tests.
#[derive(Debug, Default)]
pub struct InMemoryUndoStore {
    records: parking_lot::RwLock<HashMap<(u32, Hash256), Vec<u8>>>,
    marker: parking_lot::RwLock<Option<DisconnectMarker>>,
}

impl UndoStore for InMemoryUndoStore {
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

    fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
        Ok(self.marker.read().clone())
    }
}

/// Undo storage backed by a [`KvStore`] column family.
pub struct KvUndoStore<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> KvUndoStore<S> {
    /// Creates an undo store over `store`.
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
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
    ///
    /// The rest of block apply does not fsync because a crash there is
    /// recoverable by re-applying blocks. This one is different: it is the only
    /// record that a rollback started, and it is worthless if the crash that it
    /// exists to survive can lose it. One fsync per disconnect, and disconnects
    /// are rare.
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
    ///
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
        let after = Arc::new(crate::FjallStore::open(dir.path())?);
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
}
