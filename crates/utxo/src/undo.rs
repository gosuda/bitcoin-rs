//! Block-level undo persistence and the durable rollback-marker transaction.
//!
//! The node crate decides *when* a block connects or disconnects and orders
//! that against its other stores; this module owns the UTXO side of it: the
//! undo record a connect writes, the read that a disconnect pairs with it, and
//! the marker-fenced rollback that turns an [`UndoBatch`] back into UTXO and
//! coinstats state.

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{StorageError, UndoStore};

use crate::set::{UndoBatch, UtxoError, UtxoSet};
use crate::stats::{CoinStatsListener, CoinStatsRewindError};
use crate::undo_codec::{self, UndoCodecError};

/// Encodes and persists the undo record for a block that is about to connect.
///
/// Returns the encoded record so the caller can name it again in the durable
/// head batch: the row written here is the deferred one, and the head receipt
/// is what makes it authoritative.
///
/// # Errors
///
/// Propagates the store's write failure. Without a recoverable undo record the
/// block could never be disconnected, so the caller must not apply it.
pub fn persist_block_undo(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
    undo: &UndoBatch,
) -> Result<Vec<u8>, StorageError> {
    let record = undo_codec::encode(undo, hash);
    store.persist_undo(height, hash, &record)?;
    Ok(record)
}

/// Why a stored undo record could not be turned back into an [`UndoBatch`].
#[derive(Debug, thiserror::Error)]
pub enum UndoLoadError {
    /// Reading the stored record failed.
    #[error("undo record read: {0}")]
    Read(#[source] StorageError),
    /// No record is stored for the block.
    ///
    /// Fatal for the disconnect: without it the UTXO set cannot be restored,
    /// and guessing would silently corrupt the chainstate.
    #[error("no undo record for block {hash} at height {height}")]
    Missing {
        /// Block whose record is absent.
        hash: Hash256,
        /// Height the block was applied at.
        height: u32,
    },
    /// The stored record could not be decoded for this block.
    #[error("undo record for block {hash} is unreadable: {source}")]
    Unreadable {
        /// Block whose record is unreadable.
        hash: Hash256,
        /// Why the codec rejected it.
        #[source]
        source: UndoCodecError,
    },
}

/// Loads and decodes the undo record [`persist_block_undo`] wrote for a block.
///
/// # Errors
///
/// Returns [`UndoLoadError`] when the read fails, the record is absent, or the
/// bytes do not decode as this block's record.
pub fn load_block_undo(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
) -> Result<UndoBatch, UndoLoadError> {
    let encoded = store
        .load_undo(height, hash)
        .map_err(UndoLoadError::Read)?
        .ok_or(UndoLoadError::Missing { hash, height })?;
    undo_codec::decode(&encoded, hash).map_err(|source| UndoLoadError::Unreadable { hash, source })
}

/// The block a rollback takes back out of the UTXO set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRollback {
    /// Hash of the block being disconnected.
    pub hash: Hash256,
    /// Height it was connected at; keys the marker.
    pub height: u32,
    /// Height the coinstats land on once the block is gone.
    pub parent_height: u32,
    /// Transactions the block contributed to the coinstats count.
    pub tx_count_delta: u64,
}

/// Which step of a rollback failed after the marker was armed.
#[derive(Debug, thiserror::Error)]
pub enum RollbackFailure {
    /// Applying the undo batch to the UTXO set failed part-way.
    #[error("utxo undo: {0}")]
    Utxo(#[source] UtxoError),
    /// Rewinding the block-level coinstats failed.
    #[error("coinstats rewind: {0}")]
    CoinStats(#[source] CoinStatsRewindError),
    /// Moving the marker to `RolledBack` failed.
    #[error("disconnect marker: {0}")]
    Marker(#[source] StorageError),
}

/// The outcome of a refused or failed block rollback.
#[derive(Debug, thiserror::Error)]
pub enum RollbackError {
    /// Refused before anything was touched: the marker could not be read or
    /// armed. The UTXO set and coinstats are exactly as they were.
    #[error("rollback refused: {0}")]
    Refused(#[source] StorageError),
    /// Failed after the marker was armed. Some state may be rolled back and
    /// some not; only recovery can reconcile it.
    #[error("rollback failed after arming the disconnect marker: {0}")]
    Fatal(#[source] RollbackFailure),
}

/// Rolls one block out of the UTXO set under a durable disconnect marker.
///
/// The marker is armed before the first mutation and moved to `RolledBack`
/// after the last, so the window it covers is exactly the window in which
/// state can be torn. Errors are not what this guards against; a crash is. A
/// crash writes no error anywhere, and the marker is the only thing that
/// survives it.
///
/// The marker is read before it is armed. A branch switch disconnects several
/// blocks in a row, and arming overwrites the marker, so an earlier
/// disconnect's `RolledBack` debt — still owed a checkpoint — would be
/// destroyed by the next arm and then cleared by a refusal. Loading first lets
/// a read failure refuse before any mutation.
///
/// The marker stays `RolledBack` on success: the rollback is authoritative in
/// memory but not durable, and the caller disarms it only once the state it
/// covers has been published durably.
///
/// The per-coin coinstats fields need no inverse feed of their own:
/// [`CoinStatsListener`] is the [`UtxoSet`] change listener, so
/// [`UtxoSet::undo_block`] already drives them in reverse. Only the block-level
/// height and transaction count are rewound here.
///
/// # Errors
///
/// [`RollbackError::Refused`] when the marker cannot be read or armed;
/// [`RollbackError::Fatal`] for every failure after that.
pub fn rollback_block(
    store: &dyn UndoStore,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    rollback: &BlockRollback,
    undo: &UndoBatch,
) -> Result<(), RollbackError> {
    store
        .load_disconnect_marker()
        .map_err(RollbackError::Refused)?;
    store
        .arm_disconnect(rollback.height, rollback.hash)
        .map_err(RollbackError::Refused)?;
    // Past this line every failure is `Fatal`. The UTXO undo walks shards and
    // can stop part-way, so from here some state is rolled back and some is
    // not.
    utxo.undo_block(undo)
        .map_err(|error| RollbackError::Fatal(RollbackFailure::Utxo(error)))?;
    coin_stats
        .rewind_block(
            rollback.height,
            rollback.parent_height,
            rollback.tx_count_delta,
        )
        .map_err(|error| RollbackError::Fatal(RollbackFailure::CoinStats(error)))?;
    store
        .complete_disconnect(rollback.height, rollback.hash)
        .map_err(|error| RollbackError::Fatal(RollbackFailure::Marker(error)))
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, Script, TxOut, Txid};
    use bitcoin_rs_storage::{DisconnectPhase, InMemoryUndoStore, StorageError, UndoStore};

    use super::{
        BlockRollback, RollbackError, RollbackFailure, UndoLoadError, load_block_undo,
        persist_block_undo, rollback_block,
    };
    use crate::stats::{CoinStats, CoinStatsListener};
    use crate::{BlockChanges, UndoBatch, UtxoAdd, UtxoSet, aggregate_hash};

    const HEIGHT: u32 = 91;

    fn txid(byte: u8) -> Txid {
        Txid(Hash256::from_le_bytes(&[byte; 32]))
    }

    fn block_hash() -> Hash256 {
        Hash256::from_le_bytes(&[0x5a; 32])
    }

    fn coin(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }
    }

    /// A UTXO set with `coin_stats` registered as its change listener, holding
    /// one spendable coin created at height 1.
    fn funded_set(
        funded: OutPoint,
    ) -> Result<(UtxoSet, CoinStatsListener), Box<dyn std::error::Error>> {
        let mut utxo = UtxoSet::new();
        let coin_stats = CoinStatsListener::new(CoinStats::new());
        utxo.set_listener(Box::new(coin_stats.clone()));
        let mut seed = BlockChanges::default();
        seed.add(UtxoAdd::new(funded, coin(900), false, 1));
        utxo.commit_block(&seed, &Hash256::from_le_bytes(&[0x01; 32]))?;
        coin_stats.finish_block(1, 1);
        Ok((utxo, coin_stats))
    }

    /// Connect-side changes for a block spending `funded` and creating
    /// `created`, with the undo batch that reverses them.
    fn block_changes(funded: OutPoint, created: OutPoint) -> (BlockChanges, UndoBatch) {
        let mut changes = BlockChanges::default();
        changes.remove(funded);
        changes.add(UtxoAdd::new(created, coin(850), false, HEIGHT));
        let mut undo = UndoBatch::default();
        undo.restore(UtxoAdd::new(funded, coin(900), false, 1));
        undo.remove(created);
        (changes, undo)
    }

    /// The observable coinstats: the `MuHash` digest plus the scalar fields.
    /// The raw numerator/denominator pair is representation, not state.
    fn stats_view(coin_stats: &CoinStatsListener) -> (Hash256, u32, u64, u64, u64, u64) {
        let stats = coin_stats.snapshot();
        (
            stats.muhash.finalize_hash(),
            stats.height,
            stats.total_amount,
            stats.bogo_size,
            stats.tx_count,
            stats.utxo_count,
        )
    }

    fn rollback() -> BlockRollback {
        BlockRollback {
            hash: block_hash(),
            height: HEIGHT,
            parent_height: 1,
            tx_count_delta: 2,
        }
    }

    #[test]
    fn a_persisted_undo_record_loads_back_field_for_field() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = InMemoryUndoStore::default();
        let outpoint = OutPoint::new(txid(0x2c), 7);
        let removed = OutPoint::new(txid(0x3d), 1);
        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(outpoint, coin(123_456), true, HEIGHT));
        batch.remove(removed);

        let record = persist_block_undo(&store, HEIGHT, block_hash(), &batch)?;
        assert_eq!(
            store.load_undo(HEIGHT, block_hash())?.as_deref(),
            Some(record.as_slice()),
            "the returned record must be the bytes the store holds"
        );

        let loaded = load_block_undo(&store, HEIGHT, block_hash())?;
        let restored = loaded.restores().first().ok_or("restored entry missing")?;
        assert_eq!(restored.outpoint, outpoint, "outpoint must round-trip");
        assert_eq!(
            restored.txout,
            coin(123_456),
            "spent output must round-trip"
        );
        assert!(restored.coinbase, "coinbase flag must round-trip");
        assert_eq!(restored.height, HEIGHT, "creating height must round-trip");
        assert_eq!(
            loaded.removes(),
            batch.removes(),
            "outputs to remove must round-trip"
        );
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
        use std::sync::Arc;

        use bitcoin_rs_storage::{FjallStore, KvUndoStore};

        let dir = tempfile::tempdir()?;
        let outpoint = OutPoint::new(txid(0x2c), 7);
        let removed = OutPoint::new(txid(0x3d), 1);
        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(outpoint, coin(123_456), true, HEIGHT));
        batch.remove(removed);

        {
            let store = KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?));
            persist_block_undo(&store, HEIGHT, block_hash(), &batch)?;
        }

        let reopened = KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?));
        let loaded = load_block_undo(&reopened, HEIGHT, block_hash())?;
        let restored = loaded
            .restores()
            .first()
            .ok_or("restored entry missing after reopen")?;
        assert_eq!(restored.outpoint, outpoint, "outpoint must round-trip");
        assert_eq!(
            restored.txout,
            coin(123_456),
            "spent output must round-trip"
        );
        assert!(restored.coinbase, "coinbase flag must round-trip");
        assert_eq!(restored.height, HEIGHT, "creating height must round-trip");
        assert_eq!(
            loaded.removes(),
            batch.removes(),
            "outputs to remove must round-trip"
        );
        Ok(())
    }

    #[test]
    fn a_missing_record_is_reported_as_missing_not_empty() {
        let store = InMemoryUndoStore::default();
        let outcome = load_block_undo(&store, HEIGHT, block_hash());
        assert!(
            matches!(
                outcome,
                Err(UndoLoadError::Missing { hash, height }) if hash == block_hash() && height == HEIGHT
            ),
            "an absent record must refuse, got {outcome:?}"
        );
    }

    /// The record is bound to its block: the bytes stored for one hash must
    /// not decode as another block's undo.
    #[test]
    fn a_record_stored_under_another_block_is_unreadable() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = InMemoryUndoStore::default();
        let other = Hash256::from_le_bytes(&[0xab; 32]);
        let record = persist_block_undo(&store, HEIGHT, other, &UndoBatch::default())?;
        store.persist_undo(HEIGHT, block_hash(), &record)?;

        let outcome = load_block_undo(&store, HEIGHT, block_hash());
        assert!(
            matches!(outcome, Err(UndoLoadError::Unreadable { hash, .. }) if hash == block_hash()),
            "a foreign record must be unreadable, got {outcome:?}"
        );
        Ok(())
    }

    /// The round trip that makes a disconnect a disconnect: connect a block
    /// that both spends and creates, roll it back, and land on exactly the
    /// UTXO set and coinstats that preceded it, with the marker recording the
    /// completed rollback.
    #[test]
    fn rolling_back_a_block_restores_the_exact_prior_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let funded = OutPoint::new(txid(0x31), 0);
        let created = OutPoint::new(txid(0x42), 0);
        let (utxo, coin_stats) = funded_set(funded)?;
        let store = InMemoryUndoStore::default();
        let stats_before = stats_view(&coin_stats);
        let hash_before = aggregate_hash(&utxo)?;

        let (changes, undo) = block_changes(funded, created);
        utxo.commit_block(&changes, &block_hash())?;
        coin_stats.finish_block(HEIGHT, 2);
        assert!(utxo.get_entry(&funded).is_none());
        assert!(utxo.get_entry(&created).is_some());

        rollback_block(&store, &utxo, &coin_stats, &rollback(), &undo)?;

        assert!(
            utxo.get_entry(&created).is_none(),
            "created output must be gone"
        );
        assert_eq!(
            utxo.get_entry(&funded)
                .map(|entry| (entry.txout, entry.height)),
            Some((coin(900), 1)),
            "spent output must be restored with its creation metadata"
        );
        assert_eq!(aggregate_hash(&utxo)?, hash_before, "UTXO set must match");
        assert_eq!(
            stats_view(&coin_stats),
            stats_before,
            "coinstats must match"
        );
        let marker = store
            .load_disconnect_marker()?
            .ok_or("a completed rollback must leave a marker for the checkpoint")?;
        assert_eq!(marker.phase, DisconnectPhase::RolledBack);
        assert_eq!((marker.height, marker.hash), (HEIGHT, block_hash()));
        Ok(())
    }

    /// A store whose marker writes fail in a chosen phase.
    #[derive(Default)]
    struct MarkerFailsStore {
        inner: InMemoryUndoStore,
        fail_arm: bool,
        fail_complete: bool,
    }

    impl UndoStore for MarkerFailsStore {
        fn persist_undo(
            &self,
            height: u32,
            hash: Hash256,
            record: &[u8],
        ) -> Result<(), StorageError> {
            self.inner.persist_undo(height, hash, record)
        }

        fn load_undo(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_undo(height, hash)
        }

        fn arm_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
            if self.fail_arm {
                return Err(StorageError::Backend(
                    "injected marker write failure".into(),
                ));
            }
            self.inner.arm_disconnect(height, hash)
        }

        fn complete_disconnect(&self, height: u32, hash: Hash256) -> Result<(), StorageError> {
            if self.fail_complete {
                return Err(StorageError::Backend(
                    "injected marker completion failure".into(),
                ));
            }
            self.inner.complete_disconnect(height, hash)
        }

        fn disarm_disconnect(&self) -> Result<(), StorageError> {
            self.inner.disarm_disconnect()
        }

        fn load_disconnect_marker(
            &self,
        ) -> Result<Option<bitcoin_rs_storage::DisconnectMarker>, StorageError> {
            self.inner.load_disconnect_marker()
        }
    }

    #[test]
    fn a_marker_that_cannot_be_armed_refuses_before_any_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let funded = OutPoint::new(txid(0x31), 0);
        let created = OutPoint::new(txid(0x42), 0);
        let (utxo, coin_stats) = funded_set(funded)?;
        let (changes, undo) = block_changes(funded, created);
        utxo.commit_block(&changes, &block_hash())?;
        coin_stats.finish_block(HEIGHT, 2);
        let hash_before = aggregate_hash(&utxo)?;
        let stats_before = stats_view(&coin_stats);
        let store = MarkerFailsStore {
            fail_arm: true,
            ..MarkerFailsStore::default()
        };

        let outcome = rollback_block(&store, &utxo, &coin_stats, &rollback(), &undo);

        assert!(
            matches!(outcome, Err(RollbackError::Refused(_))),
            "an arm failure must refuse, got {outcome:?}"
        );
        assert_eq!(
            aggregate_hash(&utxo)?,
            hash_before,
            "UTXO set must be untouched"
        );
        assert_eq!(
            stats_view(&coin_stats),
            stats_before,
            "coinstats must be untouched"
        );
        assert_eq!(
            store.load_disconnect_marker()?,
            None,
            "no marker may be left"
        );
        Ok(())
    }

    /// The marker cannot move to `RolledBack`, so the rollback is complete in
    /// memory but has no durable receipt: fatal, with the marker left in
    /// flight for recovery.
    #[test]
    fn a_failed_marker_completion_is_fatal_and_leaves_the_marker_in_flight()
    -> Result<(), Box<dyn std::error::Error>> {
        let funded = OutPoint::new(txid(0x31), 0);
        let created = OutPoint::new(txid(0x42), 0);
        let (utxo, coin_stats) = funded_set(funded)?;
        let (changes, undo) = block_changes(funded, created);
        utxo.commit_block(&changes, &block_hash())?;
        coin_stats.finish_block(HEIGHT, 2);
        let store = MarkerFailsStore {
            fail_complete: true,
            ..MarkerFailsStore::default()
        };

        let outcome = rollback_block(&store, &utxo, &coin_stats, &rollback(), &undo);

        assert!(
            matches!(
                outcome,
                Err(RollbackError::Fatal(RollbackFailure::Marker(_)))
            ),
            "a completion failure must be fatal, got {outcome:?}"
        );
        let marker = store
            .load_disconnect_marker()?
            .ok_or("the armed marker must survive the failure")?;
        assert_eq!(marker.phase, DisconnectPhase::InFlight);
        Ok(())
    }

    /// A coinstats refusal comes after the UTXO undo, so it is fatal rather
    /// than refused: the set is already rolled back.
    #[test]
    fn a_coinstats_rewind_refusal_after_the_undo_is_fatal() -> Result<(), Box<dyn std::error::Error>>
    {
        let funded = OutPoint::new(txid(0x31), 0);
        let created = OutPoint::new(txid(0x42), 0);
        let (utxo, coin_stats) = funded_set(funded)?;
        let (changes, undo) = block_changes(funded, created);
        utxo.commit_block(&changes, &block_hash())?;
        coin_stats.finish_block(HEIGHT, 2);
        let store = InMemoryUndoStore::default();
        let wrong_height = BlockRollback {
            height: HEIGHT + 1,
            ..rollback()
        };

        let outcome = rollback_block(&store, &utxo, &coin_stats, &wrong_height, &undo);

        assert!(
            matches!(
                outcome,
                Err(RollbackError::Fatal(RollbackFailure::CoinStats(_)))
            ),
            "a rewind refusal must be fatal, got {outcome:?}"
        );
        assert!(
            utxo.get_entry(&funded).is_some(),
            "the UTXO undo had already run when the rewind refused"
        );
        Ok(())
    }
}
