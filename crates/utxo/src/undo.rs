//! Block undo persistence and the marker-fenced UTXO rollback.
//!
//! Node orders a disconnect against its other stores; this module owns the
//! undo row and the rollback that consumes it.

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{StorageError, UndoStore};

use crate::set::{UndoBatch, UtxoError, UtxoSet};
use crate::stats::{CoinStatsListener, CoinStatsRewindError};
use crate::undo_codec::{self, UndoCodecError};

/// Encodes and persists a block's undo record, returning the bytes so the
/// caller can put the same row into its durable head batch.
///
/// # Errors
///
/// The store's write failure.
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
#[allow(missing_docs)]
pub enum UndoLoadError {
    #[error("undo record read: {0}")]
    Read(#[source] StorageError),
    #[error("no undo record for block {hash} at height {height}")]
    Missing { hash: Hash256, height: u32 },
    #[error("undo record for block {hash} is unreadable: {source}")]
    Unreadable {
        hash: Hash256,
        #[source]
        source: UndoCodecError,
    },
}

/// Loads and decodes the record [`persist_block_undo`] wrote for a block.
///
/// # Errors
///
/// Read failure, absent record, or a record that does not decode as this
/// block's.
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
#[allow(missing_docs)]
pub struct BlockRollback {
    pub hash: Hash256,
    pub height: u32,
    pub parent_height: u32,
    /// Transactions the block added to the coinstats count.
    pub tx_count_delta: u64,
}

/// Only `Refused` leaves state untouched; the rest fire after the marker is
/// armed and may leave state torn for recovery to reconcile.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum RollbackError {
    #[error("rollback refused: {0}")]
    Refused(#[source] StorageError),
    #[error("utxo undo: {0}")]
    Utxo(#[source] UtxoError),
    #[error("coinstats rewind: {0}")]
    CoinStats(#[source] CoinStatsRewindError),
    #[error("disconnect marker: {0}")]
    Marker(#[source] StorageError),
}

/// Rolls one block out of the UTXO set under a durable disconnect marker.
///
/// The marker is read before arming because arming overwrites an earlier
/// disconnect's `RolledBack` debt, which a refusal would otherwise clear. On
/// success it stays `RolledBack` until the caller durably publishes the
/// rolled-back state. A marker that survives to the next startup no longer
/// refuses it: startup recovers automatically from the durable certified
/// head before anything serves (`docs/contracts/recovery.md`). Per-coin
/// coinstats follow [`UtxoSet::undo_block`] through the listener; only
/// height and transaction count are rewound here.
///
/// # Errors
///
/// [`RollbackError::Refused`] before the marker is armed; every other variant
/// after.
pub fn rollback_block(
    store: &dyn UndoStore,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    rollback: &BlockRollback,
    undo: &UndoBatch,
) -> Result<(), RollbackError> {
    let BlockRollback {
        hash,
        height,
        parent_height,
        tx_count_delta,
    } = *rollback;
    store
        .load_disconnect_marker()
        .map_err(RollbackError::Refused)?;
    store
        .arm_disconnect(height, hash)
        .map_err(RollbackError::Refused)?;
    utxo.undo_block(undo).map_err(RollbackError::Utxo)?;
    coin_stats
        .rewind_block(height, parent_height, tx_count_delta)
        .map_err(RollbackError::CoinStats)?;
    store
        .complete_disconnect(height, hash)
        .map_err(RollbackError::Marker)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, Script, TxOut, Txid};
    use bitcoin_rs_storage::{
        DisconnectMarker, DisconnectPhase, InMemoryUndoStore, StorageError, UndoStore,
    };

    use super::*;
    use crate::stats::CoinStats;
    use crate::{BlockChanges, UtxoAdd, aggregate_hash};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const HEIGHT: u32 = 91;
    const HASH: Hash256 = Hash256::from_le_bytes(&[0x5a; 32]);
    const FUNDED: OutPoint = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x31; 32])),
        vout: 0,
    };
    const CREATED: OutPoint = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x42; 32])),
        vout: 0,
    };
    const ROLLBACK: BlockRollback = BlockRollback {
        hash: HASH,
        height: HEIGHT,
        parent_height: 1,
        tx_count_delta: 2,
    };

    fn coin(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }
    }

    /// `FUNDED` at height 1, then the block at `HEIGHT` spending it and
    /// creating `CREATED`; returns the set, its listener, the observable state
    /// before that block, and the block's undo.
    fn connected() -> Result<(UtxoSet, CoinStatsListener, State, UndoBatch), UtxoError> {
        let mut utxo = UtxoSet::new();
        let coin_stats = CoinStatsListener::new(CoinStats::new());
        utxo.set_listener(Box::new(coin_stats.clone()));
        let mut seed = BlockChanges::default();
        seed.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
        utxo.commit_block(&seed, &Hash256::from_le_bytes(&[0x01; 32]))?;
        coin_stats.finish_block(1, 1);
        let before = observe(&utxo, &coin_stats)?;

        let mut changes = BlockChanges::default();
        changes.remove(FUNDED);
        changes.add(UtxoAdd::new(CREATED, coin(850), false, HEIGHT));
        utxo.commit_block(&changes, &HASH)?;
        coin_stats.finish_block(HEIGHT, 2);
        let mut undo = UndoBatch::default();
        undo.restore(UtxoAdd::new(FUNDED, coin(900), false, 1));
        undo.remove(CREATED);
        Ok((utxo, coin_stats, before, undo))
    }

    /// UTXO digest, coinstats digest (`MuHash` limbs are representation, not
    /// state) and the coinstats scalars.
    type State = (Hash256, Hash256, [u64; 5]);

    fn observe(utxo: &UtxoSet, coin_stats: &CoinStatsListener) -> Result<State, UtxoError> {
        let s = coin_stats.snapshot();
        Ok((
            aggregate_hash(utxo)?,
            s.muhash.finalize_hash(),
            [
                s.height.into(),
                s.total_amount,
                s.bogo_size,
                s.tx_count,
                s.utxo_count,
            ],
        ))
    }

    #[cfg(feature = "fjall")]
    #[test]
    fn persisted_record_survives_reopening_the_store() -> TestResult {
        use std::sync::Arc;

        use bitcoin_rs_storage::{FjallStore, KvUndoStore};

        let dir = tempfile::tempdir()?;
        let (.., undo) = connected()?;
        persist_block_undo(
            &KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?)),
            HEIGHT,
            HASH,
            &undo,
        )?;
        let reopened = KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?));
        assert_eq!(load_block_undo(&reopened, HEIGHT, HASH)?, undo);
        Ok(())
    }

    #[test]
    fn missing_and_foreign_records_are_refused() -> TestResult {
        let store = InMemoryUndoStore::default();
        let outcome = load_block_undo(&store, HEIGHT, HASH);
        assert!(
            matches!(outcome, Err(UndoLoadError::Missing { hash, height }) if hash == HASH && height == HEIGHT),
            "{outcome:?}"
        );

        let other = Hash256::from_le_bytes(&[0xab; 32]);
        let record = persist_block_undo(&store, HEIGHT, other, &UndoBatch::default())?;
        store.persist_undo(HEIGHT, HASH, &record)?;
        let outcome = load_block_undo(&store, HEIGHT, HASH);
        assert!(
            matches!(outcome, Err(UndoLoadError::Unreadable { hash, .. }) if hash == HASH),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn rollback_restores_the_exact_prior_state() -> TestResult {
        let (utxo, coin_stats, before, undo) = connected()?;
        let store = InMemoryUndoStore::default();

        rollback_block(&store, &utxo, &coin_stats, &ROLLBACK, &undo)?;

        assert!(utxo.get_entry(&CREATED).is_none());
        assert_eq!(
            utxo.get_entry(&FUNDED).map(|e| (e.txout, e.height)),
            Some((coin(900), 1))
        );
        assert_eq!(observe(&utxo, &coin_stats)?, before);
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(
            (marker.phase, marker.height, marker.hash),
            (DisconnectPhase::RolledBack, HEIGHT, HASH)
        );
        Ok(())
    }

    /// Marker writes fail in the chosen phase.
    #[derive(Default)]
    struct MarkerFails {
        inner: InMemoryUndoStore,
        at: Option<DisconnectPhase>,
    }

    impl UndoStore for MarkerFails {
        fn persist_undo(&self, h: u32, hash: Hash256, r: &[u8]) -> Result<(), StorageError> {
            self.inner.persist_undo(h, hash, r)
        }
        fn load_undo(&self, h: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_undo(h, hash)
        }
        fn arm_disconnect(&self, h: u32, hash: Hash256) -> Result<(), StorageError> {
            if self.at == Some(DisconnectPhase::InFlight) {
                return Err(StorageError::Backend("injected".into()));
            }
            self.inner.arm_disconnect(h, hash)
        }
        fn complete_disconnect(&self, h: u32, hash: Hash256) -> Result<(), StorageError> {
            if self.at == Some(DisconnectPhase::RolledBack) {
                return Err(StorageError::Backend("injected".into()));
            }
            self.inner.complete_disconnect(h, hash)
        }
        fn disarm_disconnect(&self) -> Result<(), StorageError> {
            self.inner.disarm_disconnect()
        }
        fn retire_disconnect_marker(&self) -> Result<(), StorageError> {
            self.inner.retire_disconnect_marker()
        }
        fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
            self.inner.load_disconnect_marker()
        }
    }

    #[test]
    fn arm_failure_refuses_before_any_mutation() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let connected_state = observe(&utxo, &coin_stats)?;
        let store = MarkerFails {
            at: Some(DisconnectPhase::InFlight),
            ..MarkerFails::default()
        };
        let outcome = rollback_block(&store, &utxo, &coin_stats, &ROLLBACK, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::Refused(_))),
            "{outcome:?}"
        );
        assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
        assert_eq!(store.load_disconnect_marker()?, None);
        Ok(())
    }

    #[test]
    fn completion_failure_is_fatal_and_leaves_the_marker_in_flight() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let store = MarkerFails {
            at: Some(DisconnectPhase::RolledBack),
            ..MarkerFails::default()
        };
        let outcome = rollback_block(&store, &utxo, &coin_stats, &ROLLBACK, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::Marker(_))),
            "{outcome:?}"
        );
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(marker.phase, DisconnectPhase::InFlight);
        Ok(())
    }

    #[test]
    fn coinstats_refusal_after_the_undo_is_fatal() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let wrong_height = BlockRollback {
            height: HEIGHT + 1,
            ..ROLLBACK
        };
        let store = InMemoryUndoStore::default();
        let outcome = rollback_block(&store, &utxo, &coin_stats, &wrong_height, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::CoinStats(_))),
            "{outcome:?}"
        );
        assert!(utxo.get_entry(&FUNDED).is_some(), "undo had already run");
        Ok(())
    }
}
