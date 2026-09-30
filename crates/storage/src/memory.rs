//! Process-local key-value storage.

use std::collections::BTreeMap;

use parking_lot::RwLock;

use crate::batch::{BatchOp, BufferedWriteBatch};
use crate::trait_::{
    KvIter, KvPair, KvSnapshot, KvStore, PersistBoundary, PersistFault, PersistFaultSlot,
    WriteCondition,
};
use crate::{ColumnFamily, StorageError};

/// One ordered row map per column family.
type Families = [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()];

/// Process-local key-value store.
///
/// A real implementation for tests: every batch applies atomically in its
/// recorded order, a conditional write checks and applies under one lock, and
/// a snapshot is a coherent copy of every family. Nothing survives a restart
/// because there is no restart to survive, so applied state is durable state.
/// Production wiring uses an on-disk backend.
///
/// Faults armed through [`KvStore::arm_persist_fault`] fire at the boundaries
/// the fjall and `RocksDB` backends use: an apply fault fails any write before
/// its batch becomes visible, a sync fault fails only a durable write and only
/// after its batch applied, and a flush fault fails [`KvStore::flush`]. A
/// conditional write whose conditions do not match returns `Ok(false)` without
/// consuming an armed fault.
#[derive(Default)]
pub struct InMemoryKvStore {
    families: RwLock<Families>,
    faults: PersistFaultSlot,
}

impl InMemoryKvStore {
    /// Applies `batch` behind the apply boundary, and behind the sync boundary
    /// too when the write is `durable`.
    fn commit(
        &self,
        families: &mut Families,
        batch: BufferedWriteBatch,
        durable: bool,
    ) -> Result<(), StorageError> {
        if let Some(fault) = self.faults.take_at(PersistBoundary::Apply) {
            return Err(fault.injected_error());
        }
        let sync_fault = if durable {
            self.faults.take_at(PersistBoundary::Sync)
        } else {
            None
        };
        apply_ops(families, batch.into_ops());
        if let Some(fault) = sync_fault {
            return Err(fault.injected_error());
        }
        Ok(())
    }
}

impl KvStore for InMemoryKvStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.families.read()[cf.index()].get(key).cloned())
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = prefix_rows(&self.families.read()[cf.index()], prefix);
        Ok(Box::new(rows.into_iter().map(Ok)))
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.commit(&mut self.families.write(), batch, false)
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.commit(&mut self.families.write(), batch, true)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        // Every condition observes pre-batch state; the batch may put or
        // delete a condition key itself.
        let mut families = self.families.write();
        let matched = conditions.iter().all(|condition| {
            let (cf, key) = condition.location();
            condition.matches(families[cf.index()].get(key).map(Vec::as_slice))
        });
        if !matched {
            return Ok(false);
        }
        self.commit(&mut families, batch, true)?;
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        if let Some(fault) = self.faults.take_at(PersistBoundary::Flush) {
            return Err(fault.injected_error());
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Ok(Box::new(InMemorySnapshot {
            families: self.families.read().clone(),
        }))
    }

    fn arm_persist_fault(&self, fault: PersistFault) {
        self.faults.arm(fault);
    }
}

/// Coherent copy of every family taken under one read lock.
struct InMemorySnapshot {
    families: Families,
}

impl KvSnapshot for InMemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.families[cf.index()].get(key).cloned())
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = prefix_rows(&self.families[cf.index()], prefix);
        Ok(Box::new(rows.into_iter().map(Ok)))
    }
}

/// Clones the rows under `prefix` in key order, so the returned iterator owns
/// its data and no lock outlives the call.
fn prefix_rows(family: &BTreeMap<Vec<u8>, Vec<u8>>, prefix: &[u8]) -> Vec<KvPair> {
    family
        .range(prefix.to_vec()..)
        .take_while(|(key, _value)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// Folds one batch's recorded operations into the families, in order.
fn apply_ops(families: &mut Families, ops: Vec<BatchOp>) {
    for op in ops {
        match op {
            BatchOp::Put { cf, key, value } => {
                families[cf.index()].insert(key, value.into());
            }
            BatchOp::Delete { cf, key } => {
                families[cf.index()].remove(&key);
            }
            BatchOp::DeleteRange { cf, start, end } => {
                // Splitting instead of `range(start..end)`: an inverted range
                // deletes nothing rather than panicking.
                let family = &mut families[cf.index()];
                let mut doomed = family.split_off(&start);
                let mut kept = doomed.split_off(&end);
                family.append(&mut kept);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryKvStore;
    use crate::{
        ColumnFamily, KvPair, KvStore, PersistFault, PrefixScanLimit, StorageError, WriteCondition,
    };

    const FAMILIES: [ColumnFamily; 3] = [
        ColumnFamily::ALL[0],
        ColumnFamily::ALL[1],
        ColumnFamily::ALL[2],
    ];

    const FAULTS: [PersistFault; 7] = [
        PersistFault::FailApply,
        PersistFault::LostApply,
        PersistFault::PartialApply,
        PersistFault::FailSync,
        PersistFault::LostSync,
        PersistFault::FailFlush,
        PersistFault::LostFlush,
    ];

    /// Every row in every family, in family then key order.
    fn contents(store: &InMemoryKvStore) -> Result<Vec<(usize, KvPair)>, StorageError> {
        let mut rows = Vec::new();
        for cf in ColumnFamily::ALL {
            for row in store.iter_prefix(*cf, &[])? {
                rows.push((cf.index(), row?));
            }
        }
        Ok(rows)
    }

    /// One batch writing `tag` under the same key in three families.
    fn tagged_batch(store: &InMemoryKvStore, tag: &[u8]) -> crate::BufferedWriteBatch {
        let mut batch = store.new_batch();
        for cf in FAMILIES {
            batch.put(cf, b"k", tag);
        }
        batch
    }

    #[test]
    fn batches_apply_in_recorded_order() -> Result<(), StorageError> {
        let store = InMemoryKvStore::default();
        let cf = FAMILIES[0];
        let mut batch = store.new_batch();
        for key in [&b"a1"[..], b"a2", b"a3", b"b1"] {
            batch.put(cf, key, b"v");
        }
        batch.put(cf, b"a1", b"overwritten");
        batch.delete(cf, b"b1");
        batch.delete_range(cf, b"a2", b"a3");
        // Inverted: deletes nothing instead of panicking.
        batch.delete_range(cf, b"z", b"a");
        store.write(batch)?;

        assert_eq!(store.get(cf, b"a1")?, Some(b"overwritten".to_vec()));
        assert_eq!(store.get(cf, b"a2")?, None);
        assert_eq!(store.get(cf, b"b1")?, None);
        let under_a: Vec<KvPair> = store.iter_prefix(cf, b"a")?.collect::<Result<_, _>>()?;
        assert_eq!(
            under_a,
            vec![
                (b"a1".to_vec(), b"overwritten".to_vec()),
                (b"a3".to_vec(), b"v".to_vec()),
            ]
        );
        assert!(store.iter_prefix(FAMILIES[1], &[])?.next().is_none());
        Ok(())
    }

    /// The bounded scan is the trait's own: the first row is always returned,
    /// later rows only while the byte total stays within `max_bytes`.
    #[test]
    fn bounded_scans_follow_the_trait_contract() -> Result<(), StorageError> {
        let store = InMemoryKvStore::default();
        let cf = FAMILIES[0];
        let mut batch = store.new_batch();
        for key in [&b"p1"[..], b"p2", b"p3"] {
            batch.put(cf, key, b"vv");
        }
        store.write(batch)?;

        let first_only = store.scan_prefix_bounded(
            cf,
            b"p",
            PrefixScanLimit {
                max_rows: 10,
                max_bytes: 0,
            },
        )?;
        assert_eq!(first_only.rows.len(), 1, "the first row ignores max_bytes");
        assert!(!first_only.complete);

        let two = store.scan_prefix_bounded(
            cf,
            b"p",
            PrefixScanLimit {
                max_rows: 10,
                max_bytes: 8,
            },
        )?;
        assert_eq!(two.rows.len(), 2, "8 bytes admit exactly two 4-byte rows");
        assert!(!two.complete);

        let all = store.scan_prefix_bounded(
            cf,
            b"p",
            PrefixScanLimit {
                max_rows: 3,
                max_bytes: usize::MAX,
            },
        )?;
        assert_eq!(all.rows.len(), 3);
        assert!(all.complete);
        Ok(())
    }

    #[test]
    fn mismatched_condition_applies_nothing_and_keeps_an_armed_fault() -> Result<(), StorageError> {
        let store = InMemoryKvStore::default();
        store.write_durable(tagged_batch(&store, b"old"))?;
        store.arm_persist_fault(PersistFault::FailApply);

        let absent = [WriteCondition::Absent {
            cf: FAMILIES[0],
            key: b"k",
        }];
        assert!(!store.write_durable_if(&absent, tagged_batch(&store, b"new"))?);
        assert_eq!(store.get(FAMILIES[0], b"k")?, Some(b"old".to_vec()));

        let equals = [WriteCondition::Equals {
            cf: FAMILIES[0],
            key: b"k",
            expected: b"old",
        }];
        assert!(
            store
                .write_durable_if(&equals, tagged_batch(&store, b"new"))
                .is_err(),
            "the fault stayed armed for the first matching write"
        );
        assert!(store.write_durable_if(&equals, tagged_batch(&store, b"new"))?);
        assert_eq!(store.get(FAMILIES[2], b"k")?, Some(b"new".to_vec()));
        Ok(())
    }

    #[test]
    fn snapshots_do_not_observe_later_writes() -> Result<(), StorageError> {
        let store = InMemoryKvStore::default();
        store.write(tagged_batch(&store, b"old"))?;
        let snapshot = store.snapshot()?;
        store.write(tagged_batch(&store, b"new"))?;
        assert_eq!(snapshot.get(FAMILIES[0], b"k")?, Some(b"old".to_vec()));
        assert_eq!(store.get(FAMILIES[0], b"k")?, Some(b"new".to_vec()));
        Ok(())
    }

    /// The fault matrix `tests/overhaul_atomic_durability.rs` runs against
    /// every on-disk backend, pinned to the exact fjall/`RocksDB` outcome:
    /// each route leaves the whole old or the whole new state, an apply fault
    /// always leaves the old state, and a fault the route observes is `Err`.
    #[test]
    fn persistence_faults_fire_at_the_backend_boundaries() -> Result<(), StorageError> {
        #[derive(Clone, Copy, Debug)]
        enum Route {
            Write,
            WriteDurable,
            WriteDurableIf,
            FlushDeferred,
        }

        for route in [
            Route::Write,
            Route::WriteDurable,
            Route::WriteDurableIf,
            Route::FlushDeferred,
        ] {
            for fault in FAULTS {
                let store = InMemoryKvStore::default();
                store.write_durable(tagged_batch(&store, b"old"))?;
                let old = contents(&store)?;
                store.arm_persist_fault(fault);
                let batch = tagged_batch(&store, b"new");
                let outcome = match route {
                    Route::Write => store.write(batch),
                    Route::WriteDurable => store.write_durable(batch),
                    Route::WriteDurableIf => store
                        .write_durable_if(
                            &[WriteCondition::Absent {
                                cf: FAMILIES[0],
                                key: &[0xff],
                            }],
                            batch,
                        )
                        .map(|_| ()),
                    Route::FlushDeferred => {
                        store.write_deferred(batch).and_then(|()| store.flush())
                    }
                };

                let apply_fault = matches!(
                    fault,
                    PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply
                );
                let sync_fault = matches!(fault, PersistFault::FailSync | PersistFault::LostSync);
                let flush_fault =
                    matches!(fault, PersistFault::FailFlush | PersistFault::LostFlush);
                let observed = match route {
                    Route::Write => apply_fault,
                    Route::WriteDurable | Route::WriteDurableIf => apply_fault || sync_fault,
                    Route::FlushDeferred => apply_fault || flush_fault,
                };
                let label = format!("{route:?}/{fault:?}");
                assert_eq!(outcome.is_err(), observed, "{label}: outcome");

                let after = contents(&store)?;
                if apply_fault {
                    assert_eq!(after, old, "{label}: an apply fault left rows behind");
                } else {
                    assert!(
                        after
                            .iter()
                            .all(|(_cf, (_key, value))| value.as_slice() == b"new"),
                        "{label}: the whole batch must be visible"
                    );
                }
            }
        }
        Ok(())
    }
}
