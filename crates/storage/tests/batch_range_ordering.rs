//! Ordered range-deletion laws shared by the portable storage backends.

#![cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]

use std::path::Path;

use bitcoin_rs_storage::{
    ColumnFamily, KvPair, KvStore, PersistFault, StorageError, WriteBatch, WriteCondition,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CF: ColumnFamily = ColumnFamily::UtxoMeta;
const OTHER_CF: ColumnFamily = ColumnFamily::BlockBodies;

#[derive(Clone, Copy, Debug)]
enum WriteMode {
    Regular,
    Deferred,
    Durable,
    Conditional,
}

fn seed_rows(store: &impl KvStore) -> Result<(), StorageError> {
    let mut batch = store.new_batch();
    for key in [b"bounds:a", b"bounds:m", b"bounds:z"] {
        batch.put(CF, key, b"committed");
        batch.put(OTHER_CF, key, b"other-family");
    }
    store.write_durable(batch)
}

fn ordered_batch<S: KvStore>(store: &S) -> S::WriteBatch {
    let mut batch = store.new_batch();
    batch.put(CF, b"put-range:m", b"removed");
    batch.delete_range(CF, b"put-range:a", b"put-range:z");

    batch.delete_range(CF, b"range-put:a", b"range-put:z");
    batch.put(CF, b"range-put:m", b"final");

    batch.put(CF, b"put-range-put:m", b"removed");
    batch.delete_range(CF, b"put-range-put:a", b"put-range-put:z");
    batch.put(CF, b"put-range-put:m", b"final");

    batch.put(CF, b"put-delete-range:m", b"removed");
    batch.delete(CF, b"put-delete-range:m");
    batch.delete_range(CF, b"put-delete-range:a", b"put-delete-range:z");

    // Both staged and committed keys obey the half-open bounds. A staged
    // overwrite of a committed key must not outlive the following range.
    batch.put(CF, b"bounds:0", b"before-start");
    batch.put(CF, b"bounds:a", b"overwrite-removed");
    batch.put(CF, b"bounds:b", b"staged-removed");
    batch.put(CF, b"bounds:z", b"at-end");
    batch.put(OTHER_CF, b"bounds:b", b"other-staged");
    batch.delete_range(CF, b"bounds:a", b"bounds:z");

    // A range only consumes earlier puts. Later overlapping ranges must see
    // the keys inserted between them, including a previously deleted key.
    for key in [b"overlap:b", b"overlap:l", b"overlap:s", b"overlap:x"] {
        batch.put(CF, key, b"first");
    }
    batch.delete_range(CF, b"overlap:a", b"overlap:n");
    batch.put(CF, b"overlap:l", b"reinserted-removed");
    batch.delete_range(CF, b"overlap:k", b"overlap:w");
    batch.put(CF, b"overlap:n", b"final");

    batch.put(CF, b"empty:m", b"untouched");
    batch.delete_range(CF, b"empty:m", b"empty:m");
    batch
}

fn apply_ordered_batch<S: KvStore>(mode: WriteMode, store: &S) -> Result<(), StorageError> {
    let batch = ordered_batch(store);
    match mode {
        WriteMode::Regular => store.write(batch),
        WriteMode::Deferred => store.write_deferred(batch),
        WriteMode::Durable => store.write_durable(batch),
        WriteMode::Conditional => {
            assert!(store.write_durable_if(
                &[WriteCondition::Absent {
                    cf: CF,
                    key: b"put-range:m",
                }],
                batch,
            )?);
            Ok(())
        }
    }
}

fn assert_rows(store: &impl KvStore) -> Result<(), StorageError> {
    // Explicit expected rows follow the WriteBatch contract, independently
    // of any backend's range-expansion implementation.
    let expected = [
        (b"bounds:0".as_slice(), b"before-start".as_slice()),
        (b"bounds:z", b"at-end"),
        (b"empty:m", b"untouched"),
        (b"overlap:n", b"final"),
        (b"overlap:x", b"first"),
        (b"put-range-put:m", b"final"),
        (b"range-put:m", b"final"),
    ];
    let expected_other = [
        (b"bounds:a".as_slice(), b"other-family".as_slice()),
        (b"bounds:b", b"other-staged"),
        (b"bounds:m", b"other-family"),
        (b"bounds:z", b"other-family"),
    ];
    for (cf, rows) in [(CF, expected.as_slice()), (OTHER_CF, &expected_other)] {
        let actual = store.iter_prefix(cf, b"")?.collect::<Result<Vec<_>, _>>()?;
        let expected = rows
            .iter()
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect::<Vec<KvPair>>();
        assert_eq!(actual, expected, "family {cf:?}");
        for (key, value) in &expected {
            assert_eq!(store.get(cf, key)?, Some(value.clone()));
        }
    }
    Ok(())
}

fn range_ordering_laws<S: KvStore>(open: impl Fn(&Path) -> Result<S, StorageError>) -> TestResult {
    for mode in [
        WriteMode::Regular,
        WriteMode::Deferred,
        WriteMode::Durable,
        WriteMode::Conditional,
    ] {
        let temp = tempfile::TempDir::new()?;
        {
            let store = open(temp.path())?;
            seed_rows(&store)?;
            apply_ordered_batch(mode, &store)?;
            assert_rows(&store)?;

            // A mismatched precondition must not apply even a range spanning
            // committed rows or any other operation in that batch.
            let mut rejected = store.new_batch();
            rejected.put(CF, b"rejected", b"must-not-land");
            rejected.delete_range(CF, b"a", b"z");
            assert!(!store.write_durable_if(
                &[WriteCondition::Absent {
                    cf: CF,
                    key: b"range-put:m",
                }],
                rejected,
            )?);
            assert_rows(&store)?;
            if matches!(mode, WriteMode::Regular | WriteMode::Deferred) {
                store.flush()?;
            }
        }
        let reopened = open(temp.path())?;
        assert_rows(&reopened)?;
    }
    Ok(())
}

fn range_fault_laws<S: KvStore>(open: impl Fn(&Path) -> Result<S, StorageError>) -> TestResult {
    for fault in [
        PersistFault::FailApply,
        PersistFault::LostApply,
        PersistFault::PartialApply,
        PersistFault::FailSync,
        PersistFault::LostSync,
    ] {
        let temp = tempfile::TempDir::new()?;
        let store = open(temp.path())?;
        let mut batch = store.new_batch();
        batch.put(CF, b"m", b"removed");
        batch.delete_range(CF, b"a", b"z");
        batch.put(CF, b"z", b"committed");
        batch.put(OTHER_CF, b"m", b"committed");
        store.arm_persist_fault(fault);
        assert!(matches!(
            store.write_durable(batch),
            Err(StorageError::Io(_))
        ));
        assert_eq!(store.get(CF, b"m")?, None, "fault {fault:?}");
        let expected = matches!(fault, PersistFault::FailSync | PersistFault::LostSync)
            .then(|| b"committed".to_vec());
        assert_eq!(store.get(CF, b"z")?, expected, "fault {fault:?}");
        assert_eq!(store.get(OTHER_CF, b"m")?, expected, "fault {fault:?}");
    }
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_range_ordering_and_reopen() -> TestResult {
    range_ordering_laws(|path| bitcoin_rs_storage::FjallStore::open(path))
}

#[cfg(feature = "redb")]
#[test]
fn redb_range_ordering_and_reopen() -> TestResult {
    range_ordering_laws(|path| bitcoin_rs_storage::RedbStore::open(path))
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_range_ordering_and_reopen() -> TestResult {
    range_ordering_laws(|path| bitcoin_rs_storage::RocksDbStore::open(path))
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_range_faults_preserve_atomicity_and_error_receipts() -> TestResult {
    range_fault_laws(|path| bitcoin_rs_storage::FjallStore::open(path))
}

#[cfg(feature = "redb")]
#[test]
fn redb_range_faults_preserve_atomicity_and_error_receipts() -> TestResult {
    range_fault_laws(|path| bitcoin_rs_storage::RedbStore::open(path))
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_range_faults_preserve_atomicity_and_error_receipts() -> TestResult {
    range_fault_laws(|path| bitcoin_rs_storage::RocksDbStore::open(path))
}
