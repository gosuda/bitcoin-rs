//! Cross-backend equivalence tests for the storage abstraction.

use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvPair, KvStore, StorageError, WriteBatch, WriteCondition,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[cfg(feature = "mdbx")]
use std::{path::PathBuf, process::Command};

const ROWS: u32 = 10_000;
const DELETE_ROWS: u32 = 1_000;
const RANGE_START_INDEX: usize = 1_000;
const RANGE_END_INDEX: usize = 1_500;
const PREFIX: &[u8] = &[0];
const SCRIPT_LIVE_KEY_LEN: usize = 44;

/// `ScriptLive` rows are a 44-byte empty-value locator. Other families stay
/// generic byte stores in this suite.
fn cf_key(cf: ColumnFamily, counter: u32) -> Vec<u8> {
    if cf == ColumnFamily::ScriptLive {
        let mut key = vec![0_u8; SCRIPT_LIVE_KEY_LEN];
        key[..4].copy_from_slice(&counter.to_le_bytes());
        key
    } else {
        counter.to_le_bytes().to_vec()
    }
}

fn cf_value(cf: ColumnFamily, label: impl AsRef<[u8]>) -> Vec<u8> {
    if cf == ColumnFamily::ScriptLive {
        Vec::new()
    } else {
        label.as_ref().to_vec()
    }
}

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn run_equivalence_suite<S: KvStore>(store: S) -> Result<[u8; 32], StorageError> {
    insert_rows(&store)?;
    verify_rows(&store)?;
    verify_snapshot_multi_get(&store)?;
    verify_prefix_iteration(&store)?;
    verify_mixed_column_family_batch_ordering(&store)?;
    verify_mixed_owned_value_batch_ordering(&store)?;
    verify_deferred_batch_visibility(&store)?;
    overwrite_one_row_with_direct_put(&store)?;
    verify_direct_put_overwrite(&store)?;
    delete_first_rows(&store)?;
    verify_first_rows_deleted(&store)?;
    delete_range_slice(&store)?;
    store.flush()?;
    let hash = aggregate_hash(&store)?;
    drop(store);
    Ok(hash)
}

fn verify_mixed_owned_value_batch_ordering(store: &impl KvStore) -> Result<(), StorageError> {
    let key = b"owned-batch-order";
    let mut batch = store.new_batch();
    batch.put_value(
        ColumnFamily::BlockBodies,
        key,
        Bytes::from_static(b"first-body"),
    );
    batch.put(ColumnFamily::TxConfirmed, key, b"first-confirmed-borrowed");
    batch.delete(ColumnFamily::BlockBodies, key);
    batch.put_value(
        ColumnFamily::TxConfirmed,
        key,
        Bytes::from_static(b"second-confirmed-owned"),
    );
    batch.put_value(
        ColumnFamily::BlockBodies,
        key,
        Bytes::from_static(b"second-body"),
    );
    store.write(batch)?;

    assert_eq!(
        store.get(ColumnFamily::BlockBodies, key)?,
        Some(b"second-body".to_vec())
    );
    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, key)?,
        Some(b"second-confirmed-owned".to_vec())
    );
    Ok(())
}

fn verify_deferred_batch_visibility(store: &impl KvStore) -> Result<(), StorageError> {
    let key = b"deferred-batch";
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::BlockBodies, key, b"body");
    batch.put(ColumnFamily::BlockHeaders, key, b"header");
    batch.delete(ColumnFamily::BlockHeaders, key);
    store.write_deferred(batch)?;

    assert_eq!(
        store.get(ColumnFamily::BlockBodies, key)?,
        Some(b"body".to_vec())
    );
    assert_eq!(store.get(ColumnFamily::BlockHeaders, key)?, None);
    Ok(())
}

fn verify_mixed_column_family_batch_ordering(store: &impl KvStore) -> Result<(), StorageError> {
    let key = b"batch-order";
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::TxConfirmed, key, b"first-confirmed");
    batch.put(ColumnFamily::BlockHeaders, key, b"header");
    batch.delete(ColumnFamily::TxConfirmed, key);
    batch.put(ColumnFamily::TxConfirmed, key, b"second-confirmed");
    batch.delete(ColumnFamily::BlockHeaders, key);
    store.write(batch)?;

    assert_eq!(
        store.get(ColumnFamily::TxConfirmed, key)?,
        Some(b"second-confirmed".to_vec())
    );
    assert_eq!(store.get(ColumnFamily::BlockHeaders, key)?, None);
    Ok(())
}

fn insert_rows(store: &impl KvStore) -> Result<(), StorageError> {
    let mut batch = store.new_batch();
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..ROWS {
            let key = cf_key(cf, counter);
            let value = cf_value(cf, format!("{cf:?}-{counter}"));
            batch.put(cf, &key, &value);
        }
    }
    store.write(batch)
}

fn overwrite_one_row_with_direct_put(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        store.put(cf, &cf_key(cf, 0), &cf_value(cf, format!("{cf:?}-direct")))?;
    }
    Ok(())
}

fn verify_direct_put_overwrite(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        assert_eq!(
            store.get(cf, &cf_key(cf, 0))?,
            Some(cf_value(cf, format!("{cf:?}-direct")))
        );
    }
    Ok(())
}

fn verify_rows(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..ROWS {
            let key = cf_key(cf, counter);
            let expected = cf_value(cf, format!("{cf:?}-{counter}"));
            assert_eq!(store.get(cf, &key)?, Some(expected));
        }
    }
    Ok(())
}

fn verify_prefix_iteration(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        let mut expected = (0_u32..ROWS)
            .filter_map(|counter| {
                let key = cf_key(cf, counter);
                key.starts_with(PREFIX)
                    .then(|| (key, cf_value(cf, format!("{cf:?}-{counter}"))))
            })
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| left.0.cmp(&right.0));
        let actual = collect_iter(store.iter_prefix(cf, PREFIX)?)?;
        assert_eq!(actual, expected);
    }
    Ok(())
}

fn verify_snapshot_multi_get(store: &impl KvStore) -> Result<(), StorageError> {
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    const KEY_A: &[u8] = b"snapshot-a";
    const KEY_B: &[u8] = b"snapshot-b";
    const KEY_C: &[u8] = b"snapshot-c";
    const KEY_D: &[u8] = b"snapshot-d";

    let mut batch = store.new_batch();
    batch.put(CF, KEY_A, b"value-a");
    batch.put(CF, KEY_C, b"value-c");
    batch.put(CF, KEY_D, b"value-d");
    store.write(batch)?;

    let snapshot = store.snapshot()?;
    store.put(CF, KEY_A, b"changed-after-snapshot")?;
    assert_eq!(
        snapshot.get_many_sorted(CF, &[KEY_A, KEY_B, KEY_C, KEY_D])?,
        vec![
            Some(b"value-a".to_vec()),
            None,
            Some(b"value-c".to_vec()),
            Some(b"value-d".to_vec()),
        ]
    );
    assert!(snapshot.get_many_sorted(CF, &[KEY_B, KEY_A]).is_err());
    Ok(())
}

fn delete_first_rows(store: &impl KvStore) -> Result<(), StorageError> {
    let mut batch = store.new_batch();
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..DELETE_ROWS {
            batch.delete(cf, &cf_key(cf, counter));
        }
    }
    store.write(batch)
}

fn verify_first_rows_deleted(store: &impl KvStore) -> Result<(), StorageError> {
    for cf in ColumnFamily::ALL.iter().copied() {
        for counter in 0_u32..DELETE_ROWS {
            assert_eq!(store.get(cf, &cf_key(cf, counter))?, None);
        }
    }
    Ok(())
}

fn delete_range_slice(store: &impl KvStore) -> Result<(), StorageError> {
    let mut range_deleted = Vec::new();
    let mut batch = store.new_batch();
    for cf in ColumnFamily::ALL.iter().copied() {
        let rows = collect_iter(store.iter_prefix(cf, &[])?)?;
        let start = rows
            .get(RANGE_START_INDEX)
            .ok_or(StorageError::InvalidOperation("range start missing"))?
            .0
            .clone();
        let end = rows
            .get(RANGE_END_INDEX)
            .ok_or(StorageError::InvalidOperation("range end missing"))?
            .0
            .clone();
        range_deleted.extend(
            rows[RANGE_START_INDEX..RANGE_END_INDEX]
                .iter()
                .map(|(key, _)| (cf, key.clone())),
        );
        batch.delete_range(cf, &start, &end);
    }
    store.write(batch)?;

    for (cf, key) in range_deleted {
        assert_eq!(store.get(cf, &key)?, None);
    }
    Ok(())
}

fn aggregate_hash(store: &impl KvStore) -> Result<[u8; 32], StorageError> {
    let mut rows = Vec::new();
    for cf in ColumnFamily::ALL.iter().copied() {
        for item in store.iter_prefix(cf, &[])? {
            let (key, value) = item?;
            rows.push((cf, key, value));
        }
    }
    rows.sort_by(|left, right| {
        left.0
            .index()
            .cmp(&right.0.index())
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut hasher = Sha256::new();
    for (cf, key, value) in rows {
        hasher.update(cf.name().as_bytes());
        hasher.update([0]);
        hasher.update(key);
        hasher.update([0]);
        hasher.update(value);
        hasher.update([0]);
    }
    Ok(hasher.finalize().into())
}

fn collect_iter(iterator: KvIter<'_>) -> Result<Vec<KvPair>, StorageError> {
    iterator.collect()
}

fn hash_hex(hash: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::RocksDbStore::open(temp.path())?)?;
    eprintln!("rocksdb aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::FjallStore::open(temp.path())?)?;
    eprintln!("fjall aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::RedbStore::open(temp.path())?)?;
    eprintln!("redb aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn mdbx_equivalence_hash() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let hash = run_equivalence_suite(bitcoin_rs_storage::MdbxStore::open(temp.path())?)?;
    eprintln!("mdbx aggregate hash: {}", hash_hex(&hash));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_flush_persists_deferred_write_after_reopen() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    {
        let store = bitcoin_rs_storage::RedbStore::open(temp.path())?;
        let mut batch = store.new_batch();
        batch.put(
            ColumnFamily::BlockBodies,
            b"deferred-key",
            b"deferred-value",
        );
        store.write_deferred(batch)?;
        assert_eq!(
            store.get(ColumnFamily::BlockBodies, b"deferred-key")?,
            Some(b"deferred-value".to_vec())
        );
        store.flush()?;
    }

    let reopened = bitcoin_rs_storage::RedbStore::open(temp.path())?;
    assert_eq!(
        reopened.get(ColumnFamily::BlockBodies, b"deferred-key")?,
        Some(b"deferred-value".to_vec())
    );
    Ok(())
}

#[cfg(all(feature = "rocksdb", feature = "fjall", feature = "redb"))]
#[test]
fn portable_backends_have_identical_aggregate_hashes() -> TestResult<()> {
    let rocks_temp = tempfile::TempDir::new()?;
    let fjall_temp = tempfile::TempDir::new()?;
    let redb_temp = tempfile::TempDir::new()?;
    #[cfg(feature = "mdbx")]
    let mdbx_temp = tempfile::TempDir::new()?;

    let rocksdb =
        run_equivalence_suite(bitcoin_rs_storage::RocksDbStore::open(rocks_temp.path())?)?;
    let fjall = run_equivalence_suite(bitcoin_rs_storage::FjallStore::open(fjall_temp.path())?)?;
    let redb = run_equivalence_suite(bitcoin_rs_storage::RedbStore::open(redb_temp.path())?)?;
    #[cfg(feature = "mdbx")]
    let mdbx = run_equivalence_suite(bitcoin_rs_storage::MdbxStore::open(mdbx_temp.path())?)?;

    eprintln!("rocksdb aggregate hash: {}", hash_hex(&rocksdb));
    eprintln!("fjall aggregate hash: {}", hash_hex(&fjall));
    eprintln!("redb aggregate hash: {}", hash_hex(&redb));
    #[cfg(feature = "mdbx")]
    eprintln!("mdbx aggregate hash: {}", hash_hex(&mdbx));

    assert_eq!(rocksdb, fjall);
    assert_eq!(rocksdb, redb);
    #[cfg(feature = "mdbx")]
    assert_eq!(rocksdb, mdbx);
    Ok(())
}

fn run_single_key_condition_laws<S: KvStore>(store: &S) -> Result<(), StorageError> {
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    let key = b"write-condition".as_slice();
    let unrelated = b"write-condition-unrelated".as_slice();

    // Absent claim on a missing key: the whole batch applies.
    let mut batch = store.new_batch();
    batch.put(CF, key, b"v1");
    batch.put(CF, unrelated, b"u1");
    assert!(store.write_durable_if(&[WriteCondition::Absent { cf: CF, key }], batch)?);
    assert_eq!(store.get(CF, key)?, Some(b"v1".to_vec()));
    assert_eq!(store.get(CF, unrelated)?, Some(b"u1".to_vec()));

    // Absent claim on a present key: mismatch, and no batch operation —
    // including the unrelated one — is applied.
    let mut batch = store.new_batch();
    batch.put(CF, unrelated, b"u2");
    batch.delete(CF, key);
    assert!(!store.write_durable_if(&[WriteCondition::Absent { cf: CF, key }], batch)?);
    assert_eq!(store.get(CF, key)?, Some(b"v1".to_vec()));
    assert_eq!(store.get(CF, unrelated)?, Some(b"u1".to_vec()));

    // Exact match: durable replace, and the batch may mutate the condition key.
    let mut batch = store.new_batch();
    batch.put(CF, key, b"v2");
    batch.put(CF, unrelated, b"u2");
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"v1"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, key)?, Some(b"v2".to_vec()));
    assert_eq!(store.get(CF, unrelated)?, Some(b"u2".to_vec()));

    // Stale expectation after the replace: mismatch preserves everything.
    let mut batch = store.new_batch();
    batch.delete(CF, key);
    batch.delete(CF, unrelated);
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"v1"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, key)?, Some(b"v2".to_vec()));
    assert_eq!(store.get(CF, unrelated)?, Some(b"u2".to_vec()));

    // Exact match: durable delete of the condition key inside the batch.
    let mut batch = store.new_batch();
    batch.delete(CF, key);
    batch.put(CF, unrelated, b"u3");
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"v2"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, key)?, None);
    assert_eq!(store.get(CF, unrelated)?, Some(b"u3".to_vec()));
    store.flush()?;

    // Repeat against the now-absent key: mismatch applies nothing again.
    let mut batch = store.new_batch();
    batch.put(CF, unrelated, b"u4");
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"v2"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, unrelated)?, Some(b"u3".to_vec()));

    // Ordered batch operations touching the condition key apply in order.
    store.put(CF, key, b"v3")?;
    let mut batch = store.new_batch();
    batch.put(CF, key, b"v4");
    batch.delete(CF, key);
    batch.put(CF, key, b"v5");
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"v3"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, key)?, Some(b"v5".to_vec()));

    Ok(())
}

fn run_conjunction_condition_laws<S: KvStore>(store: &S) -> Result<(), StorageError> {
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    let first = b"conjunction-first".as_slice();
    let second = b"conjunction-second".as_slice();
    let third = b"conjunction-third".as_slice();

    // Multi-key conjunction: the batch lands only when every condition
    // matches, across different keys and condition kinds.
    let mut batch = store.new_batch();
    batch.put(CF, first, b"c1");
    batch.put(CF, second, b"c2");
    assert!(store.write_durable_if(
        &[
            WriteCondition::Absent { cf: CF, key: first },
            WriteCondition::Absent {
                cf: CF,
                key: second
            },
        ],
        batch,
    )?);
    assert_eq!(store.get(CF, first)?, Some(b"c1".to_vec()));
    assert_eq!(store.get(CF, second)?, Some(b"c2".to_vec()));

    // One differing condition rejects the whole conjunction: nothing in the
    // batch — including writes to keys no condition mentions — is applied.
    let mut batch = store.new_batch();
    batch.put(CF, third, b"c3");
    batch.put(CF, first, b"overwritten");
    assert!(!store.write_durable_if(
        &[
            WriteCondition::Equals {
                cf: CF,
                key: first,
                expected: b"c1"
            },
            WriteCondition::Equals {
                cf: CF,
                key: second,
                expected: b"stale"
            },
        ],
        batch,
    )?);
    assert_eq!(store.get(CF, third)?, None);
    assert_eq!(store.get(CF, first)?, Some(b"c1".to_vec()));
    assert_eq!(store.get(CF, second)?, Some(b"c2".to_vec()));

    // The empty slice is an all-true conjunction: the batch commits
    // unconditionally.
    let mut batch = store.new_batch();
    batch.put(CF, third, b"c3");
    assert!(store.write_durable_if(&[], batch)?);
    assert_eq!(store.get(CF, third)?, Some(b"c3".to_vec()));

    // Conditions observe the pre-batch state even when two of them name the
    // same key: both members see the same pre-image.
    assert!(!store.write_durable_if(
        &[
            WriteCondition::Equals {
                cf: CF,
                key: first,
                expected: b"c1"
            },
            WriteCondition::Equals {
                cf: CF,
                key: first,
                expected: b"never"
            },
        ],
        store.new_batch(),
    )?);
    assert_eq!(store.get(CF, first)?, Some(b"c1".to_vec()));

    Ok(())
}

fn run_write_condition_laws<S: KvStore>(store: &S) -> Result<(), StorageError> {
    run_single_key_condition_laws(store)?;
    run_conjunction_condition_laws(store)?;
    store.flush()?;
    Ok(())
}

/// Competing writers holding the same pre-image: exactly one claim wins, the
/// loser's batch never lands, and the winner's bytes are the final state.
fn run_competing_writer_laws<S: KvStore>(store: &S) -> Result<(), StorageError> {
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    let key = b"write-condition-race".as_slice();
    store.put(CF, key, b"claim")?;
    store.flush()?;

    let results: Vec<Result<bool, StorageError>> = std::thread::scope(|scope| {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        [b"first".as_slice(), b"second".as_slice()]
            .map(|tag| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let mut batch = store.new_batch();
                    batch.put(CF, key, tag);
                    barrier.wait();
                    store.write_durable_if(
                        &[WriteCondition::Equals {
                            cf: CF,
                            key,
                            expected: b"claim",
                        }],
                        batch,
                    )
                })
            })
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(result) => result,
                Err(payload) => std::panic::resume_unwind(payload),
            })
            .collect()
    });
    let winners = results
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    assert_eq!(
        winners, 1,
        "exactly one competing writer may win: {results:?}"
    );
    assert!(results.iter().all(Result::is_ok));
    let winner_tag = if matches!(results[0], Ok(true)) {
        b"first".as_slice()
    } else {
        b"second".as_slice()
    };
    assert_eq!(store.get(CF, key)?, Some(winner_tag.to_vec()));
    Ok(())
}

/// `write_durable_if` success is durable on its own: a reopened store sees the
/// committed bytes without any caller flush.
fn run_reopen_durability_law<S, Reopen>(reopen: Reopen) -> Result<(), StorageError>
where
    S: KvStore,
    Reopen: Fn() -> Result<S, StorageError>,
{
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    let key = b"write-condition-durability".as_slice();
    {
        let store = reopen()?;
        let mut batch = store.new_batch();
        batch.put(CF, key, b"durable");
        assert!(store.write_durable_if(&[WriteCondition::Absent { cf: CF, key }], batch)?);
    }
    let store = reopen()?;
    assert_eq!(store.get(CF, key)?, Some(b"durable".to_vec()));
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_write_durable_if_laws() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
    run_write_condition_laws(&store)?;
    run_competing_writer_laws(&store)?;
    drop(store);
    run_reopen_durability_law(|| bitcoin_rs_storage::RocksDbStore::open(temp.path()))?;
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_write_durable_if_laws() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::FjallStore::open(temp.path())?;
    run_write_condition_laws(&store)?;
    run_competing_writer_laws(&store)?;
    drop(store);
    run_reopen_durability_law(|| bitcoin_rs_storage::FjallStore::open(temp.path()))?;
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_write_durable_if_laws() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::RedbStore::open(temp.path())?;
    run_write_condition_laws(&store)?;
    run_competing_writer_laws(&store)?;
    drop(store);
    run_reopen_durability_law(|| bitcoin_rs_storage::RedbStore::open(temp.path()))?;
    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn mdbx_write_durable_if_laws() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::MdbxStore::open(temp.path())?;
    run_write_condition_laws(&store)?;
    run_competing_writer_laws(&store)?;
    drop(store);
    run_reopen_durability_law(|| bitcoin_rs_storage::MdbxStore::open(temp.path()))?;
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_rejects_second_writable_primary_open_on_same_path() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let first = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
    let second = bitcoin_rs_storage::RocksDbStore::open(temp.path());
    assert!(
        second.is_err(),
        "a second writable primary open must fail while the first store owns the database"
    );
    drop(first);
    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn mdbx_write_durable_if_spans_processes() -> TestResult<()> {
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    const CHILD_DATA_DIR: &str = "BITCOIN_RS_MDBX_CONDITIONAL_WRITE_CHILD";
    let key = b"mdbx-cross-process".as_slice();
    if let Some(path) = std::env::var_os(CHILD_DATA_DIR) {
        // Child mode: claim the parent's pre-image through the conditional
        // primitive; MDBX's cross-process write lock serializes the boundary.
        let store = bitcoin_rs_storage::MdbxStore::open(PathBuf::from(path))?;
        let mut batch = store.new_batch();
        batch.put(CF, key, b"newer");
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: CF,
                key,
                expected: b"older"
            }],
            batch,
        )?);
        return Ok(());
    }
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::MdbxStore::open(temp.path())?;
    store.put(CF, key, b"older")?;
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("mdbx_write_durable_if_spans_processes")
        .arg("--nocapture")
        .env(CHILD_DATA_DIR, temp.path())
        .status()?;
    assert!(status.success(), "MDBX writer child failed: {status}");

    // The child consumed the pre-image across processes: the stale claim
    // misses, and its unrelated write never lands either.
    let stale_key = b"mdbx-unrelated".as_slice();
    let mut batch = store.new_batch();
    batch.put(CF, stale_key, b"stale");
    assert!(!store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"older"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, key)?, Some(b"newer".to_vec()));
    assert_eq!(store.get(CF, stale_key)?, None);

    // The cross-process value satisfies a fresh claim.
    let mut batch = store.new_batch();
    batch.delete(CF, key);
    assert!(store.write_durable_if(
        &[WriteCondition::Equals {
            cf: CF,
            key,
            expected: b"newer"
        }],
        batch,
    )?);
    assert_eq!(store.get(CF, key)?, None);
    Ok(())
}
