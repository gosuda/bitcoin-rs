use bitcoin_rs_storage::{ColumnFamily, KvIter, KvPair, KvStore, StorageError, WriteCondition};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const ROWS: u32 = 10_000;
const DELETE_ROWS: u32 = 1_000;
const RANGE_START_INDEX: usize = 1_000;
const RANGE_END_INDEX: usize = 1_500;
const PREFIX: &[u8] = &[0];
const SCRIPT_LIVE_KEY_LEN: usize = 43;

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

use crate::support::TestResult;

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

#[test]
fn rocksdb_flush_persists_deferred_write_after_reopen() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    {
        let store = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
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

    let reopened = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
    assert_eq!(
        reopened.get(ColumnFamily::BlockBodies, b"deferred-key")?,
        Some(b"deferred-value".to_vec())
    );
    Ok(())
}

fn run_reopen_pool_ledger_suite<S: KvStore>(
    open: impl Fn(&std::path::Path) -> Result<S, StorageError>,
) -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    {
        let store = open(temp.path())?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockHeaders, b"reopen-anchor", b"anchor-v1");
        batch.put(ColumnFamily::PoolLedger, b"ledger-pre", b"pre-v1");
        store.write(batch)?;
        store.flush()?;
    }

    let reopened = open(temp.path())?;
    assert_eq!(
        reopened.get(ColumnFamily::BlockHeaders, b"reopen-anchor")?,
        Some(b"anchor-v1".to_vec())
    );
    assert_eq!(
        reopened.get(ColumnFamily::PoolLedger, b"ledger-pre")?,
        Some(b"pre-v1".to_vec())
    );
    let mut batch = reopened.new_batch();
    batch.put(ColumnFamily::PoolLedger, b"ledger-post", b"post-v1");
    reopened.write(batch)?;
    assert_eq!(
        reopened.get(ColumnFamily::PoolLedger, b"ledger-post")?,
        Some(b"post-v1".to_vec())
    );
    Ok(())
}

#[test]
fn rocksdb_reopen_preserves_rows_and_serves_pool_ledger() -> TestResult<()> {
    run_reopen_pool_ledger_suite(|path| bitcoin_rs_storage::RocksDbStore::open(path))
}
#[test]
fn rocksdb_open_creates_missing_column_families_without_reset() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    {
        let mut db_opts = rust_rocksdb::Options::default();
        db_opts.create_if_missing(true);
        let mut db =
            rust_rocksdb::DB::open(&db_opts, temp.path()).map_err(StorageError::backend)?;
        let cf_opts = rust_rocksdb::Options::default();
        db.create_cf(ColumnFamily::BlockHeaders.name(), &cf_opts)
            .map_err(StorageError::backend)?;
        let handle = db.cf_handle(ColumnFamily::BlockHeaders.name()).ok_or(
            StorageError::UnknownColumnFamily(ColumnFamily::BlockHeaders),
        )?;
        db.put_cf(handle, b"legacy-header", b"legacy-value")
            .map_err(StorageError::backend)?;
    }

    let store = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
    assert_eq!(
        store.get(ColumnFamily::BlockHeaders, b"legacy-header")?,
        Some(b"legacy-value".to_vec())
    );
    store.put(ColumnFamily::PoolLedger, b"ledger-first", b"row-v1")?;
    assert_eq!(
        store.get(ColumnFamily::PoolLedger, b"ledger-first")?,
        Some(b"row-v1".to_vec())
    );
    Ok(())
}

#[test]
fn rocksdb_equivalence_suite() -> TestResult<()> {
    let temp1 = tempfile::TempDir::new()?;
    let store1 = bitcoin_rs_storage::RocksDbStore::open(temp1.path())?;
    let hash1 = run_equivalence_suite(store1)?;

    let temp2 = tempfile::TempDir::new()?;
    let store2 = bitcoin_rs_storage::RocksDbStore::open(temp2.path())?;
    let hash2 = run_equivalence_suite(store2)?;

    assert_eq!(
        hash1, hash2,
        "deterministic RocksDb equivalence suite must produce identical aggregate hashes"
    );
    Ok(())
}

fn run_single_key_condition_laws<S: KvStore>(store: &S) -> Result<(), StorageError> {
    const CF: ColumnFamily = ColumnFamily::BlockBodies;
    let key = b"write-condition".as_slice();
    let unrelated = b"write-condition-unrelated".as_slice();

    let mut batch = store.new_batch();
    batch.put(CF, key, b"v1");
    batch.put(CF, unrelated, b"u1");
    assert!(store.write_durable_if(&[WriteCondition::Absent { cf: CF, key }], batch)?);
    assert_eq!(store.get(CF, key)?, Some(b"v1".to_vec()));
    assert_eq!(store.get(CF, unrelated)?, Some(b"u1".to_vec()));

    let mut batch = store.new_batch();
    batch.put(CF, unrelated, b"u2");
    batch.delete(CF, key);
    assert!(!store.write_durable_if(&[WriteCondition::Absent { cf: CF, key }], batch)?);
    assert_eq!(store.get(CF, key)?, Some(b"v1".to_vec()));
    assert_eq!(store.get(CF, unrelated)?, Some(b"u1".to_vec()));

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

    let mut batch = store.new_batch();
    batch.put(CF, third, b"c3");
    assert!(store.write_durable_if(&[], batch)?);
    assert_eq!(store.get(CF, third)?, Some(b"c3".to_vec()));

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

macro_rules! engine_tests {
    ($engine:ident, $open:expr) => {
        mod $engine {
            use super::*;

            #[test]
            fn get_and_put() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;

                let cf = ColumnFamily::TxConfirmed;
                assert_eq!(store.get(cf, b"missing")?, None);

                store.put(cf, b"k1", b"v1")?;
                assert_eq!(store.get(cf, b"k1")?, Some(b"v1".to_vec()));

                store.put(cf, b"k1", b"v1_updated")?;
                assert_eq!(store.get(cf, b"k1")?, Some(b"v1_updated".to_vec()));

                let cf2 = ColumnFamily::BlockHeaders;
                assert_eq!(store.get(cf2, b"k1")?, None);
                store.put(cf2, b"k1", b"v2")?;
                assert_eq!(store.get(cf2, b"k1")?, Some(b"v2".to_vec()));
                assert_eq!(store.get(cf, b"k1")?, Some(b"v1_updated".to_vec()));
                Ok(())
            }

            #[test]
            fn prefix_and_bounded_scans() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;
                let cf = ColumnFamily::Funding;

                for i in 0..10u8 {
                    let key = format!("prefix/{i:02}").into_bytes();
                    let val = format!("val/{i:02}").into_bytes();
                    store.put(cf, &key, &val)?;
                }
                store.put(cf, b"other/00", b"other_val")?;

                let all_iter: Vec<_> = store
                    .iter_prefix(cf, b"prefix/")?
                    .collect::<Result<Vec<_>, _>>()?;
                assert_eq!(all_iter.len(), 10);
                assert_eq!(all_iter[0].0, b"prefix/00".to_vec());
                assert_eq!(all_iter[9].0, b"prefix/09".to_vec());

                let scan_limit_rows = store.scan_prefix_bounded(
                    cf,
                    b"prefix/",
                    bitcoin_rs_storage::PrefixScanLimit {
                        max_rows: 5,
                        max_bytes: usize::MAX,
                    },
                )?;
                assert_eq!(scan_limit_rows.rows.len(), 5);
                assert!(!scan_limit_rows.complete);
                assert_eq!(scan_limit_rows.rows[0].0, b"prefix/00".to_vec());
                assert_eq!(scan_limit_rows.rows[4].0, b"prefix/04".to_vec());

                let scan_limit_bytes = store.scan_prefix_bounded(
                    cf,
                    b"prefix/",
                    bitcoin_rs_storage::PrefixScanLimit {
                        max_rows: 100,
                        max_bytes: 40,
                    },
                )?;
                assert!(scan_limit_bytes.rows.len() < 10);
                assert!(!scan_limit_bytes.complete);

                let scan_from = store.scan_prefix_from_bounded(
                    cf,
                    b"prefix/",
                    b"prefix/05",
                    bitcoin_rs_storage::PrefixScanLimit {
                        max_rows: 100,
                        max_bytes: usize::MAX,
                    },
                )?;
                assert_eq!(scan_from.rows.len(), 5);
                assert!(scan_from.complete);
                assert_eq!(scan_from.rows[0].0, b"prefix/05".to_vec());
                assert_eq!(scan_from.rows[4].0, b"prefix/09".to_vec());

                let scan_past = store.scan_prefix_from_bounded(
                    cf,
                    b"prefix/",
                    b"prefix/99",
                    bitcoin_rs_storage::PrefixScanLimit {
                        max_rows: 100,
                        max_bytes: usize::MAX,
                    },
                )?;
                assert!(scan_past.rows.is_empty());
                assert!(scan_past.complete);
                Ok(())
            }

            #[test]
            fn snapshot_isolation() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;
                let cf = ColumnFamily::TxConfirmed;

                store.put(cf, b"k_snap", b"v_initial")?;
                let snap = store.snapshot()?;

                store.put(cf, b"k_snap", b"v_mutated")?;
                store.put(cf, b"k_new", b"v_new")?;

                assert_eq!(snap.get(cf, b"k_snap")?, Some(b"v_initial".to_vec()));
                assert_eq!(snap.get(cf, b"k_new")?, None);

                assert_eq!(store.get(cf, b"k_snap")?, Some(b"v_mutated".to_vec()));
                assert_eq!(store.get(cf, b"k_new")?, Some(b"v_new".to_vec()));

                let sorted_keys: &[&[u8]] = &[b"k_new", b"k_snap"];
                let snap_multi = snap.get_many_sorted(cf, sorted_keys)?;
                assert_eq!(snap_multi[0], None);
                assert_eq!(snap_multi[1], Some(b"v_initial".to_vec()));

                let unsorted_keys: &[&[u8]] = &[b"k_snap", b"k_new"];
                let unsorted_err = snap.get_many_sorted(cf, unsorted_keys);
                assert!(matches!(
                    unsorted_err,
                    Err(StorageError::InvalidOperation(_))
                ));
                Ok(())
            }

            #[test]
            fn conditional_write_success_and_mismatch() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;
                let cf = ColumnFamily::TxConfirmed;

                store.put(cf, b"k_cond", b"v_base")?;

                let mut success_batch = store.new_batch();
                success_batch.put(cf, b"k_result", b"v_result");
                let cond_success = [
                    WriteCondition::Equals {
                        cf,
                        key: b"k_cond",
                        expected: b"v_base",
                    },
                    WriteCondition::Absent {
                        cf,
                        key: b"k_absent",
                    },
                ];
                let ok = store.write_durable_if(&cond_success, success_batch)?;
                assert!(ok);
                assert_eq!(store.get(cf, b"k_result")?, Some(b"v_result".to_vec()));

                let mut fail_batch1 = store.new_batch();
                fail_batch1.put(cf, b"k_unapplied1", b"val");
                let cond_mismatch = [WriteCondition::Equals {
                    cf,
                    key: b"k_cond",
                    expected: b"wrong_val",
                }];
                let rejected1 = store.write_durable_if(&cond_mismatch, fail_batch1)?;
                assert!(!rejected1);
                assert_eq!(store.get(cf, b"k_unapplied1")?, None);

                let mut fail_batch2 = store.new_batch();
                fail_batch2.put(cf, b"k_unapplied2", b"val");
                let cond_absent_fails = [WriteCondition::Absent { cf, key: b"k_cond" }];
                let rejected2 = store.write_durable_if(&cond_absent_fails, fail_batch2)?;
                assert!(!rejected2);
                assert_eq!(store.get(cf, b"k_unapplied2")?, None);
                Ok(())
            }

            #[test]
            fn multi_get_ordering_and_absence() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;

                let empty = store.multi_get(ColumnFamily::Coins, &[])?;
                assert!(empty.is_empty());

                store.put(ColumnFamily::Coins, b"apple", b"val_apple")?;
                store.put(ColumnFamily::Coins, b"banana", b"val_banana")?;
                store.put(ColumnFamily::Coins, b"cherry", b"val_cherry")?;

                let sorted_keys: &[&[u8]] = &[b"apple", b"banana", b"cherry"];
                let sorted_res = store.multi_get(ColumnFamily::Coins, sorted_keys)?;
                assert_eq!(
                    sorted_res,
                    vec![
                        Some(Bytes::from_static(b"val_apple")),
                        Some(Bytes::from_static(b"val_banana")),
                        Some(Bytes::from_static(b"val_cherry")),
                    ]
                );

                let unsorted_keys: &[&[u8]] = &[b"cherry", b"apple", b"date", b"banana", b"apple"];
                let unsorted_res = store.multi_get(ColumnFamily::Coins, unsorted_keys)?;
                assert_eq!(
                    unsorted_res,
                    vec![
                        Some(Bytes::from_static(b"val_cherry")),
                        Some(Bytes::from_static(b"val_apple")),
                        None,
                        Some(Bytes::from_static(b"val_banana")),
                        Some(Bytes::from_static(b"val_apple")),
                    ]
                );
                Ok(())
            }

            #[test]
            fn ingest_sorted_valid_and_queryable() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let db_path = temp.path().join("db");
                let scratch_path = temp.path().join("scratch");
                let store = ($open)(&db_path)?;

                let empty_rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                let mut empty_iter = empty_rows.into_iter();
                let count =
                    store.ingest_sorted(ColumnFamily::Coins, &mut empty_iter, &scratch_path)?;
                assert_eq!(count, 0);

                let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..500u32)
                    .map(|i| {
                        let key = format!("k_{i:06}").into_bytes();
                        let val = format!("v_{i:06}").into_bytes();
                        (key, val)
                    })
                    .collect();

                let mut row_iter = rows.into_iter();
                let count =
                    store.ingest_sorted(ColumnFamily::Coins, &mut row_iter, &scratch_path)?;
                assert_eq!(count, 500);

                let val = store
                    .get(ColumnFamily::Coins, b"k_000042")?
                    .expect("key must be present");
                assert_eq!(val, b"v_000042");

                let keys: &[&[u8]] = &[b"k_000499", b"k_000000", b"k_000250"];
                let multi = store.multi_get(ColumnFamily::Coins, keys)?;
                assert_eq!(
                    multi,
                    vec![
                        Some(Bytes::from_static(b"v_000499")),
                        Some(Bytes::from_static(b"v_000000")),
                        Some(Bytes::from_static(b"v_000250")),
                    ]
                );
                Ok(())
            }

            #[test]
            fn ingest_sorted_order_rejection_and_oversize_single_row() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let db_path = temp.path().join("db");
                let scratch_path = temp.path().join("scratch");
                let store = ($open)(&db_path)?;

                let unsorted_rows: Vec<(Vec<u8>, Vec<u8>)> = vec![
                    (b"key_a".to_vec(), b"val_a".to_vec()),
                    (b"key_c".to_vec(), b"val_c".to_vec()),
                    (b"key_b".to_vec(), b"val_b".to_vec()),
                ];
                let mut iter = unsorted_rows.into_iter();
                let err = store
                    .ingest_sorted(ColumnFamily::Coins, &mut iter, &scratch_path)
                    .unwrap_err();
                assert!(matches!(
                    err,
                    StorageError::InvalidOperation("keys not strictly ascending")
                ));

                let equal_rows: Vec<(Vec<u8>, Vec<u8>)> = vec![
                    (b"key_a".to_vec(), b"val_a".to_vec()),
                    (b"key_a".to_vec(), b"val_a2".to_vec()),
                ];
                let mut iter2 = equal_rows.into_iter();
                let err2 = store
                    .ingest_sorted(ColumnFamily::Coins, &mut iter2, &scratch_path)
                    .unwrap_err();
                assert!(matches!(
                    err2,
                    StorageError::InvalidOperation("keys not strictly ascending")
                ));

                let scratch_files: Vec<_> = if scratch_path.exists() {
                    std::fs::read_dir(&scratch_path)?
                        .filter_map(Result::ok)
                        .collect()
                } else {
                    Vec::new()
                };
                assert!(scratch_files.is_empty());

                let oversize_target = if stringify!($engine) == "rocksdb" {
                    256 * 1024 * 1024
                } else {
                    65 * 1024 * 1024
                };
                let large_val = vec![0xaa; oversize_target];
                let mut oversize_stream = vec![
                    (b"row1".to_vec(), b"val1".to_vec()),
                    (b"row2".to_vec(), large_val),
                    (b"row3".to_vec(), b"val3".to_vec()),
                ]
                .into_iter();
                let count = store.ingest_sorted(
                    ColumnFamily::Coins,
                    &mut oversize_stream,
                    &scratch_path,
                )?;
                assert_eq!(count, 3);
                assert_eq!(
                    store.get(ColumnFamily::Coins, b"row1")?,
                    Some(b"val1".to_vec())
                );
                let r2 = store
                    .get(ColumnFamily::Coins, b"row2")?
                    .expect("oversize row must be present");
                assert_eq!(r2.len(), oversize_target);
                assert_eq!(r2[0], 0xaa);
                assert_eq!(
                    store.get(ColumnFamily::Coins, b"row3")?,
                    Some(b"val3".to_vec())
                );
                Ok(())
            }

            #[test]
            fn delete_range_end_exclusive() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;

                for i in 0..10u8 {
                    let key = [b'k', i];
                    let val = [b'v', i];
                    store.put(ColumnFamily::Coins, &key, &val)?;
                }

                store.delete_range(ColumnFamily::Coins, &[b'k', 3], &[b'k', 7])?;

                for i in 0..10u8 {
                    let key = [b'k', i];
                    let val = store.get(ColumnFamily::Coins, &key)?;
                    if (3..7).contains(&i) {
                        assert_eq!(val, None, "key k{i} should be deleted");
                    } else {
                        assert_eq!(val, Some(vec![b'v', i]), "key k{i} should remain");
                    }
                }
                Ok(())
            }

            #[test]
            fn checkpoint_reopen_equality() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let original_dir = temp.path().join("original");
                let checkpoint_dir = temp.path().join("checkpoint");

                let store = ($open)(&original_dir)?;
                store.put(ColumnFamily::Coins, b"cp_key", b"cp_value")?;
                store.flush()?;

                store.checkpoint(&checkpoint_dir)?;

                store.put(ColumnFamily::Coins, b"post_cp_key", b"post_cp_value")?;
                store.flush()?;

                let reopened = ($open)(&checkpoint_dir)?;
                assert_eq!(
                    reopened.get(ColumnFamily::Coins, b"cp_key")?,
                    Some(b"cp_value".to_vec())
                );
                assert_eq!(reopened.get(ColumnFamily::Coins, b"post_cp_key")?, None);
                Ok(())
            }

            #[test]
            fn engine_cache_bytes_reported() -> TestResult<()> {
                let temp = tempfile::TempDir::new()?;
                let store = ($open)(temp.path())?;

                for i in 0..100u32 {
                    let key = format!("k_{i:04}").into_bytes();
                    let val = vec![0xaa; 1024];
                    store.put(ColumnFamily::Coins, &key, &val)?;
                }

                let cache_bytes = store.engine_cache_bytes();
                assert!(cache_bytes > 0 || stringify!($engine) == "mdbx");
                Ok(())
            }
        }
    };
}

engine_tests!(rocksdb, |path: &std::path::Path| {
    bitcoin_rs_storage::RocksDbStore::open(path)
});

#[cfg(feature = "surrealkv")]
engine_tests!(surrealkv, |path: &std::path::Path| {
    bitcoin_rs_storage::SurrealKvStore::open(path)
});

#[cfg(feature = "mdbx")]
engine_tests!(mdbx, |path: &std::path::Path| {
    bitcoin_rs_storage::MdbxStore::open(path)
});

#[test]
fn detect_engine_rocksdb() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
    store.put(ColumnFamily::TxConfirmed, b"k", b"v")?;
    store.flush()?;
    drop(store);

    let detected = bitcoin_rs_storage::detect_engine(temp.path())?;
    assert_eq!(detected, Some(bitcoin_rs_storage::StorageBackend::RocksDb));
    Ok(())
}

#[cfg(feature = "surrealkv")]
#[test]
fn detect_engine_surrealkv() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::SurrealKvStore::open(temp.path())?;
    store.put(ColumnFamily::TxConfirmed, b"k", b"v")?;
    store.flush()?;
    drop(store);

    let detected = bitcoin_rs_storage::detect_engine(temp.path())?;
    assert_eq!(
        detected,
        Some(bitcoin_rs_storage::StorageBackend::SurrealKv)
    );
    Ok(())
}

#[cfg(feature = "mdbx")]
#[test]
fn detect_engine_mdbx() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::MdbxStore::open(temp.path())?;
    store.put(ColumnFamily::TxConfirmed, b"k", b"v")?;
    store.flush()?;
    drop(store);

    let detected = bitcoin_rs_storage::detect_engine(temp.path())?;
    assert_eq!(detected, Some(bitcoin_rs_storage::StorageBackend::Mdbx));
    Ok(())
}

#[test]
fn detect_engine_empty_or_absent_dir_is_none() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let empty_dir = temp.path().join("empty");
    std::fs::create_dir_all(&empty_dir)?;
    assert_eq!(bitcoin_rs_storage::detect_engine(&empty_dir)?, None);

    let absent_dir = temp.path().join("absent");
    assert_eq!(bitcoin_rs_storage::detect_engine(&absent_dir)?, None);
    Ok(())
}

#[test]
fn detect_engine_junk_file_is_incompatible_data() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    std::fs::write(temp.path().join("random_junk.txt"), b"corrupted")?;

    let res = bitcoin_rs_storage::detect_engine(temp.path());
    assert!(matches!(res, Err(StorageError::IncompatibleData(_))));
    Ok(())
}
