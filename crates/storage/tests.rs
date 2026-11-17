mod test_support_error;
mod support {

    pub(crate) use crate::test_support_error::TestResult;
    pub(crate) mod utxo {
        pub(crate) mod error {
            #[derive(Debug, thiserror::Error)]
            pub(crate) enum TestError {
                #[error(transparent)]
                Io(#[from] std::io::Error),
                #[error(transparent)]
                TryFromInt(#[from] std::num::TryFromIntError),
                #[error(transparent)]
                Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),

                #[error(transparent)]
                CoinStatsDecode(#[from] bitcoin_rs_storage::utxo::stats::CoinStatsDecodeError),
                #[error("missing: {0}")]
                Missing(&'static str),
                #[error("unexpected success: {0}")]
                UnexpectedSuccess(&'static str),
            }

            pub(crate) type TestResult<T = ()> = Result<T, TestError>;
        }

        pub(crate) use error::{TestError, TestResult};
    }
}

mod backend_equivalence {
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

                    let unsorted_keys: &[&[u8]] =
                        &[b"cherry", b"apple", b"date", b"banana", b"apple"];
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
}
mod backend_metrics {
    use hashbrown::HashMap;
    use std::sync::Arc;

    use parking_lot::Mutex;

    use crate::support::TestResult;
    use bitcoin_rs_storage::cache_budget::{MIN_DBCACHE_BYTES, split_cache_budget_with_txindex};
    use bitcoin_rs_storage::{ColumnFamily, KvStore};
    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
        Recorder, SharedString, Unit,
    };

    fn txindex_share() -> u64 {
        let share = split_cache_budget_with_txindex(MIN_DBCACHE_BYTES)[1].bytes;
        assert_eq!(share, 3_355_443, "txindex keeps a floored 20% of 16 MiB");
        share
    }

    #[derive(Clone, Debug, Default)]
    struct LabeledRecorder {
        counters: Arc<Mutex<HashMap<String, u64>>>,
        gauges: Arc<Mutex<HashMap<String, f64>>>,
    }

    impl LabeledRecorder {
        fn metric_key(key: &Key) -> String {
            let labels = key
                .labels()
                .map(|label| format!("{}=\"{}\"", label.key(), label.value()))
                .collect::<Vec<_>>()
                .join(",");
            if labels.is_empty() {
                key.name().to_owned()
            } else {
                format!("{}{{{}}}", key.name(), labels)
            }
        }

        fn counter(&self, key: &str) -> u64 {
            *self.counters.lock().get(key).unwrap_or(&0)
        }

        fn writes_total(&self, backend: &str) -> u64 {
            let prefix = format!("storage.writes_total{{backend=\"{backend}\"");
            self.counters
                .lock()
                .iter()
                .filter(|(key, _)| key.starts_with(&prefix))
                .map(|(_, value)| value)
                .sum()
        }

        fn gauge(&self, key: &str) -> f64 {
            *self.gauges.lock().get(key).unwrap_or(&0.0)
        }
    }

    impl Recorder for LabeledRecorder {
        fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {
        }
        fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
        fn describe_histogram(
            &self,
            _key: KeyName,
            _unit: Option<Unit>,
            _description: SharedString,
        ) {
        }

        fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
            let name = Self::metric_key(key);
            self.counters.lock().entry(name.clone()).or_insert(0);
            Counter::from_arc(Arc::new(CounterCell {
                counters: Arc::clone(&self.counters),
                name,
            }))
        }

        fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
            let name = Self::metric_key(key);
            self.gauges.lock().entry(name.clone()).or_insert(0.0);
            Gauge::from_arc(Arc::new(GaugeCell {
                gauges: Arc::clone(&self.gauges),
                name,
            }))
        }

        fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(Arc::new(NoopHistogram))
        }
    }

    struct CounterCell {
        counters: Arc<Mutex<HashMap<String, u64>>>,
        name: String,
    }

    impl CounterFn for CounterCell {
        fn increment(&self, value: u64) {
            *self.counters.lock().entry(self.name.clone()).or_insert(0) += value;
        }

        fn absolute(&self, value: u64) {
            self.counters.lock().insert(self.name.clone(), value);
        }
    }

    struct GaugeCell {
        gauges: Arc<Mutex<HashMap<String, f64>>>,
        name: String,
    }

    impl GaugeFn for GaugeCell {
        fn increment(&self, value: f64) {
            *self.gauges.lock().entry(self.name.clone()).or_insert(0.0) += value;
        }

        fn decrement(&self, value: f64) {
            if let Some(entry) = self.gauges.lock().get_mut(&self.name) {
                *entry -= value;
            }
        }

        fn set(&self, value: f64) {
            self.gauges.lock().insert(self.name.clone(), value);
        }
    }

    struct NoopHistogram;

    impl HistogramFn for NoopHistogram {
        fn record(&self, _value: f64) {}
    }

    fn writes_total(backend: &str, durability: &str) -> String {
        format!("storage.writes_total{{backend=\"{backend}\",durability=\"{durability}\"}}")
    }

    fn cache_capacity(backend: &str) -> String {
        format!("storage.cache_capacity_bytes{{backend=\"{backend}\"}}")
    }

    fn put_one_row(store: &impl KvStore) -> Result<(), bitcoin_rs_storage::StorageError> {
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        store.write(batch)?;
        Ok(())
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "byte counts < 2^24, lossless in f64"
    )]
    #[expect(clippy::as_conversions, reason = "byte counts < 2^24, lossless in f64")]
    fn assert_gauge_eq(recorder: &LabeledRecorder, key: &str, expected: u64) {
        let actual = recorder.gauge(key);
        assert!(
            (actual - expected as f64).abs() < 1.0,
            "{key}: expected {expected}, got {actual}"
        );
    }

    #[test]
    fn rocksdb_deferred_and_durable_writes_count_once() -> TestResult {
        let recorder = LabeledRecorder::default();
        let dir = tempfile::tempdir()?;
        let store = bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), txindex_share())?;
        metrics::with_local_recorder(&recorder, || {
            let Ok(()) = put_one_row(&store) else {
                panic!("rocksdb default write failed")
            };
            let mut batch = store.new_batch();
            batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
            let Ok(()) = store.write_deferred(batch) else {
                panic!("rocksdb deferred write failed")
            };
            let mut batch = store.new_batch();
            batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
            let Ok(()) = store.write_durable(batch) else {
                panic!("rocksdb durable write failed")
            };
        });
        assert_eq!(recorder.counter(&writes_total("rocksdb", "default")), 1);
        assert_eq!(recorder.counter(&writes_total("rocksdb", "deferred")), 1);
        assert_eq!(recorder.counter(&writes_total("rocksdb", "durable")), 1);
        assert_eq!(
            recorder.writes_total("rocksdb"),
            3,
            "three logical writes must produce exactly three events"
        );
        Ok(())
    }

    #[test]
    fn rocksdb_configures_the_budgeted_share_verbatim() -> TestResult {
        let recorder = LabeledRecorder::default();
        let dir = tempfile::tempdir()?;
        let share = txindex_share();
        metrics::with_local_recorder(&recorder, || {
            let Ok(_store) = bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), share)
            else {
                panic!("rocksdb open with budgeted share failed")
            };
        });
        assert_gauge_eq(&recorder, &cache_capacity("rocksdb"), share);
        Ok(())
    }
}
mod batch_range_ordering {
    use std::path::Path;

    use bitcoin_rs_storage::{
        BufferedWriteBatch, ColumnFamily, KvPair, KvStore, PersistFault, StorageError,
        WriteCondition,
    };

    use crate::support::TestResult;

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

    fn ordered_batch<S: KvStore>(store: &S) -> BufferedWriteBatch {
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

        batch.put(CF, b"bounds:0", b"before-start");
        batch.put(CF, b"bounds:a", b"overwrite-removed");
        batch.put(CF, b"bounds:b", b"staged-removed");
        batch.put(CF, b"bounds:z", b"at-end");
        batch.put(OTHER_CF, b"bounds:b", b"other-staged");
        batch.delete_range(CF, b"bounds:a", b"bounds:z");

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

    fn range_ordering_laws<S: KvStore>(
        open: impl Fn(&Path) -> Result<S, StorageError>,
    ) -> TestResult {
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

    #[test]
    fn rocksdb_range_ordering_and_reopen() -> TestResult {
        range_ordering_laws(|path| bitcoin_rs_storage::RocksDbStore::open(path))
    }

    #[test]
    fn rocksdb_range_faults_preserve_atomicity_and_error_receipts() -> TestResult {
        range_fault_laws(|path| bitcoin_rs_storage::RocksDbStore::open(path))
    }
}
mod bounded_prefix_scan {
    use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScan, PrefixScanLimit, StorageError};

    use crate::support::TestResult;

    fn seed_rows<S: KvStore>(store: &S) -> Result<(), StorageError> {
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &[0x00], b"a");
        batch.put(ColumnFamily::TxConfirmed, &[0x00, 0x01], b"bb");
        batch.put(ColumnFamily::TxConfirmed, &[0x01], b"ccc");
        batch.put(ColumnFamily::TxConfirmed, &[0x01, 0xff], b"dddd");
        batch.put(ColumnFamily::TxConfirmed, &[0x02], b"eeeee");
        batch.put(ColumnFamily::TxConfirmed, &[0xff], b"f");
        batch.put(ColumnFamily::TxConfirmed, &[0xff, 0x00], b"gg");
        store.write(batch)
    }

    fn assert_limit_semantics<S: KvStore>(store: &S) -> Result<(), StorageError> {
        let scan = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[0x00],
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: usize::MAX,
            },
        )?;
        assert_eq!(scan.rows.len(), 1);
        assert_eq!(scan.rows[0].0, vec![0x00]);
        assert!(!scan.complete);

        let scan = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[0x00],
            PrefixScanLimit {
                max_rows: usize::MAX,
                max_bytes: 3,
            },
        )?;
        assert_eq!(scan.rows.len(), 1);
        assert!(!scan.complete);

        let scan = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[0x00],
            PrefixScanLimit {
                max_rows: 2,
                max_bytes: 6,
            },
        )?;
        assert_eq!(scan.rows.len(), 2);
        assert_eq!(scan.rows[0].0, vec![0x00]);
        assert_eq!(scan.rows[1].0, vec![0x00, 0x01]);
        assert!(scan.complete);

        let scan = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[0x00],
            PrefixScanLimit {
                max_rows: 0,
                max_bytes: usize::MAX,
            },
        )?;
        assert_eq!(scan.rows, []);
        assert!(!scan.complete);

        let scan = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[0x00],
            PrefixScanLimit {
                max_rows: usize::MAX,
                max_bytes: 0,
            },
        )?;
        assert_eq!(scan.rows.len(), 1);
        assert_eq!(scan.rows[0].0, vec![0x00]);
        assert!(!scan.complete);
        Ok(())
    }

    fn assert_prefix_boundaries<S: KvStore>(store: &S) -> Result<(), StorageError> {
        let scan = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[],
            PrefixScanLimit {
                max_rows: 100,
                max_bytes: usize::MAX,
            },
        )?;
        assert_eq!(scan.rows.len(), 7);
        assert!(scan.complete);

        for (prefix, expected) in [
            (vec![0x01], vec![vec![0x01], vec![0x01, 0xff]]),
            (vec![0xff], vec![vec![0xff], vec![0xff, 0x00]]),
        ] {
            let scan = store.scan_prefix_bounded(
                ColumnFamily::TxConfirmed,
                &prefix,
                PrefixScanLimit {
                    max_rows: 100,
                    max_bytes: usize::MAX,
                },
            )?;
            let keys: Vec<_> = scan.rows.into_iter().map(|(key, _)| key).collect();
            assert_eq!(keys, expected);
            assert!(scan.complete);
        }
        Ok(())
    }

    type ContinuationScan<'a> =
        &'a dyn Fn(&[u8], &[u8], PrefixScanLimit) -> Result<PrefixScan, StorageError>;

    const ROOMY: PrefixScanLimit = PrefixScanLimit {
        max_rows: 100,
        max_bytes: usize::MAX,
    };

    const fn rows_limit(max_rows: usize) -> PrefixScanLimit {
        PrefixScanLimit {
            max_rows,
            max_bytes: usize::MAX,
        }
    }

    fn scan_keys(scan: &PrefixScan) -> Vec<Vec<u8>> {
        scan.rows.iter().map(|(key, _)| key.clone()).collect()
    }

    fn assert_seek_positions(scan: ContinuationScan<'_>) -> Result<(), StorageError> {
        let one = vec![vec![0x01], vec![0x01, 0xff]];

        let from_first: [&[u8]; 3] = [&[], &[0x00, 0xff], &[0x01]];
        for start in from_first {
            let page = scan(&[0x01], start, ROOMY)?;
            assert_eq!(scan_keys(&page), one);
            assert!(page.complete);
        }

        let from_last: [&[u8]; 2] = [&[0x01, 0x00], &[0x01, 0xff]];
        for start in from_last {
            let page = scan(&[0x01], start, ROOMY)?;
            assert_eq!(scan_keys(&page), vec![vec![0x01, 0xff]]);
            assert!(page.complete);
        }

        let beyond: [&[u8]; 3] = [&[0x01, 0xff, 0x00], &[0x02], &[0xff]];
        for start in beyond {
            let page = scan(&[0x01], start, ROOMY)?;
            assert_eq!(page.rows, []);
            assert!(page.complete);
        }

        let page = scan(&[0xff], &[], ROOMY)?;
        assert_eq!(scan_keys(&page), vec![vec![0xff], vec![0xff, 0x00]]);
        assert!(page.complete);
        let page = scan(&[0xff], &[0xff, 0x00], ROOMY)?;
        assert_eq!(scan_keys(&page), vec![vec![0xff, 0x00]]);
        assert!(page.complete);
        let page = scan(&[0xff], &[0xff, 0x00, 0x00], ROOMY)?;
        assert_eq!(page.rows, []);
        assert!(page.complete);

        let page = scan(&[], &[0x01, 0xff], ROOMY)?;
        assert_eq!(
            scan_keys(&page),
            vec![vec![0x01, 0xff], vec![0x02], vec![0xff], vec![0xff, 0x00]]
        );
        assert!(page.complete);

        let page = scan(&[0x09], &[], ROOMY)?;
        assert_eq!(page.rows, []);
        assert!(page.complete);

        Ok(())
    }

    fn assert_limit_boundaries(scan: ContinuationScan<'_>) -> Result<(), StorageError> {
        let one = vec![vec![0x01], vec![0x01, 0xff]];

        let page = scan(&[0x01], &[], rows_limit(0))?;
        assert_eq!(page.rows, []);
        assert!(!page.complete);
        let exhausted: [(&[u8], &[u8]); 2] = [(&[0x01], &[0x02]), (&[0x09], &[])];
        for (prefix, start) in exhausted {
            let page = scan(prefix, start, rows_limit(0))?;
            assert_eq!(page.rows, []);
            assert!(page.complete);
        }

        let page = scan(&[0x01], &[], rows_limit(1))?;
        assert_eq!(scan_keys(&page), vec![vec![0x01]]);
        assert!(!page.complete);
        let page = scan(&[0x01], &[], rows_limit(2))?;
        assert_eq!(scan_keys(&page), one);
        assert!(page.complete);
        let page = scan(&[0x01], &[0x01, 0x00], rows_limit(1))?;
        assert_eq!(scan_keys(&page), vec![vec![0x01, 0xff]]);
        assert!(page.complete);

        let bytes = |max_bytes| PrefixScanLimit {
            max_rows: 10,
            max_bytes,
        };
        let page = scan(&[0x00], &[], bytes(0))?;
        assert_eq!(scan_keys(&page), vec![vec![0x00]]);
        assert!(!page.complete);
        let page = scan(&[0x00], &[], bytes(5))?;
        assert_eq!(scan_keys(&page), vec![vec![0x00]]);
        assert!(!page.complete);
        let page = scan(&[0x00], &[], bytes(6))?;
        assert_eq!(scan_keys(&page), vec![vec![0x00], vec![0x00, 0x01]]);
        assert!(page.complete);
        Ok(())
    }

    fn assert_pages_resume_without_gaps(scan: ContinuationScan<'_>) -> Result<(), StorageError> {
        let prefixes: [&[u8]; 3] = [&[], &[0x01], &[0xff]];
        for prefix in prefixes {
            let all = scan_keys(&scan(prefix, &[], ROOMY)?);
            assert_ne!(all, Vec::<Vec<u8>>::new());
            for rows_per_page in 1..=all.len() + 1 {
                let mut seen = Vec::new();
                let mut start = Vec::new();
                loop {
                    let page = scan(prefix, &start, rows_limit(rows_per_page))?;
                    let keys = scan_keys(&page);
                    if let Some(last) = keys.last() {
                        start.clone_from(last);
                        start.push(0x00);
                    }
                    seen.extend(keys);
                    if page.complete {
                        break;
                    }
                    assert!(!page.rows.is_empty(), "an incomplete page must progress");
                }
                assert_eq!(seen, all);
            }
        }
        Ok(())
    }

    fn assert_continuation<S: KvStore>(store: &S) -> Result<(), StorageError> {
        let live = |prefix: &[u8], start: &[u8], limit: PrefixScanLimit| {
            store.scan_prefix_from_bounded(ColumnFamily::TxConfirmed, prefix, start, limit)
        };
        assert_seek_positions(&live)?;
        assert_limit_boundaries(&live)?;
        assert_pages_resume_without_gaps(&live)?;

        let snapshot = store.snapshot()?;
        let view = |prefix: &[u8], start: &[u8], limit: PrefixScanLimit| {
            snapshot.scan_prefix_from_bounded(ColumnFamily::TxConfirmed, prefix, start, limit)
        };
        assert_seek_positions(&view)?;
        assert_limit_boundaries(&view)?;
        assert_pages_resume_without_gaps(&view)
    }

    fn assert_snapshot_isolation<S: KvStore>(store: &S) -> Result<(), StorageError> {
        let snapshot = store.snapshot()?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &[0x03], b"after");
        store.write(batch)?;

        let limit = PrefixScanLimit {
            max_rows: 100,
            max_bytes: usize::MAX,
        };
        let snap_scan = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], limit)?;
        assert_eq!(snap_scan.rows.len(), 7);
        assert!(snap_scan.complete);

        let live_scan = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], limit)?;
        assert_eq!(live_scan.rows.len(), 8);
        assert!(live_scan.complete);

        let snap_prefix =
            snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x00], limit)?;
        assert_eq!(snap_prefix.rows.len(), 2);
        assert!(snap_prefix.complete);

        let snap_tail =
            snapshot.scan_prefix_from_bounded(ColumnFamily::TxConfirmed, &[], &[0x02], limit)?;
        assert_eq!(
            scan_keys(&snap_tail),
            vec![vec![0x02], vec![0xff], vec![0xff, 0x00]]
        );
        assert!(snap_tail.complete);
        let live_tail =
            store.scan_prefix_from_bounded(ColumnFamily::TxConfirmed, &[], &[0x02], limit)?;
        assert_eq!(
            scan_keys(&live_tail),
            vec![vec![0x02], vec![0x03], vec![0xff], vec![0xff, 0x00]]
        );
        assert!(live_tail.complete);
        Ok(())
    }

    fn assert_oversized_first_row<S: KvStore>(store: &S) -> Result<(), StorageError> {
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::Spending, &[0x10], &[0u8; 200]);
        batch.put(ColumnFamily::Spending, &[0x10, 0x01], b"small");
        store.write(batch)?;

        let scan = store.scan_prefix_bounded(
            ColumnFamily::Spending,
            &[0x10],
            PrefixScanLimit {
                max_rows: 10,
                max_bytes: 10,
            },
        )?;
        assert_eq!(scan.rows.len(), 1);
        assert_eq!(scan.rows[0].0, vec![0x10]);
        assert!(!scan.complete);

        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::Spending, &[0x10]);
        store.write(batch)?;

        let scan = store.scan_prefix_bounded(
            ColumnFamily::Spending,
            &[0x10],
            PrefixScanLimit {
                max_rows: 10,
                max_bytes: 10,
            },
        )?;
        assert_eq!(scan.rows.len(), 1);
        assert_eq!(scan.rows[0].0, vec![0x10, 0x01]);
        assert!(scan.complete);

        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::Spending, &[0x10, 0x01]);
        store.write(batch)?;

        Ok(())
    }

    fn run_bounded_scan_suite<S: KvStore>(store: &S) -> Result<(), StorageError> {
        seed_rows(store)?;
        assert_limit_semantics(store)?;
        assert_prefix_boundaries(store)?;
        assert_continuation(store)?;
        assert_snapshot_isolation(store)?;
        assert_oversized_first_row(store)
    }

    // ARCH-02
    #[test]
    fn rocksdb_bounded_prefix_scan() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
        run_bounded_scan_suite(&store)?;
        Ok(())
    }
}
mod bounded_value_read {
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::{BoundedReadError, ColumnFamily, KvStore, KvUndoStore, UndoStore};
    use std::sync::Arc;

    use crate::support::TestResult as Result;

    fn check_store(store: impl KvStore) -> Result {
        let store = Arc::new(store);
        store.put(ColumnFamily::UndoData, b"row", b"abcd")?;
        assert!(matches!(
            store.get_bounded(ColumnFamily::UndoData, b"row", 3),
            Err(BoundedReadError::Limit { size: 4, limit: 3 })
        ));
        assert_eq!(
            store.get_bounded(ColumnFamily::UndoData, b"row", 4)?,
            Some(b"abcd".to_vec())
        );
        assert_eq!(
            store.get_bounded(ColumnFamily::UndoData, b"absent", 0)?,
            None
        );
        store.put(ColumnFamily::UndoData, b"empty", b"")?;
        assert_eq!(
            store.get_bounded(ColumnFamily::UndoData, b"empty", 0)?,
            Some(Vec::new())
        );
        let undo = KvUndoStore::new(Arc::clone(&store));
        let hash = Hash256::from_le_bytes(&[7; 32]);
        undo.persist_undo(12, hash, b"undo")?;
        assert!(matches!(
            undo.load_undo_bounded(12, hash, 3),
            Err(BoundedReadError::Limit { .. })
        ));
        assert_eq!(undo.load_undo_bounded(12, hash, 4)?, Some(b"undo".to_vec()));
        assert_eq!(undo.load_undo(12, hash)?, Some(b"undo".to_vec()));
        Ok(())
    }

    #[test]
    fn rocksdb_checks_pinned_length_before_owned_copy() -> Result {
        let dir = tempfile::tempdir()?;
        check_store(bitcoin_rs_storage::RocksDbStore::open(dir.path())?)
    }

    #[test]
    fn memory_undo_checks_length_and_preserves_record() -> Result {
        let undo = bitcoin_rs_storage::InMemoryUndoStore::default();
        let hash = Hash256::from_le_bytes(&[8; 32]);
        undo.persist_undo(1, hash, b"record")?;
        assert!(matches!(
            undo.load_undo_bounded(1, hash, 5),
            Err(BoundedReadError::Limit { size: 6, limit: 5 })
        ));
        assert_eq!(
            undo.load_undo_bounded(1, hash, 6)?,
            Some(b"record".to_vec())
        );
        assert_eq!(undo.load_undo(1, hash)?, Some(b"record".to_vec()));
        Ok(())
    }

    struct Unsupported;
    impl KvStore for Unsupported {
        fn get(
            &self,
            _: ColumnFamily,
            _: &[u8],
        ) -> std::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            panic!("bounded default must never invoke unbounded get")
        }
        fn iter_prefix<'a>(
            &'a self,
            _: ColumnFamily,
            _: &[u8],
        ) -> std::result::Result<bitcoin_rs_storage::KvIter<'a>, bitcoin_rs_storage::StorageError>
        {
            panic!("unused")
        }
        fn scan_prefix_from_bounded(
            &self,
            _: ColumnFamily,
            _: &[u8],
            _: &[u8],
            _: bitcoin_rs_storage::PrefixScanLimit,
        ) -> std::result::Result<bitcoin_rs_storage::PrefixScan, bitcoin_rs_storage::StorageError>
        {
            panic!("unused")
        }
        fn new_batch(&self) -> bitcoin_rs_storage::BufferedWriteBatch {
            panic!("unused")
        }
        fn write(
            &self,
            _: bitcoin_rs_storage::BufferedWriteBatch,
        ) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn write_durable_if(
            &self,
            _: &[bitcoin_rs_storage::WriteCondition<'_>],
            _: bitcoin_rs_storage::BufferedWriteBatch,
        ) -> std::result::Result<bool, bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn flush(&self) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn snapshot(
            &self,
        ) -> std::result::Result<
            Box<dyn bitcoin_rs_storage::KvSnapshot + '_>,
            bitcoin_rs_storage::StorageError,
        > {
            panic!("unused")
        }
        #[cfg(feature = "test-seam")]
        fn arm_persist_fault(&self, _: bitcoin_rs_storage::PersistFault) {
            panic!("unused")
        }
        fn multi_get(
            &self,
            _: ColumnFamily,
            _: &[&[u8]],
        ) -> std::result::Result<Vec<Option<bytes::Bytes>>, bitcoin_rs_storage::StorageError>
        {
            panic!("unused")
        }
        fn ingest_sorted(
            &self,
            _: ColumnFamily,
            _: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            _: &std::path::Path,
        ) -> std::result::Result<u64, bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn delete_range(
            &self,
            _: ColumnFamily,
            _: &[u8],
            _: &[u8],
        ) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn checkpoint(
            &self,
            _: &std::path::Path,
        ) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn engine_cache_bytes(&self) -> u64 {
            0
        }
    }

    #[test]
    fn unsupported_bounded_read_never_uses_unbounded_fallback() {
        assert!(matches!(
            Unsupported.get_bounded(ColumnFamily::UndoData, b"row", 4),
            Err(BoundedReadError::Unsupported)
        ));
        assert!(matches!(
            KvUndoStore::new(Arc::new(Unsupported)).load_undo_bounded(1, Hash256::default(), 4),
            Err(BoundedReadError::Unsupported)
        ));
    }

    struct UnsupportedBody;
    impl bitcoin_rs_storage::block_body::BlockBodyStore for UnsupportedBody {
        fn persist_block_body(
            &self,
            _: u32,
            _: Hash256,
            _: &[u8],
        ) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
        fn load_block_body(
            &self,
            _: u32,
            _: Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            panic!("bounded body default must not load metadata or a full body")
        }
        fn sync(&self) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
            panic!("unused")
        }
    }

    #[test]
    fn unsupported_body_read_never_materializes_metadata_or_body() {
        use bitcoin_rs_storage::block_body::BlockBodyStore as _;
        assert!(matches!(
            UnsupportedBody.load_block_body_bounded(1, Hash256::default(), 4),
            Err(BoundedReadError::Unsupported)
        ));
        assert!(matches!(
            UnsupportedBody.load_block_body_for_verification_bounded(1, Hash256::default(), 4),
            Err(BoundedReadError::Unsupported)
        ));
    }

    #[test]
    fn indexed_body_checks_locator_and_frame_length_before_copy() -> Result {
        use bitcoin_rs_storage::block_body::{BlockBodyStore as _, IndexedBlockBodyStore};
        let dir = tempfile::tempdir()?;
        let index = Arc::new(bitcoin_rs_storage::RocksDbStore::open(
            dir.path().join("index"),
        )?);
        let files = Arc::new(bitcoin_rs_storage::FlatFileBlockStore::open(
            dir.path().join("bodies"),
        )?);
        let store = IndexedBlockBodyStore::new(Arc::clone(&index), files);
        let hash = Hash256::from_le_bytes(&[9; 32]);
        store.persist_block_body(1, hash, b"body")?;
        assert!(matches!(
            store.load_block_body_bounded(1, hash, 3),
            Err(BoundedReadError::Limit { size: 4, limit: 3 })
        ));
        assert_eq!(
            store.load_block_body_bounded(1, hash, 4)?,
            Some(b"body".to_vec())
        );
        let key = bitcoin_rs_storage::pruning::block_body_key(1, hash);
        index.put(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key, &[0; 17])?;
        assert!(matches!(
            store.load_block_body_bounded(1, hash, 4),
            Err(BoundedReadError::Limit {
                size: 17,
                limit: 16
            })
        ));
        Ok(())
    }

    #[test]
    fn empty_and_maximum_size_values_and_read_after_error() -> Result {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);
        let cf = ColumnFamily::TxConfirmed;

        store.put(cf, b"empty_val", b"")?;
        assert_eq!(store.get(cf, b"empty_val")?, Some(Vec::new()));
        assert_eq!(store.get_bounded(cf, b"empty_val", 0)?, Some(Vec::new()));

        let large = vec![0x42_u8; 1024 * 1024];
        store.put(cf, b"large_row", &large)?;
        assert!(matches!(
            store.get_bounded(cf, b"large_row", 512),
            Err(BoundedReadError::Limit {
                size: 1_048_576,
                limit: 512
            })
        ));
        assert_eq!(
            store.get_bounded(cf, b"large_row", 1024 * 1024)?,
            Some(large.clone())
        );
        assert_eq!(store.get(cf, b"large_row")?, Some(large));

        assert!(matches!(
            store.get_bounded(cf, b"large_row", 10),
            Err(BoundedReadError::Limit { .. })
        ));
        assert_eq!(store.get(cf, b"empty_val")?, Some(Vec::new()));

        store.put(cf, b"prefix", b"short")?;
        store.put(cf, b"prefix_longer", b"long")?;
        assert_eq!(store.get(cf, b"prefix")?, Some(b"short".to_vec()));
        assert_eq!(store.get(cf, b"prefix_longer")?, Some(b"long".to_vec()));
        assert_eq!(store.get(cf, b"prefi")?, None);

        Ok(())
    }

    #[test]
    fn flat_file_zero_byte_body_and_read_after_error_recovery() -> Result {
        let dir = tempfile::tempdir()?;
        let store = bitcoin_rs_storage::FlatFileBlockStore::open(dir.path())?;
        let hash1 = [0x11_u8; 32];
        let hash2 = [0x22_u8; 32];

        let pos_empty = store.append(1, hash1, b"")?;
        assert_eq!(pos_empty.len, 0);
        assert_eq!(store.load(pos_empty, 1, hash1)?, Some(Vec::new()));

        let pos_real = store.append(2, hash2, b"actual_payload")?;
        assert_eq!(
            store.load(pos_real, 2, hash2)?,
            Some(b"actual_payload".to_vec())
        );

        assert_eq!(store.load(pos_empty, 1, hash2)?, None);
        assert_eq!(
            store.load(pos_real, 2, hash2)?,
            Some(b"actual_payload".to_vec())
        );
        assert_eq!(store.load(pos_empty, 1, hash1)?, Some(Vec::new()));

        Ok(())
    }
}
mod cache_budget {
    use bitcoin_rs_storage::cache_budget::{
        CHAINSTATE_CACHE_SHARE_PCT, MAX_DBCACHE_BYTES, MIN_DBCACHE_BYTES, TXINDEX_CACHE_SHARE_PCT,
        clamp_dbcache_bytes, split_cache_budget_with_txindex, split_cache_budget_without_txindex,
    };

    #[test]
    fn shares_sum_within_budget_for_every_enabled_combination() {
        let splits = [
            split_cache_budget_with_txindex,
            split_cache_budget_without_txindex,
        ];
        for mb in [0_u64, 1, 16, 17, 333, 450, 999, 1 << 20, u64::MAX] {
            let total = clamp_dbcache_bytes(mb);
            assert!(
                (MIN_DBCACHE_BYTES..=MAX_DBCACHE_BYTES).contains(&total),
                "clamped budget {total} escaped the documented bounds for input {mb}"
            );
            for split in splits {
                let shares = split(total);
                let sum = shares.iter().map(|share| share.bytes).sum::<u64>();
                assert!(
                    sum <= total,
                    "shares ({sum}) exceed budget ({total}) at input {mb}"
                );
            }
        }
    }

    #[test]
    fn disabled_namespaces_redistribute_to_chainstate() {
        let total = clamp_dbcache_bytes(450);
        let shares = split_cache_budget_without_txindex(total);
        assert_eq!(shares[0].bytes, total, "chainstate takes the full budget");
        assert_eq!(shares[1].bytes, 0);

        let shares = split_cache_budget_with_txindex(total);
        assert_eq!(
            shares[1].bytes,
            total * TXINDEX_CACHE_SHARE_PCT / 100,
            "txindex keeps its fixed share"
        );
        assert_eq!(
            shares[0].bytes + shares[1].bytes,
            total,
            "redistributed remainder lands on chainstate"
        );
    }

    #[test]
    fn exact_percentages_at_a_clean_budget() {
        let total = clamp_dbcache_bytes(1000);
        let shares = split_cache_budget_with_txindex(total);
        assert_eq!(shares[0].bytes, total * CHAINSTATE_CACHE_SHARE_PCT / 100);
        assert_eq!(shares[1].bytes, total * TXINDEX_CACHE_SHARE_PCT / 100);
    }

    #[test]
    fn minimum_budget_split_with_all_namespaces_enabled() {
        let total = clamp_dbcache_bytes(16);
        assert_eq!(total, MIN_DBCACHE_BYTES);
        let shares = split_cache_budget_with_txindex(total);
        assert_eq!(
            shares[0].bytes, 13_421_773,
            "chainstate keeps the remainder"
        );
        assert_eq!(shares[1].bytes, 3_355_443, "txindex keeps a floored 20%");
        assert_eq!(
            shares.iter().map(|share| share.bytes).sum::<u64>(),
            total,
            "the 16 MiB budget is fully distributed"
        );
    }
}
mod coins {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use bitcoin_rs_storage::{
        BatchOp, CoinKey, CoinStatsFeed, CoinStore, ColumnFamily, KvStore, PersistFault,
        RocksDbStore, StorageError, WindowDelta,
    };
    use bytes::Bytes;

    use crate::support::TestResult;

    #[test]
    fn multi_get_returns_input_order_absence_and_duplicates() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let mut oracle: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for i in 0_u8..16 {
            let key = vec![i; 4];
            let value = vec![i.wrapping_mul(7); 40];
            store.put(ColumnFamily::Coins, &key, &value)?;
            oracle.insert(key, value);
        }
        let absent = vec![0xff_u8; 4];
        let expected = |key: &[u8]| oracle.get(key).cloned();

        let ascending: Vec<Vec<u8>> = oracle.keys().cloned().collect();
        let refs: Vec<&[u8]> = ascending.iter().map(Vec::as_slice).collect();
        let got = store.multi_get(ColumnFamily::Coins, &refs)?;
        assert_eq!(got.len(), ascending.len());
        for (key, value) in ascending.iter().zip(&got) {
            assert_eq!(value.as_deref(), expected(key).as_deref(), "key {key:?}");
        }

        let query = [
            absent.clone(),
            vec![5_u8; 4],
            vec![0_u8; 4],
            vec![15_u8; 4],
            vec![5_u8; 4],
            absent.clone(),
            vec![7_u8; 4],
        ];
        let refs: Vec<&[u8]> = query.iter().map(Vec::as_slice).collect();
        let got = store.multi_get(ColumnFamily::Coins, &refs)?;
        let expected_order: Vec<Option<Bytes>> = query
            .iter()
            .map(|key| expected(key).map(Bytes::from))
            .collect();
        assert_eq!(got, expected_order);

        assert!(store.multi_get(ColumnFamily::Coins, &[])?.is_empty());
        Ok(())
    }

    #[test]
    fn multi_get_is_isolated_per_column_family() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;
        let key = [9_u8; 8];
        store.put(ColumnFamily::Coins, &key, b"coins-value")?;
        store.put(ColumnFamily::BlockHeaders, &key, b"headers-value")?;

        let got = store.multi_get(ColumnFamily::Coins, &[&key])?;
        assert_eq!(got, vec![Some(Bytes::from_static(b"coins-value"))]);

        let got = store.multi_get(ColumnFamily::BlockHeaders, &[&key])?;
        assert_eq!(got, vec![Some(Bytes::from_static(b"headers-value"))]);

        let got = store.multi_get(ColumnFamily::ScriptLive, &[&key])?;
        assert_eq!(got, vec![None]);
        Ok(())
    }

    fn coin_key(seed: u8) -> CoinKey {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        for (index, byte) in bytes.iter_mut().enumerate().skip(1) {
            *byte = seed
                .wrapping_mul(31)
                .wrapping_add(u8::try_from(index % 251).unwrap_or(0));
        }
        CoinKey(bytes)
    }

    fn committed_delta(key: CoinKey, value: Bytes) -> WindowDelta {
        WindowDelta {
            records: vec![(key, Some(value))],
        }
    }

    #[test]
    fn coin_store_multi_get_merges_cache_and_engine_in_input_order() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let mut seeded: Vec<(CoinKey, Bytes)> = Vec::new();
        for i in 0_u8..8 {
            let key = coin_key(i);
            let value = Bytes::from(vec![i; 96]);
            store.put(ColumnFamily::Coins, key.as_bytes(), &value)?;
            seeded.push((key, value));
        }

        let coins = CoinStore::open(Arc::clone(&store), 64 * 1024);
        let committed = seeded[3].clone();
        coins.install_committed(
            &committed_delta(committed.0, committed.1.clone()),
            CoinStatsFeed::default(),
        );

        let query = [
            coin_key(9),
            seeded[3].0,
            seeded[0].0,
            seeded[5].0,
            seeded[3].0,
        ];
        let got = coins.multi_get(&query)?;
        let expected = vec![
            None,
            Some(committed.1.clone()),
            Some(seeded[0].1.clone()),
            Some(seeded[5].1.clone()),
            Some(committed.1.clone()),
        ];
        assert_eq!(got, expected);

        assert!(
            coins.cache().lookup(&seeded[0].0).is_some(),
            "engine hit arms the cache"
        );
        assert!(coins.cache().lookup(&seeded[5].0).is_some());
        assert!(
            coins.cache().lookup(&coin_key(9)).is_none(),
            "absence never resides"
        );
        assert_eq!(coins.get(&seeded[2].0)?, Some(seeded[2].1.clone()));
        Ok(())
    }

    #[test]
    fn append_window_writes_engine_batch_without_cache_change() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let created = coin_key(1);
        let created_value = Bytes::from(vec![7_u8; 64]);
        let spent = coin_key(2);
        let spent_value = Bytes::from(vec![8_u8; 64]);
        store.put(ColumnFamily::Coins, created.as_bytes(), &created_value)?;
        store.put(ColumnFamily::Coins, spent.as_bytes(), &spent_value)?;
        let created_and_spent = coin_key(3);
        let spent_final = Bytes::from(vec![9_u8; 64]);

        let coins = CoinStore::open(Arc::clone(&store), 16 * 1024);
        let mut delta = WindowDelta::default();
        delta.push_final(created_and_spent, None);
        delta.push_final(spent, Some(spent_final.clone()));
        delta.push_final(created, Some(created_value.clone()));

        let mut inspected = store.new_batch();
        coins.append_window(&mut inspected, &delta)?;
        let ops = inspected.into_ops();
        assert_eq!(ops.len(), 3);
        assert!(
            matches!(&ops[0], BatchOp::Delete { cf: ColumnFamily::Coins, key } if key == created_and_spent.as_bytes()),
            "create-and-spend commits as a delete"
        );
        assert!(
            matches!(&ops[1], BatchOp::Put { cf: ColumnFamily::Coins, key, value } if key == spent.as_bytes() && value == &spent_final)
        );
        assert!(
            matches!(&ops[2], BatchOp::Put { cf: ColumnFamily::Coins, key, value } if key == created.as_bytes() && value == &created_value)
        );

        let mut batch = store.new_batch();
        coins.append_window(&mut batch, &delta)?;
        store.write(batch)?;
        assert!(
            coins.cache().lookup(&created_and_spent).is_none(),
            "append never installs into the cache"
        );
        assert!(coins.cache().lookup(&spent).is_none());
        assert_eq!(
            store.get(ColumnFamily::Coins, created_and_spent.as_bytes())?,
            None
        );
        assert_eq!(
            store.get(ColumnFamily::Coins, spent.as_bytes())?,
            Some(spent_final.to_vec())
        );
        Ok(())
    }

    #[test]
    fn install_ordering_touches_cache_only_after_durable_success() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let created = coin_key(1);
        let created_value = Bytes::from(vec![7_u8; 64]);
        store.put(ColumnFamily::Coins, created.as_bytes(), &created_value)?;
        let created_and_spent = coin_key(3);
        let spent_once = Bytes::from(vec![4_u8; 32]);

        let coins = CoinStore::open(Arc::clone(&store), 16 * 1024);
        let mut delta = WindowDelta::default();
        delta.push_final(created_and_spent, Some(spent_once.clone()));
        delta.push_final(created, None);

        store.arm_persist_fault(PersistFault::FailApply);
        let mut batch = store.new_batch();
        coins.append_window(&mut batch, &delta)?;
        let outcome = store.write_durable(batch);
        assert!(outcome.is_err(), "injected apply fault must fail the batch");
        assert!(
            coins.cache().lookup(&created_and_spent).is_none(),
            "failed batch leaves the cache untouched"
        );
        assert!(coins.cache().lookup(&created).is_none());
        assert_eq!(
            store.get(ColumnFamily::Coins, created_and_spent.as_bytes())?,
            None,
            "failed batch leaves the engine untouched"
        );
        assert_eq!(
            store.get(ColumnFamily::Coins, created.as_bytes())?,
            Some(created_value.to_vec())
        );

        let mut batch = store.new_batch();
        coins.append_window(&mut batch, &delta)?;
        store.write_durable(batch)?;
        assert!(
            coins.cache().lookup(&created_and_spent).is_none(),
            "a durable receipt alone does not install"
        );
        assert_eq!(store.get(ColumnFamily::Coins, created.as_bytes())?, None);

        coins.install_committed(&delta, CoinStatsFeed::default());
        assert_eq!(
            coins.cache().lookup(&created_and_spent),
            Some(spent_once.clone())
        );
        assert!(
            coins.cache().lookup(&created).is_none(),
            "committed delete drops any entry"
        );
        assert_eq!(coins.get(&created_and_spent)?, Some(spent_once));
        Ok(())
    }

    #[test]
    fn ingest_sorted_replaces_values_rejects_unsorted_and_clears_cache() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let coins = CoinStore::open(store, 16 * 1024);
        let k1 = coin_key(1);
        let k2 = coin_key(2);
        let v1 = Bytes::from(vec![1_u8; 40]);
        let v2 = Bytes::from(vec![2_u8; 40]);

        coins.ingest_sorted([(k1, v1.clone()), (k2, v2.clone())].into_iter())?;
        assert_eq!(coins.get(&k1)?, Some(v1));
        assert_eq!(coins.get(&k2)?, Some(v2));

        let stale = Bytes::from_static(b"stale-value");
        coins.install_committed(
            &committed_delta(k1, stale.clone()),
            CoinStatsFeed::default(),
        );
        assert_eq!(coins.cache().lookup(&k1), Some(stale));

        let v1_new = Bytes::from(vec![5_u8; 40]);
        let k3 = coin_key(5);
        let v3 = Bytes::from(vec![3_u8; 40]);
        coins.ingest_sorted([(k1, v1_new.clone()), (k3, v3)].into_iter())?;
        assert_eq!(coins.cache().lookup(&k1), None, "ingest clears the cache");
        assert_eq!(coins.get(&k1)?, Some(v1_new));

        let outcome = coins.ingest_sorted(
            [
                (k3, Bytes::from_static(b"x")),
                (k1, Bytes::from_static(b"y")),
            ]
            .into_iter(),
        );
        assert!(
            matches!(
                outcome,
                Err(StorageError::InvalidOperation(
                    "coin ingest keys must be strictly increasing"
                ))
            ),
            "unsorted ingest must fail closed"
        );
        Ok(())
    }

    #[test]
    fn oversized_committed_replacement_evicts_old_resident_entry() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let coins = CoinStore::open(store, 16 * 1024);
        let k = coin_key(4);
        let v_old = Bytes::from(vec![1_u8; 256]);
        coins.install_committed(&committed_delta(k, v_old.clone()), CoinStatsFeed::default());
        assert_eq!(coins.cache().lookup(&k), Some(v_old));

        let v_huge = Bytes::from(vec![2_u8; 32 * 1024]);
        coins.install_committed(&committed_delta(k, v_huge), CoinStatsFeed::default());
        assert_eq!(
            coins.cache().lookup(&k),
            None,
            "oversized replacement must purge prior resident entry"
        );
        Ok(())
    }

    #[test]
    fn stale_read_fill_does_not_overwrite_newer_commit_or_resurrect_delete() -> TestResult {
        let temp = tempfile::TempDir::new()?;
        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let coins = CoinStore::open(store, 16 * 1024);
        let k = coin_key(7);
        let stale_epoch = coins.cache().epoch(k.shard());

        let v_committed = Bytes::from_static(b"committed-latest");
        coins.install_committed(
            &committed_delta(k, v_committed.clone()),
            CoinStatsFeed::default(),
        );
        assert_eq!(coins.cache().lookup(&k), Some(v_committed.clone()));

        let v_stale = Bytes::from_static(b"stale-read-value");
        coins
            .cache()
            .fill_after_read_guarded(&k, v_stale.clone(), stale_epoch);
        assert_eq!(
            coins.cache().lookup(&k),
            Some(v_committed),
            "stale read fill must be rejected by epoch guard"
        );

        let epoch_before_delete = coins.cache().epoch(k.shard());
        let mut delete_delta = WindowDelta::default();
        delete_delta.push_final(k, None);
        coins.install_committed(&delete_delta, CoinStatsFeed::default());
        assert_eq!(coins.cache().lookup(&k), None);

        coins
            .cache()
            .fill_after_read_guarded(&k, v_stale, epoch_before_delete);
        assert_eq!(
            coins.cache().lookup(&k),
            None,
            "stale read fill must not resurrect deleted coin"
        );
        Ok(())
    }

    #[test]
    fn committed_record_with_440_outputs_survives_store_reopen() -> TestResult {
        use bitcoin_rs_consensus::primitives::Hash256;
        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

        const OUTPUT_COUNT: u32 = 440;
        let temp = tempfile::TempDir::new()?;
        let key = coin_key(11);
        let expected: Vec<OwnedUtxoOut> = (0..OUTPUT_COUNT)
            .map(|vout| OwnedUtxoOut::new(vout, u64::from(vout) + 1, vec![0x51, 0x21], false, 3))
            .collect();
        let record = UtxoRecord::from_owned_outputs(Hash256::from_le_bytes(&key.0), &expected)?;
        let encoded = Bytes::copy_from_slice(record.bytes());

        {
            let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
            let coins = CoinStore::open(Arc::clone(&store), 1 << 20);
            let mut delta = WindowDelta::default();
            delta.push_final(key, Some(encoded.clone()));
            let mut batch = store.new_batch();
            coins.append_window(&mut batch, &delta)?;
            store.write_durable(batch)?;
        }

        let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
        let reopened = CoinStore::open(store, 1 << 20);
        let bytes = reopened.get(&key)?.ok_or(StorageError::InvalidOperation(
            "coin record must survive reopen",
        ))?;
        assert_eq!(bytes, encoded, "reopened record bytes must match");

        let decoded = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?;
        assert_eq!(
            decoded.output_count(),
            usize::try_from(OUTPUT_COUNT).unwrap_or(0)
        );
        let observed: Vec<(u32, u64, Vec<u8>)> = decoded
            .outputs()
            .map(|out| (out.vout, out.value, out.script_pubkey.to_vec()))
            .collect();
        let wanted: Vec<(u32, u64, Vec<u8>)> = expected
            .iter()
            .map(|out| (out.vout, out.value, out.script_pubkey.clone()))
            .collect();
        assert_eq!(observed, wanted, "every output must round-trip");
        Ok(())
    }

    #[test]
    fn duplicate_final_images_match_last_engine_write_and_stats() -> TestResult {
        use bitcoin_rs_consensus::primitives::Hash256;
        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
        use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsListener};

        for delete_final in [false, true] {
            let temp = tempfile::TempDir::new()?;
            let store: Arc<dyn KvStore> = Arc::new(RocksDbStore::open(temp.path())?);
            let coins = CoinStore::open(Arc::clone(&store), 1 << 20);
            let listener = CoinStatsListener::new(CoinStats::new());
            coins.track_coin_stats(listener.clone());
            let key = coin_key(20);
            let other = coin_key(21);
            let image = |key: CoinKey, amount| -> TestResult<Bytes> {
                let record = UtxoRecord::from_owned_outputs(
                    Hash256::from_le_bytes(&key.0),
                    &[OwnedUtxoOut::new(0, amount, vec![0x51], false, 3)],
                )?;
                Ok(Bytes::copy_from_slice(record.bytes()))
            };
            let initial = WindowDelta {
                records: vec![
                    (key, Some(image(key, 100)?)),
                    (other, Some(image(other, 700)?)),
                ],
            };
            let feed = coins.plan_stats_feed(&initial)?;
            let mut batch = store.new_batch();
            coins.append_window(&mut batch, &initial)?;
            store.write_durable(batch)?;
            coins.install_committed(&initial, feed);

            let final_image = if delete_final {
                None
            } else {
                Some(image(key, 250)?)
            };
            let delta = WindowDelta {
                records: vec![
                    (key, Some(image(key, 900)?)),
                    (key, None),
                    (key, final_image.clone()),
                ],
            };
            let feed = coins.plan_stats_feed(&delta)?;
            let mut batch = store.new_batch();
            coins.append_window(&mut batch, &delta)?;
            store.write_durable(batch)?;
            coins.install_committed(&delta, feed);

            assert_eq!(
                store
                    .get(ColumnFamily::Coins, key.as_bytes())?
                    .map(Bytes::from),
                final_image
            );
            assert_eq!(coins.get(&key)?, final_image);
            let stats = listener.snapshot();
            assert_eq!(stats.utxo_count, if delete_final { 1 } else { 2 });
            assert_eq!(stats.total_amount, if delete_final { 700 } else { 950 });
        }
        Ok(())
    }
}
mod durable_head_store {
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::{
        AcceptedPrefix, CoinStore, CommitAuthority, CommitError, CommitRecords, DurableHead,
        DurableHeadStore, KvDurableHeadStore, KvStore, PersistFault, ScriptAttestation,
        StorageError, WindowDelta,
    };

    fn head(commit_id: u64, height: u32) -> DurableHead {
        DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id,
            height,
            tip: Hash256::from_le_bytes(&[0xB0; 32]),
            chain_tx_count: 10,
            body_extent: None,
            undo_extent: None,
        }
    }

    struct Family {
        backend: Arc<bitcoin_rs_storage::RocksDbStore>,
        head: KvDurableHeadStore<bitcoin_rs_storage::RocksDbStore>,
        authority: CommitAuthority,
    }

    fn authority_for(backend: &Arc<bitcoin_rs_storage::RocksDbStore>) -> CommitAuthority {
        let dyn_store: Arc<dyn KvStore> = backend.clone();
        let coins = Arc::new(CoinStore::open(Arc::clone(&dyn_store), 64 * 1024 * 1024));
        CommitAuthority::new(dyn_store, coins)
    }

    fn commit(
        authority: &CommitAuthority,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        authority
            .commit_prefix(AcceptedPrefix {
                expected_head: expected.copied(),
                next_head: *next,
                undo_rows: records
                    .undo_rows
                    .into_iter()
                    .map(|(height, hash, bytes)| {
                        (height, hash, bytes::Bytes::copy_from_slice(bytes))
                    })
                    .collect(),
                body_rows: records.body_rows,
                attestation: records.attestation,
                coin_delta: WindowDelta::default(),
            })
            .map(|_receipt| ())
            .map_err(|error| match error {
                CommitError::Storage(storage) => storage,
                other => StorageError::backend(other),
            })
    }

    fn disconnect(
        authority: &CommitAuthority,
        expected: &DurableHead,
        next: &DurableHead,
    ) -> Result<(), StorageError> {
        authority
            .commit_disconnect(expected, next, WindowDelta::default())
            .map(|_receipt| ())
            .map_err(|error| match error {
                CommitError::Storage(storage) => storage,
                other => StorageError::backend(other),
            })
    }

    fn run_reopen_and_fence_laws() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
        let store = KvDurableHeadStore::new(Arc::clone(&backend));
        let authority = authority_for(&backend);

        let first = head(1, 1);
        commit(&authority, None, &first, CommitRecords::default())?;
        assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));

        let second = head(2, 2);
        let stale = head(9, 9);
        assert!(commit(&authority, Some(&stale), &second, CommitRecords::default()).is_err());
        assert_eq!(store.load()?.map(|h| h.commit_id), Some(1));
        commit(&authority, Some(&first), &second, CommitRecords::default())?;

        drop(authority);
        drop(store);
        drop(backend);
        let reopened = KvDurableHeadStore::new(Arc::new(bitcoin_rs_storage::RocksDbStore::open(
            temp.path(),
        )?));
        assert_eq!(reopened.load()?.map(|h| h.commit_id), Some(2));
        Ok(())
    }

    #[test]
    fn rocksdb_durable_head_reopen_and_fence_laws() -> Result<(), StorageError> {
        run_reopen_and_fence_laws()?;
        Ok(())
    }

    #[test]
    fn malformed_file_maximum_refuses_the_entire_head_batch() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let first = head(1, 20);
        commit(&family.authority, None, &first, CommitRecords::default())?;
        let key = bitcoin_rs_storage::block_file_max_height_key(0);
        let cf = bitcoin_rs_storage::pruning::BLOCK_DATA_CF;
        let mut batch = family.backend.new_batch();
        batch.put(cf, &key, b"corrupt");
        family.backend.write_durable(batch)?;
        let mut records = CommitRecords::default();
        records.body_rows.push((
            1,
            first.tip,
            bitcoin_rs_storage::BlockFilePosition {
                file_no: 0,
                offset: 0,
                len: 80,
            },
        ));
        assert!(matches!(
            commit(&family.authority, Some(&first), &head(2, 20), records),
            Err(StorageError::IncompatibleData(_))
        ));
        assert_eq!(family.head.load()?, Some(first));
        assert_eq!(
            family.backend.get(cf, &key)?.as_deref(),
            Some(b"corrupt".as_slice())
        );
        assert!(
            family
                .backend
                .get(
                    cf,
                    &bitcoin_rs_storage::pruning::block_body_key(1, first.tip)
                )?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn rocksdb_durable_head_faults_never_tear_the_state() -> Result<(), StorageError> {
        for fault in [
            PersistFault::FailApply,
            PersistFault::LostApply,
            PersistFault::PartialApply,
            PersistFault::FailSync,
            PersistFault::LostSync,
            PersistFault::FailFlush,
            PersistFault::LostFlush,
        ] {
            fault_leaves_an_intact_head(fault)?;
        }
        Ok(())
    }

    fn fault_leaves_an_intact_head(fault: PersistFault) -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let first = head(1, 1);
        let next = head(2, 2);
        let outcome = {
            let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
            let authority = authority_for(&backend);

            commit(&authority, None, &first, CommitRecords::default())?;
            backend.arm_persist_fault(fault);
            commit(&authority, Some(&first), &next, CommitRecords::default())
        };

        let reopened = KvDurableHeadStore::new(Arc::new(bitcoin_rs_storage::RocksDbStore::open(
            temp.path(),
        )?));
        let recovered = reopened
            .load()?
            .ok_or_else(|| StorageError::Backend("head row vanished".to_owned()))?;
        assert!(
            recovered == first || recovered == next,
            "fault {fault:?} left a torn head: {recovered:?} (commit outcome {outcome:?})"
        );
        Ok(())
    }

    fn open_store(path: &std::path::Path) -> Result<Family, StorageError> {
        let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(path)?);
        let head = KvDurableHeadStore::new(Arc::clone(&backend));
        let authority = authority_for(&backend);
        Ok(Family {
            backend,
            head,
            authority,
        })
    }

    fn batch_of(level: ScriptAttestation) -> CommitRecords<'static> {
        CommitRecords {
            attestation: Some(level),
            ..CommitRecords::default()
        }
    }

    // RCV-02
    #[test]
    fn a_commit_keeps_the_weakest_attestation_of_the_chain_so_far() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;

        let first = head(1, 1);
        commit(
            &family.authority,
            None,
            &first,
            batch_of(ScriptAttestation::Full),
        )?;
        assert_eq!(
            family.head.load_attestation(&first)?,
            ScriptAttestation::Full
        );

        let second = head(2, 2);
        commit(
            &family.authority,
            Some(&first),
            &second,
            batch_of(ScriptAttestation::AssumeValid),
        )?;
        assert_eq!(
            family.head.load_attestation(&second)?,
            ScriptAttestation::AssumeValid
        );

        let third = head(3, 3);
        commit(
            &family.authority,
            Some(&second),
            &third,
            batch_of(ScriptAttestation::Full),
        )?;
        assert_eq!(
            family.head.load_attestation(&third)?,
            ScriptAttestation::AssumeValid,
            "executing scripts for a later block never repairs an earlier skipped one"
        );

        let fourth = head(4, 4);
        commit(
            &family.authority,
            Some(&third),
            &fourth,
            CommitRecords::default(),
        )?;
        assert_eq!(
            family.head.load_attestation(&fourth)?,
            ScriptAttestation::AssumeValid,
            "a replay that attests nothing carries the previous value to the new head"
        );
        Ok(())
    }

    // RCV-02
    #[test]
    fn a_head_committed_before_attestation_existed_reads_unattested_and_still_commits()
    -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let legacy = head(7, 7);
        let mut batch = family.backend.new_batch();
        batch.put(
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
            &legacy.encode(),
        );
        family.backend.write_durable(batch)?;
        assert_eq!(family.head.load()?, Some(legacy));
        assert_eq!(
            family.head.load_attestation(&legacy)?,
            ScriptAttestation::Unattested
        );

        let next = head(8, 8);
        commit(
            &family.authority,
            Some(&legacy),
            &next,
            batch_of(ScriptAttestation::Full),
        )?;
        assert_eq!(
            family.head.load_attestation(&next)?,
            ScriptAttestation::Unattested,
            "a weaker or unknown history is never upgraded by a stronger batch"
        );
        Ok(())
    }

    // RCV-02
    #[test]
    fn an_attestation_row_bound_to_another_head_reads_unattested() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let first = head(1, 1);
        commit(
            &family.authority,
            None,
            &first,
            batch_of(ScriptAttestation::Full),
        )?;
        let other = head(2, 2);
        assert_eq!(
            family.head.load_attestation(&other)?,
            ScriptAttestation::Unattested,
            "the row names commit 1, so a different head cannot inherit it"
        );
        Ok(())
    }

    // RCV-02
    #[test]
    fn a_corrupt_attestation_row_fails_closed() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let first = head(1, 1);
        commit(
            &family.authority,
            None,
            &first,
            batch_of(ScriptAttestation::Full),
        )?;
        for corrupt in [&[0_u8; 3][..], &[1, 0, 0, 0, 0, 0, 0, 0, 9][..]] {
            let mut batch = family.backend.new_batch();
            batch.put(
                bitcoin_rs_storage::ColumnFamily::UtxoMeta,
                bitcoin_rs_storage::SCRIPT_ATTESTATION_KEY,
                corrupt,
            );
            family.backend.write_durable(batch)?;
            assert!(
                matches!(
                    family.head.load_attestation(&first),
                    Err(StorageError::IncompatibleData(_))
                ),
                "{corrupt:?} must be refused, never read as a weaker or stronger level"
            );
        }
        Ok(())
    }

    // RCV-02
    #[test]
    fn attest_raises_only_the_current_head() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let first = head(1, 1);
        commit(
            &family.authority,
            None,
            &first,
            batch_of(ScriptAttestation::AssumeValid),
        )?;
        family.head.attest(&first, ScriptAttestation::Full)?;
        assert_eq!(
            family.head.load_attestation(&first)?,
            ScriptAttestation::Full
        );
        let moved = head(2, 2);
        commit(
            &family.authority,
            Some(&first),
            &moved,
            CommitRecords::default(),
        )?;
        assert!(
            family.head.attest(&first, ScriptAttestation::Full).is_err(),
            "a head that is no longer current cannot be attested"
        );
        Ok(())
    }

    // RCV-01, RCV-04
    #[test]
    fn rejects_reopen_with_corrupt_or_truncated_durable_head() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let valid = head(1, 1);
        commit(&family.authority, None, &valid, CommitRecords::default())?;
        let encoded = valid.encode();
        let cf = bitcoin_rs_storage::ColumnFamily::UtxoMeta;
        let key = bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY;

        let mut truncated = family.backend.new_batch();
        truncated.put(cf, key, &encoded[..10]);
        family.backend.write_durable(truncated)?;
        assert!(matches!(
            family.head.load(),
            Err(StorageError::IncompatibleData(_))
        ));

        let mut bad_magic = encoded;
        bad_magic[0] = b'X';
        let mut batch = family.backend.new_batch();
        batch.put(cf, key, &bad_magic);
        family.backend.write_durable(batch)?;
        assert!(matches!(
            family.head.load(),
            Err(StorageError::IncompatibleData(_))
        ));

        let mut bad_version = encoded;
        bad_version[4] = 99;
        let mut batch = family.backend.new_batch();
        batch.put(cf, key, &bad_version);
        family.backend.write_durable(batch)?;
        assert!(matches!(
            family.head.load(),
            Err(StorageError::IncompatibleData(_))
        ));

        let mut bad_crc = encoded;
        let last = bad_crc.len() - 1;
        bad_crc[last] ^= 0xff;
        let mut batch = family.backend.new_batch();
        batch.put(cf, key, &bad_crc);
        family.backend.write_durable(batch)?;
        assert!(matches!(
            family.head.load(),
            Err(StorageError::IncompatibleData(_))
        ));

        Ok(())
    }

    // RCV-03, RCV-04
    #[test]
    fn crash_windows_failing_backend_writer_at_each_write_index_preserves_atomic_reopen()
    -> Result<(), StorageError> {
        let cf = bitcoin_rs_storage::ColumnFamily::TxConfirmed;
        let mut wrote_keys_before_fault = false;
        for fail_index in 0..=5_u8 {
            let temp = tempfile::tempdir()?;
            let present;
            {
                let backend = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
                let mut prefix_batch = backend.new_batch();
                for i in 0..fail_index {
                    prefix_batch.put(cf, &[i], &[i, i]);
                }
                backend.write_durable(prefix_batch)?;
                if fail_index < 5 {
                    for i in 0..fail_index {
                        assert_eq!(
                            backend.get(cf, &[i])?.as_deref(),
                            Some(&[i, i][..]),
                            "fail_index {fail_index}: witness key {i} missing before the fault"
                        );
                    }
                    if fail_index > 0 {
                        wrote_keys_before_fault = true;
                    }
                    let mut full_batch = backend.new_batch();
                    for i in 0..5_u8 {
                        full_batch.put(cf, &[i], &[i, i]);
                    }
                    backend.arm_persist_fault(PersistFault::LostApply);
                    let _ = backend.write_durable(full_batch);
                }
                present = key_states(&backend, cf)?;
            }
            let reopened = Arc::new(bitcoin_rs_storage::RocksDbStore::open(temp.path())?);
            let reopened_present = key_states(&reopened, cf)?;
            let pre_batch: Vec<u8> = (0..fail_index).collect();
            let post_batch: Vec<u8> = (0..5).collect();
            assert!(
                reopened_present == pre_batch || reopened_present == post_batch,
                "fail_index {fail_index} reopened a torn state with keys {reopened_present:?} \
             present; expected exactly {pre_batch:?} or {post_batch:?}"
            );
            assert_eq!(present, pre_batch);
            assert_eq!(reopened_present, present);
        }
        assert!(
            wrote_keys_before_fault,
            "no fail_index run observed written keys before its fault"
        );
        Ok(())
    }

    fn validating_head(commit_id: u64, height: u32) -> DurableHead {
        DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Validating {
                base_height: 2,
                base_hash: Hash256::from_le_bytes(&[0xB1; 32]),
                expected_hash_serialized: Hash256::from_le_bytes(&[0xB2; 32]),
                chain_tx_count: 3,
                historical_height: 0,
                historical_hash: Hash256::default(),
                pending: None,
                checkpoint: None,
            },
            commit_id,
            height,
            tip: Hash256::from_le_bytes(&[0xB0; 32]),
            chain_tx_count: 10,
            body_extent: None,
            undo_extent: None,
        }
    }

    #[test]
    fn rocksdb_suffix_attestation_tracks_only_pending_validation_commits()
    -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let family = open_store(temp.path())?;
        let base = validating_head(1, 2);
        commit(&family.authority, None, &base, CommitRecords::default())?;
        assert_eq!(
            family.head.load_suffix_attestation(&base)?,
            ScriptAttestation::Full,
            "installing the base leaves no suffix commit to distrust"
        );
        let skipped = validating_head(2, 3);
        commit(
            &family.authority,
            Some(&base),
            &skipped,
            CommitRecords {
                attestation: Some(ScriptAttestation::AssumeValid),
                ..CommitRecords::default()
            },
        )?;
        assert_eq!(
            family.head.load_suffix_attestation(&skipped)?,
            ScriptAttestation::AssumeValid
        );
        let executed = validating_head(3, 4);
        commit(
            &family.authority,
            Some(&skipped),
            &executed,
            CommitRecords {
                attestation: Some(ScriptAttestation::Full),
                ..CommitRecords::default()
            },
        )?;
        assert_eq!(
            family.head.load_suffix_attestation(&executed)?,
            ScriptAttestation::AssumeValid,
            "a commit never raises the weakest suffix level"
        );
        let progress = validating_head(4, 4);
        commit(
            &family.authority,
            Some(&executed),
            &progress,
            CommitRecords::default(),
        )?;
        assert_eq!(
            family.head.load_suffix_attestation(&progress)?,
            ScriptAttestation::AssumeValid,
            "a status-only commit keeps the suffix level"
        );
        let finalized = head(5, 4);
        commit(
            &family.authority,
            Some(&progress),
            &finalized,
            CommitRecords::default(),
        )?;
        assert_eq!(
            family.head.load_suffix_attestation(&finalized)?,
            ScriptAttestation::Unattested,
            "the suffix row names only a pending-validation head"
        );
        Ok(())
    }

    // RCV-02, RCV-08
    #[test]
    fn a_disconnect_carries_the_attestation_to_the_new_commit() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let first = head(1, 1);
        let disconnected = head(2, 2);
        let back = head(3, 1);
        {
            let family = open_store(temp.path())?;
            commit(
                &family.authority,
                None,
                &first,
                batch_of(ScriptAttestation::Full),
            )?;
            commit(
                &family.authority,
                Some(&first),
                &disconnected,
                CommitRecords::default(),
            )?;
            disconnect(&family.authority, &disconnected, &back)?;
        }
        let reopened = open_store(temp.path())?;
        assert_eq!(reopened.head.load()?, Some(back));
        assert_eq!(
            reopened.head.load_attestation(&back)?,
            ScriptAttestation::Full,
            "a disconnect re-labels the previous attestation under the new commit id"
        );
        Ok(())
    }

    // RCV-02, RCV-08
    #[test]
    fn a_disconnect_carries_the_suffix_attestation_to_the_new_commit() -> Result<(), StorageError> {
        let temp = tempfile::tempdir()?;
        let base = validating_head(1, 2);
        let skipped = validating_head(2, 3);
        let back = validating_head(3, 2);
        {
            let family = open_store(temp.path())?;
            commit(&family.authority, None, &base, CommitRecords::default())?;
            commit(
                &family.authority,
                Some(&base),
                &skipped,
                batch_of(ScriptAttestation::AssumeValid),
            )?;
            disconnect(&family.authority, &skipped, &back)?;
        }
        let reopened = open_store(temp.path())?;
        assert_eq!(reopened.head.load()?, Some(back));
        assert_eq!(
            reopened.head.load_suffix_attestation(&back)?,
            ScriptAttestation::AssumeValid,
            "a disconnect re-labels the suffix level under the new commit id"
        );
        Ok(())
    }

    fn key_states(
        store: &Arc<bitcoin_rs_storage::RocksDbStore>,
        cf: bitcoin_rs_storage::ColumnFamily,
    ) -> Result<Vec<u8>, StorageError> {
        let mut present = Vec::new();
        for i in 0..5_u8 {
            let value = store.get(cf, &[i])?;
            if let Some(bytes) = value {
                assert_eq!(bytes.as_slice(), &[i, i][..], "key {i} holds torn bytes");
                present.push(i);
            }
        }
        Ok(present)
    }
}
mod engine_findings {
    use std::sync::Arc;
    use std::time::Duration;

    #[cfg(feature = "surrealkv")]
    use bitcoin_rs_storage::StorageError;
    use bitcoin_rs_storage::{
        BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore, WriteCondition,
    };

    use crate::support::TestResult;

    fn map_err(e: impl std::fmt::Display) -> crate::test_support_error::TestError {
        crate::test_support_error::TestError::Io(std::io::Error::other(e.to_string()))
    }

    fn thread_err(_: Box<dyn std::any::Any + Send>) -> crate::test_support_error::TestError {
        crate::test_support_error::TestError::Io(std::io::Error::other("thread panicked"))
    }
    struct PausingIter {
        items: Vec<(Vec<u8>, Vec<u8>)>,
        idx: usize,
        pause_at: usize,
        started_tx: Option<std::sync::mpsc::SyncSender<()>>,
        resume_rx: std::sync::mpsc::Receiver<()>,
    }

    impl Iterator for PausingIter {
        type Item = (Vec<u8>, Vec<u8>);

        fn next(&mut self) -> Option<Self::Item> {
            if self.idx == self.pause_at {
                if let Some(tx) = self.started_tx.take() {
                    let _ = tx.send(());
                }
                let _ = self.resume_rx.recv();
            }
            if self.idx < self.items.len() {
                let item = self.items[self.idx].clone();
                self.idx += 1;
                Some(item)
            } else {
                None
            }
        }
    }

    #[test]
    fn eng_01_concurrent_ingest_and_write_durable_if() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let db_path = temp.path().join("db");
        let scratch_path = temp.path().join("scratch");
        std::fs::create_dir_all(&scratch_path)?;

        let store = Arc::new(RocksDbStore::open(&db_path)?);
        let cf = ColumnFamily::Coins;

        let mut batch = BufferedWriteBatch::default();
        batch.put(cf, b"k", b"v0");
        store.write_durable(batch)?;

        let (started_tx, started_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(1);

        let store_clone1 = Arc::clone(&store);
        let scratch_clone = scratch_path.clone();
        let ingest_handle = std::thread::spawn(move || {
            let mut iter = PausingIter {
                items: vec![(b"ingest_k".to_vec(), b"ingest_v".to_vec())],
                idx: 0,
                pause_at: 0,
                started_tx: Some(started_tx),
                resume_rx,
            };
            store_clone1.ingest_sorted(cf, &mut iter, &scratch_clone)
        });

        started_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(map_err)?;

        let store_clone2 = Arc::clone(&store);
        let (cond_done_tx, cond_done_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let cond_handle = std::thread::spawn(move || {
            let cond = WriteCondition::Equals {
                cf,
                key: b"k",
                expected: b"v0",
            };
            let mut b = BufferedWriteBatch::default();
            b.put(cf, b"k", b"v1");
            let res = store_clone2.write_durable_if(&[cond], b);
            let _ = cond_done_tx.send(());
            res
        });

        let early_completion = cond_done_rx.recv_timeout(Duration::from_millis(100));
        assert!(
            early_completion.is_err(),
            "ENG-01 regression: write_durable_if executed concurrently while ingest_sorted was in flight; write_lock was not held!"
        );

        let _ = resume_tx.send(());
        let ingest_res = ingest_handle.join().map_err(thread_err)?;
        assert!(ingest_res.is_ok());
        let cond_res = cond_handle.join().map_err(thread_err)?;
        assert!(cond_res.is_ok());

        let scratch_shared = temp.path().join("scratch_shared");
        std::fs::create_dir_all(&scratch_shared)?;

        let (t1_started_tx, t1_started_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (t1_resume_tx, t1_resume_rx) = std::sync::mpsc::sync_channel::<()>(1);

        let store_c1 = Arc::clone(&store);
        let scratch_c1 = scratch_shared.clone();
        let h1 = std::thread::spawn(move || {
            let mut iter = PausingIter {
                items: vec![
                    (b"shared_k1".to_vec(), b"v1".to_vec()),
                    (b"shared_k2".to_vec(), b"v2".to_vec()),
                ],
                idx: 0,
                pause_at: 1,
                started_tx: Some(t1_started_tx),
                resume_rx: t1_resume_rx,
            };
            store_c1.ingest_sorted(cf, &mut iter, &scratch_c1)
        });

        t1_started_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(map_err)?;

        let store_c2 = Arc::clone(&store);
        let scratch_c2 = scratch_shared.clone();
        let h2 = std::thread::spawn(move || {
            let mut rows = vec![(b"shared_k2".to_vec(), b"v2".to_vec())].into_iter();
            store_c2.ingest_sorted(cf, &mut rows, &scratch_c2)
        });

        let _ = t1_resume_tx.send(());
        let res1 = h1.join().map_err(thread_err)?;
        let res2 = h2.join().map_err(thread_err)?;
        assert!(res1.is_ok(), "t1 ingest failed: {res1:?}");
        assert!(res2.is_ok(), "t2 ingest failed: {res2:?}");
        Ok(())
    }

    #[cfg(feature = "surrealkv")]
    #[test]
    fn eng_02_surrealkv_iter_prefix_paged_streaming() -> TestResult<()> {
        use bitcoin_rs_storage::SurrealKvStore;
        use std::collections::BTreeMap;

        let temp = tempfile::TempDir::new()?;
        let db_path = temp.path().join("db");

        let store = SurrealKvStore::open_with_cache(&db_path, 64 * 1024 * 1024)?;
        let cf = ColumnFamily::Coins;

        let mut oracle = BTreeMap::new();
        let mut batch = BufferedWriteBatch::default();

        for i in 0..200 {
            let key = format!("pfx:{i:05}").into_bytes();
            let value = format!("val:{i:05}").into_bytes();
            oracle.insert(key.clone(), value.clone());
            batch.put(cf, &key, &value);
        }

        for i in 0..50 {
            let key = format!("other:{i:05}").into_bytes();
            let value = format!("oval:{i:05}").into_bytes();
            batch.put(cf, &key, &value);
        }
        batch.put(cf, b"pfy:00000", b"val:pfy");

        store.write_durable(batch)?;

        let iter = store.iter_prefix(cf, b"pfx:")?;
        let rows: Vec<(Vec<u8>, Vec<u8>)> = iter.collect::<Result<_, _>>()?;
        let expected: Vec<(Vec<u8>, Vec<u8>)> =
            oracle.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        assert_eq!(rows.len(), 200);
        assert_eq!(rows, expected);

        let snapshot = store.snapshot()?;
        let snap_iter = snapshot.iter_prefix(cf, b"pfx:")?;
        let snap_rows: Vec<(Vec<u8>, Vec<u8>)> = snap_iter.collect::<Result<_, _>>()?;
        assert_eq!(snap_rows.len(), 200);
        assert_eq!(snap_rows, expected);

        let mut early_iter = store.iter_prefix(cf, b"pfx:")?;
        let first_ten: Vec<_> = early_iter.by_ref().take(10).collect::<Result<_, _>>()?;
        assert_eq!(first_ten.len(), 10);
        drop(early_iter);
        Ok(())
    }

    #[cfg(feature = "surrealkv")]
    #[test]
    fn eng_03_surrealkv_concurrent_close_barrier() -> TestResult<()> {
        use bitcoin_rs_storage::SurrealKvStore;

        for i in 0..20 {
            let temp = tempfile::TempDir::new()?;
            let db_path = temp.path().join("db");

            let store = SurrealKvStore::open_with_cache(&db_path, 64 * 1024 * 1024)?;
            let cf = ColumnFamily::Coins;

            let mut batch = BufferedWriteBatch::default();
            let key = format!("close_key_{i}").into_bytes();
            let val = format!("close_val_{i}").into_bytes();
            batch.put(cf, &key, &val);
            store.write_durable(batch)?;

            let store = Arc::new(store);

            let (t2_done_tx, t2_done_rx) =
                std::sync::mpsc::sync_channel::<Result<(), StorageError>>(1);
            let s1 = Arc::clone(&store);
            let h1 = std::thread::spawn(move || s1.close());

            let s2 = Arc::clone(&store);
            let h2 = std::thread::spawn(move || {
                let res = s2.close();
                let _ = t2_done_tx.send(res);
            });

            let res2 = t2_done_rx.recv().map_err(map_err)?;
            assert!(res2.is_ok(), "closer 2 failed: {res2:?}");

            let reopened = SurrealKvStore::open_with_cache(&db_path, 64 * 1024 * 1024)?;
            let read_val = reopened.get(cf, &key)?;
            assert_eq!(read_val, Some(val));

            let res1 = h1.join().map_err(thread_err)?;
            let _ = h2.join();
            assert!(res1.is_ok(), "closer 1 failed: {res1:?}");
        }
        Ok(())
    }
}
mod kv_store_object_safety {
    use crate::support::TestResult;
    use bitcoin_rs_storage::{ColumnFamily, KvStore};

    #[test]
    fn kv_store_dispatches_through_a_trait_object() -> TestResult {
        let dir = tempfile::tempdir()?;
        let store: Box<dyn KvStore> = Box::new(bitcoin_rs_storage::RocksDbStore::open(dir.path())?);

        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"dispatch-key", b"v");
        store.write(batch)?;

        assert_eq!(
            store.get(ColumnFamily::BlockBodies, b"dispatch-key")?,
            Some(b"v".to_vec())
        );
        Ok(())
    }
}
mod overhaul_atomic_durability {
    #![expect(clippy::expect_used, reason = "test assertions")]

    use bitcoin_rs_storage::{
        BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault,
        PrefixScan, PrefixScanLimit, StorageError, WriteCondition,
    };
    use std::collections::BTreeMap;
    use std::fmt;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, LazyLock};

    const FAMILIES: [ColumnFamily; 3] = [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
    ];

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FamilyState {
        rows: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl fmt::Display for FamilyState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{} rows: ", self.rows.len())?;
            for (key, value) in &self.rows {
                write!(f, "{key:02x?}->{value:02x?}, ")?;
            }
            Ok(())
        }
    }

    fn snapshot_all(store: &impl KvStore) -> Vec<FamilyState> {
        FAMILIES
            .iter()
            .map(|cf| {
                let mut rows = Vec::new();
                if let Ok(iter) = store.iter_prefix(*cf, b"") {
                    for (key, value) in iter.flatten() {
                        rows.push((key, value));
                    }
                }
                FamilyState { rows }
            })
            .collect()
    }

    fn multi_family_batch<S: KvStore>(store: &S, label: &[u8]) -> BufferedWriteBatch {
        let mut batch = store.new_batch();
        for (index, cf) in FAMILIES.iter().enumerate() {
            batch.put(*cf, &[u8::try_from(index).unwrap_or(0)], label);
        }
        batch
    }

    enum Route {
        Write,
        WriteDurable,
        WriteDurableIf,
        FlushDeferred,
    }

    impl Route {
        fn label(&self) -> &'static str {
            match self {
                Self::Write => "write",
                Self::WriteDurable => "write_durable",
                Self::WriteDurableIf => "write_durable_if",
                Self::FlushDeferred => "write_deferred+flush",
            }
        }
    }

    const FAULTS: [PersistFault; 7] = [
        PersistFault::FailApply,
        PersistFault::LostApply,
        PersistFault::PartialApply,
        PersistFault::FailSync,
        PersistFault::LostSync,
        PersistFault::FailFlush,
        PersistFault::LostFlush,
    ];

    fn fault_name(fault: PersistFault) -> &'static str {
        match fault {
            PersistFault::FailApply => "FailApply",
            PersistFault::LostApply => "LostApply",
            PersistFault::PartialApply => "PartialApply",
            PersistFault::FailSync => "FailSync",
            PersistFault::LostSync => "LostSync",
            PersistFault::FailFlush => "FailFlush",
            PersistFault::LostFlush => "LostFlush",
        }
    }

    #[test]
    fn rocksdb_injected_faults_never_mix_families() {
        run_fault_matrix("rocksdb", |path| {
            bitcoin_rs_storage::RocksDbStore::open(path)
        });
    }

    fn run_fault_matrix<S, F>(backend: &str, open: F)
    where
        S: KvStore,
        F: Fn(&Path) -> Result<S, bitcoin_rs_storage::StorageError> + Copy,
    {
        let routes = [
            Route::Write,
            Route::WriteDurable,
            Route::WriteDurableIf,
            Route::FlushDeferred,
        ];
        for route in &routes {
            for fault in FAULTS {
                let dir = tempfile::tempdir().expect("tempdir");
                one_scenario(backend, open, dir.path(), fault, route);
            }
        }
        let dir = tempfile::tempdir().expect("tempdir");
        assert_later_durable_receipt_covers_deferred(backend, open, dir.path());
    }

    fn assert_later_durable_receipt_covers_deferred<S, F>(backend: &str, open: F, path: &Path)
    where
        S: KvStore,
        F: Fn(&Path) -> Result<S, StorageError> + Copy,
    {
        let rows: [(ColumnFamily, &[u8]); 2] = [
            (ColumnFamily::TxConfirmed, b"receipt/deferred"),
            (ColumnFamily::Funding, b"receipt/durable"),
        ];
        for guarded in [false, true] {
            let label = if guarded {
                format!("{backend}/guarded-receipt")
            } else {
                format!("{backend}/durable-receipt")
            };
            {
                let store = open(path).expect("open for deferred receipt seed");
                let mut seed = store.new_batch();
                for (cf, key) in rows {
                    seed.put(cf, key, b"old");
                }
                store
                    .write_durable(seed)
                    .expect("seed deferred receipt state");
                let mut deferred = store.new_batch();
                deferred.put(rows[0].0, rows[0].1, b"deferred");
                store.write_deferred(deferred).expect("deferred write");
                if guarded {
                    let mut receipt = store.new_batch();
                    receipt.put(rows[1].0, rows[1].1, b"receipt");
                    let committed = store
                        .write_durable_if(
                            &[WriteCondition::Equals {
                                cf: rows[1].0,
                                key: rows[1].1,
                                expected: b"old",
                            }],
                            receipt,
                        )
                        .expect("guarded durable receipt");
                    assert!(committed, "{label}: guard unexpectedly mismatched");
                } else {
                    let mut receipt = store.new_batch();
                    receipt.put(rows[1].0, rows[1].1, b"receipt");
                    store.write_durable(receipt).expect("durable receipt");
                }
            }

            let store = open(path).expect("reopen after durable receipt");
            assert_eq!(
                store
                    .get(rows[0].0, rows[0].1)
                    .expect("read earlier deferred row")
                    .as_deref(),
                Some(&b"deferred"[..]),
                "{label}: earlier deferred write did not survive reopen"
            );
            assert_eq!(
                store
                    .get(rows[1].0, rows[1].1)
                    .expect("read receipt row")
                    .as_deref(),
                Some(&b"receipt"[..]),
                "{label}: durable receipt row did not survive reopen"
            );
        }
    }

    fn one_scenario<S, F>(backend: &str, open: F, path: &Path, fault: PersistFault, route: &Route)
    where
        S: KvStore,
        F: Fn(&Path) -> Result<S, bitcoin_rs_storage::StorageError>,
    {
        let label = format!("{backend}/{}/{})", route.label(), fault_name(fault));

        let old = {
            let store = open(path).expect("open for seed");
            store
                .write_durable(multi_family_batch(&store, b"old"))
                .expect("seed write");
            snapshot_all(&store)
        };

        let outcome = {
            let store = open(path).expect("reopen to arm");
            store.arm_persist_fault(fault);
            let batch = multi_family_batch(&store, b"new");
            match route {
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
                Route::FlushDeferred => store.write_deferred(batch).and_then(|()| store.flush()),
            }
        };

        let after = {
            let store = open(path).expect("reopen to inspect");
            snapshot_all(&store)
        };
        let expected_old = sorted_families(&old);
        let expected_new = retagged_new(&expected_old);
        let observed = sorted_families(&after);
        assert!(
            observed == expected_old || observed == expected_new,
            "{label}: recovered as a mix: {observed:?} (old {expected_old:?}, new {expected_new:?})"
        );

        if matches!(
            fault,
            PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply
        ) {
            assert_eq!(
                observed, expected_old,
                "{label}: apply-boundary fault left batch rows behind"
            );
        }

        assert_fault_outcome(route, fault, outcome.is_ok(), &label);
    }

    fn sorted_families(state: &[FamilyState]) -> Vec<FamilyState> {
        let mut sorted = state.to_vec();
        for family in &mut sorted {
            family.rows.sort();
        }
        sorted
    }

    fn retagged_new(state: &[FamilyState]) -> Vec<FamilyState> {
        state
            .iter()
            .map(|family| FamilyState {
                rows: family
                    .rows
                    .iter()
                    .map(|(key, _)| (key.clone(), b"new".to_vec()))
                    .collect(),
            })
            .collect()
    }

    fn assert_fault_outcome(
        route: &Route,
        fault: PersistFault,
        reported_success: bool,
        label: &str,
    ) {
        match route {
            Route::Write => {
                if matches!(fault, PersistFault::FailApply | PersistFault::PartialApply) {
                    assert!(
                        !reported_success,
                        "{label}: plain write reported success on a faulted apply"
                    );
                }
            }
            Route::WriteDurable | Route::WriteDurableIf => match fault {
                PersistFault::FailApply
                | PersistFault::LostApply
                | PersistFault::PartialApply
                | PersistFault::FailSync
                | PersistFault::LostSync => assert!(
                    !reported_success,
                    "{label}: durable route reported success despite an observed fault"
                ),
                PersistFault::FailFlush | PersistFault::LostFlush => {}
            },
            Route::FlushDeferred => match fault {
                PersistFault::FailApply
                | PersistFault::LostApply
                | PersistFault::PartialApply
                | PersistFault::FailFlush
                | PersistFault::LostFlush => assert!(
                    !reported_success,
                    "{label}: deferred+flush route reported success despite an observed fault"
                ),
                PersistFault::FailSync | PersistFault::LostSync => {}
            },
        }
    }

    #[test]
    fn rocksdb_condition_mismatch_applies_nothing_and_consumes_no_fault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("open");
        assert_mismatch_applies_nothing_and_consumes_no_fault(&store);
    }

    fn assert_mismatch_applies_nothing_and_consumes_no_fault<S: KvStore>(store: &S) {
        store
            .write_durable(multi_family_batch(store, b"old"))
            .expect("seed");

        store.arm_persist_fault(PersistFault::FailApply);

        let committed = store
            .write_durable_if(
                &[WriteCondition::Equals {
                    cf: FAMILIES[0],
                    key: &[0],
                    expected: b"not-the-seeded-value",
                }],
                multi_family_batch(store, b"new"),
            )
            .expect("condition evaluation must not error");
        assert!(!committed, "condition mismatch must report Ok(false)");

        for (index, cf) in FAMILIES.iter().enumerate() {
            let observed = store
                .get(*cf, &[u8::try_from(index).unwrap_or(0)])
                .expect("read")
                .expect("row exists");
            assert_eq!(
                observed,
                b"old".to_vec(),
                "family {index} observed batch effects from a mismatched conditional write"
            );
        }

        let outcome = store.write_durable_if(
            &[WriteCondition::Equals {
                cf: FAMILIES[0],
                key: &[0],
                expected: b"old",
            }],
            multi_family_batch(store, b"newer"),
        );
        assert!(
            outcome.is_err(),
            "the armed FailApply fault must fire on the matching conditional write"
        );
    }

    #[test]
    fn rocksdb_fail_apply_errors_on_plain_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("open");
        store.arm_persist_fault(PersistFault::FailApply);
        assert!(
            store.write(multi_family_batch(&store, b"new")).is_err(),
            "FailApply must return Err on the plain write route"
        );
    }

    #[test]
    fn rocksdb_snapshot_is_coherent_across_batch_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = bitcoin_rs_storage::RocksDbStore::open(dir.path()).expect("open");
        store
            .write_durable(multi_family_batch(&store, b"before"))
            .expect("seed");

        let snapshot = store.snapshot().expect("snapshot");
        store
            .write(multi_family_batch(&store, b"after"))
            .expect("commit while held");

        for (index, cf) in FAMILIES.iter().enumerate() {
            let observed = snapshot
                .get(*cf, &[u8::try_from(index).unwrap_or(0)])
                .expect("snapshot read")
                .expect("row exists");
            assert_eq!(
                observed,
                b"before".to_vec(),
                "snapshot mixed pre- and post-batch rows in family {index}"
            );
        }
    }

    type OneFamilyRows = BTreeMap<(u8, Vec<u8>), Vec<u8>>;

    type SharedOneFamilyRows = Arc<parking_lot::Mutex<OneFamilyShared>>;

    struct OneFamilyShared {
        rows: OneFamilyRows,
        defect_armed: bool,
    }

    fn shared_one_family_rows(path: &Path) -> SharedOneFamilyRows {
        static REGISTRY: LazyLock<parking_lot::Mutex<BTreeMap<PathBuf, SharedOneFamilyRows>>> =
            LazyLock::new(|| parking_lot::Mutex::new(BTreeMap::new()));
        REGISTRY
            .lock()
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                Arc::new(parking_lot::Mutex::new(OneFamilyShared {
                    rows: OneFamilyRows::new(),
                    defect_armed: false,
                }))
            })
            .clone()
    }

    struct OneFamilyStore {
        rows: SharedOneFamilyRows,
    }

    impl OneFamilyStore {
        fn open(path: &Path) -> Self {
            Self {
                rows: shared_one_family_rows(path),
            }
        }
    }

    fn family_index(cf: ColumnFamily) -> u8 {
        u8::try_from(cf.index()).unwrap_or(0)
    }

    fn op_cf(op: &BatchOp) -> ColumnFamily {
        match op {
            BatchOp::Put { cf, .. }
            | BatchOp::Delete { cf, .. }
            | BatchOp::DeleteRange { cf, .. } => *cf,
        }
    }

    fn apply_one_family_ops(rows: &mut OneFamilyShared, ops: Vec<BatchOp>) {
        let defect_armed = rows.defect_armed;
        rows.defect_armed = false;
        let Some(committed) = ops.first().map(op_cf) else {
            return;
        };
        for op in ops
            .into_iter()
            .filter(|op| !defect_armed || op_cf(op) == committed)
        {
            let cf = family_index(op_cf(&op));
            match op {
                BatchOp::Put { key, value, .. } => {
                    rows.rows.insert((cf, key), value.into());
                }
                BatchOp::Delete { key, .. } => {
                    rows.rows.remove(&(cf, key));
                }
                BatchOp::DeleteRange { start, end, .. } => {
                    let doomed: Vec<Vec<u8>> = rows
                        .rows
                        .keys()
                        .filter(|(row_cf, key)| *row_cf == cf && *key >= start && *key < end)
                        .map(|(_, key)| key.clone())
                        .collect();
                    for key in doomed {
                        rows.rows.remove(&(cf, key));
                    }
                }
            }
        }
    }

    fn scan_one_family_from(
        rows: &OneFamilyRows,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> PrefixScan {
        let family = family_index(cf);
        let mut taken = Vec::new();
        let mut bytes = 0usize;
        for ((row_cf, key), value) in rows.range((family, std::cmp::max(start, prefix).to_vec())..)
        {
            if *row_cf != family || !key.starts_with(prefix) {
                break;
            }
            let next_bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if taken.len() >= limit.max_rows || (!taken.is_empty() && next_bytes > limit.max_bytes)
            {
                return PrefixScan {
                    rows: taken,
                    complete: false,
                };
            }
            bytes = next_bytes;
            taken.push((key.clone(), value.clone()));
        }
        PrefixScan {
            rows: taken,
            complete: true,
        }
    }

    impl KvStore for OneFamilyStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self
                .rows
                .lock()
                .rows
                .get(&(family_index(cf), key.to_vec()))
                .cloned())
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            let rows: Vec<(Vec<u8>, Vec<u8>)> = self
                .rows
                .lock()
                .rows
                .iter()
                .filter(|((row_cf, key), _)| *row_cf == family_index(cf) && key.starts_with(prefix))
                .map(|((_, key), value)| (key.clone(), value.clone()))
                .collect();
            Ok(Box::new(rows.into_iter().map(Ok)))
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            Ok(scan_one_family_from(
                &self.rows.lock().rows,
                cf,
                prefix,
                start,
                limit,
            ))
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            BufferedWriteBatch::default()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            apply_one_family_ops(&mut self.rows.lock(), batch.into_ops());
            Ok(())
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            for condition in conditions {
                let (cf, key) = condition.location();
                let current = self.get(cf, key)?;
                if !condition.matches(current.as_deref()) {
                    return Ok(false);
                }
            }
            self.write(batch)?;
            Ok(true)
        }

        fn flush(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            Ok(Box::new(OneFamilySnapshot {
                rows: self.rows.lock().rows.clone(),
            }))
        }

        fn arm_persist_fault(&self, _fault: PersistFault) {
            self.rows.lock().defect_armed = true;
        }

        fn multi_get(
            &self,
            cf: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<bytes::Bytes>>, StorageError> {
            let guard = self.rows.lock();
            let f_idx = family_index(cf);
            Ok(keys
                .iter()
                .map(|k| {
                    guard
                        .rows
                        .get(&(f_idx, k.to_vec()))
                        .map(|v| bytes::Bytes::copy_from_slice(v))
                })
                .collect())
        }

        fn ingest_sorted(
            &self,
            cf: ColumnFamily,
            rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            _scratch: &std::path::Path,
        ) -> Result<u64, StorageError> {
            let mut count = 0u64;
            let mut prev_key: Option<Vec<u8>> = None;
            let mut to_insert = Vec::new();
            for (k, v) in rows {
                if let Some(prev) = &prev_key {
                    if k.as_slice() <= prev.as_slice() {
                        return Err(StorageError::InvalidOperation(
                            "keys not strictly ascending",
                        ));
                    }
                }
                prev_key = Some(k.clone());
                to_insert.push((k, v));
                count += 1;
            }
            let mut guard = self.rows.lock();
            let f_idx = family_index(cf);
            for (k, v) in to_insert {
                guard.rows.insert((f_idx, k), v);
            }
            Ok(count)
        }

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            if start >= end {
                return Ok(());
            }
            let mut guard = self.rows.lock();
            let f_idx = family_index(cf);
            guard.rows.retain(|(row_cf, key), _| {
                if *row_cf != f_idx {
                    return true;
                }
                key.as_slice() < start || key.as_slice() >= end
            });
            Ok(())
        }

        fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
            std::fs::create_dir_all(dir).map_err(StorageError::Io)
        }

        fn engine_cache_bytes(&self) -> u64 {
            0
        }
    }

    struct OneFamilySnapshot {
        rows: OneFamilyRows,
    }

    impl KvSnapshot for OneFamilySnapshot {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.rows.get(&(family_index(cf), key.to_vec())).cloned())
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            Ok(scan_one_family_from(&self.rows, cf, prefix, start, limit))
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            let rows: Vec<(Vec<u8>, Vec<u8>)> = self
                .rows
                .iter()
                .filter(|((row_cf, key), _)| *row_cf == family_index(cf) && key.starts_with(prefix))
                .map(|((_, key), value)| (key.clone(), value.clone()))
                .collect();
            Ok(Box::new(rows.into_iter().map(Ok)))
        }
    }

    #[test]
    #[should_panic(expected = "recovered as a mix")]
    fn one_family_store_matrix_rejects_cross_family_mix() {
        let dir = tempfile::tempdir().expect("tempdir");
        one_scenario(
            "one-family",
            |path| Ok(OneFamilyStore::open(path)),
            dir.path(),
            PersistFault::LostSync,
            &Route::WriteDurable,
        );
    }
}
mod prune_then_reorg {
    extern crate alloc;

    use alloc::sync::Arc;
    use std::collections::BTreeMap;
    use std::ops::Bound;

    use crate::support::TestResult;
    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN;
    use bitcoin_rs_storage::pruning::{
        BLOCK_DATA_CF, ExecutedFrontier, HistoryAccess, HistoryUnavailable, PrunePolicy,
        RetentionBudget, RetentionRegistry, block_body_key, load_executed_frontier,
        load_pruneheight, prune_to_height, reclaim_staged_flat_block_files,
        stage_block_and_undo_prune,
    };
    use bitcoin_rs_storage::{
        BatchOp, BlockFilePosition, BufferedWriteBatch, ColumnFamily, FlatFileBlockStore, KvIter,
        KvSnapshot, KvStore, KvUndoStore, PrefixScan, PrefixScanLimit, StorageError, UndoStore,
        WriteCondition, block_file_max_height_key, decode_block_file_max_height,
        encode_block_file_max_height,
    };
    use parking_lot::{Mutex, RwLock};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tempfile::tempdir;

    /// Prune everything below the requested height; `retention_depth` still
    /// floors at the 288-block reorg margin.
    const AGGRESSIVE: PrunePolicy = PrunePolicy {
        target_size_mb: 0,
        keep_below_tip: 0,
    };

    fn memory_store_with_block_files()
    -> TestResult<(Arc<MemoryStore>, tempfile::TempDir, FlatFileBlockStore)> {
        let data_dir = tempdir()?;
        let block_files = FlatFileBlockStore::open(data_dir.path())?;
        Ok((Arc::new(MemoryStore::default()), data_dir, block_files))
    }

    fn prune_at(
        store: &MemoryStore,
        block_files: &FlatFileBlockStore,
        retention: &Arc<RetentionRegistry>,
        height: u32,
    ) -> Result<bitcoin_rs_storage::pruning::StagedPrune, bitcoin_rs_storage::pruning::PruneError>
    {
        prune_to_height(
            store,
            block_files,
            retention,
            height + CORE_REORG_SAFETY_MARGIN,
            height + CORE_REORG_SAFETY_MARGIN,
            height,
            |_| Ok(()),
        )
    }

    fn row_stored(store: &MemoryStore, key: &[u8]) -> Result<bool, StorageError> {
        Ok(store.get(BLOCK_DATA_CF, key)?.is_some())
    }

    type StoredRow = (u32, Hash256, BlockFilePosition);

    fn write_body_rows(
        store: &MemoryStore,
        block_files: &FlatFileBlockStore,
        rows: &[(u32, &[u8])],
    ) -> TestResult<Vec<StoredRow>> {
        let mut appended = Vec::with_capacity(rows.len());
        let mut batch = store.new_batch();
        for &(height, payload) in rows {
            let hash = fake_hash(height);
            let position = block_files.append(height, *hash.as_byte_array(), payload)?;
            batch.put(
                BLOCK_DATA_CF,
                &block_body_key(height, hash),
                &position.encode(),
            );
            appended.push((height, hash, position));
        }
        if let Some(appended_max) = appended.iter().map(|&(height, _, _)| height).max() {
            let key = block_file_max_height_key(appended[0].2.file_no);
            let max_height = store
                .get(BLOCK_DATA_CF, &key)?
                .as_deref()
                .and_then(decode_block_file_max_height)
                .map_or(appended_max, |previous| previous.max(appended_max));
            batch.put(
                BLOCK_DATA_CF,
                &key,
                &encode_block_file_max_height(max_height),
            );
        }
        store.write(batch)?;
        Ok(appended)
    }

    // ARCH-08, SYNC-07
    #[test]
    fn undo_pruning_keeps_records_the_durable_tip_still_needs() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;
        let undo_store = KvUndoStore::new(Arc::clone(&store));
        for height in 10_u32..=12 {
            undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
        }
        let retention = Arc::new(RetentionRegistry::new());
        let staged = prune_to_height(
            &*store,
            &block_files,
            &retention,
            11 + CORE_REORG_SAFETY_MARGIN,
            0,
            11,
            |_| Ok(()),
        )?;

        assert_eq!(
            staged.undo.blocks_removed, 0,
            "no undo record may go while a crash would restore below all of them"
        );
        assert!(
            undo_store.load_undo(10, fake_hash(10))?.is_some(),
            "the record a restore would need must survive"
        );
        Ok(())
    }

    #[test]
    fn prune_to_height_deletes_rows_below_the_line_and_persists_pruneheight() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;
        let undo_store = KvUndoStore::new(Arc::clone(&store));
        for height in 10_u32..=12 {
            undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
        }
        let retention = Arc::new(RetentionRegistry::new());
        let staged = prune_at(&store, &block_files, &retention, 11)?;

        assert_eq!(staged.blocks.blocks_removed, 1);
        assert_eq!(staged.undo.blocks_removed, 1);
        assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
        assert!(row_stored(&store, &block_body_key(12, fake_hash(12)))?);
        assert!(undo_store.load_undo(10, fake_hash(10))?.is_none());
        assert!(undo_store.load_undo(11, fake_hash(11))?.is_some());
        assert!(undo_store.load_undo(12, fake_hash(12))?.is_some());
        assert_eq!(load_pruneheight(&*store)?, Some(11));
        Ok(())
    }

    // SYNC-07
    #[test]
    fn prune_to_height_respects_an_active_retention_lease() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;
        let undo_store = KvUndoStore::new(Arc::clone(&store));
        for height in 10_u32..=12 {
            undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
        }
        let retention = Arc::new(RetentionRegistry::new());
        let lease = retention.acquire(10)?;

        let pinned = prune_at(&store, &block_files, &retention, 11)?;
        assert_eq!(pinned.blocks.blocks_removed, 0);
        assert_eq!(pinned.undo.blocks_removed, 0);
        assert!(row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        assert_eq!(retention.pruned_below(), 0);
        assert!(
            retention.acquire(9).is_ok(),
            "a pass that deleted nothing must not mark any height gone"
        );

        lease.release();
        assert_eq!(retention.active_leases(), 0);
        let released = prune_at(&store, &block_files, &retention, 11)?;
        assert_eq!(released.blocks.blocks_removed, 1);
        assert_eq!(released.undo.blocks_removed, 1);
        assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
        assert_eq!(retention.pruned_below(), 11);
        Ok(())
    }

    #[test]
    fn staged_flat_file_pruning_removes_all_selected_indexes_before_reclaim() -> TestResult {
        let store = MemoryStore::default();
        let data_dir = tempdir()?;
        let old_rows = {
            let seeding = FlatFileBlockStore::open(data_dir.path())?;
            write_body_rows(
                &store,
                &seeding,
                &[(1, b"first old body"), (2, b"second old body")],
            )?
        };
        std::fs::File::create(data_dir.path().join("blocks/blk00001.dat"))?;
        let block_files = FlatFileBlockStore::open(data_dir.path())?;
        let current = write_body_rows(&store, &block_files, &[(800, b"current body")])?.remove(0);
        assert_eq!(old_rows[0].2.file_no, 0);
        assert_eq!(current.2.file_no, 1);

        let policy = PrunePolicy {
            target_size_mb: 1,
            keep_below_tip: 0,
        };
        let first_old_key = block_body_key(1, old_rows[0].1);
        let second_old_key = block_body_key(2, old_rows[1].1);
        let current_key = block_body_key(800, current.1);

        let retention = Arc::new(RetentionRegistry::new());
        let reservation = retention.reserve(1_000_u32.saturating_sub(policy.retention_depth()));
        let mut prune_batch = store.new_batch();
        let staged = stage_block_and_undo_prune(
            &store,
            &mut prune_batch,
            &block_files,
            policy,
            &reservation,
        )?;
        assert_eq!(staged.blocks.blocks_removed, 2);
        assert_eq!(staged.blocks.bytes_freed, 32);
        assert!(staged.undo.is_empty());
        assert_eq!(staged.file_numbers, vec![old_rows[0].2.file_no]);
        assert_eq!(staged.pruned_below, 3);

        store.write(prune_batch)?;
        assert!(!row_stored(&store, &first_old_key)?);
        assert!(!row_stored(&store, &second_old_key)?);
        assert!(row_stored(&store, &current_key)?);
        assert!(block_files.file_path(old_rows[0].2.file_no).exists());

        reclaim_staged_flat_block_files(&store, &block_files, &staged.file_numbers)?;
        assert!(!row_stored(
            &store,
            &block_file_max_height_key(old_rows[0].2.file_no)
        )?);
        assert!(!block_files.file_path(old_rows[0].2.file_no).exists());
        assert!(row_stored(&store, &current_key)?);
        assert!(row_stored(
            &store,
            &block_file_max_height_key(current.2.file_no)
        )?);
        assert_eq!(
            block_files.load(current.2, current.0, *current.1.as_byte_array())?,
            Some(b"current body".to_vec())
        );
        Ok(())
    }

    #[test]
    fn target_pruning_deletes_old_indexes_in_the_current_flat_file() -> TestResult {
        let store = MemoryStore::default();
        let data_dir = tempdir()?;
        let hash = fake_hash(1);
        let block_files = FlatFileBlockStore::open(data_dir.path())?;
        let position = block_files.append(1, *hash.as_byte_array(), b"current old body")?;
        let key = block_body_key(1, hash);
        let mut initial_batch = store.new_batch();
        initial_batch.put(BLOCK_DATA_CF, &key, &position.encode());
        initial_batch.put(
            BLOCK_DATA_CF,
            &block_file_max_height_key(position.file_no),
            &encode_block_file_max_height(1),
        );
        store.write(initial_batch)?;

        let retention = Arc::new(RetentionRegistry::new());
        let reservation = retention.reserve(1_000_u32.saturating_sub(AGGRESSIVE.retention_depth()));
        let mut prune_batch = store.new_batch();
        let staged = stage_block_and_undo_prune(
            &store,
            &mut prune_batch,
            &block_files,
            AGGRESSIVE,
            &reservation,
        )?;
        assert_eq!(staged.file_numbers, Vec::<u32>::new());
        assert_eq!(staged.blocks.blocks_removed, 1);
        assert_eq!(staged.blocks.bytes_freed, 16);

        store.write(prune_batch)?;
        assert!(!row_stored(&store, &key)?);
        assert!(block_files.file_path(position.file_no).exists());
        assert!(row_stored(
            &store,
            &block_file_max_height_key(position.file_no)
        )?);
        Ok(())
    }

    #[test]
    fn retention_lease_stops_the_prune_line_at_its_floor() -> TestResult {
        let store = MemoryStore::default();
        let data_dir = tempdir()?;
        let old_hash = fake_hash(1);
        let leased_hash = fake_hash(2);
        let block_files = FlatFileBlockStore::open(data_dir.path())?;
        let old_position = block_files.append(1, *old_hash.as_byte_array(), b"old body")?;
        let leased_position =
            block_files.append(2, *leased_hash.as_byte_array(), b"leased body")?;
        let old_key = block_body_key(1, old_hash);
        let leased_key = block_body_key(2, leased_hash);
        let mut initial_batch = store.new_batch();
        initial_batch.put(BLOCK_DATA_CF, &old_key, &old_position.encode());
        initial_batch.put(BLOCK_DATA_CF, &leased_key, &leased_position.encode());
        initial_batch.put(
            BLOCK_DATA_CF,
            &block_file_max_height_key(old_position.file_no),
            &encode_block_file_max_height(2),
        );
        store.write(initial_batch)?;

        let retention = Arc::new(RetentionRegistry::new());
        let lease = retention.acquire(2)?;
        assert_eq!(retention.retention_floor(), Some(2));

        let policy = PrunePolicy {
            target_size_mb: 0,
            keep_below_tip: 0,
        };
        let mut leased_batch = store.new_batch();
        let leased_pass = retention.reserve(1_000_u32.saturating_sub(policy.retention_depth()));
        assert_eq!(leased_pass.line(), 2);
        let staged = stage_block_and_undo_prune(
            &store,
            &mut leased_batch,
            &block_files,
            policy,
            &leased_pass,
        )?;
        assert_eq!(staged.pruned_below, 2);
        assert_eq!(staged.blocks.blocks_removed, 1);
        store.write(leased_batch)?;
        assert!(store.get(BLOCK_DATA_CF, &old_key)?.is_none());
        assert!(store.get(BLOCK_DATA_CF, &leased_key)?.is_some());

        lease.release();
        assert_eq!(retention.retention_floor(), None);
        drop(leased_pass);
        let mut released_batch = store.new_batch();
        let released_pass = retention.reserve(1_000_u32.saturating_sub(policy.retention_depth()));
        let staged = stage_block_and_undo_prune(
            &store,
            &mut released_batch,
            &block_files,
            policy,
            &released_pass,
        )?;
        assert_eq!(staged.pruned_below, 3);
        store.write(released_batch)?;
        assert!(store.get(BLOCK_DATA_CF, &leased_key)?.is_none());
        released_pass.commit(staged.pruned_below);
        assert!(matches!(
            retention.acquire(2),
            Err(bitcoin_rs_storage::pruning::RetentionError { .. })
        ));
        Ok(())
    }

    #[test]
    fn history_request_between_planning_and_commit_is_refused() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;
        let undo_store = KvUndoStore::new(Arc::clone(&store));
        for height in 10_u32..=12 {
            undo_store.persist_undo(height, fake_hash(height), b"undo-body")?;
        }
        let retention = Arc::new(RetentionRegistry::new());

        let staged = prune_to_height(
            &*store,
            &block_files,
            &retention,
            11 + CORE_REORG_SAFETY_MARGIN,
            11 + CORE_REORG_SAFETY_MARGIN,
            11,
            |pruned_below| {
                assert_eq!(retention.pruned_below(), 0);
                assert!(matches!(
                    retention.acquire(pruned_below - 1),
                    Err(bitcoin_rs_storage::pruning::RetentionError {
                        requested: 10,
                        pruned_below: 11,
                    })
                ));
                assert!(retention.acquire(pruned_below).is_ok());
                Ok(())
            },
        )?;
        assert_eq!(staged.pruned_below, 11);
        assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        assert_eq!(retention.pruned_below(), 11);

        let failed = prune_to_height(
            &*store,
            &block_files,
            &retention,
            12 + CORE_REORG_SAFETY_MARGIN,
            12 + CORE_REORG_SAFETY_MARGIN,
            12,
            |pruned_below| {
                assert!(retention.acquire(pruned_below - 1).is_err());
                Err(StorageError::InvalidOperation(
                    "injected pre-commit failure",
                ))
            },
        );
        assert!(failed.is_err());
        assert_eq!(retention.pruned_below(), 11);
        assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
        let reacquired = retention.acquire(11)?;
        assert_eq!(reacquired.floor(), 11);
        reacquired.release();
        Ok(())
    }

    /// The executed frontier is a durable fact: it commits with its deletions,
    /// a restart reconstructs exactly that boundary, and the restarted authority
    /// refuses a lease over rows the previous process deleted.
    #[test]
    fn executed_frontier_survives_restart_and_refuses_deleted_heights() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;
        let retention = Arc::new(RetentionRegistry::new());

        let staged = prune_at(&store, &block_files, &retention, 11)?;
        assert_eq!(staged.pruned_below, 11);
        assert_eq!(
            load_executed_frontier(&*store)?,
            Some(ExecutedFrontier::new(11)),
            "the frontier commits in the same batch as the deletions"
        );

        let frontier = ExecutedFrontier::reconstruct(&*store)?;
        assert_eq!(frontier, ExecutedFrontier::new(11));
        let restarted = Arc::new(RetentionRegistry::seeded(frontier));
        assert!(matches!(
            restarted.acquire(10),
            Err(bitcoin_rs_storage::pruning::RetentionError {
                requested: 10,
                pruned_below: 11,
            })
        ));
        assert_eq!(restarted.acquire(11)?.floor(), 11);
        Ok(())
    }

    #[test]
    fn executed_frontier_is_monotonic_across_passes_and_reintroduced_rows() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
                (13, b"block-body"),
            ],
        )?;
        let retention = Arc::new(RetentionRegistry::new());

        let first = prune_at(&store, &block_files, &retention, 12)?;
        assert_eq!(first.pruned_below, 12);
        assert_eq!(
            load_executed_frontier(&*store)?,
            Some(ExecutedFrontier::new(12))
        );

        write_body_rows(&store, &block_files, &[(11, b"reintroduced body")])?;
        assert!(row_stored(&store, &block_body_key(11, fake_hash(11)))?);
        assert_eq!(
            ExecutedFrontier::reconstruct(&*store)?,
            ExecutedFrontier::new(12)
        );
        let restarted = Arc::new(RetentionRegistry::seeded(ExecutedFrontier::new(12)));
        assert!(restarted.acquire(11).is_err());

        let second = prune_at(&store, &block_files, &retention, 13)?;
        assert_eq!(second.pruned_below, 13);
        assert_eq!(
            load_executed_frontier(&*store)?,
            Some(ExecutedFrontier::new(13))
        );
        assert!(!row_stored(&store, &block_body_key(11, fake_hash(11)))?);
        assert!(!row_stored(&store, &block_body_key(12, fake_hash(12)))?);
        assert!(row_stored(&store, &block_body_key(13, fake_hash(13)))?);
        let empty = prune_at(&store, &block_files, &retention, 13)?;
        assert_eq!(empty.pruned_below, 0);
        assert_eq!(
            ExecutedFrontier::reconstruct(&*store)?,
            ExecutedFrontier::new(13),
            "an empty pass preserves the committed frontier"
        );
        Ok(())
    }

    #[test]
    fn unpruned_store_has_no_executed_frontier() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        assert_eq!(
            ExecutedFrontier::reconstruct(&*store)?,
            ExecutedFrontier::NONE
        );
        write_body_rows(&store, &block_files, &[(30, b"block-body")])?;
        assert_eq!(
            ExecutedFrontier::reconstruct(&*store)?,
            ExecutedFrontier::NONE
        );
        let retention = Arc::new(RetentionRegistry::new());
        let staged = prune_at(&store, &block_files, &retention, 20)?;
        assert_eq!(staged.pruned_below, 0);
        assert_eq!(
            load_executed_frontier(&*store)?,
            Some(ExecutedFrontier::NONE)
        );
        assert_eq!(load_pruneheight(&*store)?, Some(20));
        assert_eq!(
            ExecutedFrontier::reconstruct(&*store)?,
            ExecutedFrontier::NONE
        );
        Ok(())
    }

    #[test]
    fn missing_executed_frontier_after_prune_fails_closed() -> TestResult {
        for survivors in [false, true] {
            let (store, _data_dir, block_files) = memory_store_with_block_files()?;
            write_body_rows(&store, &block_files, &[(10, b"body"), (11, b"body")])?;
            let retention = Arc::new(RetentionRegistry::new());
            prune_at(
                &store,
                &block_files,
                &retention,
                if survivors { 11 } else { 12 },
            )?;
            let mut damaged = store.new_batch();
            damaged.delete(ColumnFamily::UtxoMeta, EXECUTED_FRONTIER_KEY);
            store.write(damaged)?;
            assert!(matches!(
                ExecutedFrontier::reconstruct(&*store),
                Err(StorageError::IncompatibleData(_))
            ));
            let mut damaged = store.new_batch();
            damaged.delete(ColumnFamily::UtxoMeta, b"node:pruneheight");
            store.write(damaged)?;
            assert!(matches!(
                ExecutedFrontier::reconstruct(&*store),
                Err(StorageError::IncompatibleData(_))
            ));
        }
        let store = MemoryStore::default();
        store.put(
            ColumnFamily::UtxoMeta,
            b"node:pruneheight",
            &0_u32.to_be_bytes(),
        )?;
        assert!(matches!(
            ExecutedFrontier::reconstruct(&store),
            Err(StorageError::IncompatibleData(_))
        ));
        Ok(())
    }

    #[test]
    fn corrupt_prune_metadata_never_becomes_an_empty_frontier() -> TestResult {
        for key in [
            EXECUTED_FRONTIER_KEY,
            b"node:pruneheight",
            b"node:prune_batch",
        ] {
            let store = MemoryStore::default();
            store.put(ColumnFamily::UtxoMeta, key, b"bad")?;
            assert!(matches!(
                ExecutedFrontier::reconstruct(&store),
                Err(StorageError::IncompatibleData(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn ambiguous_durability_promotes_the_line_the_batch_already_persisted() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;
        let retention = Arc::new(RetentionRegistry::new());

        store.arm_write_durable(WriteDurableOutcome::AppliedThenFailed);
        let staged = prune_at(&store, &block_files, &retention, 11)?;
        assert_eq!(
            load_executed_frontier(&*store)?,
            Some(ExecutedFrontier::new(11)),
        );
        assert_eq!(
            retention.pruned_below(),
            11,
            "a provably committed batch promotes the executed line"
        );
        assert_eq!(
            staged.pruned_below, 11,
            "the staged result carries the committed range"
        );
        assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        Ok(())
    }

    #[test]
    fn ambiguous_durability_releases_the_claim_when_nothing_applied() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[(10, b"block-body"), (11, b"block-body")],
        )?;
        let retention = Arc::new(RetentionRegistry::new());

        store.arm_write_durable(WriteDurableOutcome::FailedBeforeApply);
        let failed = prune_at(&store, &block_files, &retention, 11);
        assert!(failed.is_err());
        assert_eq!(retention.pruned_below(), 0);
        assert!(row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        assert!(retention.acquire(10).is_ok(), "the claim is released");
        assert_eq!(load_pruneheight(&*store)?, None);
        assert_eq!(load_executed_frontier(&*store)?, None);
        assert_eq!(
            ExecutedFrontier::reconstruct(&*store)?,
            ExecutedFrontier::NONE
        );
        Ok(())
    }

    #[test]
    fn ambiguous_durability_fails_closed_when_the_outcome_is_unprovable() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[(10, b"block-body"), (11, b"block-body")],
        )?;
        let retention = Arc::new(RetentionRegistry::new());

        store.arm_executed_reads(1);
        store.arm_write_durable(WriteDurableOutcome::AppliedThenFailed);
        let failed = prune_at(&store, &block_files, &retention, 11);
        assert!(failed.is_err());
        assert_eq!(
            retention.pruned_below(),
            0,
            "an unprovable outcome never promotes the line"
        );
        assert!(
            retention.acquire(10).is_err(),
            "the claim refuses leases below its line until restart recovery"
        );

        store.arm_executed_reads(usize::MAX);
        let frontier = ExecutedFrontier::reconstruct(&*store)?;
        assert_eq!(
            frontier,
            ExecutedFrontier::new(11),
            "the restart reconciles the committed boundary"
        );
        let restarted = Arc::new(RetentionRegistry::seeded(frontier));
        assert!(restarted.acquire(10).is_err());
        Ok(())
    }

    #[test]
    fn ambiguous_durability_does_not_confuse_a_retry_with_its_earlier_pass() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[(10, b"block-body"), (11, b"block-body")],
        )?;
        let retention = Arc::new(RetentionRegistry::new());

        let first = prune_at(&store, &block_files, &retention, 11)?;
        assert_eq!(first.pruned_below, 11);
        assert_eq!(
            load_executed_frontier(&*store)?,
            Some(ExecutedFrontier::new(11)),
        );

        write_body_rows(&store, &block_files, &[(9, b"reintroduced")])?;

        store.arm_write_durable(WriteDurableOutcome::FailedBeforeApply);
        let failed = prune_at(&store, &block_files, &retention, 11);
        assert!(failed.is_err());
        assert!(
            row_stored(&store, &block_body_key(9, fake_hash(9)))?,
            "the unapplied batch's deletions remain staged, not effective"
        );
        Ok(())
    }

    #[test]
    fn optional_consumer_budget_exhaustion_unblocks_pruning() -> TestResult {
        let (store, _data_dir, block_files) = memory_store_with_block_files()?;
        write_body_rows(
            &store,
            &block_files,
            &[
                (10, b"block-body"),
                (11, b"block-body"),
                (12, b"block-body"),
            ],
        )?;

        let bounded = Arc::new(RetentionRegistry::new());
        let roomy = HistoryAccess::new(Arc::clone(&bounded), RetentionBudget::Depth(5));
        let held = roomy.request_history(10)?;
        let staged = prune_at(&store, &block_files, &bounded, 12)?;
        assert_eq!(staged.pruned_below, 0);
        assert_eq!(bounded.pruned_below(), 0);
        assert!(row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        held.release();

        let lagging = Arc::new(RetentionRegistry::new());
        let tight = HistoryAccess::new(Arc::clone(&lagging), RetentionBudget::Depth(1));
        let stale = tight.request_history(10)?;
        let staged = prune_at(&store, &block_files, &lagging, 12)?;
        assert_eq!(staged.pruned_below, 12);
        assert_eq!(lagging.active_leases(), 0, "the expired pin is gone");
        assert_eq!(stale.floor(), None);
        assert!(!row_stored(&store, &block_body_key(10, fake_hash(10)))?);
        assert!(!row_stored(&store, &block_body_key(11, fake_hash(11)))?);
        assert!(matches!(
            tight.request_history(10),
            Err(HistoryUnavailable::Pruned { below: 12 })
        ));
        assert_eq!(tight.request_history(12)?.floor(), Some(12));
        Ok(())
    }

    fn fake_hash(height: u32) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    #[derive(Clone, Copy)]
    enum WriteDurableOutcome {
        AppliedThenFailed,
        FailedBeforeApply,
    }

    const EXECUTED_FRONTIER_KEY: &[u8] = b"node:prune_executed";

    struct MemoryStore {
        cfs: RwLock<Families>,
        write_durable_outcome: Mutex<Option<WriteDurableOutcome>>,
        executed_reads_allowed: AtomicUsize,
    }

    impl Default for MemoryStore {
        fn default() -> Self {
            Self {
                cfs: RwLock::new(Default::default()),
                write_durable_outcome: Mutex::new(None),
                executed_reads_allowed: AtomicUsize::new(usize::MAX),
            }
        }
    }

    impl MemoryStore {
        fn arm_write_durable(&self, outcome: WriteDurableOutcome) {
            *self.write_durable_outcome.lock() = Some(outcome);
        }

        fn arm_executed_reads(&self, allowed: usize) {
            self.executed_reads_allowed
                .store(allowed, AtomicOrdering::Relaxed);
        }
    }

    impl KvStore for MemoryStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            if cf == ColumnFamily::UtxoMeta && key == EXECUTED_FRONTIER_KEY {
                let mut remaining = self.executed_reads_allowed.load(AtomicOrdering::Relaxed);
                let exhausted = loop {
                    let Some(next) = remaining.checked_sub(1) else {
                        break true;
                    };
                    match self.executed_reads_allowed.compare_exchange_weak(
                        remaining,
                        next,
                        AtomicOrdering::Relaxed,
                        AtomicOrdering::Relaxed,
                    ) {
                        Ok(_) => break false,
                        Err(actual) => remaining = actual,
                    }
                };
                if exhausted {
                    return Err(StorageError::InvalidOperation(
                        "injected executed-frontier read failure",
                    ));
                }
            }
            let guard = self.cfs.read();
            Ok(guard[cf.index()].get(key).cloned())
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            let rows = self
                .cfs
                .read()
                .get(cf.index())
                .into_iter()
                .flat_map(|cf_rows| {
                    cf_rows
                        .range(prefix.to_vec()..)
                        .take_while(|(key, _value)| key.starts_with(prefix))
                })
                .map(|(key, value)| Ok((key.clone(), value.clone())))
                .collect::<Vec<_>>();
            Ok(Box::new(rows.into_iter()))
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            Ok(scan_family_from(
                &self.cfs.read()[cf.index()],
                prefix,
                start,
                limit,
            ))
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            BufferedWriteBatch::default()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            apply_ops(&mut self.cfs.write(), batch);
            Ok(())
        }

        fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            let armed = self.write_durable_outcome.lock().take();
            match armed {
                Some(WriteDurableOutcome::AppliedThenFailed) => {
                    self.write(batch)?;
                    Err(StorageError::InvalidOperation(
                        "injected post-apply durability failure",
                    ))
                }
                Some(WriteDurableOutcome::FailedBeforeApply) => Err(
                    StorageError::InvalidOperation("injected pre-apply durability failure"),
                ),
                None => self.write(batch),
            }
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            let mut guard = self.cfs.write();
            for condition in conditions {
                let (cf, key) = condition.location();
                let current = guard[cf.index()].get(key);
                if !condition.matches(current.map(Vec::as_slice)) {
                    return Ok(false);
                }
            }
            apply_ops(&mut guard, batch);
            Ok(true)
        }

        fn flush(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            let guard = self.cfs.read();
            Ok(Box::new(MemorySnapshot { cfs: guard.clone() }))
        }

        fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {}

        fn multi_get(
            &self,
            cf: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<bytes::Bytes>>, StorageError> {
            keys.iter()
                .map(|k| self.get(cf, k).map(|opt| opt.map(bytes::Bytes::from)))
                .collect()
        }

        fn ingest_sorted(
            &self,
            cf: ColumnFamily,
            rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            _scratch: &std::path::Path,
        ) -> Result<u64, StorageError> {
            let mut count = 0u64;
            let mut prev_key: Option<Vec<u8>> = None;
            let mut to_insert = Vec::new();
            for (k, v) in rows {
                if let Some(prev) = &prev_key {
                    if k.as_slice() <= prev.as_slice() {
                        return Err(StorageError::InvalidOperation(
                            "keys not strictly ascending",
                        ));
                    }
                }
                prev_key = Some(k.clone());
                to_insert.push((k, v));
                count += 1;
            }
            let mut guard = self.cfs.write();
            let map = &mut guard[cf.index()];
            for (k, v) in to_insert {
                map.insert(k, v);
            }
            Ok(count)
        }

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            if start >= end {
                return Ok(());
            }
            let mut guard = self.cfs.write();
            let map = &mut guard[cf.index()];
            map.retain(|k, _| k.as_slice() < start || k.as_slice() >= end);
            Ok(())
        }

        fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
            std::fs::create_dir_all(dir).map_err(StorageError::Io)
        }

        fn engine_cache_bytes(&self) -> u64 {
            0
        }
    }

    type Families = [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()];

    fn scan_family_from(
        rows: &BTreeMap<Vec<u8>, Vec<u8>>,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> PrefixScan {
        let mut taken = Vec::new();
        let mut bytes = 0usize;
        for (key, value) in rows.range::<[u8], _>((
            Bound::Included(std::cmp::max(start, prefix)),
            Bound::Unbounded,
        )) {
            if !key.starts_with(prefix) {
                break;
            }
            let next_bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
            if taken.len() >= limit.max_rows || (!taken.is_empty() && next_bytes > limit.max_bytes)
            {
                return PrefixScan {
                    rows: taken,
                    complete: false,
                };
            }
            bytes = next_bytes;
            taken.push((key.clone(), value.clone()));
        }
        PrefixScan {
            rows: taken,
            complete: true,
        }
    }

    fn apply_ops(families: &mut Families, batch: BufferedWriteBatch) {
        for op in batch.into_ops() {
            match op {
                BatchOp::Put { cf, key, value } => {
                    families[cf.index()].insert(key, value.into());
                }
                BatchOp::Delete { cf, key } => {
                    families[cf.index()].remove(&key);
                }
                BatchOp::DeleteRange { cf, start, end } => {
                    let keys = families[cf.index()]
                        .range(start..end)
                        .map(|(key, _value)| key.clone())
                        .collect::<Vec<_>>();
                    for key in keys {
                        families[cf.index()].remove(&key);
                    }
                }
            }
        }
    }

    struct MemorySnapshot {
        cfs: Families,
    }

    impl KvSnapshot for MemorySnapshot {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.cfs[cf.index()].get(key).cloned())
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            Ok(scan_family_from(
                &self.cfs[cf.index()],
                prefix,
                start,
                limit,
            ))
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            let rows = self.cfs[cf.index()]
                .range(prefix.to_vec()..)
                .take_while(|(key, _value)| key.starts_with(prefix))
                .map(|(key, value)| Ok((key.clone(), value.clone())))
                .collect::<Vec<_>>();
            Ok(Box::new(rows.into_iter()))
        }
    }
}
mod rocksdb_txindex {
    use bitcoin_rs_storage::{
        ColumnFamily, KvStore, PrefixScan, PrefixScanLimit, RocksDbStore, StorageError,
        WriteCondition,
    };

    use crate::support::TestResult;

    const MAX_SCAN: PrefixScanLimit = PrefixScanLimit {
        max_rows: 10_000,
        max_bytes: 10_000_000,
    };

    fn key_12(counter: u32) -> [u8; 12] {
        let mut k = [0u8; 12];
        k[0..4].copy_from_slice(&counter.to_le_bytes());
        k
    }

    fn header_80(counter: u32) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[0..4].copy_from_slice(&counter.to_le_bytes());
        h
    }

    fn script_live_43(counter: u32) -> [u8; 43] {
        let mut k = [0u8; 43];
        k[0..4].copy_from_slice(&counter.to_le_bytes());
        k[40..].copy_from_slice(&counter.to_le_bytes()[..3]);
        k
    }

    fn row_count<S: KvStore>(store: &S, cf: ColumnFamily) -> Result<usize, StorageError> {
        store
            .scan_prefix_bounded(cf, &[], MAX_SCAN)
            .map(|scan| scan.rows.len())
    }

    #[test]
    fn txindex_all_six_family_roundtrips() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let confirmed = key_12(1);
        store.put(ColumnFamily::TxConfirmed, &confirmed, b"")?;
        assert_eq!(
            store.get(ColumnFamily::TxConfirmed, &confirmed)?,
            Some(Vec::new())
        );

        let funding = key_12(2);
        store.put(ColumnFamily::Funding, &funding, b"")?;
        assert_eq!(
            store.get(ColumnFamily::Funding, &funding)?,
            Some(Vec::new())
        );

        let spending = key_12(3);
        store.put(ColumnFamily::Spending, &spending, b"")?;
        assert_eq!(
            store.get(ColumnFamily::Spending, &spending)?,
            Some(Vec::new())
        );

        let header = header_80(4);
        store.put(ColumnFamily::BlockHeaders, &header, b"")?;
        assert_eq!(
            store.get(ColumnFamily::BlockHeaders, &header)?,
            Some(Vec::new())
        );

        let live = script_live_43(5);
        store.put(ColumnFamily::ScriptLive, &live, b"")?;
        assert_eq!(
            store.get(ColumnFamily::ScriptLive, &live)?,
            Some(Vec::new())
        );

        let meta_key = b"version";
        let meta_value = b"1";
        store.put(ColumnFamily::UtxoMeta, meta_key, meta_value)?;
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, meta_key)?,
            Some(meta_value.to_vec())
        );

        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::TxConfirmed, &confirmed);
        batch.delete(ColumnFamily::Funding, &funding);
        batch.delete(ColumnFamily::Spending, &spending);
        batch.delete(ColumnFamily::BlockHeaders, &header);
        batch.delete(ColumnFamily::ScriptLive, &live);
        batch.delete(ColumnFamily::UtxoMeta, meta_key);
        store.write(batch)?;

        for cf in [
            ColumnFamily::TxConfirmed,
            ColumnFamily::Funding,
            ColumnFamily::Spending,
            ColumnFamily::BlockHeaders,
            ColumnFamily::ScriptLive,
            ColumnFamily::UtxoMeta,
        ] {
            assert_eq!(row_count(&store, cf)?, 0);
        }
        Ok(())
    }

    #[test]
    fn txindex_script_live_roundtrips_with_empty_value() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let live = script_live_43(1);
        store.put(ColumnFamily::ScriptLive, &live, b"")?;
        assert_eq!(
            store.get(ColumnFamily::ScriptLive, &live)?,
            Some(Vec::new())
        );

        Ok(())
    }

    #[test]
    fn txindex_position_values_follow_authoritative_rows() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;
        let confirmed = key_12(1);
        let funding = key_12(2);

        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &confirmed, b"tx-position");
        batch.put(ColumnFamily::Funding, &funding, b"funding-position");
        store.write(batch)?;

        assert_eq!(
            store.get(ColumnFamily::TxConfirmed, &confirmed)?,
            Some(b"tx-position".to_vec())
        );
        assert_eq!(
            store.get(ColumnFamily::Funding, &funding)?,
            Some(b"funding-position".to_vec())
        );
        let rows = store
            .iter_prefix(ColumnFamily::TxConfirmed, &confirmed[..4])?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(rows, vec![(confirmed.to_vec(), b"tx-position".to_vec())]);
        let scan = store.scan_prefix_bounded(ColumnFamily::Funding, &funding[..4], MAX_SCAN)?;
        assert_eq!(
            scan.rows,
            vec![(funding.to_vec(), b"funding-position".to_vec())]
        );

        store.put(ColumnFamily::TxConfirmed, &confirmed, b"")?;
        assert_eq!(
            store.get(ColumnFamily::TxConfirmed, &confirmed)?,
            Some(Vec::new())
        );

        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::Funding, &funding);
        store.write(batch)?;
        store.put(ColumnFamily::Funding, &funding, b"")?;
        assert_eq!(
            store.get(ColumnFamily::Funding, &funding)?,
            Some(Vec::new())
        );

        let confirmed_2 = key_12(2);
        store.put(ColumnFamily::TxConfirmed, &confirmed_2, b"stale")?;
        let mut batch = store.new_batch();
        batch.delete_range(ColumnFamily::TxConfirmed, &confirmed, &key_12(3));
        store.write(batch)?;
        store.put(ColumnFamily::TxConfirmed, &confirmed_2, b"")?;
        assert_eq!(
            store.get(ColumnFamily::TxConfirmed, &confirmed_2)?,
            Some(Vec::new())
        );

        store.put(ColumnFamily::Funding, &key_12(3), b"abcd")?;
        let bounded = store.scan_prefix_bounded(
            ColumnFamily::Funding,
            &key_12(3),
            PrefixScanLimit {
                max_rows: 1,
                max_bytes: 15,
            },
        )?;
        assert_eq!(bounded.rows, vec![(key_12(3).to_vec(), b"abcd".to_vec())]);
        assert!(bounded.complete);
        Ok(())
    }

    #[test]
    fn spending_rows_round_trip_values() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;
        let spending = key_12(3);
        let value = b"position";

        store.put(ColumnFamily::Spending, &spending, value)?;
        assert_eq!(
            store.get(ColumnFamily::Spending, &spending)?,
            Some(value.to_vec())
        );
        assert_eq!(
            store
                .scan_prefix_bounded(ColumnFamily::Spending, &spending[..4], MAX_SCAN)?
                .rows,
            vec![(spending.to_vec(), value.to_vec())]
        );

        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::Spending, &spending);
        store.write(batch)?;
        assert_eq!(store.get(ColumnFamily::Spending, &spending)?, None);

        store.put(ColumnFamily::Spending, &spending, b"")?;
        assert_eq!(
            store.get(ColumnFamily::Spending, &spending)?,
            Some(Vec::new())
        );
        Ok(())
    }

    #[test]
    fn txindex_fixed_prefix_boundaries_12() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let zero = [0u8; 12];
        let mut zero_one = zero;
        zero_one[11] = 0x01;
        let mut one = zero;
        one[0] = 0x01;
        let mut one_ff = zero;
        one_ff[0] = 0x01;
        one_ff[1..].fill(0xff);
        let mut ff = zero;
        ff[0] = 0xff;
        let ff_ff = [0xffu8; 12];

        let mut batch = store.new_batch();
        for key in [&zero, &zero_one, &one, &one_ff, &ff, &ff_ff] {
            batch.put(ColumnFamily::TxConfirmed, key.as_slice(), b"");
        }
        store.write(batch)?;

        let all = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
        assert!(all.complete);
        assert_eq!(all.rows.len(), 6);

        let prefix_zero =
            store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x00], MAX_SCAN)?;
        assert!(prefix_zero.complete);
        let zero_keys: Vec<_> = prefix_zero.rows.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(zero_keys, vec![zero.to_vec(), zero_one.to_vec()]);

        let prefix_one = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x01], MAX_SCAN)?;
        assert!(prefix_one.complete);
        let one_keys: Vec<_> = prefix_one.rows.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(one_keys, vec![one.to_vec(), one_ff.to_vec()]);

        let prefix_ff = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0xff], MAX_SCAN)?;
        assert!(prefix_ff.complete);
        let ff_keys: Vec<_> = prefix_ff.rows.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(ff_keys, vec![ff.to_vec(), ff_ff.to_vec()]);

        assert!(zero_keys.iter().all(|k| !one_keys.contains(k)));

        let exact = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &zero, MAX_SCAN)?;
        assert!(exact.complete);
        assert_eq!(exact.rows.len(), 1);

        Ok(())
    }

    #[test]
    fn txindex_fixed_prefix_boundaries_80() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let zero = [0u8; 80];
        let mut zero_one = zero;
        zero_one[79] = 0x01;
        let mut one = zero;
        one[0] = 0x01;
        let mut one_ff = zero;
        one_ff[0] = 0x01;
        one_ff[1..].fill(0xff);
        let mut ff = zero;
        ff[0] = 0xff;
        let ff_ff = [0xffu8; 80];

        let mut batch = store.new_batch();
        for key in [&zero, &zero_one, &one, &one_ff, &ff, &ff_ff] {
            batch.put(ColumnFamily::BlockHeaders, key.as_slice(), b"");
        }
        store.write(batch)?;

        let prefix_zero =
            store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0x00], MAX_SCAN)?;
        assert!(prefix_zero.complete);
        let zero_keys: Vec<_> = prefix_zero.rows.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(zero_keys, vec![zero.to_vec(), zero_one.to_vec()]);

        let prefix_one =
            store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0x01], MAX_SCAN)?;
        assert!(prefix_one.complete);
        let one_keys: Vec<_> = prefix_one.rows.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(one_keys, vec![one.to_vec(), one_ff.to_vec()]);

        let prefix_ff = store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &[0xff], MAX_SCAN)?;
        assert!(prefix_ff.complete);
        let ff_keys: Vec<_> = prefix_ff.rows.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(ff_keys, vec![ff.to_vec(), ff_ff.to_vec()]);

        assert!(zero_keys.iter().all(|k| !one_keys.contains(k)));

        let exact = store.scan_prefix_bounded(ColumnFamily::BlockHeaders, &zero, MAX_SCAN)?;
        assert!(exact.complete);
        assert_eq!(exact.rows.len(), 1);

        Ok(())
    }

    #[test]
    fn txindex_bounded_scan_empty_values() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let mut batch = store.new_batch();
        for i in 0..5u32 {
            batch.put(ColumnFamily::TxConfirmed, &key_12(i), b"");
        }
        store.write(batch)?;

        let limited = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[],
            PrefixScanLimit {
                max_rows: 2,
                max_bytes: usize::MAX,
            },
        )?;
        assert_eq!(limited.rows.len(), 2);
        assert!(!limited.complete);

        let byte_limited = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[],
            PrefixScanLimit {
                max_rows: usize::MAX,
                max_bytes: 24,
            },
        )?;
        assert_eq!(byte_limited.rows.len(), 2);
        assert!(!byte_limited.complete);

        let exact = store.scan_prefix_bounded(
            ColumnFamily::TxConfirmed,
            &[],
            PrefixScanLimit {
                max_rows: 5,
                max_bytes: usize::MAX,
            },
        )?;
        assert_eq!(exact.rows.len(), 5);
        assert!(exact.complete);

        for (_key, value) in exact.rows {
            assert_eq!(value, Vec::<u8>::new());
        }

        Ok(())
    }

    type ContinuationScan<'a> =
        &'a dyn Fn(&[u8], &[u8], PrefixScanLimit) -> Result<PrefixScan, StorageError>;

    fn fixed_width_keys(width: usize) -> [Vec<u8>; 4] {
        let key = |head: u8, fill: u8, last: u8| {
            let mut key = vec![fill; width];
            key[0] = head;
            key[width - 1] = last;
            key
        };
        [key(1, 0, 0), key(1, 0, 5), key(1, 0xff, 0xff), key(2, 0, 0)]
    }

    fn assert_fixed_width_continuation(
        scan: ContinuationScan<'_>,
        width: usize,
        value: &[u8],
    ) -> Result<(), StorageError> {
        let [low_key, mid_key, high_key, _] = fixed_width_keys(width);
        let (low, mid, high) = (low_key.as_slice(), mid_key.as_slice(), high_key.as_slice());
        let past_mid = [mid, &[0x00_u8][..]].concat();
        let past_high = [high, &[0x00_u8][..]].concat();
        let check = |prefix: &[u8],
                     start: &[u8],
                     max_rows: usize,
                     expected: &[&[u8]],
                     complete: bool|
         -> Result<(), StorageError> {
            let page = scan(
                prefix,
                start,
                PrefixScanLimit {
                    max_rows,
                    max_bytes: usize::MAX,
                },
            )?;
            let keys: Vec<&[u8]> = page.rows.iter().map(|(key, _)| key.as_slice()).collect();
            assert_eq!(keys, expected, "prefix {prefix:02x?} start {start:02x?}");
            assert!(page.rows.iter().all(|(_, row_value)| row_value == value));
            assert_eq!(
                page.complete, complete,
                "prefix {prefix:02x?} start {start:02x?}"
            );
            Ok(())
        };
        let prefix: &[u8] = &[0x01];

        let from_first: [&[u8]; 4] = [&[], &[0x00, 0xff], &[0x01, 0x00, 0x00], low];
        for start in from_first {
            check(prefix, start, usize::MAX, &[low, mid, high], true)?;
        }

        check(prefix, mid, usize::MAX, &[mid, high], true)?;
        check(prefix, &past_mid, usize::MAX, &[high], true)?;
        check(prefix, &[0x01, 0x80], usize::MAX, &[high], true)?;

        check(prefix, &past_high, usize::MAX, &[], true)?;
        check(prefix, &[0x02], usize::MAX, &[], true)?;

        check(mid, &[], usize::MAX, &[mid], true)?;
        check(mid, &past_mid, usize::MAX, &[], true)?;

        check(prefix, &[], 0, &[], false)?;
        check(prefix, &[0x02], 0, &[], true)?;

        check(prefix, &[], 2, &[low, mid], false)?;
        check(prefix, &past_mid, 1, &[high], true)?;

        Ok(())
    }

    fn assert_fixed_width_pages(scan: ContinuationScan<'_>) -> Result<(), StorageError> {
        let all: Vec<Vec<u8>> = scan(&[], &[], MAX_SCAN)?
            .rows
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_ne!(all, Vec::<Vec<u8>>::new());
        for rows_per_page in 1..=all.len() + 1 {
            let mut seen = Vec::new();
            let mut start = Vec::new();
            loop {
                let page = scan(
                    &[],
                    &start,
                    PrefixScanLimit {
                        max_rows: rows_per_page,
                        max_bytes: usize::MAX,
                    },
                )?;
                if let Some((last, _)) = page.rows.last() {
                    start.clone_from(last);
                    start.push(0x00);
                }
                seen.extend(page.rows.iter().map(|(key, _)| key.clone()));
                if page.complete {
                    break;
                }
                assert!(!page.rows.is_empty(), "an incomplete page must progress");
            }
            assert_eq!(seen, all);
        }
        Ok(())
    }

    #[test]
    fn txindex_continuation_seeks_every_fixed_width_family() -> TestResult<()> {
        let families: [(ColumnFamily, usize, &[u8]); 5] = [
            (ColumnFamily::TxConfirmed, 12, &b"tx-position"[..]),
            (ColumnFamily::Funding, 12, &b"funding-position"[..]),
            (ColumnFamily::Spending, 12, &b"spending-position"[..]),
            (ColumnFamily::BlockHeaders, 80, &b""[..]),
            (ColumnFamily::ScriptLive, 43, &b""[..]),
        ];
        for (cf, width, value) in families {
            let temp = tempfile::TempDir::new()?;
            let store = RocksDbStore::open(temp.path())?;
            let mut batch = store.new_batch();
            for key in fixed_width_keys(width) {
                batch.put(cf, &key, value);
            }
            store.write(batch)?;

            let live = |prefix: &[u8], start: &[u8], limit: PrefixScanLimit| {
                store.scan_prefix_from_bounded(cf, prefix, start, limit)
            };
            assert_fixed_width_continuation(&live, width, value)?;
            assert_fixed_width_pages(&live)?;

            let snapshot = store.snapshot()?;
            let view = |prefix: &[u8], start: &[u8], limit: PrefixScanLimit| {
                snapshot.scan_prefix_from_bounded(cf, prefix, start, limit)
            };
            assert_fixed_width_continuation(&view, width, value)?;
            assert_fixed_width_pages(&view)?;
        }
        Ok(())
    }

    #[test]
    fn txindex_continuation_snapshot_is_point_in_time() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &key_12(1), b"one");
        batch.put(ColumnFamily::TxConfirmed, &key_12(3), b"three");
        store.write(batch)?;

        let snapshot = store.snapshot()?;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &key_12(2), b"two");
        batch.put(ColumnFamily::TxConfirmed, &key_12(4), b"four");
        store.write(batch)?;

        let seen = snapshot.scan_prefix_from_bounded(
            ColumnFamily::TxConfirmed,
            &[],
            &key_12(2),
            MAX_SCAN,
        )?;
        assert_eq!(seen.rows, vec![(key_12(3).to_vec(), b"three".to_vec())]);
        assert!(seen.complete);

        let live =
            store.scan_prefix_from_bounded(ColumnFamily::TxConfirmed, &[], &key_12(2), MAX_SCAN)?;
        assert_eq!(
            live.rows,
            vec![
                (key_12(2).to_vec(), b"two".to_vec()),
                (key_12(3).to_vec(), b"three".to_vec()),
                (key_12(4).to_vec(), b"four".to_vec()),
            ]
        );
        assert!(live.complete);
        Ok(())
    }

    #[test]
    fn txindex_mixed_batch_ordering_and_interleaved_cf() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let k1 = key_12(1);
        let k2 = key_12(2);
        let k3 = key_12(3);
        let k4 = key_12(4);

        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &k1, b"");
        batch.put(ColumnFamily::TxConfirmed, &k2, b"");
        batch.delete(ColumnFamily::TxConfirmed, &k1);
        batch.put(ColumnFamily::TxConfirmed, &k3, b"");
        batch.delete_range(ColumnFamily::TxConfirmed, &k2, &k3);
        batch.put(ColumnFamily::TxConfirmed, &k4, b"");
        store.write(batch)?;

        let confirmed = store.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
        let keys: Vec<_> = confirmed.rows.into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec![k3.to_vec(), k4.to_vec()]);

        let mut f1 = key_12(0);
        f1[0] = 0x10;
        let mut f2 = key_12(0);
        f2[0] = 0x11;
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &k1, b"");
        batch.put(ColumnFamily::Funding, &f1, b"");
        batch.delete(ColumnFamily::TxConfirmed, &k1);
        batch.put(ColumnFamily::Funding, &f2, b"");
        batch.delete(ColumnFamily::Funding, &f1);
        batch.put(ColumnFamily::TxConfirmed, &k2, b"");
        store.write(batch)?;

        assert!(store.get(ColumnFamily::TxConfirmed, &k1)?.is_none());
        assert!(store.get(ColumnFamily::TxConfirmed, &k2)?.is_some());
        assert!(store.get(ColumnFamily::Funding, &f1)?.is_none());
        assert!(store.get(ColumnFamily::Funding, &f2)?.is_some());

        Ok(())
    }

    #[test]
    fn txindex_snapshot_isolation() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let k1 = key_12(1);
        store.put(ColumnFamily::TxConfirmed, &k1, b"old")?;

        let snapshot = store.snapshot()?;

        let k2 = key_12(2);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &k1, b"new");
        batch.put(ColumnFamily::TxConfirmed, &k2, b"second");
        store.write(batch)?;

        let snap_scan = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
        assert_eq!(snap_scan.rows, vec![(k1.to_vec(), b"old".to_vec())]);

        let fresh = store.snapshot()?;
        let fresh_scan = fresh.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
        assert_eq!(
            fresh_scan.rows,
            vec![
                (k1.to_vec(), b"new".to_vec()),
                (k2.to_vec(), b"second".to_vec()),
            ]
        );

        let snap_scan2 = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[], MAX_SCAN)?;
        assert_eq!(snap_scan2.rows, vec![(k1.to_vec(), b"old".to_vec())]);
        Ok(())
    }

    #[test]
    fn txindex_durable_reopen() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let k = key_12(42);
        let h = header_80(42);
        let meta_key = b"watermark";
        let meta_value = b"123:abcd";

        {
            let store = RocksDbStore::open(temp.path())?;
            let mut batch = store.new_batch();
            batch.put(ColumnFamily::TxConfirmed, &k, b"");
            batch.put(ColumnFamily::BlockHeaders, &h, b"");
            batch.put(ColumnFamily::UtxoMeta, meta_key, meta_value);
            store.write(batch)?;
        }

        let store = RocksDbStore::open(temp.path())?;
        assert!(store.get(ColumnFamily::TxConfirmed, &k)?.is_some());
        assert!(store.get(ColumnFamily::BlockHeaders, &h)?.is_some());
        assert_eq!(
            store.get(ColumnFamily::UtxoMeta, meta_key)?,
            Some(meta_value.to_vec())
        );

        Ok(())
    }

    #[test]
    fn txindex_deferred_write_flush_and_reopen() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let k = key_12(7);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::Funding, &k, b"");
        store.write_deferred(batch)?;
        assert!(store.get(ColumnFamily::Funding, &k)?.is_some());

        store.flush()?;
        drop(store);

        let reopened = RocksDbStore::open(temp.path())?;
        assert!(reopened.get(ColumnFamily::Funding, &k)?.is_some());

        Ok(())
    }

    #[test]
    fn txindex_write_durable_if_roundtrip() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let confirmed = key_12(1);
        store.put(ColumnFamily::TxConfirmed, &confirmed, b"position")?;
        assert!(!store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::TxConfirmed,
                key: &confirmed,
                expected: b"wrong",
            }],
            store.new_batch(),
        )?);
        assert_eq!(
            store.get(ColumnFamily::TxConfirmed, &confirmed)?,
            Some(b"position".to_vec())
        );
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &key_12(99), b"swept");
        batch.put(ColumnFamily::UtxoMeta, b"side", b"effect");
        assert!(!store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::TxConfirmed,
                key: &confirmed,
                expected: b"stale-position",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::TxConfirmed, &key_12(99))?, None);
        assert_eq!(store.get(ColumnFamily::UtxoMeta, b"side")?, None);
        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::TxConfirmed, &confirmed);
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::TxConfirmed,
                key: &confirmed,
                expected: b"position",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::TxConfirmed, &confirmed)?, None);
        assert!(!store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::TxConfirmed,
                key: &confirmed,
                expected: b"position",
            }],
            store.new_batch(),
        )?);
        Ok(())
    }

    #[test]
    fn txindex_write_durable_if_unit_tables() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let funding = key_12(2);
        store.put(ColumnFamily::Funding, &funding, b"")?;
        assert!(!store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::Funding,
                key: &funding,
                expected: b"nonempty",
            }],
            store.new_batch(),
        )?);
        assert!(store.get(ColumnFamily::Funding, &funding)?.is_some());
        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::Funding, &funding);
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::Funding,
                key: &funding,
                expected: b"",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::Funding, &funding)?, None);

        let spending = key_12(3);
        store.put(ColumnFamily::Spending, &spending, b"")?;
        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::Spending, &spending);
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::Spending,
                key: &spending,
                expected: b"",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::Spending, &spending)?, None);

        let header = header_80(4);
        store.put(ColumnFamily::BlockHeaders, &header, b"")?;
        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::BlockHeaders, &header);
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::BlockHeaders,
                key: &header,
                expected: b"",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::BlockHeaders, &header)?, None);

        let live = script_live_43(5);
        store.put(ColumnFamily::ScriptLive, &live, b"")?;
        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::ScriptLive, &live);
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::ScriptLive,
                key: &live,
                expected: b"",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::ScriptLive, &live)?, None);
        Ok(())
    }

    #[test]
    fn txindex_write_durable_if_metadata_and_widths() -> TestResult<()> {
        let temp = tempfile::TempDir::new()?;
        let store = RocksDbStore::open(temp.path())?;

        let meta_key = b"cursor";
        store.put(ColumnFamily::UtxoMeta, meta_key, b"52-bytes-of-cursor")?;
        assert!(!store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: meta_key,
                expected: b"different",
            }],
            store.new_batch(),
        )?);
        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::UtxoMeta, meta_key);
        assert!(store.write_durable_if(
            &[WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: meta_key,
                expected: b"52-bytes-of-cursor",
            }],
            batch,
        )?);
        assert_eq!(store.get(ColumnFamily::UtxoMeta, meta_key)?, None);

        let absent = key_12(5);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::TxConfirmed, &absent, b"");
        assert!(store.write_durable_if(
            &[WriteCondition::Absent {
                cf: ColumnFamily::TxConfirmed,
                key: &absent,
            }],
            batch,
        )?);
        assert_eq!(
            store.get(ColumnFamily::TxConfirmed, &absent)?,
            Some(Vec::new())
        );

        Ok(())
    }
}
mod store_guard {
    use bitcoin_rs_storage::StoreGuard;
    use std::panic::AssertUnwindSafe;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::support::TestResult;

    struct Probe {
        live: Arc<AtomicBool>,
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.live.store(false, Ordering::SeqCst);
        }
    }

    fn probe() -> (StoreGuard, Arc<AtomicBool>) {
        let live = Arc::new(AtomicBool::new(true));
        let guard: StoreGuard = Arc::new(Probe {
            live: Arc::clone(&live),
        });
        (guard, live)
    }

    #[test]
    fn flat_file_guard_install_is_single() -> TestResult {
        use bitcoin_rs_storage::FlatFileBlockStore;

        let dir = tempfile::TempDir::new()?;
        let (first, first_live) = probe();
        let store = FlatFileBlockStore::open(dir.path())?.guarded_by(first);
        assert!(
            first_live.load(Ordering::SeqCst),
            "the installed guard must stay alive with the store"
        );
        let (second, second_live) = probe();
        let refused = std::panic::catch_unwind(AssertUnwindSafe(|| store.guarded_by(second)));
        assert!(
            refused.is_err(),
            "a second guard must not silently replace the first"
        );
        assert!(
            !second_live.load(Ordering::SeqCst),
            "the refused guard must drop with the rejected call"
        );
        Ok(())
    }

    #[test]
    fn dropped_flat_file_store_releases_its_guard() -> TestResult {
        use bitcoin_rs_storage::FlatFileBlockStore;

        let dir = tempfile::TempDir::new()?;
        let (guard, live) = probe();
        let store = FlatFileBlockStore::open(dir.path())?.guarded_by(guard);
        assert!(live.load(Ordering::SeqCst));
        drop(store);
        assert!(
            !live.load(Ordering::SeqCst),
            "the guard must die with the store handle"
        );
        Ok(())
    }

    #[test]
    fn rocksdb_guard_install_is_single() -> TestResult {
        use bitcoin_rs_storage::RocksDbStore;

        let dir = tempfile::TempDir::new()?;
        let (first, first_live) = probe();
        let store = RocksDbStore::open(dir.path())?.guarded_by(first);
        assert!(first_live.load(Ordering::SeqCst));
        let (second, second_live) = probe();
        let refused = std::panic::catch_unwind(AssertUnwindSafe(|| store.guarded_by(second)));
        assert!(
            refused.is_err(),
            "a second guard must not silently replace the first"
        );
        assert!(!second_live.load(Ordering::SeqCst));
        Ok(())
    }
}
mod utxo_coin_stats_roundtrip {
    use crate::support::utxo::TestResult;
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut};
    use bitcoin_rs_storage::utxo::stats::coin_stats::COIN_STATS_ENCODED_LEN;
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsDecodeError, CoinStatsListener};

    #[test]
    fn finish_block_applies_height_and_transaction_delta() {
        let mut stats = CoinStats::new();
        stats.finish_block(7, 3);
        stats.finish_block(8, 5);

        assert_eq!(stats.height, 8);
        assert_eq!(stats.tx_count, 8);

        let listener = CoinStatsListener::new(CoinStats::new());
        listener.finish_block(9, 2);
        listener.finish_block(10, 4);
        let snapshot = listener.snapshot();

        assert_eq!(snapshot.height, 10);
        assert_eq!(snapshot.tx_count, 6);
    }

    #[test]
    fn coin_stats_codec_is_exact_and_preserves_muhash_continuation() -> TestResult {
        let old_op = OutPoint::new(txid(1_000).into(), 3);
        let old_txout = TxOut {
            value: Amount::from_sat(12_345),
            script_pubkey: vec![0x51, 0x21].into(),
        };
        let mut original = CoinStats::new();
        original.insert_utxo(&old_op, &old_txout, 100, true);
        original.finish_block(100, 1);

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), COIN_STATS_ENCODED_LEN);
        let mut restored = CoinStats::from_bytes(&bytes)?;
        assert_eq!(restored, original);

        assert!(matches!(
            CoinStats::from_bytes(&bytes[..bytes.len() - 1]),
            Err(CoinStatsDecodeError::Truncated)
        ));
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            CoinStats::from_bytes(&trailing),
            Err(CoinStatsDecodeError::TrailingBytes)
        ));

        let new_op = OutPoint::new(txid(1_001).into(), 4);
        let new_txout = TxOut {
            value: Amount::from_sat(54_321),
            script_pubkey: vec![0x51, 0x22].into(),
        };
        original.remove_utxo(&old_op, &old_txout, 100, true);
        restored.remove_utxo(&old_op, &old_txout, 100, true);
        original.insert_utxo(&new_op, &new_txout, 101, false);
        restored.insert_utxo(&new_op, &new_txout, 101, false);

        assert_eq!(restored, original);
        assert_eq!(restored.to_bytes(), original.to_bytes());
        Ok(())
    }

    fn txid(index: u32) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }
}
mod utxo_commit_roundtrip {
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd, populate_block_changes};
    use bitcoin_rs_storage::utxo::{UtxoError, UtxoReader};
    use bitcoin_rs_storage::{CoinStore, MemoryKvStore};
    use std::sync::Arc;
    type Entry = (OutPoint, TxOut, bool, u32);
    use crate::support::utxo::{TestError, TestResult};

    fn txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(0xa5a5_a5a5_a5a5_a5a5).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn txout(seed: u64) -> TxOut {
        let mut script = Vec::with_capacity(10);
        script.extend_from_slice(&[0x51, 0x20]);
        script.extend_from_slice(&seed.to_le_bytes());
        TxOut {
            value: Amount::from_sat(1_000 + seed),
            script_pubkey: script.into(),
        }
    }

    fn oversized_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0; usize::from(u16::MAX) + 1].into(),
        }
    }

    fn txid_with_prefix(prefix: u64, suffix: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&prefix.to_le_bytes());
        bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
        bytes[16..24].copy_from_slice(&suffix.rotate_left(11).to_le_bytes());
        bytes[24..32].copy_from_slice(&suffix.wrapping_mul(17).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[0] = shard;
        bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
        bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
        bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn borrowed_changes<'a>(adds: &'a [Entry], removes: &[OutPoint]) -> BlockChanges<&'a TxOut> {
        let mut changes = BlockChanges::with_capacity(adds.len(), removes.len());
        for remove in removes {
            changes.remove(*remove);
        }
        for (outpoint, txout, coinbase, height) in adds {
            changes.add(UtxoAdd::new(*outpoint, txout, *coinbase, *height));
        }
        changes
    }

    fn owned_changes(adds: &[Entry], removes: &[OutPoint]) -> BlockChanges {
        let mut changes = BlockChanges::with_capacity(adds.len(), removes.len());
        for remove in removes {
            changes.remove(*remove);
        }
        for (outpoint, txout, coinbase, height) in adds {
            changes.add(UtxoAdd::new(*outpoint, txout.clone(), *coinbase, *height));
        }
        changes
    }

    type CommitPath = fn(&CoinStore, &[Entry], &[OutPoint], &Hash256) -> Result<(), UtxoError>;

    fn commit_borrowed(
        store: &CoinStore,
        adds: &[Entry],
        removes: &[OutPoint],
        _block: &Hash256,
    ) -> Result<(), UtxoError> {
        populate_block_changes(store, &borrowed_changes(adds, removes))
    }

    fn commit_owned(
        store: &CoinStore,
        adds: &[Entry],
        removes: &[OutPoint],
        _block: &Hash256,
    ) -> Result<(), UtxoError> {
        populate_block_changes(store, &owned_changes(adds, removes))
    }

    #[test]
    fn owned_and_borrowed_commits_preserve_coin_fields() -> TestResult {
        for shard_count in [1_u8, 20] {
            let store1 = Arc::new(MemoryKvStore::new());
            let owned = Arc::new(CoinStore::open(store1, 64 * 1024 * 1024));
            let store2 = Arc::new(MemoryKvStore::new());
            let borrowed = Arc::new(CoinStore::open(store2, 64 * 1024 * 1024));

            let mut entries: Vec<Entry> = (0_u8..64)
                .map(|index| {
                    let outpoint = OutPoint::new(
                        txid_in_shard(index % shard_count, u64::from(index)).into(),
                        u32::from(index),
                    );
                    (outpoint, txout(u64::from(index)), index % 2 == 0, 100)
                })
                .collect();
            let mut removes = Vec::new();
            for round in 0..2 {
                commit_owned(&owned, &entries, &removes, &txid(round))?;
                commit_borrowed(&borrowed, &entries, &removes, &txid(round))?;
                let reader_owned = UtxoReader::from_coin_store(Arc::clone(&owned));
                let reader_borrowed = UtxoReader::from_coin_store(Arc::clone(&borrowed));
                for (outpoint, txout, coinbase, height) in &entries {
                    let expected = Some((txout.clone(), *coinbase, *height));
                    assert_eq!(
                        reader_owned.get_entry(outpoint)?.map(|coin| (
                            coin.txout,
                            coin.coinbase,
                            coin.height
                        )),
                        expected
                    );
                    assert_eq!(
                        reader_borrowed.get_entry(outpoint)?.map(|coin| (
                            coin.txout,
                            coin.coinbase,
                            coin.height
                        )),
                        expected
                    );
                }
                for outpoint in &removes {
                    assert_eq!(reader_owned.get(outpoint)?, None);
                    assert_eq!(reader_borrowed.get(outpoint)?, None);
                }
                removes = entries.drain(..16).map(|entry| entry.0).collect();
                for (_, txout, coinbase, height) in &mut entries {
                    txout.value = Amount::from_sat(77);
                    *coinbase = !*coinbase;
                    *height += 1;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn an_invalid_add_rejects_the_whole_commit_in_every_commit_path() -> TestResult {
        let commit_paths: [CommitPath; 2] = [commit_owned, commit_borrowed];
        for cross_shard in [false, true] {
            let far_shard = u8::from(cross_shard);
            for commit in commit_paths {
                let store = Arc::new(MemoryKvStore::new());
                let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
                let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
                let retained = OutPoint::new(txid_in_shard(0, 100).into(), 0);
                let peer = OutPoint::new(txid_in_shard(far_shard, 101).into(), 0);
                let retained_txout = txout(100);
                let peer_txout = txout(101);
                let preload = [
                    (retained, retained_txout.clone(), false, 10),
                    (peer, peer_txout.clone(), false, 10),
                ];
                commit_owned(&coin_store, &preload, &[], &txid(102))?;

                let valid_add = OutPoint::new(txid_in_shard(0, 200).into(), 0);
                let invalid_add = OutPoint::new(txid_in_shard(far_shard, 201).into(), 0);
                let adds = [
                    (valid_add, txout(200), false, 11),
                    (invalid_add, oversized_txout(201), false, 11),
                ];
                let error = match commit(&coin_store, &adds, &[retained], &txid(103)) {
                    Ok(()) => {
                        return Err(TestError::UnexpectedSuccess(
                            "oversized script unexpectedly committed",
                        ));
                    }
                    Err(error) => error,
                };
                assert!(
                    matches!(
                        error,
                        UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1
                    ),
                    "unexpected error: {error}"
                );
                assert_eq!(
                    reader.get(&retained)?,
                    Some(retained_txout),
                    "a rejected commit applied its removes"
                );
                assert_eq!(reader.get(&peer)?, Some(peer_txout));
                assert_eq!(
                    reader.get(&valid_add)?,
                    None,
                    "a rejected commit applied an earlier add"
                );
                assert_eq!(reader.get(&invalid_add)?, None);
            }
        }
        Ok(())
    }

    #[test]
    fn output_boundaries_roundtrip_through_get_scan_and_spend() -> TestResult {
        let cases: [(u32, u64, bool, u32, Vec<u8>); 6] = [
            (0, 100, false, 0, Vec::new()),
            (63, 200, true, 123, vec![0x51]),
            (64, 300, true, 301, vec![0x00; 34]),
            (65, 0, false, 840_000, vec![0x6a]),
            (1_000, 500, true, u32::MAX, vec![0x52; 10_000]),
            (
                u32::MAX,
                2_099_999_999_999_999,
                false,
                u32::MAX,
                vec![0x51; 520],
            ),
        ];
        let live = txid(88);
        let store = Arc::new(MemoryKvStore::new());
        let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
        let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
        let entries: Vec<Entry> = cases
            .iter()
            .map(|(vout, value, coinbase, height, script)| {
                (
                    OutPoint::new(live.into(), *vout),
                    TxOut {
                        value: Amount::from_sat(*value),
                        script_pubkey: script.clone().into(),
                    },
                    *coinbase,
                    *height,
                )
            })
            .collect();
        commit_owned(&coin_store, &entries, &[], &txid(90))?;

        assert!(reader.has_live_outputs_for_txid(&live)?);
        assert!(!reader.has_live_outputs_for_txid(&txid(89))?);

        for (outpoint, txout, coinbase, height) in &entries {
            assert_eq!(reader.get(outpoint)?.as_ref(), Some(txout));
            let entry = reader
                .get_entry(outpoint)?
                .ok_or(TestError::Missing("expected a committed output to be live"))?;
            assert_eq!(&entry.txout, txout);
            assert_eq!(entry.coinbase, *coinbase, "coinbase lost at {outpoint:?}");
            assert_eq!(entry.height, *height, "height lost at {outpoint:?}");
        }

        let view = reader.lock_stable_view()?;
        let mut remaining: std::collections::HashSet<_> =
            entries.iter().map(|(outpoint, ..)| *outpoint).collect();
        let mut scan_failure: Option<TestError> = None;
        view.for_each_all(|outpoint, script| {
            assert!(
                remaining.remove(outpoint),
                "unexpected or duplicate output {outpoint:?}"
            );
            if scan_failure.is_some() {
                return;
            }
            let Some((_, txout, coinbase, height)) = entries
                .iter()
                .find(|(expected_outpoint, ..)| expected_outpoint == outpoint)
            else {
                scan_failure = Some(TestError::Missing(
                    "scanned output does not belong to the supplied inputs",
                ));
                return;
            };
            assert_eq!(script, txout.script_pubkey.as_slice());
            let Some(coin) = view.get_entry(outpoint) else {
                scan_failure = Some(TestError::Missing("scanned coin must be live"));
                return;
            };
            assert_eq!(
                (&coin.txout, coin.coinbase, coin.height),
                (txout, *coinbase, *height)
            );
        });
        if let Some(failure) = scan_failure {
            return Err(failure);
        }
        assert!(remaining.is_empty());
        drop(view);

        for (index, (outpoint, _txout, _coinbase, _height)) in entries.iter().enumerate() {
            assert!(reader.has_live_outputs_for_txid(&live)?);
            let block = txid(91 + u64::try_from(index)?);
            commit_owned(&coin_store, &[], std::slice::from_ref(outpoint), &block)?;
            assert_eq!(reader.get(outpoint)?, None);
        }
        assert!(!reader.has_live_outputs_for_txid(&live)?);
        Ok(())
    }

    #[test]
    fn high_vout_full_record_delete_removes_all_outputs_in_one_commit() -> TestResult {
        let store = Arc::new(MemoryKvStore::new());
        let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
        let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
        let live = txid(93);
        let adds: Vec<Entry> = (64_u32..128)
            .map(|vout| {
                (
                    OutPoint::new(live.into(), vout),
                    txout(1_000 + u64::from(vout)),
                    false,
                    302,
                )
            })
            .collect();
        let removes: Vec<OutPoint> = adds.iter().map(|entry| entry.0).collect();
        commit_owned(&coin_store, &adds, &[], &txid(94))?;

        commit_owned(&coin_store, &[], &removes, &txid(95))?;

        for remove in &removes {
            assert_eq!(reader.get(remove)?, None);
        }
        assert!(!reader.has_live_outputs_for_txid(&live)?);
        Ok(())
    }

    #[test]
    fn a_shared_txid_prefix_keeps_records_and_deletes_independent() -> TestResult {
        for reverse in [false, true] {
            let prefix = 0xfeed_face_cafe_beef_u64;
            let store = Arc::new(MemoryKvStore::new());
            let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
            let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
            let first = txid_with_prefix(prefix, if reverse { 2 } else { 1 });
            let second = txid_with_prefix(prefix, if reverse { 1 } else { 2 });
            let first_a = OutPoint::new(first.into(), 0);
            let first_b = OutPoint::new(first.into(), 1);
            let peer = OutPoint::new(second.into(), 0);
            let first_b_txout = txout(102);
            let peer_txout = txout(202);
            let mut adds = [
                (first_a, txout(101), false, 1),
                (first_b, first_b_txout.clone(), false, 1),
                (peer, peer_txout.clone(), false, 1),
            ];
            if reverse {
                adds.reverse();
            }
            commit_owned(&coin_store, &adds, &[], &txid(300))?;

            commit_owned(&coin_store, &[], &[first_a], &txid(301))?;
            assert_eq!(reader.get(&first_a)?, None);
            assert_eq!(reader.get(&first_b)?, Some(first_b_txout));
            assert_eq!(reader.get(&peer)?, Some(peer_txout.clone()));

            commit_owned(&coin_store, &[], &[first_b], &txid(302))?;
            assert_eq!(reader.get(&peer)?, Some(peer_txout));
            assert!(!reader.has_live_outputs_for_txid(&first)?);
            assert!(reader.has_live_outputs_for_txid(&second)?);
        }
        Ok(())
    }

    #[test]
    fn duplicate_remove_does_not_fast_delete_unspent_vout() -> TestResult {
        let store = Arc::new(MemoryKvStore::new());
        let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
        let reader = UtxoReader::from_coin_store(Arc::clone(&coin_store));
        let live = txid(700);
        let removed = OutPoint::new(live.into(), 0);
        let retained = OutPoint::new(live.into(), 1);
        let retained_txout = txout(701);
        let adds = [
            (removed, txout(700), false, 1),
            (retained, retained_txout.clone(), false, 1),
        ];
        commit_owned(&coin_store, &adds, &[], &txid(702))?;

        commit_owned(&coin_store, &[], &[removed, removed], &txid(703))?;

        assert_eq!(reader.get(&removed)?, None);
        assert_eq!(reader.get(&retained)?, Some(retained_txout));
        assert!(reader.has_live_outputs_for_txid(&live)?);
        Ok(())
    }

    #[test]
    fn coin_store_scans_b_framed_values_matching_oracle() -> TestResult {
        use bitcoin_rs_storage::utxo::record::{B_FRAMING_FLAG, RecordFraming, UtxoRecord};
        use bitcoin_rs_storage::{ColumnFamily, KvStore};

        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let coin_store = Arc::new(CoinStore::open(Arc::clone(&store), 64 * 1024 * 1024));

        let txid1 = txid(1);
        let txid2 = txid(2);
        let out1_0 = OutPoint::new(txid1.into(), 0);
        let out1_1 = OutPoint::new(txid1.into(), 1);
        let out2_0 = OutPoint::new(txid2.into(), 0);

        let txout1_0 = txout(10);
        let txout1_1 = txout(20);
        let txout2_0 = txout(30);

        let adds1 = [
            (out1_0, txout1_0.clone(), false, 100),
            (out1_1, txout1_1.clone(), true, 100),
            (out2_0, txout2_0.clone(), false, 100),
        ];
        commit_owned(&coin_store, &adds1, &[], &txid(101))?;

        let spend_out1_0 = [out1_0];
        let txid3 = txid(3);
        let out3_0 = OutPoint::new(txid3.into(), 0);
        let txout3_0 = txout(40);
        let adds2 = [(out3_0, txout3_0.clone(), false, 101)];
        commit_owned(&coin_store, &adds2, &spend_out1_0, &txid(102))?;

        let mut scanned_rows = 0;
        for item in store
            .iter_prefix(ColumnFamily::Coins, &[])
            .map_err(UtxoError::from)?
        {
            let (key, value) = item.map_err(UtxoError::from)?;
            scanned_rows += 1;

            assert!(value.len() > 36, "coin row must have header");
            assert_eq!(
                value[36] & B_FRAMING_FLAG,
                B_FRAMING_FLAG,
                "engine coin row must have b-framing discriminator set"
            );

            let record = UtxoRecord::from_encoded(value.to_vec().into_boxed_slice())?;
            assert_eq!(record.framing(), RecordFraming::B);

            let mut key_bytes = [0_u8; 32];
            key_bytes.copy_from_slice(&key);
            let row_txid = Hash256::from_le_bytes(&key_bytes);
            assert_eq!(record.txid(), row_txid);

            if row_txid == txid1 {
                assert_eq!(record.output_count(), 1);
                let out = record
                    .find_output(1)
                    .ok_or(TestError::Missing("out1_1 must exist"))?;
                assert_eq!(out.value, txout1_1.value.to_sat());
                assert_eq!(out.script_pubkey, txout1_1.script_pubkey.as_slice());
                assert!(out.coinbase);
                assert_eq!(out.height, 100);
                assert!(record.find_output(0).is_none());
            } else if row_txid == txid2 {
                assert_eq!(record.output_count(), 1);
                let out = record
                    .find_output(0)
                    .ok_or(TestError::Missing("out2_0 must exist"))?;
                assert_eq!(out.value, txout2_0.value.to_sat());
                assert_eq!(out.script_pubkey, txout2_0.script_pubkey.as_slice());
                assert!(!out.coinbase);
                assert_eq!(out.height, 100);
            } else if row_txid == txid3 {
                assert_eq!(record.output_count(), 1);
                let out = record
                    .find_output(0)
                    .ok_or(TestError::Missing("out3_0 must exist"))?;
                assert_eq!(out.value, txout3_0.value.to_sat());
                assert_eq!(out.script_pubkey, txout3_0.script_pubkey.as_slice());
                assert!(!out.coinbase);
                assert_eq!(out.height, 101);
            } else {
                panic!("unexpected txid {row_txid:?}");
            }
        }
        assert_eq!(scanned_rows, 3);

        Ok(())
    }
}
mod utxo_key_prefix_collisions {
    use std::io::Cursor;

    use crate::support::utxo::{TestError, TestResult};
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut, Txid};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use bitcoin_rs_storage::utxo::read_snapshot_strict_v4;

    fn make_txid(prefix: [u8; 8], suffix_byte: u8) -> Hash256 {
        let mut bytes = [suffix_byte; 32];
        bytes[..8].copy_from_slice(&prefix);
        Hash256::from_le_bytes(&bytes)
    }

    fn sample_txout(value: u64, tag: u8) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![0x51, tag].into(),
        }
    }

    // RCV-01, RCV-03
    #[test]
    fn recovers_from_key_prefix_collisions_in_utxo_set_and_snapshot() -> TestResult {
        use bitcoin_rs_storage::utxo::UtxoReader;
        use bitcoin_rs_storage::utxo::contract::populate_block_changes;
        use bitcoin_rs_storage::{CoinStore, MemoryKvStore};
        use std::sync::Arc;

        let store = Arc::new(MemoryKvStore::new());
        let coin_store = Arc::new(CoinStore::open(store, 64 * 1024 * 1024));
        let reader = UtxoReader::from_coin_store(coin_store.clone());
        let prefix = [0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let txid_a = make_txid(prefix, 0xaa);
        let txid_b = make_txid(prefix, 0xbb);
        assert_ne!(txid_a, txid_b);

        let op_a0 = OutPoint::new(Txid::from(txid_a), 0);
        let op_a1 = OutPoint::new(Txid::from(txid_a), 1);
        let op_b0 = OutPoint::new(Txid::from(txid_b), 0);
        let op_b2 = OutPoint::new(Txid::from(txid_b), 2);

        let txout_a0 = sample_txout(1_000, 0xa0);
        let txout_a1 = sample_txout(2_000, 0xa1);
        let txout_b0 = sample_txout(3_000, 0xb0);
        let txout_b2 = sample_txout(4_000, 0xb2);

        let mut block1 = BlockChanges::default();
        block1.add(UtxoAdd::new(op_a0, txout_a0.clone(), false, 100));
        block1.add(UtxoAdd::new(op_a1, txout_a1.clone(), true, 100));
        block1.add(UtxoAdd::new(op_b0, txout_b0.clone(), false, 101));
        block1.add(UtxoAdd::new(op_b2, txout_b2.clone(), false, 101));
        populate_block_changes(&coin_store, &block1)?;

        assert!(reader.has_live_outputs_for_txid(&txid_a)?);
        assert!(reader.has_live_outputs_for_txid(&txid_b)?);
        assert_eq!(reader.get(&op_a0)?, Some(txout_a0));
        assert_eq!(reader.get(&op_a1)?, Some(txout_a1.clone()));
        assert_eq!(reader.get(&op_b0)?, Some(txout_b0.clone()));
        assert_eq!(reader.get(&op_b2)?, Some(txout_b2.clone()));

        let mut block2 = BlockChanges::<TxOut>::default();
        block2.remove(op_a0);
        populate_block_changes(&coin_store, &block2)?;

        assert!(reader.has_live_outputs_for_txid(&txid_a)?);
        assert!(reader.has_live_outputs_for_txid(&txid_b)?);
        assert_eq!(reader.get(&op_a0)?, None);
        assert_eq!(reader.get(&op_a1)?, Some(txout_a1));
        assert_eq!(reader.get(&op_b0)?, Some(txout_b0.clone()));
        assert_eq!(reader.get(&op_b2)?, Some(txout_b2.clone()));

        let mut block3 = BlockChanges::<TxOut>::default();
        block3.remove(op_a1);
        populate_block_changes(&coin_store, &block3)?;

        assert!(!reader.has_live_outputs_for_txid(&txid_a)?);
        assert!(reader.has_live_outputs_for_txid(&txid_b)?);
        assert_eq!(reader.get(&op_a1)?, None);
        assert_eq!(reader.get(&op_b0)?, Some(txout_b0.clone()));
        assert_eq!(reader.get(&op_b2)?, Some(txout_b2.clone()));

        let mut block4 = BlockChanges::default();
        let op_a5 = OutPoint::new(Txid::from(txid_a), 5);
        let txout_a5 = sample_txout(5_000, 0xa5);
        block4.add(UtxoAdd::new(op_a5, txout_a5.clone(), false, 104));
        populate_block_changes(&coin_store, &block4)?;

        assert!(reader.has_live_outputs_for_txid(&txid_a)?);
        assert!(reader.has_live_outputs_for_txid(&txid_b)?);
        assert_eq!(reader.get(&op_a5)?, Some(txout_a5.clone()));
        assert_eq!(reader.get(&op_b0)?, Some(txout_b0.clone()));

        let expected = [
            (op_a5, txout_a5, false, 104),
            (op_b0, txout_b0, false, 101),
            (op_b2, txout_b2, false, 101),
        ];
        let view = reader.lock_stable_view()?;
        let mut remaining: std::collections::HashSet<_> =
            expected.iter().map(|(outpoint, ..)| *outpoint).collect();
        let mut first_error: Option<TestError> = None;
        view.for_each_all(|outpoint, script| {
            assert!(
                remaining.remove(outpoint),
                "unexpected or duplicate output {outpoint:?}"
            );
            if first_error.is_some() {
                return;
            }
            let Some((_, txout, coinbase, height)) = expected
                .iter()
                .find(|(expected_outpoint, ..)| expected_outpoint == outpoint)
            else {
                first_error = Some(TestError::Missing(
                    "scanned output must belong to the supplied inputs",
                ));
                return;
            };
            assert_eq!(script, txout.script_pubkey.as_slice());
            let Some(coin) = view.get_entry(outpoint) else {
                first_error = Some(TestError::Missing("scanned coin must be live"));
                return;
            };
            assert_eq!(
                (&coin.txout, coin.coinbase, coin.height),
                (txout, *coinbase, *height)
            );
        });
        assert!(remaining.is_empty());
        if let Some(error) = first_error {
            return Err(error);
        }
        assert!(view.get_entry(&op_a0).is_none());
        assert!(view.get_entry(&op_a1).is_none());
        assert_eq!(view.len(), 3);
        assert_eq!(view.record_count(), 2);

        let mut snapshot_bytes = Vec::new();
        let tip = Hash256::from_le_bytes(&[5; 32]);
        view.write_snapshot_observed(&tip, 104, &mut snapshot_bytes, ())?;
        let loaded = read_snapshot_strict_v4(&mut Cursor::new(&snapshot_bytes))?;
        assert_eq!(loaded.set.len(), 3);
        assert_eq!(loaded.set.record_count(), 2);
        assert!(loaded.set.has_live_outputs_for_txid(&txid_a));
        assert!(loaded.set.has_live_outputs_for_txid(&txid_b));
        assert!(loaded.set.get_entry(&op_a0).is_none());
        assert!(loaded.set.get_entry(&op_a1).is_none());
        for (outpoint, txout, coinbase, height) in &expected {
            let coin = loaded
                .set
                .get_entry(outpoint)
                .ok_or(TestError::Missing("snapshot coin must be live"))?;
            assert_eq!(
                (&coin.txout, coin.coinbase, coin.height),
                (txout, *coinbase, *height)
            );
        }

        Ok(())
    }
}
mod utxo_muhash_unit {
    use bitcoin_rs_storage::utxo::stats::MuHash3072;

    const IDENTITY: [u8; 384] = {
        let mut bytes = [0_u8; 384];
        bytes[383] = 1;
        bytes
    };

    const HELLO_MUHASH: [u8; 384] = hex_384(
        "1a3d6ed31c98e21c99ef030208244720f8dbcdd28854389255031e9ffb5f6a60\
     0689dee672161b98848c8b1afc104819cd6cd7c7cee3df9d84fd5fc2007ba3ed\
     62cd1db4a01baf88d5fd25715c0ff09c41220988a8324d8eb8e46a51870c96c\
     d582e9541fecadf5861a4505323e03ccb0efdc910c1cdec49e02fbe2091f81\
     9df2edf619b7ced051f5a6fba688ad4909da5e79db27202d379eefc7a2a01\
     655d4c622f8d7748d5a69dcf8959ec4d2c371cd9fde3172bcf69980a3d9\
     c02a0f14dfa041992299fe8d3dbbd095055188dc44943a9b9bf9a48f15b72\
     0e10989e35332ff65450b24747efc46996974a499494e4463cd1af2ba02896\
     a4cc9377f2dc63bc49366b4d2ec2f5e139602f8bbfbb0ade7cdcde6e8b\
     128e95d3d40eccea452134818d8602e1909eb052cad138ea4237632261e5f3\
     84ae9cdc5f081d93f826e20e557249b944f0b653ae8ac0977f917b34a4c0\
     c51798b70b12cf5d0e63004b0fd010d0d7e7450047ef2c3f945e98387cf\
     163fcbbcd305fe34ef44491e73a6df582",
    );

    const IDENTITY_CORE_HASH: &str =
        "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8";
    const HELLO_CORE_HASH: &str =
        "981bf4c996ee963cd067e765c15111a6c8d3d6f0257fda0af7371f77fca8c472";

    #[test]
    fn empty_muhash_finalizes_to_identity_element() {
        assert_eq!(MuHash3072::new().finalize(), IDENTITY);
    }

    #[test]
    fn empty_muhash_hash_matches_core_digest() {
        assert_eq!(
            MuHash3072::new().finalize_hash().to_string_be(),
            IDENTITY_CORE_HASH
        );
    }

    #[test]
    fn single_insert_matches_known_answer() {
        let mut muhash = MuHash3072::new();
        muhash.insert(b"hello");

        assert_eq!(muhash.finalize(), HELLO_MUHASH);
    }

    #[test]
    fn single_insert_hash_matches_core_digest() {
        let mut muhash = MuHash3072::new();
        muhash.insert(b"hello");

        assert_eq!(muhash.finalize_hash().to_string_be(), HELLO_CORE_HASH);
    }

    #[test]
    fn insert_order_is_commutative() {
        let mut left = MuHash3072::new();
        left.insert(b"alpha");
        left.insert(b"beta");

        let mut right = MuHash3072::new();
        right.insert(b"beta");
        right.insert(b"alpha");

        assert_eq!(left.finalize(), right.finalize());
    }

    #[test]
    fn insert_then_remove_collapses_to_identity() {
        let mut muhash = MuHash3072::new();
        muhash.insert(b"spent output");
        muhash.remove(b"spent output");

        assert_eq!(muhash.finalize(), IDENTITY);
    }

    const fn hex_384(hex: &str) -> [u8; 384] {
        let bytes = hex.as_bytes();
        let mut out = [0_u8; 384];
        let mut in_idx = 0;
        let mut out_idx = 0;
        while in_idx < bytes.len() {
            let hi = bytes[in_idx];
            if hi == b' ' || hi == b'\n' || hi == b'\t' {
                in_idx += 1;
                continue;
            }
            let lo = bytes[in_idx + 1];
            out[out_idx] = (hex_nibble(hi) << 4) | hex_nibble(lo);
            out_idx += 1;
            in_idx += 2;
        }
        out
    }

    const fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0,
        }
    }
}
mod utxo_reader_faults {
    use std::collections::HashSet;
    use std::path::Path;
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, Script, TxOut};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use bitcoin_rs_storage::utxo::{UtxoError, UtxoReader};
    use bitcoin_rs_storage::{
        BufferedWriteBatch, Bytes, CoinKey, CoinStore, ColumnFamily, KvIter, KvSnapshot, KvStore,
        MemoryKvStore, PersistFault, PrefixScan, PrefixScanLimit, StorageError, WriteCondition,
    };
    use parking_lot::Mutex;

    use crate::support::TestResult;

    const CACHE_BUDGET: u64 = 64 * 1024 * 1024;
    const VALUE_SATS: u64 = 12_345;
    const COIN_HEIGHT: u32 = 7;

    #[derive(Clone, Copy)]
    enum ScanFault {
        Open,
        Row,
    }

    struct ReadFaultSnapshot<'a> {
        inner: Box<dyn KvSnapshot + 'a>,
        fault: Option<ScanFault>,
    }

    impl KvSnapshot for ReadFaultSnapshot<'_> {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            if cf == ColumnFamily::Coins
                && let Some(fault) = self.fault
            {
                let error = StorageError::Io(std::io::Error::other("injected coin scan failure"));
                return match fault {
                    ScanFault::Open => Err(error),
                    ScanFault::Row => Ok(Box::new(std::iter::once(Err(error)))),
                };
            }
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }
    }

    struct ReadFaultStore {
        inner: MemoryKvStore,
        poisoned: Mutex<HashSet<Vec<u8>>>,
        scan_fault: Mutex<Option<ScanFault>>,
    }

    impl ReadFaultStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: MemoryKvStore::new(),
                poisoned: Mutex::new(HashSet::new()),
                scan_fault: Mutex::new(None),
            })
        }

        fn poison_coin(&self, txid: &Hash256) {
            self.poisoned.lock().insert(txid.to_le_bytes().to_vec());
        }
    }

    impl KvStore for ReadFaultStore {
        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            if cf == ColumnFamily::Coins && self.poisoned.lock().contains(key) {
                return Err(StorageError::Io(std::io::Error::other(
                    "injected coin read failure",
                )));
            }
            self.inner.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<KvIter<'a>, StorageError> {
            if cf == ColumnFamily::Coins
                && let Some(fault) = *self.scan_fault.lock()
            {
                let error = StorageError::Io(std::io::Error::other("injected coin scan failure"));
                return match fault {
                    ScanFault::Open => Err(error),
                    ScanFault::Row => Ok(Box::new(std::iter::once(Err(error)))),
                };
            }
            self.inner.iter_prefix(cf, prefix)
        }

        fn scan_prefix_from_bounded(
            &self,
            cf: ColumnFamily,
            prefix: &[u8],
            start: &[u8],
            limit: PrefixScanLimit,
        ) -> Result<PrefixScan, StorageError> {
            self.inner
                .scan_prefix_from_bounded(cf, prefix, start, limit)
        }

        fn new_batch(&self) -> BufferedWriteBatch {
            self.inner.new_batch()
        }

        fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
            self.inner.write(batch)
        }

        fn write_durable_if(
            &self,
            conditions: &[WriteCondition<'_>],
            batch: BufferedWriteBatch,
        ) -> Result<bool, StorageError> {
            self.inner.write_durable_if(conditions, batch)
        }

        fn flush(&self) -> Result<(), StorageError> {
            self.inner.flush()
        }

        fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
            Ok(Box::new(ReadFaultSnapshot {
                inner: self.inner.snapshot()?,
                fault: *self.scan_fault.lock(),
            }))
        }

        fn multi_get(
            &self,
            cf: ColumnFamily,
            keys: &[&[u8]],
        ) -> Result<Vec<Option<Bytes>>, StorageError> {
            self.inner.multi_get(cf, keys)
        }

        fn ingest_sorted(
            &self,
            cf: ColumnFamily,
            rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
            scratch: &Path,
        ) -> Result<u64, StorageError> {
            self.inner.ingest_sorted(cf, rows, scratch)
        }

        fn delete_range(
            &self,
            cf: ColumnFamily,
            start: &[u8],
            end: &[u8],
        ) -> Result<(), StorageError> {
            self.inner.delete_range(cf, start, end)
        }

        fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
            self.inner.checkpoint(dir)
        }

        fn engine_cache_bytes(&self) -> u64 {
            self.inner.engine_cache_bytes()
        }

        fn arm_persist_fault(&self, fault: PersistFault) {
            self.inner.arm_persist_fault(fault);
        }
    }

    fn txid(seed: u8) -> Hash256 {
        Hash256::from_le_bytes(&[seed; 32])
    }

    fn outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint::new(txid(seed).into(), vout)
    }

    fn reader_over(store: &Arc<ReadFaultStore>) -> UtxoReader {
        UtxoReader::from_coin_store(Arc::new(CoinStore::open(store.clone(), CACHE_BUDGET)))
    }

    fn commit_coins(store: &Arc<ReadFaultStore>, outpoints: &[OutPoint]) -> TestResult {
        let mut changes = BlockChanges::with_capacity(outpoints.len(), 0);
        for outpoint in outpoints {
            changes.add(UtxoAdd::new(
                *outpoint,
                TxOut {
                    value: Amount::from_sat(VALUE_SATS),
                    script_pubkey: Script::from_bytes(vec![0x51]),
                },
                true,
                COIN_HEIGHT,
            ));
        }
        reader_over(store).populate_fixture_coins(&changes)?;
        Ok(())
    }

    // ARCH-07a
    #[test]
    fn engine_read_fault_is_an_error_never_an_absent_coin() -> TestResult {
        let store = ReadFaultStore::new();
        let faulted = outpoint(0xA1, 0);
        let healthy = outpoint(0xB2, 1);
        let never_stored = outpoint(0xC3, 0);
        commit_coins(&store, &[faulted, healthy])?;
        store.poison_coin(&txid(0xA1));
        let reader = reader_over(&store);

        assert!(matches!(
            reader.get_entry(&faulted),
            Err(UtxoError::Storage(StorageError::Io(_)))
        ));
        assert!(matches!(
            reader.get(&faulted),
            Err(UtxoError::Storage(StorageError::Io(_)))
        ));
        assert!(matches!(
            reader.confirmation_height(&txid(0xA1), u32::MAX),
            Err(UtxoError::Storage(StorageError::Io(_)))
        ));
        assert!(matches!(
            reader.has_live_outputs_for_txid(&txid(0xA1)),
            Err(UtxoError::Storage(StorageError::Io(_)))
        ));

        let coin = reader.get_entry(&healthy)?;
        assert_eq!(
            coin.as_ref().map(|coin| coin.txout.value.to_sat()),
            Some(VALUE_SATS)
        );
        assert_eq!(coin.as_ref().map(|coin| coin.height), Some(COIN_HEIGHT));
        assert_eq!(coin.as_ref().map(|coin| coin.coinbase), Some(true));
        assert!(reader.has_live_outputs_for_txid(&txid(0xB2))?);

        assert!(reader.get_entry(&never_stored)?.is_none());
        assert!(reader.get_entry(&outpoint(0xB2, 0))?.is_none());
        assert!(!reader.has_live_outputs_for_txid(&txid(0xC3))?);
        assert_eq!(
            reader.confirmation_height(&txid(0xB2), 2)?,
            Some(COIN_HEIGHT)
        );
        assert_eq!(reader.confirmation_height(&txid(0xC3), u32::MAX)?, None);
        Ok(())
    }

    // ARCH-07a
    #[test]
    fn undecodable_coin_row_is_an_error_never_an_absent_coin() -> TestResult {
        let store = ReadFaultStore::new();
        store.put(
            ColumnFamily::Coins,
            CoinKey(txid(0xD4).to_le_bytes()).as_bytes(),
            &[0xff; 3],
        )?;
        let reader = reader_over(&store);

        assert!(matches!(
            reader.get_entry(&outpoint(0xD4, 0)),
            Err(UtxoError::CorruptRecord)
        ));
        assert!(matches!(
            reader.get(&outpoint(0xD4, 0)),
            Err(UtxoError::CorruptRecord)
        ));
        assert!(matches!(
            reader.has_live_outputs_for_txid(&txid(0xD4)),
            Err(UtxoError::CorruptRecord)
        ));
        assert!(matches!(
            reader.confirmation_height(&txid(0xD4), u32::MAX),
            Err(UtxoError::CorruptRecord)
        ));
        assert!(matches!(
            reader.lock_stable_view(),
            Err(UtxoError::CorruptRecord)
        ));
        assert!(matches!(
            reader.with_stable_view(|_| panic!("corrupt scan must not expose a view")),
            Err(UtxoError::CorruptRecord)
        ));
        Ok(())
    }

    #[test]
    fn stable_view_scan_failures_are_typed_errors() -> TestResult {
        for fault in [ScanFault::Open, ScanFault::Row] {
            let store = ReadFaultStore::new();
            commit_coins(&store, &[outpoint(0xA1, 0)])?;
            *store.scan_fault.lock() = Some(fault);
            let reader = reader_over(&store);
            assert!(matches!(
                reader.lock_stable_view(),
                Err(UtxoError::Storage(StorageError::Io(_)))
            ));
            assert!(matches!(
                reader.with_stable_view(|_| panic!("failed scan must not expose a view")),
                Err(UtxoError::Storage(StorageError::Io(_)))
            ));
        }
        Ok(())
    }

    #[test]
    fn miskeyed_coin_row_is_an_error_for_stable_views() -> TestResult {
        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

        let store = ReadFaultStore::new();
        let record = UtxoRecord::from_owned_outputs(
            txid(0xA1),
            &[OwnedUtxoOut::new(
                0,
                VALUE_SATS,
                vec![0x51],
                true,
                COIN_HEIGHT,
            )],
        )?;
        store.put(
            ColumnFamily::Coins,
            CoinKey(txid(0xB2).to_le_bytes()).as_bytes(),
            record.bytes(),
        )?;
        let reader = reader_over(&store);
        assert!(matches!(
            reader.lock_stable_view(),
            Err(UtxoError::CorruptRecord)
        ));
        Ok(())
    }

    #[test]
    fn malformed_coin_key_is_an_error_for_stable_views() -> TestResult {
        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

        let store = ReadFaultStore::new();
        let record = UtxoRecord::from_owned_outputs(
            txid(0xA1),
            &[OwnedUtxoOut::new(
                0,
                VALUE_SATS,
                vec![0x51],
                true,
                COIN_HEIGHT,
            )],
        )?;
        store.put(ColumnFamily::Coins, &[0xA1; 31], record.bytes())?;
        assert!(matches!(
            reader_over(&store).lock_stable_view(),
            Err(UtxoError::Storage(StorageError::InvalidOperation(_)))
        ));
        Ok(())
    }
}
mod utxo_snapshot_roundtrip {
    use std::io::{Cursor, Seek};

    use crate::support::utxo::{TestError, TestResult};
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, Script, TxOut};
    use bitcoin_rs_storage::utxo::{
        SnapshotCoin, SnapshotCoinObserver, UtxoError, UtxoSet, read_snapshot_strict_v4,
        read_snapshot_strict_v4_observed, write_snapshot_observed,
    };
    use tempfile::tempfile;

    fn txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn txout(seed: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(2_000 + seed),
            script_pubkey: vec![0x51, u8::try_from(seed % 256).unwrap_or(0)].into(),
        }
    }

    #[test]
    fn snapshot_roundtrip_preserves_vout_and_metadata_boundaries() -> TestResult {
        let set = UtxoSet::new();
        let live_txid = txid(42_000);
        let low = OutPoint::new(live_txid.into(), 63);
        let high = OutPoint::new(live_txid.into(), 64);
        let max = OutPoint::new(live_txid.into(), u32::MAX);
        let low_txout = txout(42_001);
        let high_txout = txout(42_002);
        let max_txout = TxOut {
            value: Amount::from_sat(42_003),
            script_pubkey: Script::new(),
        };
        let out_low = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 63,
            value: low_txout.value.to_sat(),
            script_pubkey: low_txout.script_pubkey.to_vec(),
            coinbase: false,
            height: 400,
        };
        let out_high = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 64,
            value: high_txout.value.to_sat(),
            script_pubkey: high_txout.script_pubkey.to_vec(),
            coinbase: true,
            height: 401,
        };
        let out_max = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: u32::MAX,
            value: max_txout.value.to_sat(),
            script_pubkey: max_txout.script_pubkey.to_vec(),
            coinbase: false,
            height: u32::MAX,
        };
        let rec = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            live_txid,
            &[out_low, out_high, out_max],
        )?;
        set.insert_parsed_record(rec);

        let expected_hash = set.lock_stable_view().hash_serialized_3()?;
        let mut file = tempfile()?;
        write_snapshot_observed(&set, &txid(42_005), u32::MAX, &mut file, ())?;
        file.rewind()?;
        let loaded = read_snapshot_strict_v4(&mut file)?;

        assert_eq!(loaded.tip_hash, txid(42_005));
        assert_eq!(loaded.height, u32::MAX);
        assert_eq!(loaded.set.get(&low), Some(low_txout));
        assert_eq!(loaded.set.get(&high), Some(high_txout));
        assert_eq!(loaded.set.get(&max), Some(max_txout));
        assert_eq!(
            loaded.set.lock_stable_view().hash_serialized_3()?,
            expected_hash
        );
        assert!(
            !loaded
                .set
                .get_entry(&low)
                .ok_or(TestError::Missing("missing low entry"))?
                .coinbase
        );
        assert!(
            loaded
                .set
                .get_entry(&high)
                .ok_or(TestError::Missing("missing high entry"))?
                .coinbase
        );
        assert_eq!(
            loaded
                .set
                .get_entry(&max)
                .ok_or(TestError::Missing("missing max entry"))?
                .height,
            u32::MAX
        );
        Ok(())
    }

    #[test]
    fn strict_v4_snapshot_requires_complete_exact_input() -> TestResult {
        let mut snapshot = Vec::new();
        write_snapshot_observed(&UtxoSet::new(), &txid(64_100), 64, &mut snapshot, ())?;

        let loaded = read_snapshot_strict_v4(&mut Cursor::new(&snapshot))?;
        assert_eq!(loaded.tip_hash, txid(64_100));
        assert_eq!(loaded.height, 64);
        assert_eq!(loaded.muhash_trailer, [0_u8; 384]);

        assert!(
            read_snapshot_strict_v4(&mut Cursor::new(&snapshot[..snapshot.len() - 384])).is_err()
        );
        assert!(
            read_snapshot_strict_v4(&mut Cursor::new(&snapshot[..snapshot.len() - 1])).is_err()
        );

        let mut trailing = snapshot;
        trailing.push(0);
        assert!(read_snapshot_strict_v4(&mut Cursor::new(trailing)).is_err());
        Ok(())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SeenSnapshotCoin {
        txid: Hash256,
        vout: u32,
        value: u64,
        script_pubkey: Vec<u8>,
        height: u32,
        coinbase: bool,
    }

    #[derive(Default)]
    struct RecordingSnapshotObserver {
        coins: Vec<SeenSnapshotCoin>,
        replacement_trailer: Option<[u8; 384]>,
        trailer_calls: usize,
    }

    impl SnapshotCoinObserver for RecordingSnapshotObserver {
        fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
            self.coins.push(SeenSnapshotCoin {
                txid: coin.txid,
                vout: coin.vout,
                value: coin.value,
                script_pubkey: coin.script_pubkey.to_vec(),
                height: coin.height,
                coinbase: coin.coinbase,
            });
        }

        fn select_trailer(&mut self, fallback: [u8; 384]) -> [u8; 384] {
            self.trailer_calls += 1;
            self.replacement_trailer.unwrap_or(fallback)
        }
    }

    #[test]
    fn observed_snapshot_traversal_matches_the_current_reader() -> TestResult {
        let set = UtxoSet::new();
        let first_txid = txid(200_000);
        let second_txid = txid(200_001);
        let first = txout(200_010);
        let second = TxOut {
            value: Amount::from_sat(200_011),
            script_pubkey: Script::new(),
        };
        let rec1 = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            first_txid,
            &[
                bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                    vout: 0,
                    value: first.value.to_sat(),
                    script_pubkey: first.script_pubkey.to_vec(),
                    coinbase: false,
                    height: 2000,
                },
                bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                    vout: 9,
                    value: second.value.to_sat(),
                    script_pubkey: second.script_pubkey.to_vec(),
                    coinbase: true,
                    height: 2001,
                },
            ],
        )?;
        let rec2 = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            second_txid,
            &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                vout: 2,
                value: txout(200_012).value.to_sat(),
                script_pubkey: txout(200_012).script_pubkey.to_vec(),
                coinbase: false,
                height: 2002,
            }],
        )?;
        set.insert_parsed_record(rec1);
        set.insert_parsed_record(rec2);

        let mut ordinary = Vec::new();
        let (ordinary_trailer, ()) =
            write_snapshot_observed(&set, &txid(200_003), 2002, &mut ordinary, ())?;
        let mut observed = Vec::new();
        let (observed_trailer, writer_observer) = write_snapshot_observed(
            &set,
            &txid(200_003),
            2002,
            &mut observed,
            RecordingSnapshotObserver::default(),
        )?;

        assert_eq!(observed, ordinary);
        assert_eq!(observed_trailer, ordinary_trailer);
        assert_eq!(writer_observer.trailer_calls, 1);
        assert_eq!(writer_observer.coins.len(), 3);

        let (_, reader_observer) = read_snapshot_strict_v4_observed(
            &mut Cursor::new(&observed),
            RecordingSnapshotObserver::default(),
        )?;
        assert_eq!(reader_observer.coins, writer_observer.coins);
        Ok(())
    }

    #[test]
    fn snapshot_trailer_round_trips_without_a_listener() -> TestResult {
        let set = UtxoSet::new();

        let rec = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
            txid(130_000),
            &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                vout: 0,
                value: txout(130_001).value.to_sat(),
                script_pubkey: txout(130_001).script_pubkey.to_vec(),
                coinbase: false,
                height: 900,
            }],
        )?;
        set.insert_parsed_record(rec);

        let mut file = tempfile()?;
        let (returned_trailer, ()) =
            write_snapshot_observed(&set, &txid(130_100), 900, &mut file, ())?;
        assert_eq!(returned_trailer, [0_u8; 384]);
        file.rewind()?;
        let loaded = read_snapshot_strict_v4(&mut file)?;
        assert_eq!(loaded.muhash_trailer, [0_u8; 384]);
        Ok(())
    }

    fn v4_header(tip_hash: Hash256, height: u32, record_count: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(52);
        bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&tip_hash.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&record_count.to_le_bytes());
        bytes
    }

    fn v4_record_body(txid_bytes: &[u8; 32], output_count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(txid_bytes[0]);
        bytes.extend_from_slice(&txid_bytes[..8]);
        bytes.extend_from_slice(txid_bytes);
        bytes.extend_from_slice(&output_count.to_le_bytes());
        bytes
    }

    #[test]
    fn snapshot_read_refuses_malformed_v4_bytes() {
        type Expected = fn(&UtxoError) -> bool;
        let duplicate_vouts = {
            let mut bytes = v4_header(txid(160_011), 1601, 1);
            bytes.extend_from_slice(&v4_record_body(&txid(160_010).to_le_bytes(), 4));
            for vout in [9, 1, 9, 1] {
                append_snapshot_output(&mut bytes, vout, 1_000, 1601, false, &[0x51]);
            }
            bytes.extend_from_slice(&[0_u8; 384]);
            bytes
        };
        let mut invalid_magic = v4_header(txid(1), 100, 0);
        invalid_magic[0..4].copy_from_slice(&0xDE_AD_BE_EF_u32.to_le_bytes());
        let mut count_mismatch = v4_header(txid(170_001), 1700, 1);
        count_mismatch.extend_from_slice(&v4_record_body(&txid(170_000).to_le_bytes(), 0));
        count_mismatch.extend_from_slice(&[0_u8; 384]);

        let cases: [(&str, Vec<u8>, Expected); 3] = [
            (
                "invalid magic",
                invalid_magic,
                |error| matches!(error, UtxoError::InvalidSnapshotMagic { actual } if *actual == 0xDE_AD_BE_EF),
            ),
            ("duplicate vout", duplicate_vouts, |error| {
                matches!(error, UtxoError::SnapshotDuplicateVout { vout: 9 })
            }),
            ("record count mismatch", count_mismatch, |error| {
                matches!(
                    error,
                    UtxoError::SnapshotRecordCountMismatch {
                        declared: 1,
                        actual: 0
                    }
                )
            }),
        ];
        for version in [2_u32, 3, 99] {
            let mut bytes = v4_header(txid(1), 100, 0);
            bytes[4..8].copy_from_slice(&version.to_le_bytes());
            let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
                panic!("unsupported version {version} was accepted");
            };
            assert!(
                matches!(error, UtxoError::UnsupportedSnapshotVersion { version: actual } if actual == version)
            );
        }
        for (name, bytes, expected) in cases {
            let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
                panic!("{name} was accepted");
            };
            assert!(expected(&error), "{name} gave {error:?}");
        }
    }

    #[test]
    fn strict_v4_observer_is_dropped_on_error() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        struct DropObserver {
            dropped: Arc<AtomicBool>,
        }

        impl SnapshotCoinObserver for DropObserver {
            fn observe_coin(&mut self, _: SnapshotCoin<'_>) {}
        }

        impl Drop for DropObserver {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::SeqCst);
            }
        }

        let record_txid = txid(180_000);
        let mut bytes = v4_header(txid(180_001), 1800, 2);
        for vout in 0..2 {
            bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 1));
            append_snapshot_output(
                &mut bytes,
                vout,
                4_000 + u64::from(vout),
                1800,
                false,
                &[0x51],
            );
        }
        bytes.extend_from_slice(&[0_u8; 384]);

        let dropped = Arc::new(AtomicBool::new(false));
        let result = read_snapshot_strict_v4_observed(
            &mut Cursor::new(bytes),
            DropObserver {
                dropped: Arc::clone(&dropped),
            },
        );
        assert!(matches!(
            result,
            Err(UtxoError::SnapshotRecordCountMismatch { .. })
        ));
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn append_snapshot_output(
        bytes: &mut Vec<u8>,
        vout: u32,
        value: u64,
        height: u32,
        coinbase: bool,
        script_pubkey: &[u8],
    ) {
        let script_len = u16::try_from(script_pubkey.len()).unwrap_or(u16::MAX);
        bytes.extend_from_slice(&vout.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.push(u8::from(coinbase));
        bytes.extend_from_slice(&script_len.to_le_bytes());
        bytes.extend_from_slice(script_pubkey);
    }

    #[test]
    fn rejects_snapshot_record_with_zero_outputs() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        data.extend_from_slice(&4_u32.to_le_bytes());
        data.extend_from_slice(&[0x11; 32]);
        data.extend_from_slice(&100_u32.to_le_bytes());
        data.extend_from_slice(&1_u64.to_le_bytes());
        let txid = [0x22; 32];
        data.push(txid[0]);
        data.extend_from_slice(&txid[..8]);
        data.extend_from_slice(&txid);
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&[0_u8; 384]);

        let result = read_snapshot_strict_v4(&mut Cursor::new(&data));
        assert!(matches!(
            &result,
            Err(UtxoError::SnapshotRecordCountMismatch {
                declared: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn rejects_snapshot_record_with_too_many_outputs() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        data.extend_from_slice(&4_u32.to_le_bytes());
        data.extend_from_slice(&[0x11; 32]);
        data.extend_from_slice(&100_u32.to_le_bytes());
        data.extend_from_slice(&1_u64.to_le_bytes());
        let txid = [0x22; 32];
        data.push(txid[0]);
        data.extend_from_slice(&txid[..8]);
        data.extend_from_slice(&txid);
        data.extend_from_slice(&2_000_000_u32.to_le_bytes());
        data.extend_from_slice(&[0_u8; 384]);

        let result = read_snapshot_strict_v4(&mut Cursor::new(&data));
        assert!(matches!(
            &result,
            Err(UtxoError::SnapshotOutputCountTooLarge { count: 2_000_000 })
        ));
    }

    #[test]
    fn rejects_snapshot_with_record_count_exceeding_budget() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        data.extend_from_slice(&4_u32.to_le_bytes());
        data.extend_from_slice(&[0x11; 32]);
        data.extend_from_slice(&100_u32.to_le_bytes());
        data.extend_from_slice(&300_000_000_u64.to_le_bytes());
        data.extend_from_slice(&[0_u8; 384]);

        let result = read_snapshot_strict_v4(&mut Cursor::new(&data));
        assert!(matches!(
            &result,
            Err(UtxoError::SnapshotRecordCountTooLarge { count: 300_000_000 })
        ));
    }

    fn valid_two_output_snapshot(record_txid: Hash256, height: u32) -> Vec<u8> {
        let mut bytes = v4_header(txid(190_001), height, 1);
        bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 2));
        append_snapshot_output(&mut bytes, 0, 1_000, height, false, &[0x51]);
        append_snapshot_output(&mut bytes, 1, 2_000, height, true, &[0x51, 0x52]);
        bytes.extend_from_slice(&[0_u8; 384]);
        bytes
    }

    #[test]
    fn strict_v4_refuses_every_truncation_length() -> TestResult {
        let bytes = valid_two_output_snapshot(txid(190_000), 1900);
        read_snapshot_strict_v4(&mut Cursor::new(&bytes))?;
        for cut in 0..bytes.len() {
            assert!(
                read_snapshot_strict_v4(&mut Cursor::new(&bytes[..cut])).is_err(),
                "truncation at {cut} decoded"
            );
        }
        Ok(())
    }

    #[test]
    fn strict_v4_refuses_a_duplicated_record() {
        let record_txid = txid(191_000);
        let mut bytes = v4_header(txid(191_001), 1910, 2);
        for vout in [0_u32, 1] {
            bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 1));
            append_snapshot_output(&mut bytes, vout, 1_000, 1910, false, &[0x51]);
        }
        bytes.extend_from_slice(&[0_u8; 384]);
        let result = read_snapshot_strict_v4(&mut Cursor::new(bytes));
        assert!(matches!(
            result,
            Err(UtxoError::SnapshotRecordCountMismatch {
                declared: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn strict_v4_coin_hash_ignores_output_order() -> TestResult {
        fn ordered_snapshot(vouts: [u32; 2]) -> Vec<u8> {
            let record_txid = txid(192_000);
            let mut bytes = v4_header(txid(192_001), 1920, 1);
            bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 2));
            for vout in vouts {
                append_snapshot_output(
                    &mut bytes,
                    vout,
                    1_000 + u64::from(vout),
                    1920,
                    false,
                    &[0x51],
                );
            }
            bytes.extend_from_slice(&[0_u8; 384]);
            bytes
        }
        let forward = read_snapshot_strict_v4(&mut Cursor::new(ordered_snapshot([3, 9])))?;
        let reverse = read_snapshot_strict_v4(&mut Cursor::new(ordered_snapshot([9, 3])))?;
        assert_eq!(
            forward.set.lock_stable_view().hash_serialized_3()?,
            reverse.set.lock_stable_view().hash_serialized_3()?,
            "an unordered record must hash to the same coin commitment"
        );
        for vout in [3_u32, 9] {
            let outpoint = OutPoint::new(txid(192_000).into(), vout);
            assert!(
                reverse.set.get_entry(&outpoint).is_some(),
                "unordered record lost vout {vout}"
            );
        }
        Ok(())
    }
}
mod utxo_snapshot_v4_golden {
    #![allow(clippy::expect_used)]

    use std::io::Cursor;

    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_consensus::primitives::hex::hex_encode;
    use bitcoin_rs_storage::utxo::read_snapshot_strict_v4;

    const GOLDEN: &[u8] = include_bytes!("../../testdata/storage/fixtures/utxo-v4-golden.dat");

    const GOLDEN_HASH_HEX: &str =
        "020e5a59271f9db60e11102c4262702747676e868e80e7837b6e6d5fb05213ff";

    const GOLDEN_OUTPUTS: usize = 433;
    const GOLDEN_TIP_HEIGHT: u32 = 412_732;

    fn txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    #[test]
    fn a_v4_snapshot_loads_to_the_hash_and_trailer_it_was_written_with() {
        let loaded = read_snapshot_strict_v4(&mut Cursor::new(GOLDEN)).expect("v4 snapshot loads");

        assert_eq!(loaded.height, GOLDEN_TIP_HEIGHT);
        assert_eq!(loaded.tip_hash, txid(4_242));
        assert_eq!(loaded.set.len(), GOLDEN_OUTPUTS, "output count drifted");
        assert_eq!(
            loaded.muhash_trailer, [0_u8; 384],
            "the MuHash trailer must survive the load byte for byte"
        );
        assert_eq!(
            hex_encode(
                &loaded
                    .set
                    .lock_stable_view()
                    .hash_serialized_3()
                    .expect("hash")
                    .to_le_bytes()
            ),
            GOLDEN_HASH_HEX,
            "a v4 snapshot no longer hashes to what the v4 build computed"
        );
    }
}
mod utxo_snapshot_with_muhash {
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut};
    use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
    use bitcoin_rs_storage::utxo::stats::{CoinStats, CoinStatsAccumulator};
    use bitcoin_rs_storage::utxo::{UtxoSet, write_snapshot_observed};

    use crate::support::utxo::TestResult;

    const TRAILER_LEN: usize = 384;

    #[derive(Clone, Copy)]
    enum SecondCommit {
        Overwrite,
        Replace,
        SpendAll,
    }

    struct Plan {
        name: &'static str,
        shards: u8,
        entries: u32,
        second: SecondCommit,
    }

    #[test]
    fn snapshot_trailer_matches_a_serial_reference() -> TestResult {
        let plans = [
            Plan {
                name: "single shard runs",
                shards: 1,
                entries: 2_048,
                second: SecondCommit::SpendAll,
            },
            Plan {
                name: "two shards chunked",
                shards: 2,
                entries: 2_048,
                second: SecondCommit::Replace,
            },
            Plan {
                name: "twenty shards in parallel",
                shards: 20,
                entries: 20,
                second: SecondCommit::Replace,
            },
            Plan {
                name: "twenty shards coalesced overwrite",
                shards: 20,
                entries: 20,
                second: SecondCommit::Overwrite,
            },
            Plan {
                name: "duplicate txid overwrite",
                shards: 1,
                entries: 1,
                second: SecondCommit::Overwrite,
            },
        ];
        for plan in &plans {
            run(plan)?;
        }
        Ok(())
    }

    fn run(plan: &Plan) -> TestResult {
        let set = UtxoSet::new();
        let mut expected = CoinStats::new();

        let capacity = usize::try_from(plan.entries)?;
        let mut first = BlockChanges::with_capacity(capacity, 0);
        let mut seeded = Vec::with_capacity(capacity);
        for index in 0..plan.entries {
            let shard = u8::try_from(index % u32::from(plan.shards))?;
            let slot = index / u32::from(plan.shards);
            let outpoint = OutPoint::new(
                txid_in_shard(shard, 3_000 + u64::from(slot / 4)).into(),
                slot % 4,
            );
            let txout = txout(3_000 + index);
            let coinbase = index % 2 == 0;
            assert_eq!(shard_of(&outpoint), shard, "{}: wrong shard", plan.name);
            expected.insert_utxo(&outpoint, &txout, 200, coinbase);
            first.add(UtxoAdd::new(outpoint, txout.clone(), coinbase, 200));
            seeded.push((outpoint, txout, coinbase));
        }
        let mut second = BlockChanges::with_capacity(capacity, capacity);
        let mut live = Vec::with_capacity(capacity);
        let mut spent = Vec::with_capacity(capacity);
        for (index, (outpoint, seeded_txout, coinbase)) in seeded.iter().enumerate().rev() {
            let index = u32::try_from(index)?;
            expected.remove_utxo(outpoint, seeded_txout, 200, *coinbase);
            match plan.second {
                SecondCommit::Overwrite => {
                    let replacement = txout(6_000 + index);
                    expected.insert_utxo(outpoint, &replacement, 201, false);
                    second.add(UtxoAdd::new(*outpoint, replacement.clone(), false, 201));
                    live.push((*outpoint, replacement));
                }
                SecondCommit::Replace => {
                    let shard = shard_of(outpoint);
                    let slot = index / u32::from(plan.shards);
                    let fresh = OutPoint::new(
                        txid_in_shard(shard, 6_000 + u64::from(slot / 4)).into(),
                        slot % 4,
                    );
                    let replacement = txout(6_000 + index);
                    assert_eq!(shard_of(&fresh), shard, "{}: wrong shard", plan.name);
                    expected.insert_utxo(&fresh, &replacement, 201, false);
                    second.remove(*outpoint);
                    second.add(UtxoAdd::new(fresh, replacement.clone(), false, 201));
                    live.push((fresh, replacement));
                    spent.push(*outpoint);
                }
                SecondCommit::SpendAll => {
                    second.remove(*outpoint);
                    spent.push(*outpoint);
                }
            }
        }
        use std::collections::HashMap;
        let mut by_txid: HashMap<Hash256, Vec<bitcoin_rs_storage::utxo::record::OwnedUtxoOut>> =
            HashMap::new();
        for (outpoint, txout) in &live {
            by_txid.entry(outpoint.txid.into()).or_default().push(
                bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
                    vout: outpoint.vout,
                    value: txout.value.to_sat(),
                    script_pubkey: txout.script_pubkey.to_vec(),
                    coinbase: false,
                    height: 201,
                },
            );
        }
        for (txid, mut outs) in by_txid {
            outs.sort_by_key(|o| o.vout);
            let rec =
                bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(txid, &outs)?;
            set.insert_parsed_record(rec);
        }
        let mut snapshot = Vec::new();
        let (trailer, _) = write_snapshot_observed(
            &set,
            &txid(3_001),
            201,
            &mut snapshot,
            CoinStatsAccumulator::with_parallel_muhash(201),
        )?;
        let expected_trailer = expected.muhash.finalize();
        assert_eq!(trailer, expected_trailer, "{}: trailer", plan.name);
        assert_ne!(
            trailer, [0_u8; TRAILER_LEN],
            "{}: identity trailer",
            plan.name
        );
        assert_eq!(
            &snapshot[snapshot.len() - TRAILER_LEN..],
            expected_trailer,
            "{}: trailer bytes",
            plan.name
        );
        if let Some((outpoint, txout)) = live.first() {
            let mut bumped = txout.clone();
            bumped.value = Amount::from_sat(txout.value.to_sat().saturating_add(1));
            let mut perturbed = expected.clone();
            perturbed.remove_utxo(outpoint, txout, 201, false);
            perturbed.insert_utxo(outpoint, &bumped, 201, false);
            assert_ne!(
                trailer,
                perturbed.muhash.finalize(),
                "{}: perturbed trailer must differ",
                plan.name
            );
        }
        for (outpoint, txout) in live {
            assert_eq!(
                set.get(&outpoint),
                Some(txout),
                "{}: lost a coin",
                plan.name
            );
        }
        for outpoint in spent {
            assert_eq!(set.get(&outpoint), None, "{}: kept a spent coin", plan.name);
        }
        Ok(())
    }

    fn txout(index: u32) -> TxOut {
        TxOut {
            value: Amount::from_sat(50_000 + u64::from(index)),
            script_pubkey: vec![0x51, index.to_le_bytes()[0]].into(),
        }
    }

    fn shard_of(outpoint: &OutPoint) -> u8 {
        outpoint.txid.0.to_le_bytes()[0]
    }

    fn txid(index: u32) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn txid_in_shard(shard: u8, suffix: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[0] = shard;
        bytes[1..9].copy_from_slice(&suffix.to_le_bytes());
        bytes[9..17].copy_from_slice(&suffix.rotate_left(13).to_le_bytes());
        bytes[17..25].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }
}
mod utxo_snapshot_witnessed {
    use std::io::{Cursor, Seek, Write};

    use crate::support::utxo::{TestError, TestResult};
    use bitcoin_rs_consensus::primitives::{Amount, Hash256, TxOut};
    use bitcoin_rs_storage::utxo::{
        SeedProvenance, SnapshotCoin, SnapshotCoinObserver, read_snapshot_strict_v4,
        read_snapshot_strict_v4_witnessed, write_snapshot_observed, write_snapshot_witnessed,
    };
    use sha2::{Digest, Sha256};

    fn txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn txout(seed: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(2_000 + seed),
            script_pubkey: vec![0x51, u8::try_from(seed % 256).unwrap_or(0)].into(),
        }
    }

    fn fixture_set() -> TestResult<(bitcoin_rs_storage::utxo::UtxoSet, Hash256, u32)> {
        let set = bitcoin_rs_storage::utxo::UtxoSet::new();
        let first = txid(7_001);
        let second = txid(7_002);
        let out1 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: txout(7_010).value.to_sat(),
            script_pubkey: txout(7_010).script_pubkey.to_vec(),
            coinbase: false,
            height: 100,
        };
        let out2 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 3,
            value: 7_011,
            script_pubkey: Vec::new(),
            coinbase: true,
            height: 101,
        };
        let out3 = bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 1,
            value: txout(7_012).value.to_sat(),
            script_pubkey: txout(7_012).script_pubkey.to_vec(),
            coinbase: false,
            height: 102,
        };
        let rec1 =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(first, &[out1, out2])?;
        let rec2 =
            bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(second, &[out3])?;
        set.insert_parsed_record(rec1);
        set.insert_parsed_record(rec2);
        Ok((set, txid(7_004), 103))
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SeenCoin {
        txid: Hash256,
        vout: u32,
        value: u64,
        script_pubkey: Vec<u8>,
        height: u32,
        coinbase: bool,
    }

    #[derive(Default)]
    struct RecordingObserver {
        coins: Vec<SeenCoin>,
    }

    impl SnapshotCoinObserver for RecordingObserver {
        fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
            self.coins.push(SeenCoin {
                txid: coin.txid,
                vout: coin.vout,
                value: coin.value,
                script_pubkey: coin.script_pubkey.to_vec(),
                height: coin.height,
                coinbase: coin.coinbase,
            });
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        digest.into()
    }

    fn encoded_witnessed() -> TestResult<(Vec<u8>, bitcoin_rs_storage::utxo::V4Witness)> {
        let (set, tip, height) = fixture_set()?;
        let mut bytes = Vec::new();
        let (_, (), witness) = write_snapshot_witnessed(&set, &tip, height, &mut bytes, ())?;
        let witness = witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;
        Ok((bytes, witness))
    }

    fn file_with(bytes: &[u8]) -> TestResult<std::fs::File> {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        file.rewind()?;
        Ok(file)
    }

    #[test]
    fn witnessed_write_matches_plain_bytes_and_mints_exact_witness() -> TestResult {
        let (set, tip, height) = fixture_set()?;
        let mut plain = Vec::new();
        let (plain_trailer, ()) = write_snapshot_observed(&set, &tip, height, &mut plain, ())?;
        let mut witnessed = Vec::new();
        let (witness_trailer, (), witness) =
            write_snapshot_witnessed(&set, &tip, height, &mut witnessed, ())?;

        assert_eq!(plain, witnessed);
        assert_eq!(plain_trailer, witness_trailer);
        let witness = witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;
        assert_eq!(witness.byte_len(), u64::try_from(plain.len())?);
        assert_eq!(witness.sha256(), sha256(&plain));
        assert_eq!(witness.tip_hash(), tip);
        assert_eq!(witness.height(), height);
        assert_eq!(witness.record_count(), u64::try_from(set.record_count())?);
        assert_eq!(witness.output_count(), u64::try_from(set.len())?);
        assert_eq!(witness.record_count(), 2);
        assert_eq!(witness.output_count(), 3);
        assert!(!witness.is_decoded());
        Ok(())
    }

    #[test]
    fn witnessed_read_accepts_exact_bytes_and_replays_the_same_coins() -> TestResult {
        let (set, tip, height) = fixture_set()?;
        let mut bytes = Vec::new();
        let (_, writer_observer, witness) =
            write_snapshot_witnessed(&set, &tip, height, &mut bytes, RecordingObserver::default())?;
        let witness = witness.ok_or(TestError::Missing("valid encode must mint a witness"))?;

        let mut file = file_with(&bytes)?;
        let (load, reader_observer, read_witness) =
            read_snapshot_strict_v4_witnessed(&mut file, RecordingObserver::default())?;
        assert_eq!(load.tip_hash, tip);
        assert_eq!(load.height, height);
        assert_eq!(reader_observer.coins, writer_observer.coins);
        assert!(read_witness.is_decoded());
        assert_eq!(read_witness.byte_len(), witness.byte_len());
        assert_eq!(read_witness.sha256(), witness.sha256());
        assert_eq!(read_witness.record_count(), 2);
        assert_eq!(read_witness.output_count(), 3);

        let artifact = bitcoin_rs_storage::utxo::VerifiedSnapshotArtifact::seal(
            read_witness,
            SeedProvenance::AssumeUtxoArchive {
                base: tip.to_le_bytes(),
            },
        );
        assert_eq!(artifact.tip(), (height, tip));
        assert_eq!(
            artifact.provenance(),
            SeedProvenance::AssumeUtxoArchive {
                base: tip.to_le_bytes()
            }
        );
        Ok(())
    }

    fn v4_header(tip_hash: Hash256, height: u32, record_count: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(52);
        bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&tip_hash.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&record_count.to_le_bytes());
        bytes
    }

    fn v4_record_body(txid_bytes: &[u8; 32], output_count: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(txid_bytes[0]);
        bytes.extend_from_slice(&txid_bytes[..8]);
        bytes.extend_from_slice(txid_bytes);
        bytes.extend_from_slice(&output_count.to_le_bytes());
        bytes
    }

    fn append_snapshot_output(
        bytes: &mut Vec<u8>,
        vout: u32,
        value: u64,
        height: u32,
        coinbase: bool,
        script_pubkey: &[u8],
    ) {
        let script_len = u16::try_from(script_pubkey.len()).unwrap_or(u16::MAX);
        bytes.extend_from_slice(&vout.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.push(u8::from(coinbase));
        bytes.extend_from_slice(&script_len.to_le_bytes());
        bytes.extend_from_slice(script_pubkey);
    }

    #[test]
    fn strict_loader_rejects_malformed_without_witness() -> TestResult {
        let (good, _) = encoded_witnessed()?;
        assert!(
            read_snapshot_strict_v4_witnessed(&mut Cursor::new(good.clone()), ()).is_ok(),
            "fixture must load before it can anchor malformed variants"
        );

        let mut bad_magic = v4_header(txid(1), 100, 0);
        bad_magic[0] ^= 0xff;
        let mut bad_version = v4_header(txid(1), 100, 0);
        bad_version[4] = 9;

        let duplicate_vout = {
            let mut bytes = v4_header(txid(2), 200, 1);
            bytes.extend_from_slice(&v4_record_body(&txid(3).to_le_bytes(), 2));
            append_snapshot_output(&mut bytes, 5, 1_000, 200, false, &[0x51]);
            append_snapshot_output(&mut bytes, 5, 2_000, 200, false, &[0x51]);
            bytes.extend_from_slice(&[0_u8; 384]);
            bytes
        };
        let duplicate_txid = {
            let record_txid = txid(4);
            let mut bytes = v4_header(txid(5), 300, 2);
            for vout in [0_u32, 1] {
                bytes.extend_from_slice(&v4_record_body(&record_txid.to_le_bytes(), 1));
                append_snapshot_output(&mut bytes, vout, 1_000, 300, false, &[0x51]);
            }
            bytes.extend_from_slice(&[0_u8; 384]);
            bytes
        };
        let empty_record = {
            let mut bytes = v4_header(txid(6), 400, 1);
            bytes.extend_from_slice(&v4_record_body(&txid(7).to_le_bytes(), 0));
            bytes.extend_from_slice(&[0_u8; 384]);
            bytes
        };
        let mut trailing_byte = good.clone();
        trailing_byte.push(0xAA);

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("bad magic", bad_magic),
            ("bad version", bad_version),
            ("duplicate vout", duplicate_vout),
            ("duplicate txid", duplicate_txid),
            ("empty record", empty_record),
            ("empty input", Vec::new()),
            ("truncated trailer", good[..good.len() - 1].to_vec()),
            ("trailing byte", trailing_byte),
        ];
        for (name, bytes) in &cases {
            assert!(
                read_snapshot_strict_v4(&mut Cursor::new(bytes.clone())).is_err(),
                "{name} was accepted by the plain loader"
            );
            assert!(
                read_snapshot_strict_v4_witnessed(&mut Cursor::new(bytes.clone()), ()).is_err(),
                "{name} minted a witness"
            );
        }
        Ok(())
    }

    #[test]
    fn empty_snapshot_mints_witness_and_decodes_zero_coins() -> TestResult {
        let set = bitcoin_rs_storage::utxo::UtxoSet::new();
        let tip = txid(99);
        let mut bytes = Vec::new();
        let (_, (), witness) = write_snapshot_witnessed(&set, &tip, 0, &mut bytes, ())?;
        let witness = witness.ok_or(TestError::Missing("empty encode must mint a witness"))?;
        assert_eq!(witness.record_count(), 0);
        assert_eq!(witness.output_count(), 0);
        assert_eq!(witness.byte_len(), u64::try_from(bytes.len())?);

        let (load, (), _) = read_snapshot_strict_v4_witnessed(&mut Cursor::new(&bytes), ())?;
        assert_eq!(load.set.record_count(), 0);
        Ok(())
    }
}
