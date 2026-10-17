//! Cross-backend tests for bounded prefix scans.

#![cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]

use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, StorageError};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

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

    let snap_prefix = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x00], limit)?;
    assert_eq!(snap_prefix.rows.len(), 2);
    assert!(snap_prefix.complete);
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

fn assert_snapshot_seek_bounds<S: KvStore>(store: &S) -> Result<(), StorageError> {
    let cf = ColumnFamily::Spending;
    for (key, value) in [
        (b"a".as_slice(), b"earlier".as_slice()),
        (b"b0", b"first"),
        (b"b1", b"second"),
        (b"c0", b"later"),
        (b"\xff", b"max"),
        (b"\xff\0", b"last"),
    ] {
        store.put(cf, key, value)?;
    }
    let snapshot = store.snapshot()?;
    // A seek must use the same point-in-time view as ordinary snapshot reads.
    store.put(cf, b"b2", b"after snapshot")?;
    let limit = PrefixScanLimit {
        max_rows: 10,
        max_bytes: usize::MAX,
    };
    for (prefix, start, expected) in [
        (
            b"b".as_slice(),
            b"a".as_slice(),
            vec![b"b0".to_vec(), b"b1".to_vec()],
        ),
        (b"b", b"b0", vec![b"b0".to_vec(), b"b1".to_vec()]),
        (b"b", b"b0\0", vec![b"b1".to_vec()]),
        (b"b", b"b1", vec![b"b1".to_vec()]),
        (b"b", b"b2", vec![]),
        (b"b", b"c0", vec![]),
        (b"d", b"a", vec![]),
        (
            b"",
            b"b1",
            vec![
                b"b1".to_vec(),
                b"c0".to_vec(),
                b"\xff".to_vec(),
                b"\xff\0".to_vec(),
            ],
        ),
        (b"\xff", b"a", vec![b"\xff".to_vec(), b"\xff\0".to_vec()]),
        (b"\xff", b"\xff\0", vec![b"\xff\0".to_vec()]),
    ] {
        let scan = snapshot.scan_prefix_from_bounded(cf, prefix, start, limit)?;
        let keys: Vec<_> = scan.rows.into_iter().map(|(key, _)| key).collect();
        assert_eq!(keys, expected, "prefix={prefix:?}, start={start:?}");
        assert!(scan.complete);
    }
    assert_snapshot_seek_limits(snapshot.as_ref())?;
    let fresh = store
        .snapshot()?
        .scan_prefix_from_bounded(cf, b"b", b"b2", limit)?;
    assert_eq!(
        fresh.rows,
        vec![(b"b2".to_vec(), b"after snapshot".to_vec())]
    );
    assert!(fresh.complete);
    Ok(())
}

fn assert_snapshot_seek_limits(
    snapshot: &dyn bitcoin_rs_storage::KvSnapshot,
) -> Result<(), StorageError> {
    for (start, rows, bytes, expected, complete) in [
        (b"b0".as_slice(), 0, usize::MAX, vec![], false),
        (b"b0", 1, usize::MAX, vec![b"b0".to_vec()], false),
        (b"b0", 2, 15, vec![b"b0".to_vec(), b"b1".to_vec()], true),
        (b"b0", 2, 7, vec![b"b0".to_vec()], false),
        // The byte cap still permits the first oversized row, including zero.
        (b"b0", 2, 0, vec![b"b0".to_vec()], false),
        (b"b1", 2, 0, vec![b"b1".to_vec()], true),
        (b"c0", 0, 0, vec![], true),
    ] {
        let scan = snapshot.scan_prefix_from_bounded(
            ColumnFamily::Spending,
            b"b",
            start,
            PrefixScanLimit {
                max_rows: rows,
                max_bytes: bytes,
            },
        )?;
        let keys: Vec<_> = scan.rows.into_iter().map(|(key, _)| key).collect();
        assert_eq!(
            keys, expected,
            "start={start:?}, rows={rows}, bytes={bytes}"
        );
        assert_eq!(scan.complete, complete);
    }
    Ok(())
}

fn run_bounded_scan_suite<S: KvStore>(store: &S) -> Result<(), StorageError> {
    seed_rows(store)?;
    assert_limit_semantics(store)?;
    assert_prefix_boundaries(store)?;
    assert_snapshot_isolation(store)?;
    assert_oversized_first_row(store)?;
    assert_snapshot_seek_bounds(store)
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_bounded_prefix_scan() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::FjallStore::open(temp.path())?;
    run_bounded_scan_suite(&store)?;
    Ok(())
}

#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_bounded_prefix_scan() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::RocksDbStore::open(temp.path())?;
    run_bounded_scan_suite(&store)?;
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_bounded_prefix_scan() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::RedbStore::open(temp.path())?;
    run_bounded_scan_suite(&store)?;
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_txindex_snapshot_seeks_cover_fixed_key_families() -> TestResult<()> {
    let temp = tempfile::TempDir::new()?;
    let store = bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?;
    for (cf, width, has_value) in [
        (ColumnFamily::TxConfirmed, 12, true),
        (ColumnFamily::Funding, 12, true),
        (ColumnFamily::Spending, 12, true),
        (ColumnFamily::BlockHeaders, 80, false),
        (ColumnFamily::ScriptLive, 43, false),
    ] {
        let prefix = b"samepref";
        let earlier = vec![0_u8; width];
        let mut first = earlier.clone();
        first[..8].copy_from_slice(prefix);
        first[8] = 1;
        let mut second = first.clone();
        second[8] = 2;
        let mut end = vec![0xff; width];
        end[..8].copy_from_slice(prefix);
        let after = vec![0xff; width];
        let value = if has_value {
            b"payload".as_slice()
        } else {
            &[]
        };
        for key in [&earlier, &first, &second, &end, &after] {
            store.put(cf, key, value)?;
        }
        let snapshot = store.snapshot()?;
        let limit = PrefixScanLimit {
            max_rows: 10,
            max_bytes: usize::MAX,
        };
        for (start, expected) in [
            (&earlier, vec![first.clone(), second.clone(), end.clone()]),
            (&first, vec![first.clone(), second.clone(), end.clone()]),
            (&second, vec![second.clone(), end.clone()]),
            (&end, vec![end.clone()]),
            (&after, vec![]),
        ] {
            let scan = snapshot.scan_prefix_from_bounded(cf, prefix, start, limit)?;
            let expected: Vec<_> = expected
                .into_iter()
                .map(|key| (key, value.to_vec()))
                .collect();
            assert_eq!(scan.rows, expected, "{cf:?} inclusive seek");
            assert!(scan.complete);
        }
        let global = snapshot.scan_prefix_from_bounded(cf, &[], &after, limit)?;
        assert_eq!(global.rows, vec![(after.clone(), value.to_vec())]);
        assert!(global.complete);
        for (start, max_rows, expected, complete) in [
            (&first, 0, vec![], false),
            (&first, 1, vec![first.clone()], false),
            (&first, 10, vec![first.clone()], false),
            (&end, 10, vec![end.clone()], true),
            (&after, 0, vec![], true),
        ] {
            let scan = snapshot.scan_prefix_from_bounded(
                cf,
                prefix,
                start,
                PrefixScanLimit {
                    max_rows,
                    max_bytes: 0,
                },
            )?;
            let keys: Vec<_> = scan.rows.into_iter().map(|(key, _)| key).collect();
            assert_eq!(keys, expected, "{cf:?} bounded seek");
            assert_eq!(scan.complete, complete);
        }
        assert!(matches!(
            snapshot.scan_prefix_from_bounded(cf, prefix, &first[..width - 1], limit),
            Err(StorageError::InvalidOperation(_))
        ));
        assert!(matches!(
            snapshot.scan_prefix_from_bounded(cf, &vec![0; width + 1], &first, limit),
            Err(StorageError::InvalidOperation(_))
        ));
    }
    Ok(())
}
