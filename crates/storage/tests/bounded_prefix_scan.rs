//! Cross-backend tests for bounded prefix scans.

use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, StorageError, WriteBatch};

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

    // max_rows = 0 always yields an empty, incomplete scan.
    let scan = store.scan_prefix_bounded(
        ColumnFamily::TxConfirmed,
        &[0x00],
        PrefixScanLimit {
            max_rows: 0,
            max_bytes: usize::MAX,
        },
    )?;
    assert!(scan.rows.is_empty());
    assert!(!scan.complete);

    // max_bytes = 0 with max_rows > 0 still admits the first row (soft limit),
    // then stops because every subsequent row exceeds the hard byte budget.
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
    // Seed a prefix range where the first row is larger than max_bytes.
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Spending, &[0x10], &[0u8; 200]);
    batch.put(ColumnFamily::Spending, &[0x10, 0x01], b"small");
    store.write(batch)?;

    // The first row is admitted even though it alone exceeds max_bytes.
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

    // After deleting the oversized row, scanning progresses to the next row.
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

    // Cleanup so the store is reusable.
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::Spending, &[0x10, 0x01]);
    store.write(batch)?;

    Ok(())
}

fn run_bounded_scan_suite<S: KvStore>(store: &S) -> Result<(), StorageError> {
    seed_rows(store)?;
    assert_limit_semantics(store)?;
    assert_prefix_boundaries(store)?;
    assert_snapshot_isolation(store)?;
    assert_oversized_first_row(store)
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
