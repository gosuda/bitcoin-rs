//! Cross-backend tests for bounded prefix scans.

#![cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]

use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScan, PrefixScanLimit, StorageError};

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

/// One continuation scan over `TxConfirmed`: `(prefix, start, limit)`.
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

/// Seek position, ordering, prefix exit, and exhaustion of
/// `scan_prefix_from_bounded` over the rows written by `seed_rows`.
fn assert_seek_positions(scan: ContinuationScan<'_>) -> Result<(), StorageError> {
    let one = vec![vec![0x01], vec![0x01, 0xff]];

    // A seek before the prefix, at it, or on its first row starts at the first row.
    let from_first: [&[u8]; 3] = [&[], &[0x00, 0xff], &[0x01]];
    for start in from_first {
        let page = scan(&[0x01], start, ROOMY)?;
        assert_eq!(scan_keys(&page), one);
        assert!(page.complete);
    }

    // The seek is inclusive and stops at the last row of the prefix.
    let from_last: [&[u8]; 2] = [&[0x01, 0x00], &[0x01, 0xff]];
    for start in from_last {
        let page = scan(&[0x01], start, ROOMY)?;
        assert_eq!(scan_keys(&page), vec![vec![0x01, 0xff]]);
        assert!(page.complete);
    }

    // A seek past the last row of the prefix, or past the prefix, is exhausted.
    let beyond: [&[u8]; 3] = [&[0x01, 0xff, 0x00], &[0x02], &[0xff]];
    for start in beyond {
        let page = scan(&[0x01], start, ROOMY)?;
        assert_eq!(page.rows, []);
        assert!(page.complete);
    }

    // An all-0xff prefix has no successor prefix to bound the engine range.
    let page = scan(&[0xff], &[], ROOMY)?;
    assert_eq!(scan_keys(&page), vec![vec![0xff], vec![0xff, 0x00]]);
    assert!(page.complete);
    let page = scan(&[0xff], &[0xff, 0x00], ROOMY)?;
    assert_eq!(scan_keys(&page), vec![vec![0xff, 0x00]]);
    assert!(page.complete);
    let page = scan(&[0xff], &[0xff, 0x00, 0x00], ROOMY)?;
    assert_eq!(page.rows, []);
    assert!(page.complete);

    // The empty prefix continues across every row.
    let page = scan(&[], &[0x01, 0xff], ROOMY)?;
    assert_eq!(
        scan_keys(&page),
        vec![vec![0x01, 0xff], vec![0x02], vec![0xff], vec![0xff, 0x00]]
    );
    assert!(page.complete);

    // A prefix without rows is exhausted, not truncated.
    let page = scan(&[0x09], &[], ROOMY)?;
    assert_eq!(page.rows, []);
    assert!(page.complete);

    Ok(())
}

/// Row and byte limits of `scan_prefix_from_bounded` over the rows written by
/// `seed_rows`.
fn assert_limit_boundaries(scan: ContinuationScan<'_>) -> Result<(), StorageError> {
    let one = vec![vec![0x01], vec![0x01, 0xff]];

    // Zero rows: withheld rows make the scan incomplete; none left completes it.
    let page = scan(&[0x01], &[], rows_limit(0))?;
    assert_eq!(page.rows, []);
    assert!(!page.complete);
    let exhausted: [(&[u8], &[u8]); 2] = [(&[0x01], &[0x02]), (&[0x09], &[])];
    for (prefix, start) in exhausted {
        let page = scan(prefix, start, rows_limit(0))?;
        assert_eq!(page.rows, []);
        assert!(page.complete);
    }

    // A row limit that exactly fits the remaining rows is complete.
    let page = scan(&[0x01], &[], rows_limit(1))?;
    assert_eq!(scan_keys(&page), vec![vec![0x01]]);
    assert!(!page.complete);
    let page = scan(&[0x01], &[], rows_limit(2))?;
    assert_eq!(scan_keys(&page), one);
    assert!(page.complete);
    let page = scan(&[0x01], &[0x01, 0x00], rows_limit(1))?;
    assert_eq!(scan_keys(&page), vec![vec![0x01, 0xff]]);
    assert!(page.complete);

    // Byte limits count key plus value and always admit the first row.
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

/// Resuming each page just after its last key visits every row once, in order.
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

    let snap_prefix = snapshot.scan_prefix_bounded(ColumnFamily::TxConfirmed, &[0x00], limit)?;
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
