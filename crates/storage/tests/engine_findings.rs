use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "surrealkv")]
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore, WriteCondition};

use crate::support::TestResult;

fn map_err(e: impl std::fmt::Display) -> crate::support::error::TestError {
    crate::support::error::TestError::Io(std::io::Error::other(e.to_string()))
}

fn thread_err(_: Box<dyn std::any::Any + Send>) -> crate::support::error::TestError {
    crate::support::error::TestError::Io(std::io::Error::other("thread panicked"))
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

        let (t2_done_tx, t2_done_rx) = std::sync::mpsc::sync_channel::<Result<(), StorageError>>(1);
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
