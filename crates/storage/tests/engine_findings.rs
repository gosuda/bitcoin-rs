use std::sync::Arc;
use std::time::Duration;

use bitcoin_rs_storage::{BufferedWriteBatch, ColumnFamily, KvStore, RocksDbStore, WriteCondition};

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
fn eng_01_concurrent_ingest_and_write_durable_if() {
    let temp = tempfile::TempDir::new().unwrap();
    let db_path = temp.path().join("db");
    let scratch_path = temp.path().join("scratch");
    std::fs::create_dir_all(&scratch_path).unwrap();

    let store = Arc::new(RocksDbStore::open(&db_path).unwrap());
    let cf = ColumnFamily::CoinRecords;

    let mut batch = BufferedWriteBatch::default();
    batch.put(cf, b"k", b"v0");
    store.write_durable(batch).unwrap();

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
        .expect("ingest thread failed to start");

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
    let ingest_res = ingest_handle.join().unwrap();
    assert!(ingest_res.is_ok());
    let cond_res = cond_handle.join().unwrap();
    assert!(cond_res.is_ok());

    let scratch_shared = temp.path().join("scratch_shared");
    std::fs::create_dir_all(&scratch_shared).unwrap();

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
        .expect("t1 failed to start");

    let store_c2 = Arc::clone(&store);
    let scratch_c2 = scratch_shared.clone();
    let h2 = std::thread::spawn(move || {
        let mut rows = vec![(b"shared_k2".to_vec(), b"v2".to_vec())].into_iter();
        store_c2.ingest_sorted(cf, &mut rows, &scratch_c2)
    });

    let _ = t1_resume_tx.send(());
    let res1 = h1.join().unwrap();
    let res2 = h2.join().unwrap();
    assert!(res1.is_ok(), "t1 ingest failed: {:?}", res1);
    assert!(res2.is_ok(), "t2 ingest failed: {:?}", res2);
}

#[cfg(feature = "surrealkv")]
#[test]
fn eng_02_surrealkv_iter_prefix_paged_streaming() {
    use bitcoin_rs_storage::SurrealKvStore;
    use std::collections::BTreeMap;

    let temp = tempfile::TempDir::new().unwrap();
    let db_path = temp.path().join("db");

    let store = SurrealKvStore::open_with_cache(&db_path, 64 * 1024 * 1024).unwrap();
    let cf = ColumnFamily::CoinRecords;

    let mut oracle = BTreeMap::new();
    let mut batch = BufferedWriteBatch::default();

    for i in 0..200 {
        let key = format!("pfx:{:05}", i).into_bytes();
        let value = format!("val:{:05}", i).into_bytes();
        oracle.insert(key.clone(), value.clone());
        batch.put(cf, &key, &value);
    }

    for i in 0..50 {
        let key = format!("other:{:05}", i).into_bytes();
        let value = format!("oval:{:05}", i).into_bytes();
        batch.put(cf, &key, &value);
    }
    batch.put(cf, b"pfy:00000", b"val:pfy");

    store.write_durable(batch).unwrap();

    let iter = store.iter_prefix(cf, b"pfx:").unwrap();
    let rows: Vec<(Vec<u8>, Vec<u8>)> = iter.map(|r| r.unwrap()).collect();
    let expected: Vec<(Vec<u8>, Vec<u8>)> =
        oracle.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    assert_eq!(rows.len(), 200);
    assert_eq!(rows, expected);

    let snapshot = store.snapshot().unwrap();
    let snap_iter = snapshot.iter_prefix(cf, b"pfx:").unwrap();
    let snap_rows: Vec<(Vec<u8>, Vec<u8>)> = snap_iter.map(|r| r.unwrap()).collect();
    assert_eq!(snap_rows.len(), 200);
    assert_eq!(snap_rows, expected);

    let mut early_iter = store.iter_prefix(cf, b"pfx:").unwrap();
    let first_ten: Vec<_> = early_iter.by_ref().take(10).map(|r| r.unwrap()).collect();
    assert_eq!(first_ten.len(), 10);
    drop(early_iter);
}
