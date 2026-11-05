#![expect(clippy::expect_used, reason = "test assertions")]

use super::*;
use fjall::AbstractTree;
use std::sync::{Arc, mpsc};
use std::time::Duration;

fn saturated_store(path: &Path) -> FjallStore {
    {
        let db = Database::builder(path)
            .worker_threads_unchecked(0)
            .open()
            .expect("fixture database");
        for cf in [ColumnFamily::Funding, ColumnFamily::Spending] {
            let keyspace = db
                .keyspace(cf.name(), KeyspaceCreateOptions::default)
                .expect("fixture keyspace");
            for seqno in 1_u64..=31 {
                keyspace
                    .tree
                    .insert(b"versioned", seqno.to_be_bytes(), seqno);
                keyspace
                    .tree
                    .insert(seqno.to_be_bytes(), b"retained", seqno);
                if seqno == 1 {
                    keyspace.tree.insert(b"deleted", b"old", seqno);
                }
                if seqno == 31 {
                    keyspace.tree.remove(b"deleted", seqno);
                }
                keyspace.tree.flush_active_memtable(0).expect("fixture L0");
            }
            assert_eq!(keyspace.tree.l0_run_count(), 31);
        }
    }
    let db = Database::builder(path)
        .worker_threads_unchecked(0)
        .open()
        .expect("recovered database");
    let keyspaces = ColumnFamily::ALL
        .iter()
        .map(|cf| {
            db.keyspace(cf.name(), KeyspaceCreateOptions::default)
                .expect("recovered keyspace")
        })
        .collect();
    FjallStore {
        _maintenance: maintenance::Maintenance::start(Vec::new()).expect("idle worker"),
        db,
        keyspaces,
        write_lock: parking_lot::Mutex::new(()),
        faults: crate::trait_::PersistFaultSlot::default(),
        guard: None,
    }
}

// SYNC-03, SYNC-06
#[test]
fn maintenance_releases_halted_batch_without_flush_events() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let store = Arc::new(saturated_store(dir.path()));
    let snapshot = store.snapshot().expect("snapshot before blocked write");
    let (done, result) = mpsc::channel();
    let writer_store = Arc::clone(&store);
    let writer = std::thread::spawn(move || {
        let mut batch = writer_store.new_batch();
        batch.put(ColumnFamily::Funding, b"versioned", b"new funding");
        batch.put(ColumnFamily::Spending, b"versioned", b"new spending");
        done.send(writer_store.write_durable(batch))
            .expect("write result");
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while store.write_lock.try_lock().is_some() {
        assert!(
            std::time::Instant::now() < deadline,
            "writer must acquire the store lock"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
    let maintenance = maintenance::Maintenance::start_with_interval(
        store.keyspaces.clone(),
        Duration::from_millis(10),
    )
    .expect("maintenance worker");
    result
        .recv_timeout(Duration::from_secs(10))
        .expect("maintenance must release write halt without flush workers")
        .expect("durable write");
    writer.join().expect("writer stopped");
    for (cf, value) in [
        (ColumnFamily::Funding, b"new funding".as_slice()),
        (ColumnFamily::Spending, b"new spending".as_slice()),
    ] {
        assert_eq!(
            store.get(cf, b"versioned").expect("current value"),
            Some(value.to_vec())
        );
        assert_eq!(
            snapshot.get(cf, b"versioned").expect("old snapshot"),
            Some(31_u64.to_be_bytes().to_vec())
        );
        assert!(store.keyspace(cf).expect("keyspace").tree.l0_run_count() < 30);
        assert_eq!(store.get(cf, b"deleted").expect("deleted value"), None);
    }
    drop(snapshot);
    drop(maintenance);
    drop(store);
    let reopened = FjallStore::open(dir.path()).expect("reopen after maintenance");
    for (cf, value) in [
        (ColumnFamily::Funding, b"new funding".as_slice()),
        (ColumnFamily::Spending, b"new spending".as_slice()),
    ] {
        assert_eq!(
            reopened.get(cf, b"versioned").expect("durable value"),
            Some(value.to_vec())
        );
        assert_eq!(
            reopened.get(cf, b"deleted").expect("durable deletion"),
            None
        );
        for seqno in 1_u64..=31 {
            assert_eq!(
                reopened
                    .get(cf, &seqno.to_be_bytes())
                    .expect("retained row"),
                Some(b"retained".to_vec())
            );
        }
    }
}

// SYNC-06
#[test]
fn maintenance_rechecks_idle_keyspaces_and_stops_without_waiting_for_tick() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let db = Database::builder(dir.path())
        .worker_threads_unchecked(0)
        .open()
        .expect("database");
    let keyspace = db
        .keyspace("funding", KeyspaceCreateOptions::default)
        .expect("keyspace");
    keyspace
        .insert(b"versioned", b"original")
        .expect("original value");
    keyspace
        .insert(b"deleted", b"original")
        .expect("original deleted value");
    keyspace
        .tree
        .flush_active_memtable(0)
        .expect("initial flush");
    let snapshot = db.snapshot();
    for seqno in 2_u64..=15 {
        keyspace
            .insert(b"versioned", seqno.to_be_bytes())
            .expect("updated value");
        if seqno == 15 {
            keyspace.remove(b"deleted").expect("deleted value");
        }
        keyspace
            .tree
            .flush_active_memtable(0)
            .expect("fixture flush");
    }
    let maintenance = maintenance::Maintenance::start_with_interval(
        vec![keyspace.clone()],
        Duration::from_millis(10),
    )
    .expect("maintenance");
    wait_for_l0_drain(&keyspace);
    assert_eq!(
        snapshot
            .get(&keyspace, b"versioned")
            .expect("old version")
            .as_deref(),
        Some(b"original".as_slice())
    );
    assert_eq!(
        snapshot
            .get(&keyspace, b"deleted")
            .expect("old deleted version")
            .as_deref(),
        Some(b"original".as_slice())
    );
    assert_eq!(
        keyspace
            .get(b"versioned")
            .expect("current version")
            .as_deref(),
        Some(15_u64.to_be_bytes().as_slice())
    );
    assert_eq!(keyspace.get(b"deleted").expect("current deletion"), None);
    for seqno in 16_u64..=30 {
        keyspace
            .insert(seqno.to_be_bytes(), b"value")
            .expect("new value");
        keyspace
            .tree
            .flush_active_memtable(0)
            .expect("new fixture flush");
    }
    wait_for_l0_drain(&keyspace);
    drop(maintenance);
    let maintenance =
        maintenance::Maintenance::start_with_interval(vec![keyspace], Duration::from_secs(3600))
            .expect("long idle worker");
    let (done, result) = mpsc::channel();
    let closer = std::thread::spawn(move || {
        drop(maintenance);
        done.send(()).expect("closed");
    });
    result
        .recv_timeout(Duration::from_secs(5))
        .expect("shutdown wakes idle maintenance");
    closer.join().expect("closer stopped");
}

fn wait_for_l0_drain(keyspace: &Keyspace) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while keyspace.tree.l0_run_count() >= maintenance::L0_DRAIN_THRESHOLD {
        assert!(
            std::time::Instant::now() < deadline,
            "periodic maintenance must drain new L0 runs"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
