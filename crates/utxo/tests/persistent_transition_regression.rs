//! Regression coverage for `RCV-04A` in `docs/contracts/recovery.md`.

#![expect(clippy::expect_used, reason = "test assertions")]

use std::{
    sync::{
        Arc, Barrier, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, PersistFault, StorageError, WriteBatch,
    WriteCondition,
};
use bitcoin_rs_utxo::set::{
    BlockChanges, CoinDurability, PersistentUtxoError, PersistentUtxoSet, UndoBatch, UtxoAdd,
    UtxoChangeEvents, UtxoChangeListener, UtxoInserted, UtxoRemoved, UtxoSet,
};

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn outpoint(txid: Hash256, vout: u32) -> OutPoint {
    OutPoint::new(txid.into(), vout)
}

fn funding(txid: Hash256) -> BlockChanges {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint(txid, 0),
        TxOut {
            value: 100,
            script_pubkey: vec![0x51],
        },
        false,
        1,
    ));
    changes
}

#[derive(Clone)]
struct FlushGate {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Clone, Default)]
struct TestStore {
    next_flush: Arc<parking_lot::Mutex<Option<FlushGate>>>,
}

impl TestStore {
    fn block_next_flush(&self) -> FlushGate {
        let gate = FlushGate {
            entered: Arc::new(Barrier::new(2)),
            release: Arc::new(Barrier::new(2)),
        };
        *self.next_flush.lock() = Some(gate.clone());
        gate
    }
}

impl KvStore for TestStore {
    type WriteBatch = TestBatch;

    fn get(&self, _cf: ColumnFamily, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    fn iter_prefix<'a>(
        &'a self,
        _cf: ColumnFamily,
        _prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        Ok(Box::new(std::iter::empty()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        TestBatch
    }

    fn write(&self, _batch: Self::WriteBatch) -> Result<(), StorageError> {
        Err(StorageError::InvalidOperation(
            "transition test store does not persist writes",
        ))
    }

    fn write_durable_if(
        &self,
        _conditions: &[WriteCondition<'_>],
        _batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        Err(StorageError::InvalidOperation(
            "transition test store does not persist writes",
        ))
    }

    fn flush(&self) -> Result<(), StorageError> {
        if let Some(gate) = self.next_flush.lock().take() {
            gate.entered.wait();
            gate.release.wait();
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Err(StorageError::InvalidOperation(
            "transition test store does not support snapshots",
        ))
    }

    fn arm_persist_fault(&self, _fault: PersistFault) {}
}

struct TestBatch;

impl WriteBatch for TestBatch {
    fn put(&mut self, _cf: ColumnFamily, _key: &[u8], _value: &[u8]) {}

    fn delete(&mut self, _cf: ColumnFamily, _key: &[u8]) {}

    fn delete_range(&mut self, _cf: ColumnFamily, _start: &[u8], _end: &[u8]) {}
}

struct ReentrantListener {
    target: Arc<OnceLock<Weak<PersistentUtxoSet<TestStore>>>>,
    called: Arc<AtomicBool>,
    rejected: Arc<AtomicBool>,
}

impl ReentrantListener {
    fn probe(&self, op: &OutPoint) {
        let set = self
            .target
            .get()
            .and_then(Weak::upgrade)
            .expect("persistent set installed");
        let hash = txid(999);
        let rejected = matches!(
            set.get(op),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.ledger(),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.flush(),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.connect_block(
                &BlockChanges::default(),
                &hash,
                CoinDurability::Durable
            ),
            Err(PersistentUtxoError::ReentrantOperation)
        ) && matches!(
            set.undo_block(&UndoBatch::default(), CoinDurability::Durable),
            Err(PersistentUtxoError::ReentrantOperation)
        );
        self.rejected.store(rejected, Ordering::SeqCst);
        self.called.store(true, Ordering::SeqCst);
    }
}

impl UtxoChangeListener for ReentrantListener {
    fn on_insert_coins(&self, insertions: &[UtxoInserted<'_>]) {
        if let Some(first) = insertions.first() {
            self.probe(first.op);
        }
    }

    fn on_remove_coins(&self, _removals: &[UtxoRemoved]) {}

    fn on_committed_event_batches(&self, _batches: &[UtxoChangeEvents<'_>]) {}
}

#[test]
fn blocked_flush_does_not_block_resident_reads() {
    let store = TestStore::default();
    let raw = UtxoSet::new();
    let a = txid(1);
    raw.commit_block(&funding(a), &a).expect("seed resident coin");
    let set = PersistentUtxoSet::new(raw, store.clone());

    let gate = store.block_next_flush();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| set.flush().expect("blocked flush completes"));
        gate.entered.wait();

        scope.spawn(|| {
            tx.send(set.get(&outpoint(a, 0)))
                .expect("send resident read");
        });

        // RCV-04A: this is a deadlock detector, not a latency requirement.
        let read_while_blocked = rx.recv_timeout(Duration::from_secs(5));
        gate.release.wait();
        let output = read_while_blocked
            .expect("resident read waited for backing-store flush")
            .expect("resident read succeeds")
            .expect("resident output");
        assert_eq!(output.value, 100);
    });
}

#[test]
fn listener_reentry_is_rejected_instead_of_deadlocking() {
    let target = Arc::new(OnceLock::new());
    let called = Arc::new(AtomicBool::new(false));
    let rejected = Arc::new(AtomicBool::new(false));

    let mut raw = UtxoSet::new();
    raw.set_listener(Box::new(ReentrantListener {
        target: Arc::clone(&target),
        called: Arc::clone(&called),
        rejected: Arc::clone(&rejected),
    }));

    let set = Arc::new(PersistentUtxoSet::new(raw, TestStore::default()));
    assert!(target.set(Arc::downgrade(&set)).is_ok());

    let a = txid(2);
    let error = set
        .connect_block(&funding(a), &a, CoinDurability::Durable)
        .expect_err("test store rejects outer persistence after the callback");
    assert!(matches!(
        error,
        PersistentUtxoError::Storage(StorageError::InvalidOperation(_))
    ));

    assert!(called.load(Ordering::SeqCst), "listener was invoked");
    assert!(
        rejected.load(Ordering::SeqCst),
        "reentrant persistent operations must fail fast"
    );
}
