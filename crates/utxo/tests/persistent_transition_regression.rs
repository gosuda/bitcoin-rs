//! Regression coverage for persistent-coin transition boundaries.

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

type Row = ((ColumnFamily, Vec<u8>), Vec<u8>);

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn outpoint(txid: Hash256, vout: u32) -> OutPoint {
    OutPoint::new(txid.into(), vout)
}

fn txout(value: u64) -> TxOut {
    TxOut {
        value,
        script_pubkey: vec![0x51],
    }
}

fn funding(txid: Hash256) -> BlockChanges {
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(outpoint(txid, 0), txout(100), false, 1));
    changes
}

#[derive(Clone)]
struct FlushGate {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[derive(Clone, Default)]
struct TestStore {
    rows: Arc<parking_lot::RwLock<Vec<Row>>>,
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

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .rows
            .read()
            .iter()
            .find(|((row_cf, row_key), _)| *row_cf == cf && row_key == key)
            .map(|(_, value)| value.clone()))
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let mut rows = self
            .rows
            .read()
            .iter()
            .filter(|((row_cf, key), _)| *row_cf == cf && key.starts_with(prefix))
            .map(|((_, key), value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| match (left, right) {
            (Ok((left_key, _)), Ok((right_key, _))) => left_key.cmp(right_key),
            _ => core::cmp::Ordering::Equal,
        });
        Ok(Box::new(rows.into_iter()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        TestBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        apply_ops(&mut self.rows.write(), batch.ops);
        Ok(())
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        {
            let mut rows = self.rows.write();
            let matched = conditions.iter().all(|condition| {
                let (cf, key) = condition.location();
                condition.matches(
                    rows.iter()
                        .find(|((row_cf, row_key), _)| *row_cf == cf && row_key == key)
                        .map(|(_, value)| value.as_slice()),
                )
            });
            if !matched {
                return Ok(false);
            }
            apply_ops(&mut rows, batch.ops);
        }
        self.flush()?;
        Ok(true)
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
            "test snapshots are unsupported",
        ))
    }

    fn arm_persist_fault(&self, _fault: PersistFault) {}
}

#[derive(Default)]
struct TestBatch {
    ops: Vec<TestOp>,
}

enum TestOp {
    Put(ColumnFamily, Vec<u8>, Vec<u8>),
    Delete(ColumnFamily, Vec<u8>),
    DeleteRange(ColumnFamily, Vec<u8>, Vec<u8>),
}

impl WriteBatch for TestBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops
            .push(TestOp::Put(cf, key.to_vec(), value.to_vec()));
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(TestOp::Delete(cf, key.to_vec()));
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops
            .push(TestOp::DeleteRange(cf, start.to_vec(), end.to_vec()));
    }
}

fn apply_ops(rows: &mut Vec<Row>, ops: Vec<TestOp>) {
    for op in ops {
        match op {
            TestOp::Put(cf, key, value) => {
                if let Some((_, current)) = rows
                    .iter_mut()
                    .find(|((row_cf, row_key), _)| *row_cf == cf && row_key == &key)
                {
                    *current = value;
                } else {
                    rows.push(((cf, key), value));
                }
            }
            TestOp::Delete(cf, key) => {
                rows.retain(|((row_cf, row_key), _)| *row_cf != cf || row_key != &key);
            }
            TestOp::DeleteRange(cf, start, end) => {
                rows.retain(|((row_cf, key), _)| {
                    *row_cf != cf
                        || key.as_slice() < start.as_slice()
                        || key.as_slice() >= end.as_slice()
                });
            }
        }
    }
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
    let set = PersistentUtxoSet::new(UtxoSet::new(), store.clone());
    let a = txid(1);
    set.connect_block(&funding(a), &a, CoinDurability::Durable)
        .expect("seed resident coin");

    let gate = store.block_next_flush();
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| set.flush().expect("blocked flush completes"));
        gate.entered.wait();

        let tx = tx.clone();
        scope.spawn(|| {
            tx.send(set.get(&outpoint(a, 0)))
                .expect("send resident read");
        });

        let read_while_blocked = rx.recv_timeout(Duration::from_secs(1));
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
    set.connect_block(&funding(a), &a, CoinDurability::Durable)
        .expect("outer mutation");

    assert!(called.load(Ordering::SeqCst), "listener was invoked");
    assert!(
        rejected.load(Ordering::SeqCst),
        "reentrant persistent operations must fail fast"
    );
}
