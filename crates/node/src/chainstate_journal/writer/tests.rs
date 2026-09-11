use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch, WriteCondition,
};
use cap_std::ambient_authority;
use parking_lot::Mutex;

use super::*;
use bitcoin_rs_primitives::{Amount, Hash256, OutPoint, TxOut, Txid};

use crate::chainstate_journal::record::{Coin, Mutation};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The permanent writer tests implement the requirements in
/// `docs/contracts/chainstate-journal-v1.md` (`chainstate-journal-writer/v1.0.0`).
/// Requirement IDs are attached to each behavior group below; keep those
/// references current when changing journal semantics.
///
/// Counts `flush()` calls and can fail them, proving JW-DUR-1:
/// the head marker must never advance without a counted flush.
struct CountingStore {
    flushes: AtomicU64,
    fail_flush: Mutex<bool>,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            flushes: AtomicU64::new(0),
            fail_flush: Mutex::new(false),
        }
    }

    fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::SeqCst)
    }

    fn set_fail_flush(&self, fail: bool) {
        *self.fail_flush.lock() = fail;
    }
}

impl KvStore for CountingStore {
    type WriteBatch = NoopBatch;

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
        NoopBatch
    }

    fn write(&self, _batch: Self::WriteBatch) -> Result<(), StorageError> {
        Ok(())
    }

    fn write_durable_if(
        &self,
        _conditions: &[WriteCondition<'_>],
        _batch: Self::WriteBatch,
    ) -> Result<bool, StorageError> {
        Ok(true)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        if *self.fail_flush.lock() {
            return Err(StorageError::InvalidOperation("injected flush failure"));
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        unreachable!("unused in writer tests")
    }

    fn arm_persist_fault(&self, _fault: bitcoin_rs_storage::PersistFault) {
        unreachable!("unused in writer tests")
    }
}

struct NoopBatch;

impl WriteBatch for NoopBatch {
    fn put(&mut self, _cf: ColumnFamily, _key: &[u8], _value: &[u8]) {}
    fn delete(&mut self, _cf: ColumnFamily, _key: &[u8]) {}
    fn delete_range(&mut self, _cf: ColumnFamily, _start: &[u8], _end: &[u8]) {}
}

fn temp_dir(tag: &str) -> TestResult<cap_std::fs::Dir> {
    let path = std::env::temp_dir().join(format!("journal-writer-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path)?;
    Ok(cap_std::fs::Dir::open_ambient_dir(
        &path,
        ambient_authority(),
    )?)
}

fn sample_record(height: u32) -> JournalRecord {
    JournalRecord {
        height,
        block_hash: [u8::try_from(height).unwrap_or(9); 32],
        prev_hash: [u8::try_from(height.wrapping_sub(1)).unwrap_or(8); 32],
        block_tx_count: 3,
        coin_stats_height_delta: 1,
        raw_header: [0; 80],
        mutations: vec![
            Mutation::Create {
                coin: Coin {
                    outpoint: OutPoint::new(
                        Txid(Hash256::from_le_bytes(
                            &[u8::try_from(height).unwrap_or(9); 32],
                        )),
                        height,
                    ),
                    txout: TxOut {
                        value: Amount::from_sat(u64::from(height)),
                        script_pubkey: vec![0x51].into(),
                    },
                    height,
                    coinbase: true,
                },
            },
            Mutation::Spend {
                coin: Coin {
                    outpoint: OutPoint::new(
                        Txid(Hash256::from_le_bytes(
                            &[u8::try_from(height.wrapping_sub(1)).unwrap_or(8); 32],
                        )),
                        height.wrapping_sub(1),
                    ),
                    txout: TxOut {
                        value: Amount::from_sat(u64::from(height)),
                        script_pubkey: vec![0x51].into(),
                    },
                    height: height.wrapping_sub(1),
                    coinbase: false,
                },
            },
        ],
    }
}

fn open_fresh(tag: &str, store: Arc<CountingStore>) -> TestResult<JournalWriter<CountingStore>> {
    let dir = temp_dir(tag)?;
    Ok(JournalWriter::initialize(
        dir,
        store,
        0,
        (0, 0),
        0,
        [1; 32],
        [0; 32],
        0,
    )?)
}

#[cfg(test)]
mod persistence_1;

#[cfg(test)]
mod behavior_1;
