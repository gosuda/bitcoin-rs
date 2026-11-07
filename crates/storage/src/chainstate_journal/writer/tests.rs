use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteCondition,
};
use cap_std::ambient_authority;
use parking_lot::Mutex;

use super::*;
use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, TxOut, Txid};

use super::super::record::{Coin, Mutation};

use crate::test_support::TestResult;

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

    fn scan_prefix_from_bounded(
        &self,
        _cf: ColumnFamily,
        _prefix: &[u8],
        _start: &[u8],
        _limit: crate::PrefixScanLimit,
    ) -> Result<crate::PrefixScan, StorageError> {
        unreachable!("unused in writer tests")
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        BufferedWriteBatch::default()
    }

    fn write(&self, _batch: BufferedWriteBatch) -> Result<(), StorageError> {
        Ok(())
    }

    fn write_durable_if(
        &self,
        _conditions: &[WriteCondition<'_>],
        _batch: BufferedWriteBatch,
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

    fn arm_persist_fault(&self, _fault: crate::PersistFault) {
        unreachable!("unused in writer tests")
    }

    fn multi_get(
        &self,
        _cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<bytes::Bytes>>, StorageError> {
        Ok(vec![None; keys.len()])
    }

    fn ingest_sorted(
        &self,
        _cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        _scratch: &std::path::Path,
    ) -> Result<u64, StorageError> {
        let mut count = 0u64;
        let mut prev_key: Option<Vec<u8>> = None;
        for (k, _) in rows {
            if let Some(prev) = &prev_key {
                if k.as_slice() <= prev.as_slice() {
                    return Err(StorageError::InvalidOperation(
                        "keys not strictly ascending",
                    ));
                }
            }
            prev_key = Some(k);
            count += 1;
        }
        Ok(count)
    }

    fn delete_range(
        &self,
        _cf: ColumnFamily,
        _start: &[u8],
        _end: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
        std::fs::create_dir_all(dir).map_err(StorageError::Io)
    }

    fn engine_cache_bytes(&self) -> u64 {
        0
    }
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
mod durability_boundaries;

#[cfg(test)]
mod segment_lifecycle;
