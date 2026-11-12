use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, Script, TxOut};
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_storage::utxo::{UtxoError, UtxoReader};
use bitcoin_rs_storage::{
    BufferedWriteBatch, Bytes, CoinKey, CoinStore, ColumnFamily, KvIter, KvSnapshot, KvStore,
    MemoryKvStore, PersistFault, PrefixScan, PrefixScanLimit, StorageError, WriteCondition,
};
use parking_lot::Mutex;

use crate::support::TestResult;

const CACHE_BUDGET: u64 = 64 * 1024 * 1024;
const VALUE_SATS: u64 = 12_345;
const COIN_HEIGHT: u32 = 7;

struct ReadFaultStore {
    inner: MemoryKvStore,
    poisoned: Mutex<HashSet<Vec<u8>>>,
}

impl ReadFaultStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryKvStore::new(),
            poisoned: Mutex::new(HashSet::new()),
        })
    }

    fn poison_coin(&self, txid: &Hash256) {
        self.poisoned.lock().insert(txid.to_le_bytes().to_vec());
    }
}

impl KvStore for ReadFaultStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if cf == ColumnFamily::Coins && self.poisoned.lock().contains(key) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected coin read failure",
            )));
        }
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn scan_prefix_from_bounded(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        start: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<PrefixScan, StorageError> {
        self.inner
            .scan_prefix_from_bounded(cf, prefix, start, limit)
    }

    fn new_batch(&self) -> BufferedWriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.inner.write(batch)
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        self.inner.write_durable_if(conditions, batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.inner.flush()
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }

    fn multi_get(
        &self,
        cf: ColumnFamily,
        keys: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, StorageError> {
        self.inner.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &Path,
    ) -> Result<u64, StorageError> {
        self.inner.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &Path) -> Result<(), StorageError> {
        self.inner.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.inner.engine_cache_bytes()
    }

    fn arm_persist_fault(&self, fault: PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}

fn txid(seed: u8) -> Hash256 {
    Hash256::from_le_bytes(&[seed; 32])
}

fn outpoint(seed: u8, vout: u32) -> OutPoint {
    OutPoint::new(txid(seed).into(), vout)
}

fn reader_over(store: &Arc<ReadFaultStore>) -> UtxoReader {
    UtxoReader::from_coin_store(Arc::new(CoinStore::open(store.clone(), CACHE_BUDGET)))
}

fn commit_coins(store: &Arc<ReadFaultStore>, outpoints: &[OutPoint]) -> TestResult {
    let mut changes = BlockChanges::with_capacity(outpoints.len(), 0);
    for outpoint in outpoints {
        changes.add(UtxoAdd::new(
            *outpoint,
            TxOut {
                value: Amount::from_sat(VALUE_SATS),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            true,
            COIN_HEIGHT,
        ));
    }
    reader_over(store).populate_fixture_coins(&changes)?;
    Ok(())
}

// ARCH-07a
#[test]
fn engine_read_fault_is_an_error_never_an_absent_coin() -> TestResult {
    let store = ReadFaultStore::new();
    let faulted = outpoint(0xA1, 0);
    let healthy = outpoint(0xB2, 1);
    let never_stored = outpoint(0xC3, 0);
    commit_coins(&store, &[faulted, healthy])?;
    store.poison_coin(&txid(0xA1));
    let reader = reader_over(&store);

    assert!(matches!(
        reader.get_entry(&faulted),
        Err(UtxoError::Storage(StorageError::Io(_)))
    ));
    assert!(matches!(
        reader.get(&faulted),
        Err(UtxoError::Storage(StorageError::Io(_)))
    ));
    assert!(matches!(
        reader.has_live_outputs_for_txid(&txid(0xA1)),
        Err(UtxoError::Storage(StorageError::Io(_)))
    ));

    let coin = reader.get_entry(&healthy)?;
    assert_eq!(
        coin.as_ref().map(|coin| coin.txout.value.to_sat()),
        Some(VALUE_SATS)
    );
    assert_eq!(coin.as_ref().map(|coin| coin.height), Some(COIN_HEIGHT));
    assert_eq!(coin.as_ref().map(|coin| coin.coinbase), Some(true));
    assert!(reader.has_live_outputs_for_txid(&txid(0xB2))?);

    assert!(reader.get_entry(&never_stored)?.is_none());
    assert!(reader.get_entry(&outpoint(0xB2, 0))?.is_none());
    assert!(!reader.has_live_outputs_for_txid(&txid(0xC3))?);
    Ok(())
}

// ARCH-07a
#[test]
fn undecodable_coin_row_is_an_error_never_an_absent_coin() -> TestResult {
    let store = ReadFaultStore::new();
    store.put(
        ColumnFamily::Coins,
        CoinKey(txid(0xD4).to_le_bytes()).as_bytes(),
        &[0xff; 3],
    )?;
    let reader = reader_over(&store);

    assert!(matches!(
        reader.get_entry(&outpoint(0xD4, 0)),
        Err(UtxoError::CorruptRecord)
    ));
    assert!(matches!(
        reader.get(&outpoint(0xD4, 0)),
        Err(UtxoError::CorruptRecord)
    ));
    assert!(matches!(
        reader.has_live_outputs_for_txid(&txid(0xD4)),
        Err(UtxoError::CorruptRecord)
    ));
    Ok(())
}
