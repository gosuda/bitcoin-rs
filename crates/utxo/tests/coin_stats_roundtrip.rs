//! Coinstats persistence round-trip tests.

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_storage::{ColumnFamily, KvIter, KvSnapshot, KvStore, StorageError, WriteBatch};
use bitcoin_rs_utxo::stats::coin_stats::COIN_STATS_ENCODED_LEN;
use bitcoin_rs_utxo::stats::{
    CoinStats, CoinStatsDecodeError, CoinStatsListener, load_coin_stats, store_coin_stats,
};

type Row = ((ColumnFamily, Vec<u8>), Vec<u8>);

#[test]
fn coin_stats_persist_load_roundtrips_byte_equal() -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::default();
    let mut stats = CoinStats::new();

    for index in 0_u32..100 {
        let outpoint = OutPoint::new(txid(index), index % 64);
        let txout = TxOut {
            value: Amount::from_sat(1_000 + u64::from(index)),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, index.to_le_bytes()[0]]),
        };
        stats.insert_utxo(&outpoint, &txout, 42, index == 0);
    }
    stats.finish_block(99, 100);

    store_coin_stats(&store, &stats)?;
    let loaded = load_coin_stats(&store, stats.height)?.ok_or("missing stored stats")?;

    assert_eq!(loaded, stats);
    assert_eq!(loaded.to_bytes(), stats.to_bytes());
    Ok(())
}

#[test]
fn finish_block_applies_height_and_transaction_delta() {
    let mut stats = CoinStats::new();
    stats.finish_block(7, 3);
    stats.finish_block(8, 5);

    assert_eq!(stats.height, 8);
    assert_eq!(stats.tx_count, 8);

    let listener = CoinStatsListener::new(CoinStats::new());
    listener.finish_block(9, 2);
    listener.finish_block(10, 4);
    let snapshot = listener.snapshot();

    assert_eq!(snapshot.height, 10);
    assert_eq!(snapshot.tx_count, 6);
}

#[test]
fn coin_stats_codec_is_exact_and_preserves_muhash_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let old_op = OutPoint::new(txid(1_000), 3);
    let old_txout = TxOut {
        value: Amount::from_sat(12_345),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x21]),
    };
    let mut original = CoinStats::new();
    original.insert_utxo(&old_op, &old_txout, 100, true);
    original.finish_block(100, 1);

    let bytes = original.to_bytes();
    assert_eq!(bytes.len(), COIN_STATS_ENCODED_LEN);
    let mut restored = CoinStats::from_bytes(&bytes)?;
    assert_eq!(restored, original);

    assert!(matches!(
        CoinStats::from_bytes(&bytes[..bytes.len() - 1]),
        Err(CoinStatsDecodeError::Truncated)
    ));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        CoinStats::from_bytes(&trailing),
        Err(CoinStatsDecodeError::TrailingBytes)
    ));

    let new_op = OutPoint::new(txid(1_001), 4);
    let new_txout = TxOut {
        value: Amount::from_sat(54_321),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x22]),
    };
    original.remove_utxo(&old_op, &old_txout, 100, true);
    restored.remove_utxo(&old_op, &old_txout, 100, true);
    original.insert_utxo(&new_op, &new_txout, 101, false);
    restored.insert_utxo(&new_op, &new_txout, 101, false);

    assert_eq!(restored, original);
    assert_eq!(restored.to_bytes(), original.to_bytes());
    Ok(())
}

fn txid(index: u32) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

#[derive(Default)]
struct MemoryStore {
    rows: parking_lot::RwLock<Vec<Row>>,
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .rows
            .read()
            .iter()
            .find(|((row_cf, row_key), _value)| *row_cf == cf && row_key == key)
            .map(|(_row, value)| value.clone()))
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
            .filter(|((row_cf, key), _value)| *row_cf == cf && key.starts_with(prefix))
            .map(|((_row_cf, key), value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| match (left, right) {
            (Ok((left_key, _)), Ok((right_key, _))) => left_key.cmp(right_key),
            _ => core::cmp::Ordering::Equal,
        });
        Ok(Box::new(rows.into_iter()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        MemoryBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut rows = self.rows.write();
        for op in batch.ops {
            match op {
                MemoryOp::Put(cf, key, value) => {
                    if let Some((_row, existing_value)) = rows
                        .iter_mut()
                        .find(|((row_cf, row_key), _value)| *row_cf == cf && row_key == &key)
                    {
                        *existing_value = value;
                    } else {
                        rows.push(((cf, key), value));
                    }
                }
                MemoryOp::Delete(cf, key) => {
                    rows.retain(|((row_cf, row_key), _value)| *row_cf != cf || row_key != &key);
                }
                MemoryOp::DeleteRange(cf, start, end) => {
                    rows.retain(|((row_cf, key), _value)| {
                        *row_cf != cf
                            || key.as_slice() < start.as_slice()
                            || key.as_slice() >= end.as_slice()
                    });
                }
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        Err(StorageError::InvalidOperation(
            "memory snapshots unsupported",
        ))
    }
}

#[derive(Default)]
struct MemoryBatch {
    ops: Vec<MemoryOp>,
}

enum MemoryOp {
    Put(ColumnFamily, Vec<u8>, Vec<u8>),
    Delete(ColumnFamily, Vec<u8>),
    DeleteRange(ColumnFamily, Vec<u8>, Vec<u8>),
}

impl WriteBatch for MemoryBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops
            .push(MemoryOp::Put(cf, key.to_vec(), value.to_vec()));
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(MemoryOp::Delete(cf, key.to_vec()));
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops
            .push(MemoryOp::DeleteRange(cf, start.to_vec(), end.to_vec()));
    }
}
