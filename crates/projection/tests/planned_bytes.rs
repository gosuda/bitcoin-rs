//! The bytes a prepared batch plans bound every write the commit hands the
//! store. The fixture spends an output created earlier in the same batch and
//! pays a script the chain already used, so the tail append writes a spend
//! row and an undo-log prior that a plan built from an empty tail would miss.

use std::sync::Arc;

use bitcoin_rs_consensus::primitives::encode::double_sha256;
use bitcoin_rs_projection::{
    IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits, PreparedBlock, SpentCoin,
    SpentCoins,
};
use bitcoin_rs_storage::{
    BatchOp, BufferedWriteBatch, ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScan,
    PrefixScanLimit, StorageError, WriteCondition,
};
use parking_lot::Mutex;

use crate::support::TestError;
use crate::support::common::MemoryStore;

const COINBASE_VALUE: u64 = 50 * 100_000_000;
const CHILD_VALUE: u64 = COINBASE_VALUE - 1_000;
const OP_TRUE: [u8; 1] = [0x51];
const P2WPKH: [u8; 22] = [
    0x00, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

#[derive(Default)]
struct RecordingStore {
    inner: MemoryStore,
    committed_bytes: Mutex<Vec<usize>>,
}

impl RecordingStore {
    fn record_and_replay(&self, batch: BufferedWriteBatch) -> BufferedWriteBatch {
        let ops = batch.into_ops();
        let total = ops
            .iter()
            .map(op_bytes)
            .fold(0_usize, usize::saturating_add);
        self.committed_bytes.lock().push(total);
        let mut replayed = self.inner.new_batch();
        for op in ops {
            match op {
                BatchOp::Put { cf, key, value } => replayed.put_value(cf, &key, value),
                BatchOp::Delete { cf, key } => replayed.delete(cf, &key),
                BatchOp::DeleteRange { cf, start, end } => replayed.delete_range(cf, &start, &end),
            }
        }
        replayed
    }
}

fn op_bytes(op: &BatchOp) -> usize {
    match op {
        BatchOp::Put { key, value, .. } => key.len().saturating_add(value.len()),
        BatchOp::Delete { key, .. } => key.len(),
        BatchOp::DeleteRange { start, end, .. } => start.len().saturating_add(end.len()),
    }
}

impl KvStore for RecordingStore {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
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
        self.inner.write(self.record_and_replay(batch))
    }

    fn write_durable(&self, batch: BufferedWriteBatch) -> Result<(), StorageError> {
        self.inner.write_durable(self.record_and_replay(batch))
    }

    fn write_durable_if(
        &self,
        conditions: &[WriteCondition<'_>],
        batch: BufferedWriteBatch,
    ) -> Result<bool, StorageError> {
        self.inner
            .write_durable_if(conditions, self.record_and_replay(batch))
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
    ) -> Result<Vec<Option<bitcoin_rs_storage::Bytes>>, StorageError> {
        self.inner.multi_get(cf, keys)
    }

    fn ingest_sorted(
        &self,
        cf: ColumnFamily,
        rows: &mut dyn Iterator<Item = (Vec<u8>, Vec<u8>)>,
        scratch: &std::path::Path,
    ) -> Result<u64, StorageError> {
        self.inner.ingest_sorted(cf, rows, scratch)
    }

    fn delete_range(&self, cf: ColumnFamily, start: &[u8], end: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_range(cf, start, end)
    }

    fn checkpoint(&self, dir: &std::path::Path) -> Result<(), StorageError> {
        self.inner.checkpoint(dir)
    }

    fn engine_cache_bytes(&self) -> u64 {
        self.inner.engine_cache_bytes()
    }

    fn arm_persist_fault(&self, fault: bitcoin_rs_storage::PersistFault) {
        self.inner.arm_persist_fault(fault);
    }
}

struct NoCoins;

impl SpentCoins for NoCoins {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        None
    }
}

struct FirstCoinbase {
    txid: [u8; 32],
}

impl SpentCoins for FirstCoinbase {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
        (txid == &self.txid && vout == 0).then_some(SpentCoin {
            script: &OP_TRUE,
            value: COINBASE_VALUE,
            height: 1,
            coinbase: true,
        })
    }
}

fn legacy_tx(inputs: &[([u8; 32], u32, Vec<u8>)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_i32.to_le_bytes());
    out.push(u8::try_from(inputs.len()).unwrap_or(u8::MAX));
    for (txid, vout, script_sig) in inputs {
        out.extend_from_slice(txid);
        out.extend_from_slice(&vout.to_le_bytes());
        out.push(u8::try_from(script_sig.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(script_sig);
        out.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    out.push(u8::try_from(outputs.len()).unwrap_or(u8::MAX));
    for (value, script) in outputs {
        out.extend_from_slice(&value.to_le_bytes());
        out.push(u8::try_from(script.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(script);
    }
    out.extend_from_slice(&0_u32.to_le_bytes());
    out
}

struct Block {
    body: Vec<u8>,
    hash: [u8; 32],
}

fn block(prev: [u8; 32], height: u32, txs: &[Vec<u8>]) -> Block {
    let mut header = [0_u8; 80];
    header[..4].copy_from_slice(&1_i32.to_le_bytes());
    header[4..36].copy_from_slice(&prev);
    header[68..72].copy_from_slice(&height.to_le_bytes());
    header[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes());
    header[76..80].copy_from_slice(&height.to_le_bytes());
    let hash = double_sha256(&header).to_le_bytes();
    let mut body = header.to_vec();
    body.push(u8::try_from(txs.len()).unwrap_or(u8::MAX));
    for tx in txs {
        body.extend_from_slice(tx);
    }
    Block { body, hash }
}

struct Chain {
    first: Block,
    second: Block,
    cb1_txid: [u8; 32],
}

fn chain() -> Chain {
    let cb1 = legacy_tx(
        &[([0; 32], u32::MAX, vec![0x01, 0x01])],
        &[(COINBASE_VALUE, OP_TRUE.to_vec())],
    );
    let first = block([0; 32], 0, std::slice::from_ref(&cb1));
    let cb1_txid = double_sha256(&cb1).to_le_bytes();

    let cb2 = legacy_tx(
        &[([0; 32], u32::MAX, vec![0x02, 0x02, 0x00])],
        &[(COINBASE_VALUE, OP_TRUE.to_vec())],
    );
    let spend = legacy_tx(
        &[(cb1_txid, 0, Vec::new())],
        &[(CHILD_VALUE, P2WPKH.to_vec())],
    );
    let second = block(first.hash, 1, &[cb2, spend]);
    Chain {
        first,
        second,
        cb1_txid,
    }
}

fn prepare_pair(
    writer: &IndexWriter<RecordingStore>,
    caps: IndexCapabilities,
    chain: &Chain,
) -> Result<[PreparedBlock; 2], TestError> {
    let first = writer.prepare_block_with_spent_scripts(
        caps,
        0,
        chain.first.hash,
        &chain.first.body,
        &NoCoins,
    )?;
    let second = writer.prepare_block_with_spent_scripts(
        caps,
        1,
        chain.second.hash,
        &chain.second.body,
        &FirstCoinbase {
            txid: chain.cb1_txid,
        },
    )?;
    Ok([first, second])
}

// IDX-06
#[test]
fn planned_bytes_bound_every_write_of_a_batch() -> Result<(), TestError> {
    let chain = chain();
    let caps = IndexCapabilities::HISTORICAL.with_compact_filters(true);
    let store = Arc::new(RecordingStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;

    let mut measure = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    for prepared in prepare_pair(&writer, caps, &chain)? {
        assert!(
            measure.try_push(prepared).is_ok(),
            "an unbounded batch admits both blocks"
        );
    }
    let limit = measure.encoded_bytes();

    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: limit,
    });
    for prepared in prepare_pair(&writer, caps, &chain)? {
        assert!(
            batch.try_push(prepared).is_ok(),
            "a batch admitted at its own planned size is admitted again"
        );
    }
    assert!(limit > 0, "the fixture must plan a nonzero batch");

    writer.commit_forward(batch)?;
    let written = store
        .committed_bytes
        .lock()
        .last()
        .copied()
        .ok_or_else(|| std::io::Error::other("the commit recorded no write"))?;
    assert!(written > 0, "the fixture must write a nonzero batch");
    assert!(
        written <= limit,
        "the batch's writes must fit its planned bytes: wrote {written}, planned {limit}"
    );
    Ok(())
}
