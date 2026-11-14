use bitcoin_rs_consensus::primitives::{Amount, OutPoint, Script, TxOut};
use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;

use crate::batch::BufferedWriteBatch;
use crate::utxo::UtxoError;
use crate::utxo::record::UtxoRecord;
use crate::utxo::snapshot::{SerializedUtxoHasher, SnapshotCoin, SnapshotCoinObserver};
use crate::utxo::stats::CoinStatsListener;
use crate::utxo::stats::{CoinStats, CoinStatsAccumulator};
use crate::{ColumnFamily, KvStore, StorageError};

pub struct CoinCommitment {
    pub hash_serialized: bitcoin_rs_consensus::primitives::Hash256,
    pub stats: CoinStats,
}

mod cache;
pub use cache::CoinCache;

pub const COIN_KEY_LEN: usize = 32;
const INGEST_BATCH_TARGET_BYTES: u64 = 64 * 1024 * 1024;

/// Exclusive upper bound for full-keyspace scans over the `coins` family.
pub const COIN_KEYSPACE_END: &[u8] = &[0xff_u8; 64];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CoinKey(pub [u8; COIN_KEY_LEN]);

impl CoinKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, StorageError> {
        let key: [u8; COIN_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| StorageError::InvalidOperation("coin key must be exactly 32 bytes"))?;
        Ok(Self(key))
    }

    #[must_use]
    pub const fn shard(self) -> u8 {
        self.0[0]
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COIN_KEY_LEN] {
        &self.0
    }
}

/// One final coin image per touched txid for the valid prefix of a window.
///
/// Each key's last entry is its final image; `None` commits as a delete
/// (create-and-spend txids never enter the store), `Some` as a replacement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowDelta {
    pub records: Vec<(CoinKey, Option<Bytes>)>,
}

impl WindowDelta {
    pub fn push_final(&mut self, key: CoinKey, record: Option<Bytes>) {
        self.records.push((key, record));
    }
}

#[derive(Debug, Default)]
pub struct CoinStatsFeed {
    ops: Vec<CoinStatsFeedOp>,
}

#[derive(Clone, Debug)]
enum CoinStatsFeedOp {
    Insert {
        op: OutPoint,
        txout: TxOut,
        height: u32,
        coinbase: bool,
    },
    Remove {
        op: OutPoint,
        txout: TxOut,
        height: u32,
        coinbase: bool,
    },
}

impl CoinStatsFeed {
    fn apply(self, listener: &CoinStatsListener) {
        listener.apply_utxos(self.ops.iter().map(|op| match op {
            CoinStatsFeedOp::Insert {
                op,
                txout,
                height,
                coinbase,
            } => (true, op, txout, *height, *coinbase),
            CoinStatsFeedOp::Remove {
                op,
                txout,
                height,
                coinbase,
            } => (false, op, txout, *height, *coinbase),
        }));
    }
}

fn decode_stats_record(bytes: &Bytes) -> Result<UtxoRecord, StorageError> {
    UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice()).map_err(|error| {
        StorageError::IncompatibleData(format!(
            "coin row for stats feed is not a valid UTXO record: {error:?}"
        ))
    })
}

fn stats_txout(out: crate::utxo::record::OneUtxoOut<'_>) -> TxOut {
    TxOut {
        value: Amount::from_sat(out.value),
        script_pubkey: Script::from_bytes(out.script_pubkey.to_vec()),
    }
}

fn push_insert_output(
    record: &UtxoRecord,
    out: crate::utxo::record::OneUtxoOut<'_>,
    ops: &mut Vec<CoinStatsFeedOp>,
) {
    ops.push(CoinStatsFeedOp::Insert {
        op: OutPoint::new(record.txid().into(), out.vout),
        txout: stats_txout(out),
        height: out.height,
        coinbase: out.coinbase,
    });
}

fn push_remove_output(
    record: &UtxoRecord,
    out: crate::utxo::record::OneUtxoOut<'_>,
    ops: &mut Vec<CoinStatsFeedOp>,
) {
    ops.push(CoinStatsFeedOp::Remove {
        op: OutPoint::new(record.txid().into(), out.vout),
        txout: stats_txout(out),
        height: out.height,
        coinbase: out.coinbase,
    });
}

fn push_changed_record_ops(
    old: Option<&UtxoRecord>,
    new: Option<&UtxoRecord>,
    ops: &mut Vec<CoinStatsFeedOp>,
) {
    let (Some(old), Some(new)) = (old, new) else {
        if let Some(record) = old {
            for out in record.outputs() {
                push_remove_output(record, out, ops);
            }
        }
        if let Some(record) = new {
            for out in record.outputs() {
                push_insert_output(record, out, ops);
            }
        }
        return;
    };
    push_record_difference(old, new, ops);
}

fn push_record_difference(old: &UtxoRecord, new: &UtxoRecord, ops: &mut Vec<CoinStatsFeedOp>) {
    if old.txid() != new.txid() {
        push_changed_record_ops(Some(old), None, ops);
        push_changed_record_ops(None, Some(new), ops);
        return;
    }
    let mut old_outputs = old.outputs().peekable();
    let mut new_outputs = new.outputs().peekable();
    while let (Some(before), Some(after)) = (old_outputs.peek(), new_outputs.peek()) {
        match before.vout.cmp(&after.vout) {
            std::cmp::Ordering::Less => {
                push_remove_output(old, *before, ops);
                old_outputs.next();
            }
            std::cmp::Ordering::Greater => {
                push_insert_output(new, *after, ops);
                new_outputs.next();
            }
            std::cmp::Ordering::Equal => {
                if before != after {
                    push_remove_output(old, *before, ops);
                    push_insert_output(new, *after, ops);
                }
                old_outputs.next();
                new_outputs.next();
            }
        }
    }
    for out in old_outputs {
        push_remove_output(old, out, ops);
    }
    for out in new_outputs {
        push_insert_output(new, out, ops);
    }
}

pub struct CoinStore {
    store: Arc<dyn KvStore>,
    cache: CoinCache,
    coin_stats: RwLock<Option<CoinStatsListener>>,
}

impl CoinStore {
    pub fn open(store: Arc<dyn KvStore>, budget_bytes: u64) -> Self {
        Self::open_with_charge(store, budget_bytes, None)
    }

    pub fn open_with_charge(
        store: Arc<dyn KvStore>,
        budget_bytes: u64,
        charge: Option<crate::budget::ChargeHandle>,
    ) -> Self {
        Self {
            store,
            cache: CoinCache::with_charge(budget_bytes, charge),
            coin_stats: RwLock::new(None),
        }
    }

    pub fn track_coin_stats(&self, listener: CoinStatsListener) {
        *self.coin_stats.write() = Some(listener);
    }

    pub fn plan_stats_feed(&self, delta: &WindowDelta) -> Result<CoinStatsFeed, StorageError> {
        if self.coin_stats.read().is_none() {
            return Ok(CoinStatsFeed::default());
        }
        let mut ops = Vec::with_capacity(delta.records.len().saturating_mul(2));
        let mut seen = HashSet::with_capacity(delta.records.len());
        for (key, record) in delta.records.iter().rev() {
            if !seen.insert(*key) {
                continue;
            }
            let old = self
                .get(key)?
                .as_ref()
                .map(decode_stats_record)
                .transpose()?;
            let new = record.as_ref().map(decode_stats_record).transpose()?;
            push_changed_record_ops(old.as_ref(), new.as_ref(), &mut ops);
        }
        Ok(CoinStatsFeed { ops })
    }

    /// Point-in-time image of the `coins` keyspace for streaming scans.
    ///
    /// Callers pair the snapshot with the chain-transition lock so the image
    /// and the applied head describe the same committed state.
    pub fn scan_snapshot(&self) -> Result<Box<dyn crate::KvSnapshot + '_>, StorageError> {
        self.store.snapshot()
    }

    pub fn get(&self, key: &CoinKey) -> Result<Option<Bytes>, StorageError> {
        if let Some(cached) = self.cache.lookup(key) {
            return Ok(Some(cached));
        }
        let epoch = self.cache.epoch(key.shard());
        match self.store.get(ColumnFamily::Coins, key.as_bytes())? {
            Some(value) => {
                let value = Bytes::from(value);
                self.cache
                    .fill_after_read_guarded(key, value.clone(), epoch);
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub fn multi_get(&self, keys: &[CoinKey]) -> Result<Vec<Option<Bytes>>, StorageError> {
        let mut results: Vec<Option<Bytes>> = vec![None; keys.len()];
        let mut missed_keys: Vec<CoinKey> = Vec::new();
        let mut missed_positions: Vec<usize> = Vec::new();
        let mut missed_epochs: Vec<u64> = Vec::new();
        for (position, key) in keys.iter().enumerate() {
            match self.cache.lookup(key) {
                Some(value) => results[position] = Some(value),
                None => {
                    missed_keys.push(*key);
                    missed_positions.push(position);
                    missed_epochs.push(self.cache.epoch(key.shard()));
                }
            }
        }
        if !missed_keys.is_empty() {
            let key_refs: Vec<&[u8]> = missed_keys.iter().map(|key| &key.0[..]).collect();
            let resolved = self.store.multi_get(ColumnFamily::Coins, &key_refs)?;
            for ((position, value), expected_epoch) in missed_positions
                .into_iter()
                .zip(resolved)
                .zip(missed_epochs)
            {
                if let Some(value) = value {
                    self.cache.fill_after_read_guarded(
                        &keys[position],
                        value.clone(),
                        expected_epoch,
                    );
                    results[position] = Some(value);
                }
            }
        }
        Ok(results)
    }

    /// Emits the window's final coin images into `batch` so they commit in the
    /// same atomic write as the durable head, undo rows, and body index.
    ///
    /// Invariant: this never mutates the resident cache; only a successful
    /// durable receipt followed by `install_committed` does.
    pub fn append_window(
        &self,
        batch: &mut BufferedWriteBatch,
        delta: &WindowDelta,
    ) -> Result<(), StorageError> {
        for (key, record) in &delta.records {
            match record {
                Some(record) => {
                    batch.put_value(ColumnFamily::Coins, key.as_bytes(), record.clone());
                }
                None => batch.delete(ColumnFamily::Coins, key.as_bytes()),
            }
        }
        Ok(())
    }

    /// Installs the delta into the resident cache and replays its coin
    /// mutations into the tracked listener. The caller passes a delta whose
    /// batch already returned success plus the feed planned before that
    /// write; a failed or ambiguous batch must not reach this method.
    pub fn install_committed(&self, delta: &WindowDelta, feed: CoinStatsFeed) {
        if let Some(listener) = self.coin_stats.read().as_ref() {
            feed.apply(listener);
        }
        for (key, record) in &delta.records {
            self.cache.install(key, record.clone());
        }
    }

    pub fn note_bytes(&self, shard: u8, bytes: usize) {
        self.cache.note_bytes(shard, bytes);
    }

    pub fn evict_to_budget(&self) {
        self.cache.evict_to_budget();
    }

    pub fn ingest_chunk(&self, delta: &WindowDelta) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        self.append_window(&mut batch, delta)?;
        self.store.write_durable(batch)
    }

    /// Bulk-writes a strictly increasing sorted run into the `coins` keyspace.
    ///
    /// On error, earlier durable batches stay committed and the cache is
    /// cleared; the caller must not publish the namespace after an error.
    pub fn ingest_sorted(
        &self,
        records: impl Iterator<Item = (CoinKey, Bytes)>,
    ) -> Result<(), StorageError> {
        let outcome = self.write_sorted_run(records);
        self.cache.clear();
        outcome
    }

    /// Deletes every engine coin row and clears the resident cache (CMT-03).
    ///
    /// Boot recovery uses this to discard staged snapshot coins after an
    /// interrupted activation; the canonical set is rebuilt from the durable
    /// head's own replay paths.
    pub fn wipe(&self) -> Result<(), StorageError> {
        let outcome = self
            .store
            .delete_range(ColumnFamily::Coins, &[], COIN_KEYSPACE_END);
        self.cache.clear();
        outcome
    }

    fn write_sorted_run(
        &self,
        records: impl Iterator<Item = (CoinKey, Bytes)>,
    ) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        let mut pending_bytes = 0_u64;
        let mut previous: Option<CoinKey> = None;
        for (key, value) in records {
            if let Some(previous) = previous {
                if key <= previous {
                    return Err(StorageError::InvalidOperation(
                        "coin ingest keys must be strictly increasing",
                    ));
                }
            }
            let row_bytes = u64::try_from(COIN_KEY_LEN + value.len()).unwrap_or(u64::MAX);
            if pending_bytes > 0 && pending_bytes + row_bytes > INGEST_BATCH_TARGET_BYTES {
                let full = std::mem::take(&mut batch);
                self.store.write_durable(full)?;
                pending_bytes = 0;
            }
            batch.put_value(ColumnFamily::Coins, key.as_bytes(), value);
            pending_bytes += row_bytes;
            previous = Some(key);
        }
        if pending_bytes > 0 {
            self.store.write_durable(batch)?;
        }
        Ok(())
    }
    #[must_use]
    pub fn store(&self) -> &Arc<dyn KvStore> {
        &self.store
    }

    pub fn commitment(
        &self,
        height: u32,
        snapshot_height: Option<u32>,
    ) -> Result<CoinCommitment, UtxoError> {
        let mut hasher = SerializedUtxoHasher::new();
        let mut accumulator = CoinStatsAccumulator::with_muhash(height);
        for item in self
            .store
            .iter_prefix(ColumnFamily::Coins, &[])
            .map_err(UtxoError::Storage)?
        {
            let (_, value) = item.map_err(UtxoError::Storage)?;
            let record = UtxoRecord::from_encoded(value.into_boxed_slice())?;
            let txid = record.txid();
            let txid_le = txid.to_le_bytes();
            let mut outputs: Vec<_> = record.outputs().collect();
            outputs.sort_unstable_by_key(|output| output.vout);
            for output in outputs {
                accumulator.observe_coin(SnapshotCoin {
                    txid,
                    vout: output.vout,
                    value: output.value,
                    script_pubkey: output.script_pubkey,
                    height: output.height,
                    coinbase: output.coinbase,
                });
                hasher.add(txid_le, output, snapshot_height)?;
            }
        }
        Ok(CoinCommitment {
            hash_serialized: hasher.finish(),
            stats: accumulator.into_stats(),
        })
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn cache(&self) -> &CoinCache {
        &self.cache
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod commitment_tests {
    use super::*;
    use crate::MemoryKvStore;
    use crate::utxo::record::{OneUtxoOut, OwnedUtxoOut, UtxoRecord};
    use bitcoin_rs_consensus::primitives::Hash256;

    fn output(vout: u32) -> OwnedUtxoOut {
        OwnedUtxoOut::new(
            vout,
            1_000 + u64::from(vout),
            vec![0x51, u8::try_from(vout).expect("vout fits a byte")],
            false,
            5,
        )
    }
    fn engine_with(record: &UtxoRecord) -> CoinStore {
        let coins = CoinStore::open(Arc::new(MemoryKvStore::new()), 1 << 20);
        let mut delta = WindowDelta::default();
        delta.push_final(
            CoinKey(record.txid().to_le_bytes()),
            Some(Bytes::copy_from_slice(record.bytes())),
        );
        coins.ingest_chunk(&delta).expect("ingest");
        coins
    }

    #[test]
    fn commitment_is_independent_of_stored_output_order() {
        let txid = Hash256::from_le_bytes(&[7_u8; 32]);
        let unsorted = UtxoRecord::from_owned_outputs(txid, &[output(2), output(0), output(1)])
            .expect("record");
        let sorted = UtxoRecord::from_owned_outputs(txid, &[output(0), output(1), output(2)])
            .expect("record");
        let from_unsorted = engine_with(&unsorted)
            .commitment(10, None)
            .expect("commitment");
        let from_sorted = engine_with(&sorted)
            .commitment(10, None)
            .expect("commitment");
        assert_eq!(from_unsorted.hash_serialized, from_sorted.hash_serialized);
    }

    #[test]
    fn commitment_matches_an_independent_fold_of_the_coin_list() {
        let coin_list = vec![
            (
                Hash256::from_le_bytes(&[3_u8; 32]),
                vec![
                    OwnedUtxoOut::new(0, 900, vec![0x51], false, 5),
                    OwnedUtxoOut::new(2, 700, vec![0x52, 0x53], true, 7),
                ],
            ),
            (
                Hash256::from_le_bytes(&[1_u8; 32]),
                vec![OwnedUtxoOut::new(1, 1_500, vec![0x54], false, 2)],
            ),
            (
                Hash256::from_le_bytes(&[2_u8; 32]),
                vec![
                    OwnedUtxoOut::new(0, 10, vec![0x55], false, 1),
                    OwnedUtxoOut::new(1, 20, vec![0x56], false, 1),
                    OwnedUtxoOut::new(3, 30, vec![], true, 4),
                ],
            ),
        ];
        let coins = CoinStore::open(Arc::new(MemoryKvStore::new()), 1 << 20);
        let mut delta = WindowDelta::default();
        for (txid, outputs) in &coin_list {
            let record = UtxoRecord::from_owned_outputs(*txid, outputs).expect("record");
            delta.push_final(
                CoinKey(txid.to_le_bytes()),
                Some(Bytes::copy_from_slice(record.bytes())),
            );
        }
        coins.ingest_chunk(&delta).expect("ingest");

        let mut coins_by_key: Vec<(Hash256, &OwnedUtxoOut)> = coin_list
            .iter()
            .flat_map(|(txid, outputs)| outputs.iter().map(move |output| (*txid, output)))
            .collect();
        coins_by_key.sort_by_key(|(txid, output)| (txid.to_le_bytes(), output.vout));
        let mut hasher = SerializedUtxoHasher::new();
        let mut accumulator = CoinStatsAccumulator::with_muhash(10);
        for (txid, output) in coins_by_key {
            hasher
                .add(
                    txid.to_le_bytes(),
                    OneUtxoOut {
                        vout: output.vout,
                        value: output.value,
                        script_pubkey: &output.script_pubkey,
                        coinbase: output.coinbase,
                        height: output.height,
                    },
                    None,
                )
                .expect("hash");
            accumulator.observe_coin(SnapshotCoin {
                txid,
                vout: output.vout,
                value: output.value,
                script_pubkey: &output.script_pubkey,
                height: output.height,
                coinbase: output.coinbase,
            });
        }

        let commitment = coins.commitment(10, None).expect("commitment");
        assert_eq!(commitment.hash_serialized, hasher.finish());
        assert_eq!(commitment.stats, accumulator.into_stats());
        assert_eq!(commitment.stats.utxo_count, 6);
    }
}
