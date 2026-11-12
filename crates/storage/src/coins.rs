use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{Amount, OutPoint, Script, TxOut};
use bytes::Bytes;
use parking_lot::RwLock;

use crate::batch::BufferedWriteBatch;
use crate::utxo::record::UtxoRecord;
use crate::utxo::stats::CoinStatsListener;
use crate::{ColumnFamily, KvStore, StorageError};

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
/// Invariant: at most one entry per `CoinKey`; `None` commits as a delete
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

fn push_insert_ops(bytes: &Bytes, ops: &mut Vec<CoinStatsFeedOp>) -> Result<(), StorageError> {
    push_record_ops(bytes, true, ops)
}

fn push_remove_ops(bytes: &Bytes, ops: &mut Vec<CoinStatsFeedOp>) -> Result<(), StorageError> {
    push_record_ops(bytes, false, ops)
}

fn push_record_ops(
    bytes: &Bytes,
    insert: bool,
    ops: &mut Vec<CoinStatsFeedOp>,
) -> Result<(), StorageError> {
    let record = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice()).map_err(|error| {
        StorageError::IncompatibleData(format!(
            "coin row for stats feed is not a valid UTXO record: {error:?}"
        ))
    })?;
    let txid = record.txid();
    for out in record.outputs() {
        let op = OutPoint::new(txid.into(), out.vout);
        let txout = TxOut {
            value: Amount::from_sat(out.value),
            script_pubkey: Script::from_bytes(out.script_pubkey.to_vec()),
        };
        if insert {
            ops.push(CoinStatsFeedOp::Insert {
                op,
                txout,
                height: out.height,
                coinbase: out.coinbase,
            });
        } else {
            ops.push(CoinStatsFeedOp::Remove {
                op,
                txout,
                height: out.height,
                coinbase: out.coinbase,
            });
        }
    }
    Ok(())
}

pub struct CoinStore {
    store: Arc<dyn KvStore>,
    cache: CoinCache,
    coin_stats: RwLock<Option<CoinStatsListener>>,
}

impl CoinStore {
    pub fn open(store: Arc<dyn KvStore>, budget_bytes: u64) -> Self {
        Self {
            store,
            cache: CoinCache::new(budget_bytes),
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
        for (key, record) in &delta.records {
            if let Some(old) = self.get(key)? {
                push_remove_ops(&old, &mut ops)?;
            }
            if let Some(new) = record {
                push_insert_ops(new, &mut ops)?;
            }
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

    #[cfg(any(test, feature = "test-seam"))]
    pub fn cache(&self) -> &CoinCache {
        &self.cache
    }
}
