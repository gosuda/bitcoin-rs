use std::sync::Arc;

use bytes::Bytes;

use crate::batch::BufferedWriteBatch;
use crate::{ColumnFamily, KvStore, StorageError};

mod cache;
pub use cache::CoinCache;

pub const COIN_KEY_LEN: usize = 32;
const INGEST_BATCH_TARGET_BYTES: u64 = 64 * 1024 * 1024;

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

pub struct CoinStore {
    store: Arc<dyn KvStore>,
    cache: CoinCache,
}

impl CoinStore {
    pub fn open(store: Arc<dyn KvStore>, budget_bytes: u64) -> Self {
        Self {
            store,
            cache: CoinCache::new(budget_bytes),
        }
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

    /// Installs the delta into the resident cache. The caller passes a delta
    /// whose batch already returned success; a failed or ambiguous batch must
    /// not reach this method.
    pub fn install_committed(&self, delta: &WindowDelta) {
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

    #[cfg(any(test, feature = "test-seam"))]
    pub fn cache(&self) -> &CoinCache {
        &self.cache
    }
}
