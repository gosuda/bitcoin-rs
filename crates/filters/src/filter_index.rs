use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch};
use thiserror::Error;

use crate::cfheaders;

/// Errors returned by [`FilterIndex`].
#[derive(Debug, Error)]
pub enum FilterIndexError {
    /// Storage backend failure.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A stored hash row had the wrong byte length.
    #[error("stored filter header for {block_hash} has {actual} bytes, expected 32")]
    InvalidHeaderLength {
        /// Block hash whose row was malformed.
        block_hash: Hash256,
        /// Actual stored byte count.
        actual: usize,
    },
}

/// Persistent BIP157/158 filter index over a backend-neutral key-value store.
pub struct FilterIndex<S: KvStore> {
    store: S,
}

impl<S: KvStore> FilterIndex<S> {
    /// Wraps a key-value store as a compact-filter index.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Returns a shared reference to the underlying store.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Consumes the index and returns the underlying store.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Stores a block filter and its BIP157 chained filter header atomically.
    pub fn put_filter(
        &self,
        block_hash: Hash256,
        prev_header: Hash256,
        filter_bytes: &[u8],
    ) -> Result<Hash256, FilterIndexError> {
        let header = cfheaders::next_header(prev_header, filter_bytes);
        let key = block_hash.to_le_bytes();
        let mut batch = self.store.new_batch();
        batch.put(ColumnFamily::Filters, &key, filter_bytes);
        batch.put(ColumnFamily::FilterHeaders, &key, header.as_byte_array());
        self.store.write(batch)?;
        tracing::trace!(%block_hash, filter_bytes = filter_bytes.len(), %header, "stored compact filter");
        Ok(header)
    }

    /// Loads the raw filter bytes for a block, if indexed.
    pub fn filter(&self, block_hash: Hash256) -> Result<Option<Vec<u8>>, FilterIndexError> {
        Ok(self
            .store
            .get(ColumnFamily::Filters, &block_hash.to_le_bytes())?)
    }
    /// Returns the count of stored block filters without materializing values.
    ///
    /// Cost O(N) iteration (no per-row value materialization).
    pub fn filter_count(&self) -> Result<usize, FilterIndexError> {
        let iter = self.store.iter_prefix(ColumnFamily::Filters, &[])?;
        let mut count = 0_usize;
        for entry in iter {
            let (_key, _value) = entry.map_err(FilterIndexError::Storage)?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    /// Iterates every persisted block-filter pair `(block_hash, filter_bytes)` in storage order.
    ///
    /// Used by SPV-style range queries that need every filter (e.g., wallet rescan).
    /// Linear scan; cost O(N) for N filters.
    pub fn iter_filters(
        &self,
    ) -> Result<Vec<(bitcoin_rs_primitives::Hash256, Vec<u8>)>, FilterIndexError> {
        let iter = self.store.iter_prefix(ColumnFamily::Filters, &[])?;
        let mut out = Vec::new();
        for entry in iter {
            let (key, value) = entry.map_err(FilterIndexError::Storage)?;
            if let Ok(hash_bytes) = <[u8; 32]>::try_from(key.as_slice()) {
                out.push((
                    bitcoin_rs_primitives::Hash256::from_le_bytes(&hash_bytes),
                    value,
                ));
            }
        }
        Ok(out)
    }

    /// Returns whether a block filter is stored for `block_hash`.
    ///
    /// Cheaper than `filter_header` when only presence matters: probes the
    /// `FilterHeaders` column family for the header row without materializing
    /// the 32-byte payload.
    ///
    /// Per `put_filter`'s atomic write contract, the presence of a filter
    /// header implies the corresponding filter body is also stored.
    pub fn has_filter(&self, block_hash: Hash256) -> Result<bool, FilterIndexError> {
        let key = block_hash.to_le_bytes();
        let maybe = self.store.get(ColumnFamily::FilterHeaders, &key)?;
        Ok(maybe.is_some())
    }

    /// Loads the BIP157 filter header for a block, if indexed.
    pub fn filter_header(&self, block_hash: Hash256) -> Result<Option<Hash256>, FilterIndexError> {
        let Some(bytes) = self
            .store
            .get(ColumnFamily::FilterHeaders, &block_hash.to_le_bytes())?
        else {
            return Ok(None);
        };
        if bytes.len() != 32 {
            return Err(FilterIndexError::InvalidHeaderLength {
                block_hash,
                actual: bytes.len(),
            });
        }
        let mut header = [0_u8; 32];
        header.copy_from_slice(&bytes);
        Ok(Some(Hash256::from_le_bytes(&header)))
    }
}

/// Storage-agnostic compact-filter ingest interface.
pub trait FilterIndexLike: Send + Sync {
    /// Stores a block filter and returns its chained BIP157 filter header.
    fn put_filter(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
        prev_header: bitcoin_rs_primitives::Hash256,
        filter_bytes: &[u8],
    ) -> Result<bitcoin_rs_primitives::Hash256, FilterIndexError>;

    /// Loads the BIP157 filter header for a block, if indexed.
    fn filter_header(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<bitcoin_rs_primitives::Hash256>, FilterIndexError>;
    /// Loads the raw filter bytes for a block, if indexed.
    fn filter(
        &self,
        _block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, FilterIndexError> {
        Ok(None)
    }

    /// Iterates every persisted block-filter pair `(block_hash, filter_bytes)` in storage order.
    fn iter_filters(
        &self,
    ) -> Result<Vec<(bitcoin_rs_primitives::Hash256, Vec<u8>)>, FilterIndexError> {
        Ok(Vec::new())
    }
}

impl<S: KvStore + Send + Sync + 'static> FilterIndexLike for FilterIndex<S> {
    fn put_filter(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
        prev_header: bitcoin_rs_primitives::Hash256,
        filter_bytes: &[u8],
    ) -> Result<bitcoin_rs_primitives::Hash256, FilterIndexError> {
        Self::put_filter(self, block_hash, prev_header, filter_bytes)
    }

    fn filter_header(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<bitcoin_rs_primitives::Hash256>, FilterIndexError> {
        Self::filter_header(self, block_hash)
    }

    fn filter(
        &self,
        block_hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, FilterIndexError> {
        Self::filter(self, block_hash)
    }

    fn iter_filters(
        &self,
    ) -> Result<Vec<(bitcoin_rs_primitives::Hash256, Vec<u8>)>, FilterIndexError> {
        Self::iter_filters(self)
    }
}

#[cfg(all(test, feature = "rocksdb"))]
mod iter_filters_tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin_rs_storage::RocksDbStore;

    use super::*;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let mut path = env::temp_dir();
            path.push(format!("bitcoin-rs-filters-{}-{nonce}", std::process::id()));
            fs::create_dir(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn filter_index() -> Result<(TestDir, FilterIndex<RocksDbStore>), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let store = RocksDbStore::open(dir.path())?;
        let index = FilterIndex::new(store);
        Ok((dir, index))
    }

    #[test]
    fn iter_filters_returns_empty_on_fresh_index() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let store = RocksDbStore::open(dir.path())?;
        let index = FilterIndex::new(store);

        let filters = index.iter_filters()?;

        assert!(filters.is_empty());
        Ok(())
    }

    #[test]
    fn filter_count_returns_zero_for_empty_index() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let store = RocksDbStore::open(dir.path())?;
        let index = FilterIndex::new(store);

        assert_eq!(index.filter_count()?, 0);
        Ok(())
    }

    #[test]
    fn filter_count_returns_one_after_put_filter() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let store = RocksDbStore::open(dir.path())?;
        let index = FilterIndex::new(store);
        let block_hash = Hash256::from_le_bytes(&[1_u8; 32]);
        let prev_header = Hash256::from_le_bytes(&[2_u8; 32]);
        let filter_bytes = vec![0xab_u8; 16];

        let _ = index.put_filter(block_hash, prev_header, &filter_bytes)?;

        assert_eq!(index.filter_count()?, 1);
        Ok(())
    }

    #[test]
    fn has_filter_returns_false_for_unindexed_hash() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, index) = filter_index()?;
        let block_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xee_u8; 32]);
        assert!(!index.has_filter(block_hash)?);
        Ok(())
    }

    #[test]
    fn has_filter_returns_true_after_put_filter() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, index) = filter_index()?;
        let block_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[1_u8; 32]);
        let prev_header = bitcoin_rs_primitives::Hash256::from_le_bytes(&[2_u8; 32]);
        let filter_bytes = vec![0xab_u8; 16];
        let _ = index.put_filter(block_hash, prev_header, &filter_bytes)?;
        assert!(index.has_filter(block_hash)?);
        Ok(())
    }

    #[test]
    fn iter_filters_returns_persisted_filters_in_storage_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let store = RocksDbStore::open(dir.path())?;
        let index = FilterIndex::new(store);
        let prev_header = Hash256::from_le_bytes(&[0_u8; 32]);
        let low_hash = Hash256::from_le_bytes(&[1_u8; 32]);
        let high_hash = Hash256::from_le_bytes(&[2_u8; 32]);

        index.put_filter(high_hash, prev_header, b"high")?;
        index.put_filter(low_hash, prev_header, b"low")?;

        assert_eq!(
            index.iter_filters()?,
            vec![(low_hash, b"low".to_vec()), (high_hash, b"high".to_vec()),]
        );
        Ok(())
    }
}
