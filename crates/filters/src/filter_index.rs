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
}
