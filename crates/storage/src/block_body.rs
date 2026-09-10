//! Indexed authoritative block bodies, read sessions, and durability.

use bitcoin_rs_primitives::{Hash256, varint};

use crate::{
    BlockFilePosition, FlatFileBlockReader, FlatFileBlockStore, KvSnapshot, KvStore, StorageError,
    WriteBatch, block_file_max_height_key, decode_block_file_max_height,
    encode_block_file_max_height,
};

use std::sync::Arc;

const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;
const SERIALIZED_BLOCK_METADATA_PREFIX_LEN: usize = SERIALIZED_BLOCK_HEADER_LEN + 9;

/// Block payload facts available without materializing a full block body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    /// Serialized block byte length.
    pub body_size: usize,
    /// Number of transactions encoded in the block.
    pub tx_count: usize,
}

fn decode_block_tx_count(bytes: &[u8]) -> Option<usize> {
    let cursor = bytes.get(SERIALIZED_BLOCK_HEADER_LEN..)?;
    let (count, _) = varint::decode(cursor).ok()?;
    usize::try_from(count).ok()
}

/// A body-read session supporting batched position lookups.
pub trait BlockBodyReader {
    /// Prefetches body positions in the order that they will be loaded.
    ///
    /// Implementations must not prefetch body bytes.
    fn prefetch_positions(
        &mut self,
        requests: &[(u32, bitcoin_rs_primitives::Hash256)],
    ) -> Result<(), StorageError> {
        let _ = requests;
        Ok(())
    }

    /// Loads a complete body, or `None` when unavailable.
    fn load_block_body(
        &mut self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError>;
}

struct DirectBlockBodyReader<'a, S: BlockBodyStore + ?Sized> {
    store: &'a S,
}

impl<S: BlockBodyStore + ?Sized> BlockBodyReader for DirectBlockBodyReader<'_, S> {
    /// Loads a complete body, or `None` when unavailable.
    fn load_block_body(
        &mut self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.store.load_block_body(height, hash)
    }
}

/// Authoritative body bytes and the storage durability boundary.
pub trait BlockBodyStore: Send + Sync {
    /// Persists an exact block body.
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError>;

    /// Persists an owned body, allowing a backend to reuse its allocation.
    fn persist_block_body_value(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: bytes::Bytes,
    ) -> Result<(), StorageError> {
        self.persist_block_body(height, hash, &body)
    }

    /// Loads a complete body, or `None` when unavailable.
    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError>;
    /// Starts a body-read session.
    fn reader(&self) -> Result<Box<dyn BlockBodyReader + '_>, StorageError> {
        Ok(Box::new(DirectBlockBodyReader { store: self }))
    }

    /// The persisted undo record for `height`/`hash`, when this store can
    /// reach one.
    ///
    /// The default answers nothing: only stores backed by the chainstate
    /// key-value index hold undo rows, and a `ScriptLive`-selecting worker
    /// step fails closed on `None` rather than indexing without its spent-coin
    /// anchor (#225).
    fn undo_record(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let _ = (height, hash);
        Ok(None)
    }

    /// Loads `len` body bytes starting `offset` bytes into the serialized block.
    ///
    /// Defaults to `Ok(None)`, meaning "this store cannot slice"; callers fall
    /// back to [`Self::load_block_body`]. Never a short read.
    fn load_block_body_range(
        &self,
        _height: u32,
        _hash: bitcoin_rs_primitives::Hash256,
        _offset: u32,
        _len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    /// Reads encoded body size and transaction count.
    fn block_body_metadata(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<BlockBodyMetadata>, StorageError> {
        let Some(body) = self.load_block_body(height, hash)? else {
            return Ok(None);
        };
        let Some(tx_count) = decode_block_tx_count(&body) else {
            return Ok(None);
        };
        Ok(Some(BlockBodyMetadata {
              body_size: body.len(),
              tx_count,
          }))
    }

    /// Bytes this store's block files occupy on disk, when it keeps files.
    ///
    /// `None` from a store with nothing on disk to measure; the caller then
    /// falls back to the block-record sum.
    fn disk_usage(&self) -> Option<u64> {
        None
    }

    /// Makes body bytes durable before their checkpoint can be published.
    fn sync(&self) -> Result<(), StorageError>;
}

/// Flat-file bodies addressed by indexed, typed positions.
pub struct IndexedBlockBodyStore<S: KvStore> {
    index: Arc<S>,
    files: Arc<FlatFileBlockStore>,
}
enum PositionLookup {
    Direct,
    Prefetched {
        entries: Vec<(u32, Hash256, Option<BlockFilePosition>)>,
        next: usize,
    },
}

fn decode_body_position(
    height: u32,
    encoded: Option<&[u8]>,
) -> Result<Option<BlockFilePosition>, StorageError> {
    encoded
        .map(|bytes| {
            BlockFilePosition::decode(bytes).ok_or_else(|| {
                StorageError::IncompatibleData(format!(
                    "block-body index row for height {height} is not a 16-byte flat-file position"
                ))
            })
        })
        .transpose()
}

struct IndexedBlockBodyReader<'a> {
    index: Box<dyn KvSnapshot + 'a>,
    files: FlatFileBlockReader,
    positions: PositionLookup,
}

impl BlockBodyReader for IndexedBlockBodyReader<'_> {
    fn prefetch_positions(&mut self, requests: &[(u32, Hash256)]) -> Result<(), StorageError> {
        if let PositionLookup::Prefetched { entries, next } = &self.positions
            && *next != entries.len()
        {
            return Err(StorageError::InvalidOperation(
                "prefetched body positions were not fully consumed",
            ));
        }

        let keys: Vec<_> = requests
            .iter()
            .map(|&(height, hash)| crate::pruning::block_body_key(height, hash))
            .collect();
        let key_refs: Vec<_> = keys.iter().map(<[u8; 37]>::as_slice).collect();
        let values = self
            .index
            .get_many_sorted(crate::pruning::BLOCK_DATA_CF, &key_refs)?;
        if values.len() != requests.len() {
            return Err(StorageError::InvalidOperation(
                "snapshot batch returned the wrong number of values",
            ));
        }

        let entries = requests
            .iter()
            .copied()
            .zip(values)
            .map(|((height, hash), value)| {
                let position = decode_body_position(height, value.as_deref())?;
                Ok((height, hash, position))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        self.positions = PositionLookup::Prefetched { entries, next: 0 };
        Ok(())
    }

    /// Loads a complete body, or `None` when unavailable.
    fn load_block_body(
        &mut self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let position = match &mut self.positions {
            PositionLookup::Direct => {
                let key = crate::pruning::block_body_key(height, hash);
                let encoded = self.index.get(crate::pruning::BLOCK_DATA_CF, &key)?;
                decode_body_position(height, encoded.as_deref())?
            }
            PositionLookup::Prefetched { entries, next } => {
                let Some(&(expected_height, expected_hash, position)) = entries.get(*next) else {
                    return Err(StorageError::InvalidOperation(
                        "prefetched body positions are exhausted",
                    ));
                };
                if expected_height != height || expected_hash != hash {
                    return Err(StorageError::InvalidOperation(
                        "prefetched body position consumed out of order",
                    ));
                }
                *next += 1;
                position
            }
        };
        let Some(position) = position else {
            return Ok(None);
        };
        self.files.load(position, height, *hash.as_byte_array())
    }
}

impl<S: KvStore> IndexedBlockBodyStore<S> {
    /// Binds the position index to its authoritative block files.
    #[must_use]
    pub fn new(index: Arc<S>, files: Arc<FlatFileBlockStore>) -> Self {
        Self { index, files }
    }
    /// Resolves the flat-file position of a block body, or `None` when the
    /// block is unknown. An index row that is not a decodable 16-byte
    /// flat-file position is `IncompatibleData`, never a silent `None`: the
    /// row's presence means the body must exist, so treating a decode failure
    /// as absence would hide a schema mismatch behind a missing-block answer.
    ///
    /// Every read path starts here, so it is written once rather than three
    /// times: divergence between the whole-body, ranged, and metadata lookups
    /// would surface as one of them silently disagreeing about which blocks
    /// exist.
    fn body_position(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<BlockFilePosition>, StorageError> {
        let key = crate::pruning::block_body_key(height, hash);
        decode_body_position(
            height,
            self.index
                .get(crate::pruning::BLOCK_DATA_CF, &key)?
                .as_deref(),
        )
    }
}

impl<S: KvStore> BlockBodyStore for IndexedBlockBodyStore<S> {
    fn undo_record(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.index.get(
            crate::ColumnFamily::UndoData,
            &crate::pruning::block_undo_key(height, hash),
        )
    }

    fn disk_usage(&self) -> Option<u64> {
        Some(self.files.disk_usage())
    }

    /// Persists an exact block body.
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let key = crate::pruning::block_body_key(height, hash);
        let existing = decode_body_position(
            height,
            self.index
                .get(crate::pruning::BLOCK_DATA_CF, &key)?
                .as_deref(),
        )?;
        let position = self
            .files
            .persist(existing, height, *hash.as_byte_array(), body)?;
        if existing == Some(position) {
            return Ok(());
        }

        let max_height_key = block_file_max_height_key(position.file_no);
        let max_height = self
            .index
            .get(crate::pruning::BLOCK_DATA_CF, &max_height_key)?
            .as_deref()
            .and_then(decode_block_file_max_height)
            .map_or(height, |previous| previous.max(height));
        let mut batch = self.index.new_batch();
        batch.put(crate::pruning::BLOCK_DATA_CF, &key, &position.encode());
        batch.put(
            crate::pruning::BLOCK_DATA_CF,
            &max_height_key,
            &encode_block_file_max_height(max_height),
        );
        self.index.write_deferred(batch)
    }

    /// Starts a body-read session.
    fn reader(&self) -> Result<Box<dyn BlockBodyReader + '_>, StorageError> {
        Ok(Box::new(IndexedBlockBodyReader {
            index: self.index.snapshot()?,
            files: self.files.reader(),
            positions: PositionLookup::Direct,
        }))
    }

    /// Loads a complete body, or `None` when unavailable.
    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(position) = self.body_position(height, hash)? else {
            return Ok(None);
        };
        self.files.load(position, height, *hash.as_byte_array())
    }

    fn load_block_body_range(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        offset: u32,
        len: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let Some(position) = self.body_position(height, hash)? else {
            return Ok(None);
        };
        self.files
            .load_range(position, height, *hash.as_byte_array(), offset, len)
    }

    /// Reads encoded body size and transaction count.
    fn block_body_metadata(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<BlockBodyMetadata>, StorageError> {
        let Some(position) = self.body_position(height, hash)? else {
            return Ok(None);
        };
        let Some(prefix) = self.files.load_prefix(
            position,
            height,
            *hash.as_byte_array(),
            SERIALIZED_BLOCK_METADATA_PREFIX_LEN,
        )?
        else {
            return Ok(None);
        };
        let Some(tx_count) = decode_block_tx_count(&prefix) else {
            return Ok(None);
        };
        let body_size = usize::try_from(position.len)
            .map_err(|_| StorageError::InvalidOperation("block body length does not fit usize"))?;
        Ok(Some(BlockBodyMetadata {
              body_size,
              tx_count,
          }))
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.files.sync()?;
        self.index.flush()
    }
}

#[cfg(all(test, feature = "fjall"))]
mod body_position_prefetch_tests {
    use super::*;

    #[test]
    fn prefetched_positions_stream_bodies_in_exact_request_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(crate::FjallStore::open(temp.path().join("index"))?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = IndexedBlockBodyStore::new(index, files);
        let hash1 = Hash256::from_le_bytes(&[1_u8; 32]);
        let hash2 = Hash256::from_le_bytes(&[2_u8; 32]);
        store.persist_block_body(1, hash1, b"first body")?;
        store.persist_block_body(2, hash2, b"second body")?;

        let mut reader = store.reader()?;
        reader.prefetch_positions(&[(1, hash1), (2, hash2)])?;
        assert!(matches!(
            reader.load_block_body(2, hash2),
            Err(StorageError::InvalidOperation(
                "prefetched body position consumed out of order"
            ))
        ));
        assert_eq!(
            reader.load_block_body(1, hash1)?.as_deref(),
            Some(b"first body".as_slice())
        );
        assert_eq!(
            reader.load_block_body(2, hash2)?.as_deref(),
            Some(b"second body".as_slice())
        );
        assert!(matches!(
            reader.load_block_body(2, hash2),
            Err(StorageError::InvalidOperation(
                "prefetched body positions are exhausted"
            ))
        ));
        Ok(())
    }

    #[test]
    fn malformed_body_row_is_incompatible_not_missing() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(crate::FjallStore::open(temp.path().join("index"))?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = IndexedBlockBodyStore::new(index.clone(), files);
        let hash = Hash256::from_le_bytes(&[9_u8; 32]);
        store.persist_block_body(7, hash, b"body")?;
        // Overwrite the position row with a legacy inline body: same key, not
        // a decodable flat-file position.
        let key = crate::pruning::block_body_key(7, hash);
        let mut batch = index.new_batch();
        batch.put(crate::pruning::BLOCK_DATA_CF, &key, b"legacy-inline-body");
        index.write(batch)?;
        let Err(error) = store.load_block_body(7, hash) else {
            return Err("malformed body row must fail closed".into());
        };
        assert!(matches!(error, StorageError::IncompatibleData(_)));

        let mut reader = store.reader()?;
        let Err(error) = reader.load_block_body(7, hash) else {
            return Err("malformed body row must fail closed in the direct reader".into());
        };
        assert!(matches!(error, StorageError::IncompatibleData(_)));
        Ok(())
    }

    #[test]
    fn missing_prefetched_body_row_is_missing_not_incompatible()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(crate::FjallStore::open(temp.path().join("index"))?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = IndexedBlockBodyStore::new(index, files);
        let hash = Hash256::from_le_bytes(&[8_u8; 32]);
        let mut reader = store.reader()?;

        reader.prefetch_positions(&[(7, hash)])?;
        assert_eq!(reader.load_block_body(7, hash)?, None);
        Ok(())
    }

    #[test]
    fn malformed_prefetched_body_row_is_incompatible_not_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let index = Arc::new(crate::FjallStore::open(temp.path().join("index"))?);
        let files = Arc::new(FlatFileBlockStore::open(temp.path())?);
        let store = IndexedBlockBodyStore::new(index.clone(), files);
        let hash = Hash256::from_le_bytes(&[7_u8; 32]);
        let key = crate::pruning::block_body_key(7, hash);
        let mut batch = index.new_batch();
        batch.put(crate::pruning::BLOCK_DATA_CF, &key, b"legacy-inline-body");
        index.write(batch)?;

        let mut reader = store.reader()?;
        let Err(error) = reader.prefetch_positions(&[(7, hash)]) else {
            return Err("malformed prefetched body row must fail closed".into());
        };
        assert!(matches!(error, StorageError::IncompatibleData(_)));
        Ok(())
    }
}
#[cfg(test)]
mod metadata_tests {
    use super::*;
    use bitcoin_rs_primitives::Network;
    use bitcoin_rs_primitives::consensus_bytes;
    #[test]
    fn decode_block_tx_count_reads_the_varint_after_the_header() {
        let block = Network::Regtest.genesis_block();
        let bytes = consensus_bytes(&block);
        assert_eq!(decode_block_tx_count(&bytes), Some(block.txs.len()));
        assert_eq!(
            decode_block_tx_count(&bytes[..SERIALIZED_BLOCK_HEADER_LEN]),
            None
        );
    }
}
