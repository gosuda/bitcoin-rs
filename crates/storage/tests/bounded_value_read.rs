//! Bounded reads preserve operator data and refuse unsupported fallbacks.

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{BoundedReadError, ColumnFamily, KvStore, KvUndoStore, UndoStore};
use std::sync::Arc;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb"))]
fn check_store(store: impl KvStore) -> Result {
    let store = Arc::new(store);
    store.put(ColumnFamily::UndoData, b"row", b"abcd")?;
    assert!(matches!(
        store.get_bounded(ColumnFamily::UndoData, b"row", 3),
        Err(BoundedReadError::Limit { size: 4, limit: 3 })
    ));
    assert_eq!(
        store.get_bounded(ColumnFamily::UndoData, b"row", 4)?,
        Some(b"abcd".to_vec())
    );
    assert_eq!(
        store.get_bounded(ColumnFamily::UndoData, b"absent", 0)?,
        None
    );
    store.put(ColumnFamily::UndoData, b"empty", b"")?;
    assert_eq!(
        store.get_bounded(ColumnFamily::UndoData, b"empty", 0)?,
        Some(Vec::new())
    );
    let undo = KvUndoStore::new(Arc::clone(&store));
    let hash = Hash256::from_le_bytes(&[7; 32]);
    undo.persist_undo(12, hash, b"undo")?;
    assert!(matches!(
        undo.load_undo_bounded(12, hash, 3),
        Err(BoundedReadError::Limit { .. })
    ));
    assert_eq!(undo.load_undo_bounded(12, hash, 4)?, Some(b"undo".to_vec()));
    assert_eq!(undo.load_undo(12, hash)?, Some(b"undo".to_vec()));
    Ok(())
}

#[cfg(feature = "fjall")]
#[test]
fn fjall_checks_borrowed_length_before_owned_copy() -> Result {
    let dir = tempfile::tempdir()?;
    check_store(bitcoin_rs_storage::FjallStore::open(dir.path())?)
}
#[cfg(feature = "redb")]
#[test]
fn redb_checks_guard_length_before_owned_copy() -> Result {
    let dir = tempfile::tempdir()?;
    check_store(bitcoin_rs_storage::RedbStore::open(dir.path())?)
}
#[cfg(feature = "rocksdb")]
#[test]
fn rocksdb_checks_pinned_length_before_owned_copy() -> Result {
    let dir = tempfile::tempdir()?;
    check_store(bitcoin_rs_storage::RocksDbStore::open(dir.path())?)
}

#[test]
fn memory_undo_checks_length_and_preserves_record() -> Result {
    let undo = bitcoin_rs_storage::InMemoryUndoStore::default();
    let hash = Hash256::from_le_bytes(&[8; 32]);
    undo.persist_undo(1, hash, b"record")?;
    assert!(matches!(
        undo.load_undo_bounded(1, hash, 5),
        Err(BoundedReadError::Limit { size: 6, limit: 5 })
    ));
    assert_eq!(
        undo.load_undo_bounded(1, hash, 6)?,
        Some(b"record".to_vec())
    );
    assert_eq!(undo.load_undo(1, hash)?, Some(b"record".to_vec()));
    Ok(())
}

struct Unsupported;
impl KvStore for Unsupported {
    fn get(
        &self,
        _: ColumnFamily,
        _: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        panic!("bounded default must never invoke unbounded get")
    }
    fn iter_prefix<'a>(
        &'a self,
        _: ColumnFamily,
        _: &[u8],
    ) -> std::result::Result<bitcoin_rs_storage::KvIter<'a>, bitcoin_rs_storage::StorageError> {
        panic!("unused")
    }
    fn new_batch(&self) -> bitcoin_rs_storage::BufferedWriteBatch {
        panic!("unused")
    }
    fn write(
        &self,
        _: bitcoin_rs_storage::BufferedWriteBatch,
    ) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
        panic!("unused")
    }
    fn write_durable_if(
        &self,
        _: &[bitcoin_rs_storage::WriteCondition<'_>],
        _: bitcoin_rs_storage::BufferedWriteBatch,
    ) -> std::result::Result<bool, bitcoin_rs_storage::StorageError> {
        panic!("unused")
    }
    fn flush(&self) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
        panic!("unused")
    }
    fn snapshot(
        &self,
    ) -> std::result::Result<
        Box<dyn bitcoin_rs_storage::KvSnapshot + '_>,
        bitcoin_rs_storage::StorageError,
    > {
        panic!("unused")
    }
    #[cfg(feature = "test-seam")]
    fn arm_persist_fault(&self, _: bitcoin_rs_storage::PersistFault) {
        panic!("unused")
    }
}

#[test]
fn unsupported_bounded_read_never_uses_unbounded_fallback() {
    assert!(matches!(
        Unsupported.get_bounded(ColumnFamily::UndoData, b"row", 4),
        Err(BoundedReadError::Unsupported)
    ));
    assert!(matches!(
        KvUndoStore::new(Arc::new(Unsupported)).load_undo_bounded(1, Hash256::default(), 4),
        Err(BoundedReadError::Unsupported)
    ));
}

struct UnsupportedBody;
impl bitcoin_rs_storage::block_body::BlockBodyStore for UnsupportedBody {
    fn persist_block_body(
        &self,
        _: u32,
        _: Hash256,
        _: &[u8],
    ) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
        panic!("unused")
    }
    fn load_block_body(
        &self,
        _: u32,
        _: Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        panic!("bounded body default must not load metadata or a full body")
    }
    fn sync(&self) -> std::result::Result<(), bitcoin_rs_storage::StorageError> {
        panic!("unused")
    }
}

#[test]
fn unsupported_body_read_never_materializes_metadata_or_body() {
    use bitcoin_rs_storage::block_body::BlockBodyStore as _;
    assert!(matches!(
        UnsupportedBody.load_block_body_bounded(1, Hash256::default(), 4),
        Err(BoundedReadError::Unsupported)
    ));
}

#[cfg(feature = "fjall")]
#[test]
fn indexed_body_checks_locator_and_frame_length_before_copy() -> Result {
    use bitcoin_rs_storage::block_body::{BlockBodyStore as _, IndexedBlockBodyStore};
    let dir = tempfile::tempdir()?;
    let index = Arc::new(bitcoin_rs_storage::FjallStore::open(
        dir.path().join("index"),
    )?);
    let files = Arc::new(bitcoin_rs_storage::FlatFileBlockStore::open(
        dir.path().join("bodies"),
    )?);
    let store = IndexedBlockBodyStore::new(Arc::clone(&index), files);
    let hash = Hash256::from_le_bytes(&[9; 32]);
    store.persist_block_body(1, hash, b"body")?;
    assert!(matches!(
        store.load_block_body_bounded(1, hash, 3),
        Err(BoundedReadError::Limit { size: 4, limit: 3 })
    ));
    assert_eq!(
        store.load_block_body_bounded(1, hash, 4)?,
        Some(b"body".to_vec())
    );
    let key = bitcoin_rs_storage::pruning::block_body_key(1, hash);
    index.put(bitcoin_rs_storage::pruning::BLOCK_DATA_CF, &key, &[0; 17])?;
    assert!(matches!(
        store.load_block_body_bounded(1, hash, 4),
        Err(BoundedReadError::Limit {
            size: 17,
            limit: 16
        })
    ));
    Ok(())
}
