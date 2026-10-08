//! Runtime storage-backend composition.
//!
//! This module is the only node owner of concrete backend constructors. Each
//! namespace is opened here and handed immediately to a generic consumer that
//! constructs the narrow capability its caller needs. The visitor is not a
//! second storage facade: all reads, writes, batches, and durability remain
//! owned by [`bitcoin_rs_storage::KvStore`].

use std::path::Path;
use std::sync::Arc;

use bitcoin_rs_storage::{KvStore, StorageBackend, StorageError};

/// Consumes one freshly opened concrete store without exposing its type to the
/// runtime caller.
pub(crate) trait StoreConsumer {
    type Output;
    type Error: From<StorageError>;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output, Self::Error>
    where
        S: KvStore;
}

pub(crate) fn open_generic<C>(
    namespace: &str,
    backend: StorageBackend,
    path: &Path,
    cache_bytes: Option<u64>,
    consumer: C,
) -> Result<C::Output, C::Error>
where
    C: StoreConsumer,
{
    // The fallback arm below is the only reader; builds with every backend
    // feature compiled in cfg it away, so consume the label here.
    let _ = namespace;
    match backend {
        #[cfg(feature = "rocksdb")]
        StorageBackend::RocksDb => consumer.consume(Arc::new(match cache_bytes {
            Some(bytes) => bitcoin_rs_storage::RocksDbStore::open_with_cache(path, bytes)?,
            None => bitcoin_rs_storage::RocksDbStore::open(path)?,
        })),
        #[cfg(feature = "fjall")]
        StorageBackend::Fjall => consumer.consume(Arc::new(match cache_bytes {
            Some(bytes) => bitcoin_rs_storage::FjallStore::open_with_cache(path, bytes)?,
            None => bitcoin_rs_storage::FjallStore::open(path)?,
        })),
        #[cfg(feature = "redb")]
        StorageBackend::Redb => consumer.consume(Arc::new(match cache_bytes {
            Some(bytes) => bitcoin_rs_storage::RedbStore::open_with_cache(path, bytes)?,
            None => bitcoin_rs_storage::RedbStore::open(path)?,
        })),
        #[cfg(any(
            not(feature = "rocksdb"),
            not(feature = "fjall"),
            not(feature = "redb")
        ))]
        other => Err(unsupported(namespace, other).into()),
    }
}

/// Opens the selected transaction-index backend exactly once. The redb lane
/// deliberately retains its fixed-width specialized store.
pub(crate) fn open_txindex<C>(
    backend: StorageBackend,
    path: &Path,
    cache_bytes: Option<u64>,
    consumer: C,
) -> Result<C::Output, C::Error>
where
    C: StoreConsumer,
{
    match backend {
        #[cfg(feature = "redb")]
        StorageBackend::Redb => match cache_bytes {
            Some(bytes) => consumer.consume(Arc::new(
                bitcoin_rs_storage::open_redb_tx_index_store_with_cache(path, bytes)?,
            )),
            None => consumer.consume(Arc::new(bitcoin_rs_storage::open_redb_tx_index_store(
                path,
            )?)),
        },
        other => open_generic("txindex", other, path, cache_bytes, consumer),
    }
}

#[cfg(any(
    not(feature = "rocksdb"),
    not(feature = "fjall"),
    not(feature = "redb")
))]
fn unsupported(namespace: &str, backend: StorageBackend) -> StorageError {
    StorageError::Backend(format!(
        "unsupported storage backend for {namespace}: {backend}"
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Concrete open entry points that may appear only in this module. A call
    /// anywhere else bypasses the budgeted `open_with_cache` path and silently
    /// runs on the engine-default cache — the defect the cache-share test in
    /// `tests/state_storage.rs` cannot see because it measures only opens that
    /// already went through here.
    const CONCRETE_OPEN_TOKENS: &[&str] = &[
        "RocksDbStore::open",
        "FjallStore::open",
        "RedbStore::open",
        "open_redb_tx_index_store",
    ];

    /// Runtime crates whose stores must be composed through this module.
    /// Test-only files are skipped: unit and integration fixtures open
    /// concrete stores by design.
    #[test]
    fn runtime_backend_construction_has_one_owner() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for src in [
            crates.join("node/src"),
            crates.join("chainstate/src"),
            crates.join("index/src"),
        ] {
            assert_no_concrete_opens(&src);
        }
    }

    fn assert_no_concrete_opens(dir: &Path) {
        for entry in
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        {
            let path = entry
                .unwrap_or_else(|e| panic!("read {} entry: {e}", dir.display()))
                .path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) != Some("tests") {
                    assert_no_concrete_opens(&path);
                }
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "storage_backend.rs" || name == "tests.rs" || name.ends_with("_tests.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            for token in CONCRETE_OPEN_TOKENS {
                assert!(
                    !source.contains(token),
                    "{} constructs a concrete backend with {token}; move it to storage_backend.rs",
                    path.display()
                );
            }
        }
    }
}
