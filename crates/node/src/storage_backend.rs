use std::path::Path;
use std::sync::Arc;

use bitcoin_rs_storage::{KvStore, StorageBackend, StorageError, StoreGuard};

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
    guard: &StoreGuard,
    consumer: C,
) -> Result<C::Output, C::Error>
where
    C: StoreConsumer,
{
    if let Some(found) = bitcoin_rs_storage::detect_engine(path)? {
        if found != backend {
            return Err(StorageError::Backend(format!(
                "{namespace} was created by {found}; start with --storage-backend {found} or convert with bitcoin-rs-storage-convert"
            ))
            .into());
        }
    }

    match backend {
        StorageBackend::RocksDb => {
            let cache_bytes =
                cache_bytes.unwrap_or(bitcoin_rs_storage::ROCKSDB_DEFAULT_CACHE_BYTES);
            consumer.consume(Arc::new(
                bitcoin_rs_storage::RocksDbStore::open_with_cache(path, cache_bytes)?
                    .guarded_by(Arc::clone(guard)),
            ))
        }
        #[cfg(feature = "surrealkv")]
        StorageBackend::SurrealKv => {
            let cache_bytes = cache_bytes.unwrap_or(0);
            consumer.consume(Arc::new(
                bitcoin_rs_storage::SurrealKvStore::open_with_cache(path, cache_bytes)?
                    .guarded_by(Arc::clone(guard)),
            ))
        }
        #[cfg(not(feature = "surrealkv"))]
        StorageBackend::SurrealKv => Err(unsupported(namespace, StorageBackend::SurrealKv).into()),
        #[cfg(feature = "mdbx")]
        StorageBackend::Mdbx => {
            let cache_bytes = cache_bytes.unwrap_or(0);
            consumer.consume(Arc::new(
                bitcoin_rs_storage::MdbxStore::open_with_cache(path, cache_bytes)?
                    .guarded_by(Arc::clone(guard)),
            ))
        }
        #[cfg(not(feature = "mdbx"))]
        StorageBackend::Mdbx => Err(unsupported(namespace, StorageBackend::Mdbx).into()),
    }
}

pub(crate) fn open_txindex<C>(
    backend: StorageBackend,
    path: &Path,
    cache_bytes: Option<u64>,
    guard: &StoreGuard,
    consumer: C,
) -> Result<C::Output, C::Error>
where
    C: StoreConsumer,
{
    open_generic("txindex", backend, path, cache_bytes, guard, consumer)
}

#[cfg(any(not(feature = "surrealkv"), not(feature = "mdbx")))]
fn unsupported(namespace: &str, backend: StorageBackend) -> StorageError {
    StorageError::Backend(format!(
        "unsupported storage backend for {namespace}: {backend}"
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    const CONCRETE_OPEN_TOKENS: &[&str] = &[
        "RocksDbStore::open",
        "SurrealKvStore::open",
        "MdbxStore::open",
    ];

    #[test]
    fn runtime_backend_construction_has_one_owner() {
        let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for src in [
            crates.join("node/src"),
            crates.join("execution/src"),
            crates.join("projection/src"),
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
