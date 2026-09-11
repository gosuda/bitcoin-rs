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

/// Opens the selected chainstate backend exactly once and transfers its whole
/// ownership unit to `consumer`.
pub(crate) fn open_chainstate<C>(
    backend: StorageBackend,
    path: &Path,
    cache_bytes: Option<u64>,
    consumer: C,
) -> Result<C::Output, C::Error>
where
    C: StoreConsumer,
{
    open_generic("chainstate", backend, path, cache_bytes, consumer)
}

/// Opens a generic store view for custody-grade logical inspection. The redb
/// txindex keeps using its specialized runtime representation; this view is
/// read for the backend-neutral column-family ledger only.
pub(crate) fn open_store_inspection<C>(
    backend: StorageBackend,
    path: &Path,
    consumer: C,
) -> Result<C::Output, C::Error>
where
    C: StoreConsumer,
{
    open_generic("inspection", backend, path, None, consumer)
}

fn open_generic<C>(
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
    const RUNTIME_CONSUMERS: &[(&str, &str, Option<&str>)] = &[
        ("state.rs", include_str!("state.rs"), None),
        (
            "state/checkpoint.rs",
            include_str!("state/checkpoint.rs"),
            None,
        ),
        ("state/events.rs", include_str!("state/events.rs"), None),
        ("state/index.rs", include_str!("state/index.rs"), None),
        ("state/open.rs", include_str!("state/open.rs"), None),
        ("state/prune.rs", include_str!("state/prune.rs"), None),
        ("state/restore.rs", include_str!("state/restore.rs"), None),
        ("state/storage.rs", include_str!("state/storage.rs"), None),
        (
            "storage_footprint.rs",
            include_str!("storage_footprint.rs"),
            None,
        ),
        (
            "storage_footprint/budget.rs",
            include_str!("storage_footprint/budget.rs"),
            None,
        ),
        (
            "storage_footprint/identity.rs",
            include_str!("storage_footprint/identity.rs"),
            None,
        ),
        (
            "storage_footprint/scan.rs",
            include_str!("storage_footprint/scan.rs"),
            None,
        ),
        (
            "txindex_worker.rs",
            include_str!("txindex_worker.rs"),
            Some("mod body_reader_tests {"),
        ),
    ];

    const CONCRETE_OPEN_TOKENS: &[&str] = &[
        "RocksDbStore::open",
        "FjallStore::open",
        "RedbStore::open",
        "open_redb_tx_index_store",
    ];

    // ARCH-03 in docs/contracts/architecture.md makes storage_backend.rs the
    // sole owner of concrete backend construction. The consumers, test-module
    // boundaries, and forbidden constructor tokens scanned here are the
    // executable form of that architecture contract.
    #[test]
    fn runtime_backend_construction_has_one_owner() {
        for (name, source, test_module) in RUNTIME_CONSUMERS {
            let production = match test_module {
                Some(boundary) => {
                    let start = source
                        .find(boundary)
                        .unwrap_or_else(|| panic!("{name} lost its expected test-module boundary"));
                    &source[..start]
                }
                None => source,
            };
            for token in CONCRETE_OPEN_TOKENS {
                assert!(
                    !production.contains(token),
                    "{name} constructs a concrete backend with {token}; move it to storage_backend.rs"
                );
            }
        }
    }
}
