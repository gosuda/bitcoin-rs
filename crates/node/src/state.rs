//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`Config`], the
//! data-directory path, the open chainstate storage backend, and the replay log
//! used by [`crate::crash_recovery`]. Subsystem wiring (chain / utxo / mempool
//! / index / p2p / rpc / electrum) parks here as the integration point matures.

use core::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::{Mutex, RwLock};

use crate::Config;

enum NodeStorage {
    #[cfg(feature = "rocksdb")]
    RocksDb(bitcoin_rs_storage::RocksDbStore),
    #[cfg(feature = "fjall")]
    Fjall(bitcoin_rs_storage::FjallStore),
    #[cfg(feature = "redb")]
    Redb(bitcoin_rs_storage::RedbStore),
    #[cfg(feature = "mdbx")]
    Mdbx(bitcoin_rs_storage::MdbxStore),
}

impl NodeStorage {
    fn open(config: &Config) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Ok(Self::RocksDb(
                bitcoin_rs_storage::RocksDbStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "fjall")]
            "fjall" => Ok(Self::Fjall(
                bitcoin_rs_storage::FjallStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "redb")]
            "redb" => Ok(Self::Redb(
                bitcoin_rs_storage::RedbStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "mdbx")]
            "mdbx" => Ok(Self::Mdbx(
                bitcoin_rs_storage::MdbxStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            )),
            other => bail!(
                "unsupported storage backend: {other} (compiled features = {CompiledStorageFeatures})"
            ),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                let _ = store;
                "rocksdb"
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => {
                let _ = store;
                "fjall"
            }
            #[cfg(feature = "redb")]
            Self::Redb(store) => {
                let _ = store;
                "redb"
            }
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => {
                let _ = store;
                "mdbx"
            }
        }
    }
}

const COMPILED_STORAGE_FEATURES: &[&str] = &[
    #[cfg(feature = "rocksdb")]
    "rocksdb",
    #[cfg(feature = "fjall")]
    "fjall",
    #[cfg(feature = "redb")]
    "redb",
    #[cfg(feature = "mdbx")]
    "mdbx",
];

struct CompiledStorageFeatures;

impl fmt::Display for CompiledStorageFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((first, rest)) = COMPILED_STORAGE_FEATURES.split_first() else {
            return f.write_str("none");
        };

        f.write_str(first)?;
        for feature in rest {
            f.write_str(",")?;
            f.write_str(feature)?;
        }
        Ok(())
    }
}

/// Aggregate handle to a running node.
pub struct NodeState {
    config: Config,
    data_dir: PathBuf,
    storage: NodeStorage,
    utxo: Arc<UtxoSet>,
    mempool: Arc<RwLock<Mempool>>,
    replayed: Mutex<Vec<u32>>,
}

impl NodeState {
    /// Opens (or creates) the node's data directory and configured storage
    /// backend.
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn open(config: Config) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let storage = NodeStorage::open(&config)?;
        let utxo = Arc::new(UtxoSet::new());
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        tracing::info!(
            backend = storage.kind(),
            chainstate_dir = %config.data_dir.join("chainstate").display(),
            "opened storage backend"
        );
        let data_dir = config.data_dir.clone();
        Ok(Self {
            config,
            data_dir,
            storage,
            utxo,
            mempool,
            replayed: Mutex::new(Vec::new()),
        })
    }

    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the configured storage backend that was opened.
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        self.storage.kind()
    }

    /// Returns the shared UTXO set handle.
    #[must_use]
    pub fn utxo(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Returns the shared mempool handle.
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(&self.mempool)
    }

    /// Heights walked by the most recent crash-recovery replay.
    #[must_use]
    pub fn replayed_heights(&self) -> Vec<u32> {
        self.replayed.lock().clone()
    }

    /// Records a height in the in-memory replay log.
    pub(crate) fn push_replayed(&self, height: u32) {
        self.replayed.lock().push(height);
    }

    /// Test helper: writes the recovery metadata as if a block at `height`
    /// had just been fully committed. Real block commits flow through the
    /// `crates/utxo` listener; this helper exists so crash-recovery tests
    /// can simulate a chain without bringing up the full subsystem stack.
    pub fn record_synthetic_block_for_recovery(&self, height: u32) -> Result<()> {
        let meta = crate::crash_recovery::Meta {
            height,
            last_committed_height: height,
        };
        crate::crash_recovery::write_meta(self, &meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_constructs_empty_handles() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
        let utxo = state.utxo();
        let mempool = state.mempool();

        assert!(
            Arc::strong_count(&utxo) >= 2,
            "caller and NodeState should both hold a strong ref"
        );
        assert!(Arc::strong_count(&mempool) >= 2);
        assert_eq!(mempool.read().len(), 0, "fresh mempool must be empty");

        Ok(())
    }
}
