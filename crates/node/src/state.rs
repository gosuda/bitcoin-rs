//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`Config`] and a
//! data-directory path, plus the replay log used by [`crate::crash_recovery`].
//! Subsystem wiring (chain / utxo / mempool / index / p2p / rpc / electrum)
//! is constructed by the binary at boot and parks here as the integration
//! point matures.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use parking_lot::Mutex;

use crate::Config;

/// Aggregate handle to a running node.
pub struct NodeState {
    config: Config,
    data_dir: PathBuf,
    replayed: Mutex<Vec<u32>>,
}

impl NodeState {
    /// Opens (or creates) the node's data directory and constructs the
    /// in-memory state. The configured storage backend is not yet bound at
    /// this layer; see [`crate::run::run`].
    pub fn open(config: Config) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let data_dir = config.data_dir.clone();
        Ok(Self {
            config,
            data_dir,
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
