//! Typed, in-process embedding surface over the node lifecycle.
//!
//! Startup returns a fully owned node from `lifecycle::startup`; this module
//! does not assemble detached state, workers, and RPC context a second time.
//!
//! The async methods defer the node's synchronous work until polled. They do
//! not create an executor or make blocking storage and lifecycle work async.
//! Embedders control placement of that work on their own runtime.

mod progress;

use bitcoin_rs_mempool::{FeeRate, MempoolStats, MutationResult};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Network, Tx, Txid, deserialize};
use bitcoin_rs_rpc::capabilities::CapabilitySnapshot;
use std::sync::Arc;
use thiserror::Error;

use crate::lifecycle::services::{DRAIN_DEADLINE, NodeServices, TeardownMode};
use crate::lifecycle::startup::start_node;
use crate::state::{ChainSnapshot, NodeState};

/// Failure at the typed node boundary.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Configuration, storage, or service startup failed.
    #[error("node startup failed: {0}")]
    Startup(String),
    /// The orderly shutdown path failed.
    #[error("node shutdown failed: {0}")]
    Shutdown(String),
    /// A requested capability is disabled or cannot answer yet.
    #[error("node capability unavailable: {0}")]
    Unavailable(String),
    /// A requested object is completely absent.
    #[error("node object not found: {0}")]
    NotFound(String),
    /// Mempool admission rejected the broadcast transaction.
    #[error("transaction broadcast failed: {0}")]
    Broadcast(String),
}

/// Typed synchronization progress behind `getblockchaininfo`.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncProgress {
    /// Consensus network the node follows.
    pub network: Network,
    /// Blocks fully applied to chainstate.
    pub blocks: u32,
    /// Validated headers known to the node (may lead `blocks` during sync).
    pub headers: u32,
    /// Hash of the best fully applied block.
    pub best_block_hash: Hash256,
    /// Difficulty at the applied tip (Core `GetDifficulty`).
    pub difficulty: f64,
    /// Applied tip header timestamp, UNIX seconds.
    pub time: u64,
    /// Median time past of the last eleven applied blocks.
    pub median_time: u64,
    /// Core `GuessVerificationProgress` in the inclusive range `[0, 1]`.
    pub verification_progress: f64,
    /// Whether the node is still in initial block download.
    pub initial_block_download: bool,
    /// Applied chain work, big-endian hex (`"00"` before the first tip).
    pub chain_work: String,
    /// Bytes the block store occupies on disk.
    pub size_on_disk: u64,
    /// Whether pruning is enabled.
    pub pruned: bool,
    /// Prune floor height, present only on a pruned node.
    pub prune_height: Option<u32>,
}

/// A running node owning its state, service graph, and RPC context.
///
/// Explicit shutdown consumes the node and reports failures. Drop stops an
/// abandoned run through the same lifecycle without a clean-run checkpoint.
pub struct Node {
    pub(crate) state: NodeState,
    pub(crate) services: Option<NodeServices>,
    pub(crate) context: Arc<bitcoin_rs_rpc::context::Context>,
}

impl Node {
    /// Starts an owned node after configuration validation and crash recovery.
    ///
    /// The method drives synchronous node workers on the caller's task. It
    /// neither installs process signal handlers nor creates an executor.
    #[allow(clippy::unused_async)]
    pub async fn start(
        config: crate::NodeConfig,
        runtime: crate::RuntimeInputs,
    ) -> Result<Self, NodeError> {
        start_node(config, runtime, false).map_err(|error| NodeError::Startup(error.to_string()))
    }

    /// Returns the current coherent, generation-stamped chain snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        self.state.active_chain_snapshot()
    }

    /// Returns the live txindex capability report.
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySnapshot {
        bitcoin_rs_rpc::capabilities::txindex_snapshot(Some(self.state.txindex_status().as_ref()))
    }

    /// Returns a decoded block, distinguishing unknown from unavailable data.
    #[allow(clippy::unused_async)]
    pub async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, NodeError> {
        let hash = Hash256::from(hash);
        let Some(record) = self.context.block_by_hash(hash) else {
            return Ok(None);
        };
        let Some(bytes) = self.context.block_body_bytes(&record) else {
            return Err(NodeError::Unavailable(format!(
                "block body pruned for {hash}"
            )));
        };
        let block = deserialize::<Block>(&bytes).map_err(|error| {
            NodeError::Unavailable(format!("block body decode failed: {error}"))
        })?;
        if block.block_hash() != record.hash {
            return Err(NodeError::Unavailable(format!(
                "block body identity mismatch for {hash}"
            )));
        }
        Ok(Some(block))
    }

    /// Resolves a transaction through the mempool, cache, then confirmed index.
    ///
    /// A disabled or unhealthy confirmed index is unavailable, not an answer
    /// that the transaction does not exist. A complete negative lookup is
    /// `NodeError::NotFound`.
    #[allow(clippy::unused_async)]
    pub async fn tx_by_id(&self, txid: Txid) -> Result<Tx, NodeError> {
        let pooled = self.state.mempool().read().transaction_by_txid(&txid);
        if let Some(tx) = pooled {
            return Ok((*tx).clone());
        }
        let cached = self.context.transactions.read().get(&txid).cloned();
        if let Some(tx) = cached {
            return Ok(tx);
        }
        let Some(query) = self.state.esplora_tx_index_query() else {
            return Err(NodeError::Unavailable(
                "confirmed transaction lookup requires txindex or scriptindex".to_owned(),
            ));
        };
        match query.transaction(&txid) {
            Ok(Some(tx)) => Ok(tx),
            Ok(None) => Err(NodeError::NotFound(format!("transaction {txid}"))),
            Err(error) => Err(NodeError::Unavailable(error.to_string())),
        }
    }

    /// Returns aggregate mempool information from one read snapshot.
    #[must_use]
    pub fn mempool_info(&self) -> MempoolStats {
        self.state.mempool().read().stats()
    }

    /// Returns a history-based fee estimate, or `None` with insufficient history.
    #[must_use]
    pub fn fee_estimate(&self, confirmation_target_blocks: u32) -> Option<FeeRate> {
        self.state
            .mempool()
            .read()
            .estimate_fee_rate(confirmation_target_blocks)
    }

    /// Admits a transaction through the same typed operation as RPC submission.
    ///
    /// Policy checks and ordered publication belong to the shared gateway;
    /// embedding does not insert directly into the pool or own another gateway.
    #[allow(clippy::unused_async)]
    pub async fn broadcast(&self, tx: Tx) -> Result<MutationResult, NodeError> {
        let max_feerate = Some(bitcoin_rs_rpc::context::DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB);
        self.context
            .admit_transaction(tx, max_feerate)
            .map_err(NodeError::Broadcast)
    }

    /// Stops owned services, then publishes the clean-shutdown checkpoint.
    #[allow(clippy::unused_async)]
    pub async fn shutdown(self) -> Result<(), NodeError> {
        self.shutdown_blocking()
    }

    pub(crate) fn shutdown_blocking(mut self) -> Result<(), NodeError> {
        // Explicit shutdown must release index stores, not abandon their
        // workers at the bounded Drop deadline.
        let Some(services) = self.services.as_mut() else {
            return Err(NodeError::Shutdown("node was already shut down".to_owned()));
        };
        let result = services
            .teardown(Some(&self.state), TeardownMode::CleanShutdown)
            .map_err(|error| NodeError::Shutdown(error.to_string()));
        self.services = None;
        // Dropping self releases state and the RPC context's storage clones
        // before this consuming operation returns, including on error.
        result
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(services) = self.services.as_mut() {
            self.state.bounded_index_shutdown(DRAIN_DEADLINE);
            if let Err(error) = services.teardown(Some(&self.state), TeardownMode::StartupAbort) {
                tracing::warn!(%error, "dropped embedded node; teardown reported an error");
            }
            self.services = None;
        }
    }
}

#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests;
