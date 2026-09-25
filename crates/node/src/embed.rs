//! Typed, in-process embedding surface over the node lifecycle.
//!
//! Startup returns a fully owned node from `lifecycle`; this module
//! does not assemble detached state, workers, and RPC context a second time.
//!
//! The async methods defer the node's synchronous work until polled. They do
//! not create an executor or make blocking storage and lifecycle work async.
//! Embedders control placement of that work on their own runtime.

use bitcoin_rs_mempool::{FeeRate, MempoolStats, MutationResult};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Tx, Txid, deserialize};
use bitcoin_rs_rpc::capabilities::CapabilitySnapshot;
pub use bitcoin_rs_rpc::context::SyncProgress;
use std::sync::Arc;
use thiserror::Error;

use crate::lifecycle::{DRAIN_DEADLINE, NodeServices, TeardownMode, start_node};
use crate::state::NodeState;
use bitcoin_rs_chainstate::events::ChainSnapshot;

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

/// A running node owning its state, service graph, and RPC context.
///
/// Explicit shutdown consumes the node and reports failures. Drop stops an
/// abandoned run through the same lifecycle without a clean-run checkpoint.
pub struct Node {
    pub(crate) state: NodeState,
    pub(crate) services: Option<NodeServices>,
    pub(crate) context: Arc<bitcoin_rs_rpc::context::Context>,
}

// Keep these async methods compatible with supported Clippy versions.
#[allow(
    unknown_lints,
    clippy::unused_async_trait_impl,
    reason = "the method bodies run when the futures are polled"
)]
impl Node {
    /// Starts an owned node after configuration validation and crash recovery.
    ///
    /// The method drives synchronous node workers on the caller's task. It
    /// neither installs process signal handlers nor creates an executor.
    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]
    pub async fn start(
        config: crate::NodeConfig,
        runtime: crate::RuntimeInputs,
    ) -> Result<Self, NodeError> {
        start_node(config, runtime, false).map_err(|error| NodeError::Startup(error.to_string()))
    }

    /// Returns the current coherent, generation-stamped chain snapshot.
    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        self.state.chainstate().chain_snapshot()
    }

    /// Returns the live txindex capability report.
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySnapshot {
        bitcoin_rs_rpc::capabilities::txindex_snapshot(Some(
            self.state.derived_index_status().as_ref(),
        ))
    }

    /// Returns typed synchronization progress without touching RPC JSON.
    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        self.context.chain.sync_progress()
    }

    /// Returns a decoded block, distinguishing unknown from unavailable data.
    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]
    pub async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, NodeError> {
        let hash = Hash256::from(hash);
        let Some(record) = self.context.chain.block_by_hash(hash) else {
            return Ok(None);
        };
        let Some(bytes) = self.context.chain.block_body_bytes(&record) else {
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
    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]
    pub async fn tx_by_id(&self, txid: Txid) -> Result<Tx, NodeError> {
        let pooled = self.state.mempool().read().transaction_by_txid(&txid);
        if let Some(tx) = pooled {
            return Ok((*tx).clone());
        }
        let cached = self.context.chain.transactions.read().get(&txid).cloned();
        if let Some(tx) = cached {
            return Ok(tx);
        }
        let Some(query) = self.state.esplora_derived_index_query() else {
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
    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]
    pub async fn broadcast(&self, tx: Tx) -> Result<MutationResult, NodeError> {
        let max_feerate = Some(bitcoin_rs_rpc::context::DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB);
        self.context
            .admit_transaction(tx, max_feerate)
            .map_err(NodeError::Broadcast)
    }

    /// Stops owned services, then publishes the clean-shutdown checkpoint.
    #[allow(
        unknown_lints,
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
    )]
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
mod tests {
    #![allow(clippy::expect_used)]

    use std::future::Future;

    use super::*;
    use crate::NodeConfig;
    use bitcoin_rs_mempool::{MempoolEntry, MempoolObserver};
    use bitcoin_rs_primitives::{
        Amount, LockTime, Network, OutPoint, Script, Sequence, TxIn, TxOut, Witness,
    };
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use parking_lot::Mutex;

    use bitcoin_rs_rpc::zmq::MempoolSequenceObserver;
    use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

    /// Polls synchronous node futures without adding an executor dependency.
    fn block_on<F: Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let mut future = std::pin::pin!(future);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Default)]
    struct RecordingSequencePublisher {
        sequence_events: Mutex<Vec<SequenceEvent>>,
    }

    impl core::fmt::Debug for RecordingSequencePublisher {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("RecordingSequencePublisher")
        }
    }

    impl ZmqPublisher for RecordingSequencePublisher {
        fn wants_notifications(&self) -> bool {
            true
        }

        fn wants_rawtx(&self) -> bool {
            false
        }

        fn wants_rawblock(&self) -> bool {
            false
        }

        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {}

        fn publish_rawtx(&self, _bytes: &[u8]) {}

        fn publish_sequence(&self, event: SequenceEvent) {
            self.sequence_events.lock().push(event);
        }
    }

    fn embedded_config(data_dir: &std::path::Path) -> NodeConfig {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = data_dir.to_path_buf();
        config.p2p.listen.clear();
        config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        config.observability.metrics_bind = None;
        config
    }

    /// `P2WSH(OP_TRUE)`, spendable without fixture signature material.
    fn spendable_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&[
            0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00,
            0x09, 0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b,
            0x8c, 0xc3, 0x32, 0x60,
        ]);
        script
    }

    fn spending_tx(previous_output: OutPoint) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::from_consensus(0),
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0xffff_ffff),
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(92_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            }],
        }
    }

    #[test]
    // CONTRACT: docs/contracts/architecture.md#ARCH-05
    fn broadcast_publishes_one_ordered_a_event_through_the_shared_gateway() {
        let dir = tempfile::tempdir().expect("tempdir");
        let publisher = Arc::new(RecordingSequencePublisher::default());
        let recording: Arc<dyn bitcoin_rs_rpc::zmq::ZmqPublisher> = publisher.clone();
        let observer: Arc<dyn MempoolObserver> = Arc::new(MempoolSequenceObserver::new(recording));
        let config = embedded_config(&dir.path().join("node"));

        let node = block_on(Node::start(
            config,
            crate::RuntimeInputs::default().with_mempool_observer(observer),
        ))
        .expect("embedded node starts");

        let broadcast_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5A; 32])), 0);
        let direct_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5B; 32])), 0);
        let mut changes = BlockChanges::default();
        for prevout in [broadcast_prevout, direct_prevout] {
            changes.add(UtxoAdd::new(
                prevout,
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: Script::from_bytes(spendable_script()),
                },
                false,
                1,
            ));
        }
        node.state
            .chainstate()
            .utxo_handle()
            .commit_block(&changes, &Hash256::from_le_bytes(&[0xAB; 32]))
            .map_err(|error| format!("fixture utxo commit failed: {error}"))
            .expect("fixture utxo commit");

        let broadcast_tx = spending_tx(broadcast_prevout);
        let broadcast_txid = broadcast_tx.txid();
        let result = block_on(node.broadcast(broadcast_tx)).expect("broadcast accepted");
        assert_eq!(result.len(), 1, "one admission commits one change");
        assert_eq!(
            result.changes[0].txid,
            Hash256::from(broadcast_txid),
            "the committed change is the broadcast transaction"
        );
        let sequence = result.sequence_of(0).expect("sequence of the change");

        let events = publisher.sequence_events.lock();
        assert_eq!(
            *events,
            vec![SequenceEvent::Added(broadcast_txid, sequence)],
            "Node::broadcast must publish exactly one ordered A event through the shared gateway"
        );
        drop(events);
        publisher.sequence_events.lock().clear();

        // Control: direct insertion cannot satisfy the gateway-publication test.
        let direct_tx = spending_tx(direct_prevout);
        let vsize = u32::try_from(direct_tx.vsize()).unwrap_or(u32::MAX);
        let entry = MempoolEntry::new(Arc::new(direct_tx), vsize, 8_000, 0, 1);
        node.state
            .mempool()
            .write()
            .insert_entry(entry)
            .expect("direct pool insert fixture");
        assert!(
            publisher.sequence_events.lock().is_empty(),
            "a direct pool insertion must not satisfy the gateway publication assertion"
        );

        block_on(node.shutdown()).expect("clean shutdown");
    }
}
