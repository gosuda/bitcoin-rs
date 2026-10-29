use bitcoin_rs_index::CapabilitySnapshot;
use bitcoin_rs_index::IndexCapability;
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_index::query_api::{
    AtPrefix, HistoricalQueryError, HistoricalUnavailableCause, ScriptIndexSnapshot,
    SpendingRecord, TxUnavailableCause,
};
use bitcoin_rs_mempool::{FeeRate, LocalOrigin, MempoolStats, MutationResult};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, OutPoint, Tx, Txid, deserialize, unix_time_secs,
};
pub(crate) use bitcoin_rs_rpc::context::SyncProgress;
use bitcoin_rs_rpc::context::{ChainAdmissionView, DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB};
use std::sync::Arc;
use thiserror::Error;

use crate::lifecycle::{NodeServices, TeardownMode, start_node};
use crate::state::NodeState;
use bitcoin_rs_chainstate::events::ChainSnapshot;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("node startup failed: {0}")]
    Startup(String),
    #[error("node shutdown failed: {0}")]
    Shutdown(String),
    #[error("node capability unavailable: {0}")]
    Unavailable(String),
    #[error("node object not found: {0}")]
    NotFound(String),
    #[error("transaction broadcast failed: {0}")]
    Broadcast(String),
    #[error("snapshot activation failed: {0}")]
    Snapshot(String),
}

pub struct Node {
    pub(crate) state: NodeState,
    pub(crate) services: Option<NodeServices>,
    pub(crate) context: Arc<bitcoin_rs_rpc::context::Context>,
}

#[allow(
    unknown_lints,
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    reason = "embedding defers synchronous work until polled; the trait-impl lint is newer than Rust 1.95"
)]
impl Node {
    pub async fn start(
        config: crate::NodeConfig,
        runtime: crate::RuntimeInputs,
    ) -> Result<Self, NodeError> {
        start_node(config, runtime, false).map_err(|error| NodeError::Startup(error.to_string()))
    }

    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        self.state.chainstate().chain_snapshot()
    }

    pub fn mining_control(&self) -> Result<&dyn bitcoin_rs_mining::MiningControl, NodeError> {
        self.context
            .mining
            .mining_control
            .as_deref()
            .ok_or_else(|| NodeError::Unavailable("mining control is not attached".to_owned()))
    }

    pub fn chainstates_summary(
        &self,
    ) -> Result<bitcoin_rs_chainstate::ChainstatesSummary, NodeError> {
        self.state
            .chainstates_summary()
            .map_err(|error| NodeError::Unavailable(error.to_string()))
    }

    pub async fn activate_assumeutxo_snapshot_file(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), NodeError> {
        self.state
            .activate_assumeutxo_snapshot_file(path)
            .map_err(|error| NodeError::Snapshot(error.to_string()))
    }

    #[must_use]
    pub fn capabilities(&self) -> CapabilitySnapshot {
        bitcoin_rs_index::txindex_snapshot(Some(self.state.derived_index_status().as_ref()))
    }

    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        self.context.chain.sync_progress()
    }

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

    pub fn transaction_at_prefix(
        &self,
        txid: &Txid,
    ) -> Result<AtPrefix<Option<(u32, Tx)>>, HistoricalQueryError> {
        let Some(adapter) = self.state.historical_index_adapter() else {
            return Err(HistoricalQueryError::Unavailable(
                HistoricalUnavailableCause::Shared(TxUnavailableCause::CapabilityDisabled(
                    IndexCapability::TxLookup,
                )),
            ));
        };
        adapter.transaction_at_prefix(txid)
    }

    pub fn script_history_at_prefix(
        &self,
        script: ScriptHash,
    ) -> Result<AtPrefix<ScriptIndexSnapshot>, HistoricalQueryError> {
        let Some(adapter) = self.state.historical_index_adapter() else {
            return Err(HistoricalQueryError::Unavailable(
                HistoricalUnavailableCause::Shared(TxUnavailableCause::CapabilityDisabled(
                    IndexCapability::ScriptHistory,
                )),
            ));
        };
        adapter.script_history_at_prefix(script)
    }

    pub fn spender_at_prefix(
        &self,
        outpoint: OutPoint,
    ) -> Result<AtPrefix<Option<SpendingRecord>>, HistoricalQueryError> {
        let Some(adapter) = self.state.historical_index_adapter() else {
            return Err(HistoricalQueryError::Unavailable(
                HistoricalUnavailableCause::Shared(TxUnavailableCause::CapabilityDisabled(
                    IndexCapability::ScriptHistory,
                )),
            ));
        };
        adapter.spender_at_prefix(outpoint)
    }

    pub async fn tx_by_id(&self, txid: Txid) -> Result<Tx, NodeError> {
        let pooled = self
            .state
            .mempool_reader()
            .read()
            .transaction_by_txid(&txid);
        if let Some(tx) = pooled {
            return Ok((*tx).clone());
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

    #[must_use]
    pub fn mempool_info(&self) -> MempoolStats {
        self.state.mempool_reader().read().stats()
    }

    #[must_use]
    pub fn fee_estimate(&self, confirmation_target_blocks: u32) -> Option<FeeRate> {
        self.state
            .mempool_reader()
            .read()
            .estimate_fee_rate(confirmation_target_blocks)
    }

    pub async fn broadcast(&self, tx: Tx) -> Result<MutationResult, NodeError> {
        let chainstate = self.state.chainstate();
        let chain = ChainAdmissionView::new(
            chainstate.utxo_reader(),
            chainstate.applied_tip_reader(),
            chainstate.block_tree_reader(),
            chainstate.network(),
        );
        self.state
            .mempool_gateway()
            .submit_local_transaction(
                Arc::new(tx),
                LocalOrigin::Rpc,
                Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB),
                unix_time_secs(),
                &chain,
            )
            .map_err(|error| NodeError::Broadcast(error.to_string()))
    }

    pub async fn broadcast_package(&self, txs: Vec<Tx>) -> Result<MutationResult, NodeError> {
        let chainstate = self.state.chainstate();
        let chain = ChainAdmissionView::new(
            chainstate.utxo_reader(),
            chainstate.applied_tip_reader(),
            chainstate.block_tree_reader(),
            chainstate.network(),
        );
        self.state
            .mempool_gateway()
            .submit_local_package(
                txs,
                LocalOrigin::Rpc,
                Some(DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB),
                unix_time_secs(),
                &chain,
            )
            .map_err(|error| NodeError::Broadcast(error.to_string()))
    }

    pub async fn shutdown(self) -> Result<(), NodeError> {
        self.shutdown_blocking()
    }

    pub(crate) fn shutdown_blocking(mut self) -> Result<(), NodeError> {
        let Some(services) = self.services.as_mut() else {
            return Err(NodeError::Shutdown("node was already shut down".to_owned()));
        };
        let result = services
            .teardown(Some(&mut self.state), TeardownMode::CleanShutdown)
            .map_err(|error| NodeError::Shutdown(error.to_string()));
        self.services = None;
        result
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(services) = self.services.as_mut() {
            if let Err(error) = services.teardown(Some(&mut self.state), TeardownMode::StartupAbort)
            {
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
    use bitcoin_rs_mempool::standardness::AcceptanceRejectReason;
    use bitcoin_rs_mempool::{MempoolEntry, MempoolObserver};
    use bitcoin_rs_primitives::{
        Amount, LockTime, Network, OutPoint, Script, Sequence, TxIn, TxOut, Witness,
    };
    use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
    use parking_lot::Mutex;

    use bitcoin_rs_rpc::zmq::MempoolSequenceObserver;
    use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

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

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one live-node scenario proves single and package submissions share ordered gateway publication, including refusal and the direct-insertion control"
    )]
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

        let mut op_true_p2wsh = vec![0x00, 0x20];
        op_true_p2wsh.extend_from_slice(&[
            0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00,
            0x09, 0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b,
            0x8c, 0xc3, 0x32, 0x60,
        ]);
        let spending = |previous_output: OutPoint| Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(92_000),
                script_pubkey: Script::from_bytes(op_true_p2wsh.clone()),
            }],
        };

        let broadcast_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5A; 32])), 0);
        let direct_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5B; 32])), 0);
        let package_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5D; 32])), 0);
        let mut changes = BlockChanges::default();
        for prevout in [broadcast_prevout, direct_prevout, package_prevout] {
            changes.add(UtxoAdd::new(
                prevout,
                TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: Script::from_bytes(op_true_p2wsh.clone()),
                },
                false,
                1,
            ));
        }
        bitcoin_rs_utxo::contract::commit_block_changes(
            &node.state.chainstate().utxo_handle(),
            &changes,
            &Hash256::from_le_bytes(&[0xAB; 32]),
        )
        .map_err(|error| format!("fixture utxo commit failed: {error}"))
        .expect("fixture utxo commit");

        let broadcast_tx = spending(broadcast_prevout);
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

        let direct_tx = spending(direct_prevout);
        let vsize = u32::try_from(direct_tx.vsize()).unwrap_or(u32::MAX);
        let entry = MempoolEntry::new(Arc::new(direct_tx), vsize, 8_000, unix_time_secs(), 1, 0);
        node.state
            .mempool()
            .write()
            .insert_entry(entry)
            .expect("direct pool insert fixture");
        assert!(
            publisher.sequence_events.lock().is_empty(),
            "a direct pool insertion must not satisfy the gateway publication assertion"
        );

        let orphan = spending(OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5C; 32])), 0));
        let orphan_txid = orphan.txid();
        let refusal = block_on(node.broadcast(orphan)).expect_err("an unknown prevout is refused");
        assert!(
            matches!(
                &refusal,
                NodeError::Broadcast(reason)
                    if *reason == AcceptanceRejectReason::MissingInputs.to_string()
            ),
            "the embedded envelope carries the gateway's policy reason verbatim: {refusal}"
        );
        let mempool = node.state.mempool_reader();
        assert!(!mempool.read().contains_txid(&orphan_txid));
        assert!(
            publisher.sequence_events.lock().is_empty(),
            "a refused broadcast publishes nothing"
        );

        let mut parent = spending(package_prevout);
        parent.outputs[0].value = Amount::from_sat(100_000);
        let parent_id = parent.txid();
        let child = spending(OutPoint::new(parent_id, 0));
        let child_id = child.txid();
        let result =
            block_on(node.broadcast_package(vec![child, parent])).expect("native CPFP accepted");
        assert_eq!(result.len(), 2);
        assert_eq!(
            publisher.sequence_events.lock().as_slice(),
            &[
                SequenceEvent::Added(parent_id, result.sequence_of(0).expect("parent sequence")),
                SequenceEvent::Added(child_id, result.sequence_of(1).expect("child sequence")),
            ]
        );
        assert!(mempool.read().contains_txid(&parent_id));
        assert!(mempool.read().contains_txid(&child_id));

        block_on(node.shutdown()).expect("clean shutdown");
    }
}
