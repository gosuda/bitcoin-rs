//! Typed, in-process embedding surface over the node lifecycle (#145).
//!
//! [`Node`] owns the same service graph the daemon wires in
//! [`crate::run::start_node`]: storage-backed state, RPC listener, P2P
//! listeners, outbound and bootstrap workers, the event loop, and the
//! metrics listener. There is one lifecycle implementation; the daemon
//! runner is the first embedder.
//!
//! # Runtime ownership
//!
//! The async API runs on the caller's Tokio runtime: [`Node::start`] and
//! [`Node::shutdown`] are `async fn` by contract, and the node itself
//! never creates, enters, or retains a runtime. Their bodies drive the
//! node's own threads (the same synchronous workers the daemon uses), so a
//! call blocks the caller's task for the duration of startup or shutdown.
//! Embedders that must not block an executor worker wrap these calls in
//! `spawn_blocking` on their own runtime.
//!
//! # Storage boundary
//!
//! No signature here names a storage backend, `NodeStorage`, or index
//! internals. Reads and writes are typed: snapshots, progress, capability
//! reports, decoded blocks and transactions, mempool statistics, fee-rate
//! estimates, and gateway-returned [`MutationResult`]s.
//!
//! `mempool_info` returns the mempool crate's existing [`MempoolStats`]
//! and `fee_estimate` its [`FeeRate`]: minimal records are defined here
//! only when no existing public type fits, and both fit.

use bitcoin_rs_mempool::{FeeRate, MempoolStats, MutationResult};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Network, Tx, Txid, deserialize};
use bitcoin_rs_rpc::context::CapabilitySnapshot;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

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

/// A running node: the daemon's service graph, addressable in process.
///
/// Created by [`Node::start`]; consumed exactly once by
/// [`Node::shutdown`]. Every field stays private on purpose — callers
/// observe the node through the typed methods, never through its handles.
///
/// Dropping a node without calling [`Node::shutdown`] still stops it: the
/// [`Drop`] implementation runs the same best-effort synchronous teardown,
/// so a cancelled embedder cannot leak a running service graph. Only the
/// explicit shutdown reports errors.
pub struct Node {
    pub(crate) state: NodeState,
    pub(crate) services: Option<crate::run::NodeServices>,
    pub(crate) context: Arc<bitcoin_rs_rpc::context::Context>,
}

impl Node {
    /// Starts a node on the caller's Tokio runtime.
    ///
    /// Configuration is validated before storage or network state is
    /// opened; then the same services the daemon wires are spawned. The
    /// returned node owns every join and shutdown handle.
    ///
    /// # Errors
    ///
    /// [`NodeError::Startup`] names the failed configuration check, storage
    /// open, crash recovery, or service bind.
    #[allow(clippy::unused_async)] // async by contract; the body is synchronous today.
    pub async fn start(
        config: crate::NodeConfig,
        runtime: crate::RuntimeInputs,
    ) -> Result<Self, NodeError> {
        let (state, services, context) = crate::run::start_node(config, runtime, false)
            .map_err(|error| NodeError::Startup(error.to_string()))?;
        Ok(Self {
            state,
            services: Some(services),
            context,
        })
    }

    /// Returns the current coherent chain snapshot.
    ///
    /// The snapshot is a non-torn view of the applied tip stamped with the
    /// process epoch and the per-run commit sequence.
    #[must_use]
    pub fn snapshot(&self) -> ChainSnapshot {
        self.state.active_chain_snapshot()
    }

    /// Returns typed synchronization progress without touching RPC JSON.
    #[must_use]
    pub fn sync_progress(&self) -> SyncProgress {
        let ctx = &self.context;
        let applied_tip = ctx.applied_tip.load_full();
        let applied = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let headers = ctx.height();
        let (difficulty, time, median_time) =
            applied_tip.as_ref().map_or((0.0, 0_u64, 0_u64), |tip| {
                let tree = ctx.block_tree.read();
                tree.node(tip.tip_id).map_or((0.0, 0, 0), |node| {
                    (
                        ctx.difficulty_for_bits(node.header.bits),
                        u64::from(node.header.time),
                        u64::from(tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0)),
                    )
                })
            });
        let now = unix_time_secs();
        let verification_progress = ctx.chain_tx_count().map_or_else(
            || height_ratio_progress(applied, headers),
            |chain_tx_count| {
                verification_progress(
                    ctx.chain_network,
                    chain_tx_count,
                    applied,
                    headers,
                    time,
                    now,
                )
            },
        );
        let prune_status = ctx.prune_status();
        SyncProgress {
            network: ctx.chain_network,
            blocks: applied,
            headers,
            best_block_hash: applied_tip
                .as_ref()
                .map_or_else(Hash256::default, |tip| tip.hash),
            difficulty,
            time,
            median_time,
            verification_progress,
            initial_block_download: ctx.is_initial_block_download(now),
            chain_work: ctx.chainwork_hex(),
            size_on_disk: ctx
                .block_storage_disk_usage()
                .unwrap_or_else(|| ctx.blocks.read().size_on_disk()),
            pruned: prune_status.pruned,
            prune_height: prune_status.pruneheight,
        }
    }

    /// Returns the live extension-registry capability report.
    ///
    /// The snapshot comes from the node capability registry — the same
    /// provider `getcapabilities` serves — so embedded callers gate on the
    /// identical compiled/enabled/health facts.
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySnapshot {
        self.state.capability_provider().snapshot()
    }

    /// Returns the decoded block with `hash`, or `None` when the node does
    /// not know it.
    ///
    /// # Errors
    ///
    /// [`NodeError::Unavailable`] when the block is known but its body is
    /// pruned or fails identity verification against its stored bytes.
    #[allow(clippy::unused_async)] // async by contract; the body is synchronous today.
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

    /// Resolves a transaction by id: mempool first, then the direct
    /// transaction cache, then the confirmed lookup.
    ///
    /// The confirmed lookup is TxLookup-gated: when neither `txindex` nor
    /// `scriptindex` is enabled the method fails with
    /// [`NodeError::Unavailable`] instead of pretending the transaction does
    /// not exist. A complete index answer of absence is
    /// [`NodeError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`NodeError::Unavailable`] for a disabled or unhealthy index,
    /// [`NodeError::NotFound`] for a proven-absent transaction.
    #[allow(clippy::unused_async)] // async by contract; the body is synchronous today.
    pub async fn tx_by_id(&self, txid: Txid) -> Result<Tx, NodeError> {
        // Bind before matching: holding a pool or map guard alive across the
        // `if let` body would keep a lock for the whole lookup chain.
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

    /// Returns the history-based fee estimate for a confirmation target,
    /// or `None` when the pool's history is too thin to answer honestly.
    #[must_use]
    pub fn fee_estimate(&self, confirmation_target_blocks: u32) -> Option<FeeRate> {
        self.state
            .mempool()
            .read()
            .estimate_fee_rate(confirmation_target_blocks)
    }

    /// Admits a native transaction through the one shared typed admission
    /// operation.
    ///
    /// [`bitcoin_rs_rpc::context::Context::admit_transaction`] is the same
    /// operation `sendrawtransaction` runs — standardness, script,
    /// package, BIP125 replacement, min-relay/max-fee, and prevout-aware
    /// sigop policy, then a single mutation through the node's one
    /// [`bitcoin_rs_mempool::MempoolGateway`]. The gateway publishes the
    /// mempool `sequence` events and the mining generation wake; there is
    /// no second admission path and no per-call gateway.
    ///
    /// An already-known transaction succeeds with an empty result, matching
    /// RPC admission's already-known success.
    ///
    /// # Errors
    ///
    /// [`NodeError::Broadcast`] when the transaction fails any policy check
    /// or the pool refuses it.
    #[allow(clippy::unused_async)] // async by contract; the body is synchronous today.
    pub async fn broadcast(&self, tx: Tx) -> Result<MutationResult, NodeError> {
        // Core's `sendrawtransaction` default `maxfeerate` (0.1 BTC/kvB);
        // the embedded surface admits under the identical cap.
        let max_feerate = Some(bitcoin_rs_rpc::context::DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB);
        self.context
            .admit_transaction(tx, max_feerate)
            .map_err(NodeError::Broadcast)
    }

    /// Stops every owned service in the daemon's order and publishes the
    /// clean-shutdown checkpoint. Consumes the node: a shutdown node has no
    /// remaining API.
    ///
    /// # Errors
    ///
    /// [`NodeError::Shutdown`] when drain, checkpoint publication, or a
    /// worker join fails.
    #[allow(clippy::unused_async)] // async by contract; the body is synchronous today.
    pub async fn shutdown(self) -> Result<(), NodeError> {
        self.shutdown_blocking()
    }
    pub(crate) fn shutdown_blocking(mut self) -> Result<(), NodeError> {
        // No bounded index shutdown here: it takes the worker handles and
        // abandons any that miss the deadline, which leaves their storage
        // open and the data dir locked against the next open. An explicit
        // shutdown is deliberate, so the state's own drop joins the index
        // workers and closes their stores. `Drop` below keeps the bounded
        // form, where blocking forever would be worse than abandoning.
        let Some(services) = self.services.as_mut() else {
            return Err(NodeError::Shutdown("node was already shut down".to_owned()));
        };
        let result = services
            .cleanup(&self.state)
            .map_err(|error| NodeError::Shutdown(error.to_string()));
        // Consumed: the Drop below must not run the teardown twice.
        self.services = None;
        result
        // `self` drops on every path here: the node's state and RPC
        // context release the mining coordinator — the last strong owner
        // of the apply handles and storage clones — so the data dir lock
        // is free before this returns.
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(services) = self.services.as_mut() {
            self.state
                .bounded_index_shutdown(crate::run::DRAIN_DEADLINE);
            // An abandoned run, not a deliberate shutdown: stop and join every
            // service, but publish no checkpoint. A clean-run marker here would
            // let the next startup resume a state this run never confirmed.
            if let Err(error) =
                services.teardown(Some(&self.state), crate::run::TeardownMode::StartupAbort)
            {
                tracing::warn!(%error, "dropped embedded node; teardown reported an error");
            }
            self.services = None;
        }
    }
}

/// Builds the node from the parts [`crate::run::start_node`] produced.
///
/// The daemon runner uses this to share one lifecycle implementation.
#[must_use]
pub(crate) fn node_from_parts(
    state: NodeState,
    services: crate::run::NodeServices,
    context: Arc<bitcoin_rs_rpc::context::Context>,
) -> Node {
    Node {
        state,
        services: Some(services),
        context,
    }
}

/// UNIX seconds now; `0` before the epoch (clocks do not go backwards here).
fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// The pre-count fallback the RPC surface uses when chain tx count is
/// unknown: a height ratio clamped into `[0, 1]`.
fn height_ratio_progress(applied: u32, headers: u32) -> f64 {
    if headers == 0 {
        0.0
    } else {
        (f64::from(applied) / f64::from(headers)).min(1.0)
    }
}

/// `u64` → `f64` without an `as` cast (this crate forbids them). Exact up
/// to 2^53.
fn u64_to_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

/// `i64` → `f64` without an `as` cast.
fn i64_to_f64(value: i64) -> f64 {
    if value >= 0 {
        u64_to_f64(u64::try_from(value).unwrap_or(u64::MAX))
    } else {
        -u64_to_f64(value.unsigned_abs())
    }
}

/// Bitcoin Core's `GuessVerificationProgress` for embedders.
///
/// Keep op-for-op identical with
/// `crates/rpc/src/handlers/chain.rs::verification_progress` — that private
/// function is the canonical implementation the RPC contract tests pin;
/// this twin exists only because those tests are outside this crate's
/// dependency direction. Changing one without the other makes
/// [`Node::sync_progress`] disagree with `getblockchaininfo`.
#[allow(clippy::too_many_arguments)]
fn verification_progress(
    network: Network,
    chain_tx_count: u64,
    applied_height: u32,
    header_height: u32,
    tip_time: u64,
    now: u64,
) -> f64 {
    const RECENT_TIP_WINDOW_SECONDS: i64 = 2 * 60 * 60;

    if chain_tx_count == 0 {
        return 0.0;
    }
    let data = network.chain_tx_data();

    let now_signed = i64::try_from(now).unwrap_or(i64::MAX);
    let tip_time_signed = i64::try_from(tip_time).unwrap_or(i64::MAX);
    let block_time = if (now_signed - tip_time_signed).abs() <= RECENT_TIP_WINDOW_SECONDS
        && header_height >= applied_height
    {
        let behind = i64::from(header_height - applied_height);
        let spacing = i64::from(network.target_spacing_seconds());
        now_signed.saturating_sub(behind.saturating_mul(spacing))
    } else {
        tip_time_signed
    };

    let total = if chain_tx_count <= data.tx_count {
        // Still behind the pinned observation: extrapolate forward from it.
        let elapsed = now_signed.saturating_sub(i64::try_from(data.time).unwrap_or(i64::MAX));
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(data.tx_count))
    } else {
        // Past it, so this node's own count is the better baseline.
        let elapsed = now_signed.saturating_sub(block_time);
        i64_to_f64(elapsed).mul_add(data.tx_rate, u64_to_f64(chain_tx_count))
    };
    if total <= 0.0 {
        return 0.0;
    }
    (u64_to_f64(chain_tx_count) / total).clamp(0.0, 1.0)
}

/// Polls a node future to completion without an executor (test-only).
///
/// `Node` futures drive the node's own threads synchronously, so a single
/// poll finishes the work; this lets in-crate tests await the async API
/// without a runtime dependency. Shared with the `run.rs` lifecycle tests.
#[cfg(test)]
pub(crate) mod testing {
    pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
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
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::NodeConfig;
    use bitcoin_rs_mempool::{MempoolEntry, MempoolObserver};
    use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use parking_lot::Mutex;

    use crate::mempool_observer::MempoolSequenceObserver;
    use crate::zmq_publisher::{SequenceEvent, ZmqPublisher};

    /// Captures every `sequence`-topic event the gateway's observer emits.
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

    /// Embedded-node config: isolated regtest datadir, P2P listeners off,
    /// ephemeral RPC bind, no metrics listener.
    fn embedded_config(data_dir: &std::path::Path) -> NodeConfig {
        let mut config = NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = data_dir.to_path_buf();
        config.p2p_listen.clear();
        config.rpc_bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        config.metrics_bind = None;
        config
    }

    /// `P2WSH(OP_TRUE)`: a version-0 push-32 program whose witness script is a
    /// bare `OP_TRUE`. Standard as an output template and spendable by a
    /// one-item `[OP_TRUE]` witness, so the fixture needs no signature
    /// material.
    fn spendable_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&[
            0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00,
            0x09, 0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b,
            0x8c, 0xc3, 0x32, 0x60,
        ]);
        script
    }

    /// A standard one-input one-output spend: a funded confirmed
    /// `P2WSH(OP_TRUE)` prevout pays 92 000 sats back to the same template
    /// (8 000 sat fee).
    fn spending_tx(previous_output: OutPoint) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: vec![vec![0x51]],
            }],
            outputs: vec![TxOut {
                value: 92_000,
                script_pubkey: spendable_script(),
            }],
        }
    }

    /// `Node::broadcast` of an accepted transaction must publish exactly one
    /// ordered `A` event through the node's shared gateway, and a direct
    /// pool insertion must not be able to satisfy that assertion.
    #[test]
    fn broadcast_publishes_one_ordered_a_event_through_the_shared_gateway() {
        let dir = tempfile::tempdir().expect("tempdir");
        let publisher = Arc::new(RecordingSequencePublisher::default());
        let recording: Arc<dyn crate::zmq_publisher::ZmqPublisher> = publisher.clone();
        let observer: Arc<dyn MempoolObserver> = Arc::new(MempoolSequenceObserver::new(recording));
        let config = embedded_config(&dir.path().join("node"));

        let node = testing::block_on(Node::start(
            config,
            crate::RuntimeInputs::default().with_mempool_observer(observer),
        ))
        .expect("embedded node starts");

        // Fund two spendable confirmed outputs in the live UTXO set: one the
        // broadcast spends, one the direct-insert control below spends.
        let broadcast_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5A; 32])), 0);
        let direct_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5B; 32])), 0);
        let mut changes = BlockChanges::default();
        for prevout in [broadcast_prevout, direct_prevout] {
            changes.add(UtxoAdd::new(
                prevout,
                TxOut {
                    value: 100_000,
                    script_pubkey: spendable_script(),
                },
                false,
                1,
            ));
        }
        node.state
            .utxo()
            .commit_block(&changes, &Hash256::from_le_bytes(&[0xAB; 32]))
            .map_err(|error| format!("fixture utxo commit failed: {error}"))
            .expect("fixture utxo commit");

        let broadcast_tx = spending_tx(broadcast_prevout);
        let broadcast_txid = broadcast_tx.txid();
        let result = testing::block_on(node.broadcast(broadcast_tx)).expect("broadcast accepted");
        assert_eq!(result.len(), 1, "one admission commits one change");
        assert_eq!(
            result.changes[0].txid,
            Hash256::from(broadcast_txid),
            "the committed change is the broadcast transaction"
        );
        let sequence = result.sequence_of(0).expect("sequence of the change");

        // Exactly one ordered `A` event, carrying the txid and the mempool
        // sequence the gateway assigned to the admission. A broadcast that
        // mutated the pool directly would leave this stream empty and fail
        // here.
        let events = publisher.sequence_events.lock();
        assert_eq!(
            *events,
            vec![SequenceEvent::Added(broadcast_txid, sequence)],
            "Node::broadcast must publish exactly one ordered A event through the shared gateway"
        );
        drop(events);
        // The control below measures the direct insertion alone, so the
        // broadcast's own event must leave the stream first.
        publisher.sequence_events.lock().clear();

        // Control: the pre-gateway broadcast inserted into the pool
        // directly. That path reaches no observer — the empty stream below
        // is what makes the assertion above gateway-specific rather than
        // pool-state-specific.
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

        testing::block_on(node.shutdown()).expect("clean shutdown");
    }
}
