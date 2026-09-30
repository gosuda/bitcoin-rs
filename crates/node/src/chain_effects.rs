//! Derived consumers of committed chain transitions.
//!
//! Ownership and ordering rules are defined by `ARCH-07` in
//! [`docs/contracts/architecture.md`](../../docs/contracts/architecture.md). Apply
//! does not import these consumer types.

use std::sync::Arc;

use bitcoin_rs_index::block_log::{BlockLog, BlockRecord};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256};
use parking_lot::RwLock;

use bitcoin_rs_chainstate::{ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_index::runtime::DerivedIndexRuntime;
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_mempool::ChainChangeGuard;
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

/// Runs one optional post-commit callback without allowing its panic to
/// escape into authoritative chain settlement.
fn isolate_optional_follower(name: &'static str, effect: impl FnOnce()) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(effect));
    if let Err(payload) = outcome {
        let message = payload.downcast_ref::<String>().map_or_else(
            || {
                payload
                    .downcast_ref::<&str>()
                    .map_or("non-string panic payload", |message| *message)
                    .to_owned()
            },
            Clone::clone,
        );
        // Dispose ordinary payloads. A hostile destructor may panic again;
        // suppress only that replacement payload to contain the boundary.
        let payload_disposal_panicked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(payload);
            }))
            .map_or_else(
                |nested| {
                    let _nested = core::mem::ManuallyDrop::new(nested);
                    true
                },
                |()| false,
            );
        metrics::counter!("node.chain_follower_panics_total", "consumer" => name).increment(1);
        tracing::warn!(
            consumer = name,
            %message,
            payload_disposal_panicked,
            "optional chain follower panicked; committed chain change stands"
        );
    }
}

/// Failure of a node-owned single-block connect.
///
/// The authoritative chainstate failure and a failure after a successful
/// commit are deliberately different variants. Callers must not retry the
/// latter as though the block had been refused.
#[derive(Debug, thiserror::Error)]
pub enum ConnectMutationError {
    /// No complete authoritative commit was returned.
    #[error("connect did not produce a committed outcome: {0}")]
    NotCommitted(#[source] bitcoin_rs_chainstate::ApplyError),
    /// Chainstate committed, but the node-owned mempool fence did not settle.
    #[error("authoritative connect committed, but node settlement failed: {source}")]
    CommittedButSettlementFailed {
        /// The authoritative outcome, retained so no caller has to infer it
        /// by rereading mutable global state.
        outcome: Box<ConnectOutcome>,
        /// Failure that forced the node into recovery-required shutdown.
        #[source]
        source: bitcoin_rs_chainstate::ApplyError,
    },
}

/// Failure of a node-owned single-block disconnect.
#[derive(Debug, thiserror::Error)]
pub enum DisconnectMutationError {
    /// No complete authoritative commit was returned.
    #[error("disconnect did not produce a committed outcome: {0}")]
    NotCommitted(#[source] bitcoin_rs_chainstate::DisconnectError),
    /// Chainstate committed, but node-owned post-commit work did not settle.
    #[error("authoritative disconnect committed, but node settlement failed: {source}")]
    CommittedButSettlementFailed {
        /// The authoritative outcome retained across settlement failure.
        outcome: Box<DisconnectOutcome>,
        /// Failure that forced the node into recovery-required shutdown.
        #[source]
        source: bitcoin_rs_chainstate::ApplyError,
    },
}

/// Node-owned derived work that follows a committed chain event.
///
/// `Chainstate` does not hold this. The composition root dispatches after
/// each committed connect or disconnect, and this type is the one owner of
/// that dispatch: the RPC block log, hash/raw ZMQ, the derived-index wake,
/// the sequence `C`/`D` events, the mining-generation wake, and mempool
/// admission all run from here, in the order `ARCH-07` fixes.
///
/// INVARIANT: optional consumer failure is isolated. A full ZMQ socket, a
/// panicking publisher, or a lagged index cannot invalidate chainstate.
#[derive(Clone)]
pub struct ChainFollowers {
    blocks: Arc<RwLock<BlockLog>>,
    zmq: Arc<dyn ZmqPublisher>,
    derived_index: Option<Arc<DerivedIndexRuntime>>,
    mining: Arc<crate::mining::MiningGenerationSignal>,
    mempool: Option<Arc<MempoolGateway>>,
}

impl ChainFollowers {
    /// Builds the follower set over its consumers.
    ///
    /// PRE: each argument is the live consumer it names; `mempool` is `None`
    /// only for a node that runs no admission gate.
    ///
    /// POST: the set holds exactly those consumers and mutates none of them.
    ///
    /// INVARIANT: construction does not attach observers or wake any
    /// consumer; effects run only through [`Self::on_connect`] and
    /// [`Self::on_disconnect`].
    #[must_use]
    pub fn new(
        blocks: Arc<RwLock<BlockLog>>,
        zmq: Arc<dyn ZmqPublisher>,
        derived_index: Option<Arc<DerivedIndexRuntime>>,
        mining: Arc<crate::mining::MiningGenerationSignal>,
        mempool: Option<Arc<MempoolGateway>>,
    ) -> Self {
        Self {
            blocks,
            zmq,
            derived_index,
            mining,
            mempool,
        }
    }

    /// Empty RPC log, no-op ZMQ, no index, no admission, a fresh mining signal.
    ///
    /// Test and planner handles use this.
    #[must_use]
    pub fn noop() -> Self {
        Self::new(
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            None,
        )
    }

    /// Returns `self` with `zmq` swapped to `publisher`.
    #[must_use]
    pub fn with_zmq_publisher(mut self, publisher: Arc<dyn ZmqPublisher>) -> Self {
        self.zmq = publisher;
        self
    }

    /// Returns `self` with the `TxIndex` wake handle swapped.
    #[must_use]
    pub fn with_tx_index(mut self, derived_index: Option<Arc<DerivedIndexRuntime>>) -> Self {
        self.derived_index = derived_index;
        self
    }

    /// Whether apply should capture per-transaction wire bytes for `rawtx`.
    #[must_use]
    pub fn needs_rawtx(&self) -> bool {
        self.zmq.wants_rawtx()
    }

    /// Whether apply should serialize the full block for a derived consumer.
    #[must_use]
    pub fn needs_block_bytes(&self) -> bool {
        self.derived_index.is_some() || self.zmq.wants_rawblock()
    }

    /// Shared RPC block log owned by this committed-effect dispatcher.
    #[must_use]
    pub fn block_log(&self) -> &Arc<RwLock<BlockLog>> {
        &self.blocks
    }

    /// Publisher used by committed chain effects and RPC notifier discovery.
    #[must_use]
    pub fn zmq_publisher(&self) -> Arc<dyn ZmqPublisher> {
        Arc::clone(&self.zmq)
    }

    /// `TxIndex` runtime, when one is wired.
    #[must_use]
    pub fn derived_index(&self) -> Option<&Arc<DerivedIndexRuntime>> {
        self.derived_index.as_ref()
    }

    /// Mining generation signal.
    #[must_use]
    pub fn mining(&self) -> &Arc<crate::mining::MiningGenerationSignal> {
        &self.mining
    }

    #[must_use]
    pub(crate) fn mempool_gateway(&self) -> Option<&Arc<MempoolGateway>> {
        self.mempool.as_ref()
    }

    pub(crate) fn begin_mempool_change(
        &self,
    ) -> core::result::Result<Option<ChainChangeGuard>, bitcoin_rs_chainstate::ApplyError> {
        self.mempool
            .as_ref()
            .map(|gateway| {
                gateway.begin_chain_change().map_err(|error| match error {
                    bitcoin_rs_mempool::ChainChangeError::AlreadyActive
                    | bitcoin_rs_mempool::ChainChangeError::GenerationMoved
                    | bitcoin_rs_mempool::ChainChangeError::ForeignGuard => {
                        bitcoin_rs_chainstate::ApplyError::ConcurrentChainChange
                    }
                    bitcoin_rs_mempool::ChainChangeError::Overflow => {
                        bitcoin_rs_chainstate::ApplyError::ChainChangeGenerationOverflow
                    }
                })
            })
            .transpose()
    }

    pub(crate) fn finish_transition(
        handles: &bitcoin_rs_chainstate::Chainstate,
        transition: bitcoin_rs_chainstate::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
    ) -> core::result::Result<(), bitcoin_rs_chainstate::ApplyError> {
        if let Some(change) = mempool_change
            && change.finish().is_err()
        {
            handles.fail_closed_for_recovery();
            return Err(bitcoin_rs_chainstate::ApplyError::Shutdown);
        }
        drop(transition);
        Ok(())
    }

    /// Dispatches a committed connect: RPC log, ZMQ, index wake, sequence `C`,
    /// mining wake, and orphan re-evaluation, in that order.
    ///
    /// PRE: `outcome` is committed and the mempool fence, when present, is
    /// held.
    ///
    /// POST: required mempool work runs once; the block-log record, hash/raw
    /// ZMQ, the derived-index wake, sequence `C`, and the mining wake are
    /// attempted once in that order. The block-inclusion removals are committed
    /// before sequence `C`; a `sequence` subscriber sees no `R` event for them,
    /// because the block event already covers the departures.
    ///
    /// INVARIANT: consumer failure cannot invalidate chainstate.
    pub fn on_connect(&self, block: &Block, outcome: &ConnectOutcome) {
        if let Some(gateway) = &self.mempool {
            let block_txs: Vec<&bitcoin_rs_primitives::Tx> = block.txs.iter().collect();
            gateway.remove_for_block(
                AdmissionOrigin::Block,
                &block_txs,
                &outcome.txids,
                outcome.height,
            );
        }
        isolate_optional_follower("rpc_block_log", || {
            self.blocks
                .write()
                .push(BlockRecord::from_block(outcome.height, block));
        });
        isolate_optional_follower("zmq_block", || self.publish_block(outcome));
        self.wake_index();
        isolate_optional_follower("zmq_sequence", || {
            if self.zmq.wants_notifications() {
                self.zmq
                    .publish_sequence(SequenceEvent::Connected(outcome.hash));
            }
        });
        isolate_optional_follower("mining", || self.mining.publish_generation());
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.txids);
        }
    }

    /// Dispatches a committed disconnect: log pop, index wake, and sequence
    /// `D`, then the mining wake and orphan re-evaluation.
    ///
    /// PRE: `outcome` is a committed production disconnect.
    ///
    /// POST: restored-parent re-evaluation runs once; the matching-tail log
    /// pop, derived-index wake, gated sequence `D`, and mining wake are
    /// attempted in that order.
    ///
    /// INVARIANT: a non-matching tail is not popped, and no consumer
    /// failure changes the chainstate result.
    pub fn on_disconnect(&self, outcome: &DisconnectOutcome) {
        isolate_optional_follower("rpc_block_log", || {
            self.pop_matching_tail(outcome.hash);
        });
        self.wake_index();
        isolate_optional_follower("zmq_sequence", || {
            if self.zmq.wants_notifications() {
                self.zmq
                    .publish_sequence(SequenceEvent::Disconnected(outcome.hash));
            }
        });
        isolate_optional_follower("mining", || self.mining.publish_generation());
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.restored_parents);
        }
    }

    /// Emits hash/raw ZMQ topics for a committed block. See `ARCH-07` for
    /// effect ordering.
    fn publish_block(&self, outcome: &ConnectOutcome) {
        if !self.zmq.wants_notifications() {
            return;
        }
        self.zmq.publish_hashblock(outcome.hash);
        if self.zmq.wants_rawblock() {
            self.zmq.publish_rawblock(&outcome.block_bytes);
        }
        if let Some(raw_txs) = &outcome.raw_txs {
            for (txid, rawtx_bytes) in outcome.txids.iter().zip(raw_txs) {
                self.zmq.publish_hashtx(*txid);
                self.zmq.publish_rawtx(rawtx_bytes);
            }
        } else {
            for txid in &outcome.txids {
                self.zmq.publish_hashtx(*txid);
            }
        }
    }

    /// Pops the RPC cache if the tail hash matches this block. See `ARCH-07`.
    ///
    /// The log starts empty on boot and pruning may drop the tail. Matching
    /// the hash stops a pop of a record that is not this block.
    fn pop_matching_tail(&self, hash: Hash256) {
        let mut blocks = self.blocks.write();
        if blocks
            .last()
            .is_some_and(|record| record.hash == BlockHash::from(hash))
        {
            blocks.pop();
        }
    }

    fn wake_index(&self) {
        if let Some(runtime) = &self.derived_index {
            runtime.wake();
        }
    }

    /// Connects `block` and dispatches this set before the transition ends.
    ///
    /// See `ARCH-07`: production single-block paths must not finish the
    /// [`bitcoin_rs_chainstate::ChainTransition`] and then dispatch, or a later
    /// connect or disconnect can publish derived effects first.
    ///
    /// PRE: no transition or fence is held.
    ///
    /// POST: `Ok` means the block committed and settlement completed;
    /// [`ConnectMutationError::CommittedButSettlementFailed`] retains the
    /// committed outcome when only settlement failed; on refusal nothing is
    /// dispatched and settlement is attempted.
    ///
    /// INVARIANT: fatal errors drop guards without settlement; operational
    /// refusal attempts settlement.
    pub fn apply_connect(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        block: &Block,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        let transition = handles
            .begin_transition()
            .map_err(ConnectMutationError::NotCommitted)?;
        let mempool_change = self
            .begin_mempool_change()
            .map_err(ConnectMutationError::NotCommitted)?;
        self.apply_connect_in_transition(handles, transition, mempool_change, block, None)
    }

    pub(crate) fn apply_connect_in_transition(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        transition: bitcoin_rs_chainstate::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
        block: &Block,
        serialized: Option<bytes::Bytes>,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        match transition.connect(block, serialized) {
            Ok(outcome) => {
                self.on_connect(block, &outcome);
                match Self::finish_transition(handles, transition, mempool_change) {
                    Ok(()) => Ok(outcome),
                    Err(source) => Err(ConnectMutationError::CommittedButSettlementFailed {
                        outcome: Box::new(outcome),
                        source,
                    }),
                }
            }
            Err(error) => {
                if bitcoin_rs_chainstate::classify_apply_error(&error)
                    == bitcoin_rs_chainstate::WindowApplyDisposition::Fatal
                {
                    drop(mempool_change);
                    drop(transition);
                    return Err(ConnectMutationError::NotCommitted(error));
                }
                if let Err(settlement) =
                    Self::finish_transition(handles, transition, mempool_change)
                {
                    tracing::error!(
                        original = %error,
                        finish = %settlement,
                        "chain transition could not be settled after connect refusal"
                    );
                    return Err(ConnectMutationError::NotCommitted(settlement));
                }
                Err(ConnectMutationError::NotCommitted(error))
            }
        }
    }

    /// Disconnects `block` and dispatches this set before the transition ends.
    ///
    /// See `ARCH-07`. [`DisconnectMutationError::NotCommitted`] contains an
    /// authoritative refusal/failure; a later node settlement failure retains
    /// the committed [`DisconnectOutcome`] in the other variant.
    pub fn apply_disconnect(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        block: &Block,
    ) -> core::result::Result<DisconnectOutcome, DisconnectMutationError> {
        let transition = handles.begin_transition().map_err(|error| {
            DisconnectMutationError::NotCommitted(bitcoin_rs_chainstate::DisconnectError::Refused(
                Box::new(error),
            ))
        })?;
        let mut mempool_change = self.begin_mempool_change().map_err(|error| {
            DisconnectMutationError::NotCommitted(bitcoin_rs_chainstate::DisconnectError::Refused(
                Box::new(error),
            ))
        })?;
        match transition.disconnect(block) {
            Ok(outcome) => {
                self.on_disconnect(&outcome);
                // Resident entries the lower tip no longer supports leave
                // before the fence finishes, through the same shared view.
                if let (Some(change), Some(gateway)) =
                    (mempool_change.as_ref(), self.mempool_gateway())
                {
                    let chain = bitcoin_rs_rpc::context::ChainAdmissionView::new(
                        handles.utxo_reader(),
                        handles.applied_tip_reader(),
                        handles.block_tree_reader(),
                        handles.network(),
                    );
                    if gateway.remove_for_reorg(change, &chain).is_err() {
                        handles.fail_closed_for_recovery();
                        drop(mempool_change.take());
                        drop(transition);
                        return Err(DisconnectMutationError::CommittedButSettlementFailed {
                            outcome: Box::new(outcome),
                            source: bitcoin_rs_chainstate::ApplyError::Shutdown,
                        });
                    }
                }
                match Self::finish_transition(handles, transition, mempool_change) {
                    Ok(()) => Ok(outcome),
                    Err(source) => Err(DisconnectMutationError::CommittedButSettlementFailed {
                        outcome: Box::new(outcome),
                        source,
                    }),
                }
            }
            Err(error @ bitcoin_rs_chainstate::DisconnectError::Refused(_)) => {
                let hash = Hash256::from(block.block_hash());
                let height = handles.applied_tip_snapshot().map_or(0, |tip| tip.height);
                if let Err(settlement) =
                    Self::finish_transition(handles, transition, mempool_change)
                {
                    tracing::error!(
                        original = %error,
                        finish = %settlement,
                        "chain transition could not be settled after disconnect refusal"
                    );
                    return Err(DisconnectMutationError::NotCommitted(
                        bitcoin_rs_chainstate::DisconnectError::Fatal {
                            hash,
                            height,
                            source: Box::new(settlement),
                        },
                    ));
                }
                Err(DisconnectMutationError::NotCommitted(error))
            }
            Err(error) => {
                drop(mempool_change);
                drop(transition);
                Err(DisconnectMutationError::NotCommitted(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolLimits,
        MutationOutcome, PeerToken, SubmitError, SubmitOutcome,
    };
    use bitcoin_rs_mining::{BlockValidationResult, MiningControl};
    use bitcoin_rs_primitives::{
        Amount, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use parking_lot::Mutex;

    /// Records every ZMQ call in the order the follower made it.
    #[derive(Debug, Default)]
    struct RecordingPublisher {
        events: Mutex<Vec<String>>,
    }

    impl RecordingPublisher {
        fn events(&self) -> Vec<String> {
            self.events.lock().clone()
        }
    }

    impl ZmqPublisher for RecordingPublisher {
        fn wants_rawblock(&self) -> bool {
            false
        }

        fn publish_hashblock(&self, hash: Hash256) {
            self.events.lock().push(format!("hashblock:{hash}"));
        }

        fn publish_hashtx(&self, txid: bitcoin_rs_primitives::Txid) {
            self.events.lock().push(format!("hashtx:{txid}"));
        }

        fn publish_rawblock(&self, _: &[u8]) {}

        fn publish_rawtx(&self, raw: &[u8]) {
            self.events.lock().push(format!("rawtx:{}", raw.len()));
        }

        fn publish_sequence(&self, event: SequenceEvent) {
            let label = match event {
                SequenceEvent::Connected(hash) => format!("C:{hash}"),
                SequenceEvent::Disconnected(hash) => format!("D:{hash}"),
                SequenceEvent::Added(txid, sequence) => format!("A:{txid}:{sequence}"),
                SequenceEvent::Removed(txid, sequence) => format!("R:{txid}:{sequence}"),
            };
            self.events.lock().push(label);
        }
    }

    /// Optional publisher whose first block callback fails while its later
    /// sequence callback records whether dispatch continued.
    #[derive(Debug, Default)]
    struct PanickingPublisher {
        sequence_calls: std::sync::atomic::AtomicUsize,
    }

    impl ZmqPublisher for PanickingPublisher {
        fn wants_rawtx(&self) -> bool {
            false
        }

        fn wants_rawblock(&self) -> bool {
            false
        }

        fn publish_hashblock(&self, _: Hash256) {
            panic!("injected optional publisher failure");
        }

        fn publish_hashtx(&self, _: bitcoin_rs_primitives::Txid) {}

        fn publish_rawblock(&self, _: &[u8]) {}

        fn publish_rawtx(&self, _: &[u8]) {}

        fn publish_sequence(&self, _: SequenceEvent) {
            self.sequence_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[derive(Debug)]
    struct MoveGenerationOnBlockEvent {
        gateway: Arc<MempoolGateway>,
        generation: u64,
    }

    impl ZmqPublisher for MoveGenerationOnBlockEvent {
        fn wants_rawtx(&self) -> bool {
            false
        }

        fn wants_rawblock(&self) -> bool {
            false
        }

        fn publish_hashblock(&self, _: Hash256) {}

        fn publish_hashtx(&self, _: bitcoin_rs_primitives::Txid) {}

        fn publish_rawblock(&self, _: &[u8]) {}

        fn publish_rawtx(&self, _: &[u8]) {}

        fn publish_sequence(&self, event: SequenceEvent) {
            if matches!(
                event,
                SequenceEvent::Connected(_) | SequenceEvent::Disconnected(_)
            ) {
                self.gateway.force_chain_generation(self.generation);
            }
        }
    }

    fn settlement_breaking_followers(
        gateway: Arc<MempoolGateway>,
        generation: u64,
    ) -> ChainFollowers {
        ChainFollowers::new(
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(MoveGenerationOnBlockEvent {
                gateway: Arc::clone(&gateway),
                generation,
            }),
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(gateway),
        )
    }

    /// `ARCH-07`: a no-op follower set asks for no derived payloads.
    #[test]
    fn noop_asks_for_no_payloads() {
        let followers = ChainFollowers::noop();
        assert!(!followers.needs_rawtx());
        assert!(!followers.needs_block_bytes());
        assert!(followers.derived_index().is_none());
        assert!(followers.block_log().read().is_empty());
    }

    fn connect_outcome(tip: &TipSnapshot, block: &Block) -> ConnectOutcome {
        ConnectOutcome {
            commit_id: 0,
            height: tip.height,
            hash: tip.hash,
            tip: tip.clone(),
            txids: block
                .txs
                .iter()
                .map(bitcoin_rs_primitives::Tx::txid)
                .collect(),
            block_bytes: bytes::Bytes::new(),
            raw_txs: None,
        }
    }

    /// `ARCH-07`: connect then disconnect rewinds the RPC log and emits ZMQ in order.
    #[test]
    fn connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order() -> anyhow::Result<()> {
        let genesis = Network::Regtest.genesis_block();
        let hash = Hash256::from(genesis.block_hash());
        let publisher = Arc::new(RecordingPublisher::default());
        let zmq: Arc<dyn ZmqPublisher> = publisher.clone();
        let followers = ChainFollowers::noop().with_zmq_publisher(zmq);
        let tip = genesis_tip(&genesis)?;

        followers.on_connect(&genesis, &connect_outcome(&tip, &genesis));
        assert_eq!(followers.block_log().read().len(), 1);
        assert_eq!(
            publisher.events(),
            vec![
                format!("hashblock:{hash}"),
                format!("hashtx:{}", genesis.txs[0].txid()),
                format!("C:{hash}"),
            ],
            "the block record and its transactions publish before sequence C"
        );

        followers.on_disconnect(&DisconnectOutcome {
            parent_tip: tip,
            hash,
            restored_parents: Vec::new(),
        });
        assert!(followers.block_log().read().is_empty());
        assert_eq!(
            publisher.events().last(),
            Some(&format!("D:{hash}")),
            "sequence D closes the disconnect"
        );
        Ok(())
    }

    /// A panic in an optional post-commit publisher cannot turn the committed
    /// block into a refusal or prevent required mempool settlement. Later
    /// optional dispatch also continues.
    #[test]
    fn optional_publisher_panic_preserves_committed_connect() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        let publisher = Arc::new(PanickingPublisher::default());
        let zmq: Arc<dyn ZmqPublisher> = publisher.clone();
        let followers = ChainFollowers::new(
            Arc::new(RwLock::new(BlockLog::new())),
            zmq,
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(state.mempool_gateway()),
        );
        let genesis = Network::Regtest.genesis_block();

        let outcome = followers.apply_connect(&state.chainstate(), &genesis)?;

        assert_eq!(outcome.hash, Hash256::from(genesis.block_hash()));
        assert_eq!(followers.block_log().read().len(), 1);
        assert_eq!(
            publisher
                .sequence_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "sequence dispatch continues after block publication panics"
        );
        assert!(state.mempool_gateway().stable_generation().is_some());
        assert!(!state.shutdown().load(std::sync::atomic::Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn optional_follower_disposes_payload_and_contains_destructor_panic() {
        struct Payload {
            drops: Arc<std::sync::atomic::AtomicUsize>,
            panic_on_drop: bool,
        }
        impl Drop for Payload {
            fn drop(&mut self) {
                self.drops
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                assert!(!self.panic_on_drop, "injected payload destructor failure");
            }
        }
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for panic_on_drop in [false, true] {
            let payload = Payload {
                drops: Arc::clone(&drops),
                panic_on_drop,
            };
            isolate_optional_follower("test", || std::panic::panic_any(payload));
        }
        assert_eq!(drops.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(Arc::strong_count(&drops), 1);
    }

    /// `ARCH-07`: disconnect does not pop a `BlockLog` tail that is not this block.
    #[test]
    fn disconnect_does_not_pop_a_different_tail() -> anyhow::Result<()> {
        let genesis = Network::Regtest.genesis_block();
        let tip = genesis_tip(&genesis)?;
        let followers = ChainFollowers::noop();
        followers.on_connect(&genesis, &connect_outcome(&tip, &genesis));
        followers.on_disconnect(&DisconnectOutcome {
            parent_tip: tip,
            hash: Hash256::from_le_bytes(&[0xAB; 32]),
            restored_parents: Vec::new(),
        });
        assert_eq!(followers.block_log().read().len(), 1);
        Ok(())
    }

    #[derive(Default)]
    struct AdmissionCoins {
        prevouts: RwLock<Vec<(OutPoint, TxOut)>>,
    }

    impl AdmissionChain for AdmissionCoins {
        fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: self.prevouts.read().clone(),
                height: 100,
                locktime_cutoff: 0,
                prevout_meta: hashbrown::HashMap::new(),
                csv_active: false,
                confirmed: false,
            })
        }
    }

    fn orphan_child(outpoint: OutPoint) -> Arc<Tx> {
        Arc::new(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]),
            }],
            lock_time: LockTime::from_consensus(0),
        })
    }

    fn genesis_tip(block: &bitcoin_rs_primitives::Block) -> anyhow::Result<TipSnapshot> {
        let mut tree = BlockTree::new();
        let tip_id = tree.insert_node(None, block.header, NodeStatus::HeaderValid)?;
        let node = tree.node(tip_id)?;
        Ok(TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        })
    }

    fn followers_with_gateway(gateway: &Arc<MempoolGateway>) -> ChainFollowers {
        ChainFollowers::new(
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
            None,
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(Arc::clone(gateway)),
        )
    }

    /// Exercise committed-outcome dispatch with a real gateway, without any
    /// mempool mutation or observer that could independently wake the child.
    /// Full chain application and transition ownership have separate tests in
    /// `crates/chainstate`; this checks the follower's lifecycle notification
    /// boundary.
    #[allow(clippy::too_many_lines)]
    fn assert_admission_followers_after_chain_change(connect: bool) -> anyhow::Result<()> {
        let gateway = MempoolGateway::shared(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            ValidationEngine::Native,
        )
        .unwrap_or_else(|error| panic!("mempool gateway intern: {error}"));
        let followers = followers_with_gateway(&gateway);
        let block = Network::Regtest.genesis_block();
        let parent = block.txs[0].txid();
        let outpoint = OutPoint::new(parent, 0);
        let child = orphan_child(outpoint);
        let source = PeerToken {
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], 18444)),
            connection_id: 7,
        };
        let chain = AdmissionCoins::default();
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source),
                None,
                0,
                &chain,
            ),
            Ok(SubmitOutcome::Held {
                missing_parents: vec![parent],
            }),
        );
        let mut rejected = (*child).clone();
        rejected.version = 4;
        let rejected_txid = rejected.txid();
        assert!(matches!(
            gateway.submit_transaction(
                Arc::new(rejected),
                AdmissionOrigin::Peer(source),
                None,
                0,
                &chain,
            ),
            Err(SubmitError::Policy(_)),
        ));
        assert!(gateway.is_rejected(Hash256::from(rejected_txid)));
        assert_eq!(gateway.orphan_count(), 1);
        assert_eq!(gateway.read().sequence_number(), 0);
        assert!(!gateway.has_observer());

        let tip = genesis_tip(&block)?;
        let hash = tip.hash;
        let change = gateway.begin_chain_change()?;
        if connect {
            followers.on_connect(&block, &connect_outcome(&tip, &block));
        } else {
            followers.on_disconnect(&DisconnectOutcome {
                parent_tip: tip,
                hash,
                restored_parents: vec![parent],
            });
        }

        assert_eq!(gateway.recent_rejects_count(), 0);
        assert!(!gateway.is_rejected(Hash256::from(rejected_txid)));
        assert_eq!(gateway.read().sequence_number(), 0);
        *chain.prevouts.write() = vec![(
            outpoint,
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )];
        assert!(gateway.stable_generation().is_none());
        assert!(gateway.retry_orphans(&chain, 1).is_empty());
        assert_eq!(
            gateway.get_tx_by_wtxid(child.wtxid()).as_ref(),
            Some(child.as_ref())
        );
        assert_eq!(gateway.orphan_count(), 1);
        assert_eq!(gateway.read().sequence_number(), 0);

        change.finish()?;
        let retries = gateway.retry_orphans(&chain, 2);
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].source, source);
        assert_eq!(retries[0].txid, child.txid());
        assert!(matches!(
            &retries[0].result,
            Ok(SubmitOutcome::Committed(result)) if result.changes.iter().any(|change| {
                change.txid == Hash256::from(child.txid())
                    && change.outcome == MutationOutcome::Accepted
            }),
        ));
        assert!(gateway.read().contains_txid(&child.txid()));
        assert_eq!(gateway.orphan_count(), 0);
        assert_eq!(gateway.read().sequence_number(), 1);
        assert!(gateway.retry_orphans(&chain, 3).is_empty());
        Ok(())
    }

    #[test]
    fn connect_without_pool_mutations_resets_rejects_and_preserves_orphan_retry()
    -> anyhow::Result<()> {
        assert_admission_followers_after_chain_change(true)
    }

    #[test]
    fn disconnect_without_pool_mutations_resets_rejects_and_preserves_orphan_retry()
    -> anyhow::Result<()> {
        assert_admission_followers_after_chain_change(false)
    }

    #[test]
    fn active_chain_change_is_retryable_not_shutdown() -> anyhow::Result<()> {
        let gateway = MempoolGateway::shared(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            ValidationEngine::Native,
        )
        .unwrap_or_else(|error| panic!("mempool gateway intern: {error}"));
        let followers = followers_with_gateway(&gateway);
        let active = gateway.begin_chain_change()?;

        assert!(matches!(
            followers.begin_mempool_change(),
            Err(bitcoin_rs_chainstate::ApplyError::ConcurrentChainChange)
        ));
        active.finish()?;
        assert!(followers.begin_mempool_change()?.is_some());
        Ok(())
    }

    #[test]
    fn committed_connect_settlement_failure_retains_outcome_and_forbids_retry() -> anyhow::Result<()>
    {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        let followers = settlement_breaking_followers(state.mempool_gateway(), 3);
        let genesis = Network::Regtest.genesis_block();
        let hash = Hash256::from(genesis.block_hash());

        let error = match followers.apply_connect(&state.chainstate(), &genesis) {
            Ok(outcome) => panic!("forced generation move settled connect {outcome:?}"),
            Err(error) => error,
        };
        let (outcome, source) = match error {
            ConnectMutationError::CommittedButSettlementFailed { outcome, source } => {
                (outcome, source)
            }
            other @ ConnectMutationError::NotCommitted(_) => {
                panic!("committed connect must retain its outcome: {other}")
            }
        };
        assert_eq!(outcome.hash, hash);
        assert!(matches!(
            source,
            bitcoin_rs_chainstate::ApplyError::Shutdown
        ));
        let Some(committed_tip) = state.chainstate().applied_tip_snapshot() else {
            panic!("committed tip missing");
        };
        assert_eq!(committed_tip.hash, hash);
        assert!(matches!(
            followers.apply_connect(&state.chainstate(), &genesis),
            Err(ConnectMutationError::NotCommitted(
                bitcoin_rs_chainstate::ApplyError::Shutdown
            ))
        ));
        Ok(())
    }

    #[test]
    fn committed_disconnect_settlement_failure_retains_outcome() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        let genesis = Network::Regtest.genesis_block();
        state.apply_block(&genesis)?;
        let child = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
        state.apply_block(&child)?;
        let child_hash = Hash256::from(child.block_hash());
        let followers = settlement_breaking_followers(state.mempool_gateway(), 7);

        let error = match followers.apply_disconnect(&state.chainstate(), &child) {
            Ok(outcome) => panic!("forced generation move settled disconnect {outcome:?}"),
            Err(error) => error,
        };
        let (outcome, source) = match error {
            DisconnectMutationError::CommittedButSettlementFailed { outcome, source } => {
                (outcome, source)
            }
            other @ DisconnectMutationError::NotCommitted(_) => {
                panic!("committed disconnect must retain its outcome: {other}")
            }
        };
        assert_eq!(outcome.hash, child_hash);
        assert!(matches!(
            source,
            bitcoin_rs_chainstate::ApplyError::Shutdown
        ));
        let Some(parent_tip) = state.chainstate().applied_tip_snapshot() else {
            panic!("parent tip missing");
        };
        assert_eq!(parent_tip.hash, Hash256::from(genesis.block_hash()));
        Ok(())
    }

    #[test]
    fn mining_reports_a_committed_settlement_failure_as_accepted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        let followers = settlement_breaking_followers(state.mempool_gateway(), 3);
        let mining = crate::MiningCoordinator::new(
            state.mempool(),
            state.chainstate(),
            state.stable_read(),
            followers,
            Vec::new(),
        );

        assert_eq!(
            mining.submit_block(Network::Regtest.genesis_block())?,
            BlockValidationResult::Accepted,
            "submitblock must not invite retry after authoritative commit"
        );
        assert!(state.shutdown().load(std::sync::atomic::Ordering::Acquire));
        Ok(())
    }
}
