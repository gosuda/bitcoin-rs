//! Derived consumers of committed chain transitions.
//!
//! Ownership and ordering rules are defined by `ARCH-07` in
//! [`docs/contracts/architecture.md`](../../docs/contracts/architecture.md). Apply
//! does not import these consumer types.

use std::sync::Arc;

use bitcoin_rs_index::block_log::{BlockLog, BlockRecord};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Txid};
use parking_lot::RwLock;

use bitcoin_rs_chainstate::{ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_index::runtime::DerivedIndexRuntime;
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_mempool::ChainChangeGuard;
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

/// Post-commit adapters that follow a committed chain transition.
///
/// Consumer failure is ignored. A full ZMQ socket or a lagged index cannot
/// invalidate chainstate.
#[derive(Clone)]
pub struct ChainEffects {
    blocks: Arc<RwLock<BlockLog>>,
    zmq: Arc<dyn ZmqPublisher>,
    derived_index: Option<Arc<DerivedIndexRuntime>>,
}

impl ChainEffects {
    /// Builds the production consumer set.
    #[must_use]
    pub fn new(
        blocks: Arc<RwLock<BlockLog>>,
        zmq: Arc<dyn ZmqPublisher>,
        derived_index: Option<Arc<DerivedIndexRuntime>>,
    ) -> Self {
        Self {
            blocks,
            zmq,
            derived_index,
        }
    }

    /// Empty RPC log, no-op ZMQ, no `TxIndex`. Test and planner handles use this.
    #[must_use]
    pub fn noop() -> Self {
        Self::new(
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
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

    /// Pushes the RPC block-log record. See `ARCH-07` for effect ordering.
    pub fn record_connected(&self, height: u32, block: &Block) {
        self.blocks
            .write()
            .push(BlockRecord::from_block(height, block));
    }

    /// Emits hash/raw ZMQ topics. See `ARCH-07` for effect ordering.
    pub fn emit_connected(
        &self,
        tip_hash: Hash256,
        block_bytes: &[u8],
        txids: &[Txid],
        raw_txs: Option<&[Vec<u8>]>,
    ) {
        if !self.zmq.wants_notifications() {
            return;
        }
        self.zmq.publish_hashblock(tip_hash);
        if self.zmq.wants_rawblock() {
            self.zmq.publish_rawblock(block_bytes);
        }
        if let Some(raw_txs) = raw_txs {
            for (txid, rawtx_bytes) in txids.iter().zip(raw_txs) {
                self.zmq.publish_hashtx(*txid);
                self.zmq.publish_rawtx(rawtx_bytes);
            }
        } else {
            for txid in txids {
                self.zmq.publish_hashtx(*txid);
            }
        }
    }

    /// `TxIndex` wake and sequence `C`. See `ARCH-07` for effect ordering.
    pub fn after_connect(&self, hash: Hash256) {
        self.wake_tx_index();
        if self.zmq.wants_notifications() {
            self.zmq.publish_sequence(SequenceEvent::Connected(hash));
        }
    }

    /// Pops the RPC cache if the tail hash matches this block. See `ARCH-07`.
    ///
    /// The log starts empty on boot and pruning may drop the tail. Matching
    /// the hash stops a pop of a record that is not this block.
    pub fn before_disconnect(&self, hash: Hash256) {
        let mut blocks = self.blocks.write();
        if blocks
            .last()
            .is_some_and(|record| record.hash == BlockHash::from(hash))
        {
            blocks.pop();
        }
    }

    /// `TxIndex` wake and sequence `D`. See `ARCH-07` for effect ordering.
    pub fn after_disconnect(&self, hash: Hash256) {
        self.wake_tx_index();
        if self.zmq.wants_notifications() {
            self.zmq.publish_sequence(SequenceEvent::Disconnected(hash));
        }
    }

    fn wake_tx_index(&self) {
        if let Some(runtime) = &self.derived_index {
            runtime.wake();
        }
    }

    /// Shared RPC block log. Production RPC reads `NodeState::blocks`.
    #[must_use]
    pub fn block_log(&self) -> &Arc<RwLock<BlockLog>> {
        &self.blocks
    }

    /// `TxIndex` runtime, when one is wired.
    #[must_use]
    pub fn derived_index(&self) -> Option<&Arc<DerivedIndexRuntime>> {
        self.derived_index.as_ref()
    }

    /// Replaces the `TxIndex` wake handle in place for tests that attach a worker
    /// after constructing the facade.
    pub fn set_tx_index(&mut self, derived_index: Option<Arc<DerivedIndexRuntime>>) {
        self.derived_index = derived_index;
    }

    /// RPC log, ZMQ, and index wake for a committed connect.
    pub fn connected(&self, block: &Block, outcome: &ConnectOutcome) {
        self.record_connected(outcome.height, block);
        self.emit_connected(
            outcome.hash,
            &outcome.block_bytes,
            &outcome.txids,
            outcome.raw_txs.as_deref(),
        );
        self.after_connect(outcome.hash);
    }

    /// RPC log, ZMQ, and index wake for a committed disconnect.
    pub fn disconnected(&self, outcome: &DisconnectOutcome) {
        self.before_disconnect(outcome.hash);
        self.after_disconnect(outcome.hash);
    }
}

/// Node-owned derived work that follows a committed chain event.
///
/// `Chainstate` does not hold this. The composition root dispatches after
/// each committed connect or disconnect.
#[derive(Clone)]
pub struct ChainFollowers {
    effects: ChainEffects,
    mining: Arc<crate::mining::MiningGenerationSignal>,
    mempool: Option<Arc<MempoolGateway>>,
}

impl ChainFollowers {
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

    pub(crate) fn mempool_gateway(&self) -> Option<&Arc<MempoolGateway>> {
        self.mempool.as_ref()
    }

    pub(crate) fn committed_connect(&self, block: &Block, outcome: &ConnectOutcome) {
        if let Some(gateway) = &self.mempool {
            let block_txs: Vec<&bitcoin_rs_primitives::Tx> = block.txs.iter().collect();
            gateway.remove_for_block(
                AdmissionOrigin::Block,
                &block_txs,
                &outcome.txids,
                outcome.height,
            );
        }
        self.connected(block, outcome);
    }

    /// Production follower set.
    #[must_use]
    pub fn new(
        effects: ChainEffects,
        mining: Arc<crate::mining::MiningGenerationSignal>,
        mempool: Option<Arc<MempoolGateway>>,
    ) -> Self {
        Self {
            effects,
            mining,
            mempool,
        }
    }

    /// No RPC log, no-op ZMQ, no index, no admission, a fresh mining signal.
    #[must_use]
    pub fn noop() -> Self {
        Self::new(
            ChainEffects::noop(),
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            None,
        )
    }

    /// Capture flags the apply path should honour for later dispatch.
    #[must_use]
    pub fn capture_flags(&self) -> (bool, bool) {
        (self.effects.needs_rawtx(), self.effects.needs_block_bytes())
    }

    /// Post-commit adapters (RPC, ZMQ, index).
    #[must_use]
    pub fn effects(&self) -> &ChainEffects {
        &self.effects
    }

    /// Mutable post-commit adapters, for tests that attach an index after open.
    pub fn effects_mut(&mut self) -> &mut ChainEffects {
        &mut self.effects
    }

    /// Mining generation signal.
    #[must_use]
    pub fn mining(&self) -> &Arc<crate::mining::MiningGenerationSignal> {
        &self.mining
    }

    /// Dispatches a committed connect: RPC/ZMQ/index, mining wake, orphan wake.
    pub fn connected(&self, block: &Block, outcome: &ConnectOutcome) {
        self.effects.connected(block, outcome);
        self.mining.publish_generation();
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.txids);
        }
    }

    /// Dispatches a committed disconnect: RPC/ZMQ/index, mining wake, orphan wake.
    pub fn disconnected(&self, outcome: &DisconnectOutcome) {
        self.effects.disconnected(outcome);
        self.mining.publish_generation();
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.restored_parents);
        }
    }

    /// Connects `block` and dispatches this set before the transition ends.
    ///
    /// See `ARCH-07`: production single-block paths must not finish the
    /// [`bitcoin_rs_chainstate::ChainTransition`] and then dispatch, or a later
    /// connect or disconnect can publish derived effects first.
    pub fn apply_connect(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        block: &Block,
    ) -> core::result::Result<ConnectOutcome, bitcoin_rs_chainstate::ApplyError> {
        let transition = handles.begin_transition()?;
        let mempool_change = self.begin_mempool_change()?;
        match transition.connect(block) {
            Ok(outcome) => {
                self.committed_connect(block, &outcome);
                Self::finish_transition(handles, transition, mempool_change)?;
                Ok(outcome)
            }
            Err(error) => {
                if bitcoin_rs_chainstate::classify_apply_error(&error)
                    == bitcoin_rs_chainstate::WindowApplyDisposition::Fatal
                {
                    drop(mempool_change);
                    drop(transition);
                    return Err(error);
                }
                if let Err(settlement) =
                    Self::finish_transition(handles, transition, mempool_change)
                {
                    tracing::error!(
                        original = %error,
                        finish = %settlement,
                        "chain transition could not be settled after connect refusal"
                    );
                    return Err(settlement);
                }
                Err(error)
            }
        }
    }

    /// Disconnects `block` and dispatches this set before the transition ends.
    ///
    /// See `ARCH-07`. An admission failure is `DisconnectError::Refused`.
    pub fn apply_disconnect(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        block: &Block,
    ) -> core::result::Result<DisconnectOutcome, bitcoin_rs_chainstate::DisconnectError> {
        let transition = handles
            .begin_transition()
            .map_err(|error| bitcoin_rs_chainstate::DisconnectError::Refused(Box::new(error)))?;
        let mut mempool_change = self
            .begin_mempool_change()
            .map_err(|error| bitcoin_rs_chainstate::DisconnectError::Refused(Box::new(error)))?;
        match transition.disconnect(block) {
            Ok(outcome) => {
                self.disconnected(&outcome);
                // Resident entries the lower tip no longer supports leave
                // before the fence finishes, through the same shared view.
                if let (Some(change), Some(gateway)) =
                    (mempool_change.as_ref(), self.mempool_gateway())
                {
                    let chain = bitcoin_rs_rpc::context::ChainAdmissionView::new(
                        handles.utxo_handle(),
                        handles.applied_tip_reader(),
                        handles.block_tree_reader(),
                        handles.network(),
                    );
                    if gateway.remove_for_reorg(change, &chain).is_err() {
                        drop(mempool_change.take());
                        drop(transition);
                        return Err(bitcoin_rs_chainstate::DisconnectError::Fatal {
                            hash: outcome.hash,
                            height: outcome.parent_tip.height.saturating_add(1),
                            source: Box::new(bitcoin_rs_chainstate::ApplyError::Shutdown),
                        });
                    }
                }
                Self::finish_transition(handles, transition, mempool_change).map_err(|error| {
                    bitcoin_rs_chainstate::DisconnectError::Fatal {
                        hash: outcome.hash,
                        height: outcome.parent_tip.height.saturating_add(1),
                        source: Box::new(error),
                    }
                })?;
                Ok(outcome)
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
                    return Err(bitcoin_rs_chainstate::DisconnectError::Fatal {
                        hash,
                        height,
                        source: Box::new(settlement),
                    });
                }
                Err(error)
            }
            Err(error) => {
                drop(mempool_change);
                drop(transition);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolLimits,
        MutationOutcome, PeerToken, SubmitError, SubmitOutcome,
    };
    use bitcoin_rs_primitives::{
        Amount, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
    };
    use parking_lot::Mutex;

    #[derive(Debug, Default)]
    struct RecordingPublisher {
        hashblocks: Mutex<Vec<Hash256>>,
        sequences: Mutex<Vec<SequenceEvent>>,
    }

    impl ZmqPublisher for RecordingPublisher {
        fn publish_hashblock(&self, hash: Hash256) {
            self.hashblocks.lock().push(hash);
        }

        fn publish_hashtx(&self, _: Txid) {}

        fn publish_rawblock(&self, _: &[u8]) {}

        fn publish_rawtx(&self, _: &[u8]) {}

        fn publish_sequence(&self, event: SequenceEvent) {
            self.sequences.lock().push(event);
        }
    }

    /// `ARCH-07`: a no-op consumer set asks for no derived payloads.
    #[test]
    fn noop_asks_for_no_payloads() {
        let effects = ChainEffects::noop();
        assert!(!effects.needs_rawtx());
        assert!(!effects.needs_block_bytes());
        assert!(effects.derived_index().is_none());
        assert!(effects.block_log().read().is_empty());
    }

    /// `ARCH-07`: connect then disconnect rewinds the RPC log and emits ZMQ in order.
    #[test]
    fn connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order() {
        let genesis = Network::Regtest.genesis_block();
        let hash = Hash256::from(genesis.block_hash());
        let publisher = Arc::new(RecordingPublisher::default());
        let zmq: Arc<dyn ZmqPublisher> = publisher.clone();
        let effects = ChainEffects::noop().with_zmq_publisher(zmq);

        effects.record_connected(0, &genesis);
        assert_eq!(effects.block_log().read().len(), 1);
        assert!(publisher.hashblocks.lock().is_empty());
        effects.emit_connected(hash, &[], &[], None);
        assert_eq!(*publisher.hashblocks.lock(), vec![hash]);
        assert!(publisher.sequences.lock().is_empty());

        effects.after_connect(hash);
        assert_eq!(
            *publisher.sequences.lock(),
            vec![SequenceEvent::Connected(hash)]
        );

        effects.before_disconnect(hash);
        assert!(effects.block_log().read().is_empty());
        effects.after_disconnect(hash);
        assert_eq!(
            *publisher.sequences.lock(),
            vec![
                SequenceEvent::Connected(hash),
                SequenceEvent::Disconnected(hash)
            ]
        );
    }

    /// `ARCH-07`: disconnect does not pop a `BlockLog` tail that is not this block.
    #[test]
    fn disconnect_does_not_pop_a_different_tail() {
        let genesis = Network::Regtest.genesis_block();
        let effects = ChainEffects::noop();
        effects.record_connected(0, &genesis);
        effects.before_disconnect(Hash256::from_le_bytes(&[0xAB; 32]));
        assert_eq!(effects.block_log().read().len(), 1);
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
        })
    }

    /// Exercise committed-outcome dispatch with a real gateway, without any
    /// mempool mutation or observer that could independently wake the child.
    /// Full chain application and transition ownership have separate tests in
    /// apply.rs; this checks the follower's lifecycle notification boundary.
    #[allow(clippy::too_many_lines)]
    fn assert_admission_followers_after_chain_change(connect: bool) -> anyhow::Result<()> {
        let gateway = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))));
        let followers = ChainFollowers::new(
            ChainEffects::noop(),
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(Arc::clone(&gateway)),
        );
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
            followers.connected(
                &block,
                &ConnectOutcome {
                    height: tip.height,
                    commit_id: 0,
                    tip,
                    hash,
                    txids: vec![parent],
                    block_bytes: bytes::Bytes::new(),
                    raw_txs: None,
                },
            );
        } else {
            followers.disconnected(&DisconnectOutcome {
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
        assert_eq!(gateway.get_tx(child.txid()).as_ref(), Some(child.as_ref()));
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
        let gateway = MempoolGateway::shared(Arc::new(RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))));
        let followers = ChainFollowers::new(
            ChainEffects::noop(),
            Arc::new(crate::mining::MiningGenerationSignal::new()),
            Some(Arc::clone(&gateway)),
        );
        let active = gateway.begin_chain_change()?;

        assert!(matches!(
            followers.begin_mempool_change(),
            Err(bitcoin_rs_chainstate::ApplyError::ConcurrentChainChange)
        ));
        active.finish()?;
        assert!(followers.begin_mempool_change()?.is_some());
        Ok(())
    }
}
