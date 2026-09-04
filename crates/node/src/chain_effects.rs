//! Derived consumers of committed chain transitions.
//!
//! Ownership and ordering are specified by `ARCH-07` in
//! [`docs/contracts/architecture.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md). Apply does not import these consumers.

use std::sync::Arc;

use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Txid};
use bitcoin_rs_rpc::context::{BlockLog, BlockRecord};
use parking_lot::RwLock;

use crate::apply::{ConnectOutcome, DisconnectOutcome};
use crate::tx_admission::TxAdmission;
use crate::txindex_worker::TxIndexRuntime;
use crate::zmq_publisher::{SequenceEvent, ZmqPublisher};

/// Post-commit adapters that follow a committed chain transition.
///
/// Consumer failure is ignored. A full ZMQ socket or a lagged index cannot
/// invalidate chainstate.
#[derive(Clone)]
pub struct ChainEffects {
    blocks: Arc<RwLock<BlockLog>>,
    zmq: Arc<dyn ZmqPublisher>,
    tx_index: Option<Arc<TxIndexRuntime>>,
}

impl ChainEffects {
    /// Builds the production consumer set.
    #[must_use]
    pub fn new(
        blocks: Arc<RwLock<BlockLog>>,
        zmq: Arc<dyn ZmqPublisher>,
        tx_index: Option<Arc<TxIndexRuntime>>,
    ) -> Self {
        Self {
            blocks,
            zmq,
            tx_index,
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
    pub fn with_tx_index(mut self, tx_index: Option<Arc<TxIndexRuntime>>) -> Self {
        self.tx_index = tx_index;
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
        self.tx_index.is_some() || self.zmq.wants_rawblock()
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
        if let Some(runtime) = &self.tx_index {
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
    pub fn tx_index(&self) -> Option<&Arc<TxIndexRuntime>> {
        self.tx_index.as_ref()
    }

    /// Replaces the `TxIndex` wake handle in place for tests that attach a worker
    /// after constructing the facade.
    pub fn set_tx_index(&mut self, tx_index: Option<Arc<TxIndexRuntime>>) {
        self.tx_index = tx_index;
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
    tx_admission: Option<Arc<TxAdmission>>,
}

impl ChainFollowers {
    /// Production follower set.
    #[must_use]
    pub fn new(
        effects: ChainEffects,
        mining: Arc<crate::mining::MiningGenerationSignal>,
        tx_admission: Option<Arc<TxAdmission>>,
    ) -> Self {
        Self {
            effects,
            mining,
            tx_admission,
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
        if let Some(admission) = &self.tx_admission {
            admission.invalidate_recent_rejects();
            for txid in &outcome.txids {
                admission.enqueue_orphans_waiting_on(*txid);
            }
        }
    }

    /// Dispatches a committed disconnect: RPC/ZMQ/index, mining wake, orphan wake.
    pub fn disconnected(&self, outcome: &DisconnectOutcome) {
        self.effects.disconnected(outcome);
        self.mining.publish_generation();
        if let Some(admission) = &self.tx_admission {
            admission.invalidate_recent_rejects();
            for parent in &outcome.restored_parents {
                admission.enqueue_orphans_waiting_on(*parent);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_primitives::Network;
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
        assert!(effects.tx_index().is_none());
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
}
