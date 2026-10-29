use std::sync::Arc;

use bitcoin_rs_index::block_log::{BlockLog, BlockRecord};
use bitcoin_rs_primitives::{Block, BlockHash, BlockPayload, Hash256};
use parking_lot::RwLock;

use bitcoin_rs_chainstate::{ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_index::runtime::DerivedIndexRuntime;
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_mempool::ChainChangeGuard;
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_mempool::MutationResult;
use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

#[derive(Debug, thiserror::Error)]
pub enum ConnectMutationError {
    #[error("connect did not produce a committed outcome: {0}")]
    NotCommitted(#[source] bitcoin_rs_chainstate::ApplyError),
    #[error("authoritative connect committed, but node settlement failed: {source}")]
    CommittedButSettlementFailed {
        outcome: Box<ConnectOutcome>,
        #[source]
        source: bitcoin_rs_chainstate::ApplyError,
    },
}

/// INVARIANT: consumer failure is ignored. A full ZMQ socket or a lagged
/// index cannot invalidate chainstate.
#[derive(Clone)]
pub struct ChainFollowers {
    blocks: Arc<RwLock<BlockLog>>,
    zmq: Arc<dyn ZmqPublisher>,
    derived_index: Option<Arc<DerivedIndexRuntime>>,
    mining: Arc<crate::mining::MiningGenerationSignal>,
    mempool: Option<Arc<MempoolGateway>>,
    block_announcer: Option<bitcoin_rs_p2p::BlockAnnounceQueue>,
}

impl ChainFollowers {
    #[must_use]
    pub(crate) fn new(
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
            block_announcer: None,
        }
    }

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

    #[cfg(test)]
    #[must_use]
    pub fn with_zmq_publisher(mut self, publisher: Arc<dyn ZmqPublisher>) -> Self {
        self.zmq = publisher;
        self
    }

    #[must_use]
    pub fn with_tx_index(mut self, derived_index: Option<Arc<DerivedIndexRuntime>>) -> Self {
        self.derived_index = derived_index;
        self
    }

    #[must_use]
    pub fn with_block_announcer(
        mut self,
        block_announcer: Option<bitcoin_rs_p2p::BlockAnnounceQueue>,
    ) -> Self {
        self.block_announcer = block_announcer;
        self
    }

    #[must_use]
    pub fn needs_rawtx(&self) -> bool {
        self.zmq.wants_rawtx()
    }

    #[must_use]
    pub fn needs_block_bytes(&self) -> bool {
        self.derived_index.is_some() || self.zmq.wants_rawblock()
    }

    #[must_use]
    pub fn block_log_reader(&self) -> bitcoin_rs_index::BlockLogReader {
        bitcoin_rs_index::BlockLogReader::new(Arc::clone(&self.blocks))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn block_log(&self) -> &Arc<RwLock<BlockLog>> {
        &self.blocks
    }

    #[must_use]
    pub(crate) fn zmq_publisher(&self) -> Arc<dyn ZmqPublisher> {
        Arc::clone(&self.zmq)
    }

    #[cfg(test)]
    #[must_use]
    pub fn derived_index(&self) -> Option<&Arc<DerivedIndexRuntime>> {
        self.derived_index.as_ref()
    }

    #[must_use]
    pub(crate) fn mining(&self) -> &Arc<crate::mining::MiningGenerationSignal> {
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

    pub(crate) fn on_connect(&self, block: &Block, outcome: &ConnectOutcome) {
        let on_connect_started = quanta::Instant::now();
        let block_removals = if let Some(gateway) = &self.mempool {
            let block_txs: Vec<&bitcoin_rs_primitives::Tx> = block.txs.iter().collect();
            gateway.remove_for_block(
                AdmissionOrigin::Block,
                &block_txs,
                &outcome.txids,
                outcome.height,
                bitcoin_rs_primitives::unix_time_secs(),
            )
        } else {
            MutationResult::empty()
        };
        self.blocks
            .write()
            .push(BlockRecord::from_block(outcome.height, block));
        self.publish_block(outcome);
        self.wake_index();
        if self.zmq.wants_notifications() {
            self.zmq
                .publish_sequence(SequenceEvent::Connected(outcome.hash));
        }
        self.mining
            .publish_block_generation(outcome.hash, &block_removals);
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.txids);
        }
        if let Some(announcer) = &self.block_announcer {
            announcer.wake();
        }
        tracing::debug!(
            height = outcome.height,
            tip_hash = %outcome.hash,
            on_connect_us = on_connect_started.elapsed().as_micros(),
            "chain_effects: on_connect profile"
        );
    }

    pub(crate) fn on_disconnect(&self, outcome: &DisconnectOutcome) {
        self.pop_matching_tail(outcome.hash);
        self.wake_index();
        if self.zmq.wants_notifications() {
            self.zmq
                .publish_sequence(SequenceEvent::Disconnected(outcome.hash));
        }
        self.mining.publish_generation();
        if let Some(admission) = &self.mempool {
            admission.chain_changed(&outcome.restored_parents);
        }
    }

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

    fn pop_matching_tail(&self, hash: Hash256) {
        let mut blocks = self.blocks.write();
        if blocks
            .last()
            .is_some_and(|record| record.hash == BlockHash::from(hash))
        {
            blocks.pop();
        }
    }

    pub(crate) fn on_snapshot(&self) {
        if let Some(gateway) = &self.mempool {
            gateway.snapshot_changed();
        }
        self.blocks.write().clear();
        self.wake_index();
        self.mining.publish_generation();
    }

    fn wake_index(&self) {
        if let Some(runtime) = &self.derived_index {
            runtime.wake();
        }
    }

    pub(crate) fn apply_connect(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        payload: &BlockPayload,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        let transition = handles
            .begin_transition()
            .map_err(ConnectMutationError::NotCommitted)?;
        let mempool_change = self
            .begin_mempool_change()
            .map_err(ConnectMutationError::NotCommitted)?;
        self.apply_connect_in_transition(handles, transition, mempool_change, payload)
    }

    pub(crate) fn apply_connect_in_transition(
        &self,
        handles: &bitcoin_rs_chainstate::Chainstate,
        transition: bitcoin_rs_chainstate::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
        payload: &BlockPayload,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        match transition.connect(payload) {
            Ok(outcome) => {
                self.on_connect(payload.block(), &outcome);
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
}

pub(crate) fn bootstrap_genesis(
    handles: &bitcoin_rs_chainstate::Chainstate,
    followers: &ChainFollowers,
) -> Result<(), ConnectMutationError> {
    if handles.applied_tip_snapshot().is_some() {
        return Ok(());
    }
    let genesis = handles.network().genesis_block();
    let payload = BlockPayload::from_local(genesis);
    match followers.apply_connect(handles, &payload) {
        Ok(outcome) => handles.publish_genesis_tip(outcome.tip),
        Err(error) => {
            if let ConnectMutationError::CommittedButSettlementFailed { outcome, .. } = &error {
                handles.publish_genesis_tip(outcome.tip.clone());
            }
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
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

    #[test]
    fn disconnect_does_not_pop_a_different_tail() -> anyhow::Result<()> {
        let genesis = Network::Regtest.genesis_block();
        let tip = genesis_tip(&genesis)?;
        let followers = ChainFollowers::noop();
        followers.on_connect(&genesis, &connect_outcome(&tip, &genesis));
        followers.on_disconnect(&DisconnectOutcome {
            hash: Hash256::from_le_bytes(&[0xAB; 32]),
            restored_parents: Vec::new(),
        });
        assert_eq!(followers.block_log().read().len(), 1);
        Ok(())
    }

    #[derive(Default)]
    struct ReceiptWake {
        receipts: Mutex<Vec<(Hash256, usize)>>,
    }

    impl bitcoin_rs_mining::MempoolSequenceWake for ReceiptWake {
        fn publish_generation_from(&self, _: u64) {}

        fn stage_tip(&self, _: &TipSnapshot, _: &Block) {}

        fn publish_block_generation(&self, tip_hash: Hash256, removals: &MutationResult) {
            self.receipts
                .lock()
                .push((tip_hash, removals.changes.len()));
        }
    }

    #[test]
    fn gatewayless_connect_publishes_an_empty_receipt_for_the_tip() -> anyhow::Result<()> {
        let genesis = Network::Regtest.genesis_block();
        let tip = genesis_tip(&genesis)?;
        let wake = Arc::new(ReceiptWake::default());
        let wake_handle: Arc<dyn bitcoin_rs_mining::MempoolSequenceWake> = wake.clone();
        let followers = ChainFollowers::noop();
        followers.mining().attach_sequence_wake(&wake_handle);
        assert!(followers.mempool_gateway().is_none());

        followers.on_connect(&genesis, &connect_outcome(&tip, &genesis));
        assert_eq!(
            *wake.receipts.lock(),
            vec![(tip.hash, 0)],
            "one receipt for the connected tip, naming no removals"
        );
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
                next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
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
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]),
            }],
            lock_time: LockTime::ZERO,
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

    #[test]
    fn snapshot_reconciles_empty_pool_and_index_without_fabricating_block_events()
    -> anyhow::Result<()> {
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let publisher = Arc::new(RecordingPublisher::default());
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
        let followers = followers_with_gateway(&gateway)
            .with_zmq_publisher(publisher.clone())
            .with_tx_index(Some(Arc::new(DerivedIndexRuntime::new(wake_tx))));
        let fence = followers
            .begin_mempool_change()?
            .ok_or_else(|| anyhow::anyhow!("missing fence"))?;
        followers.on_snapshot();
        assert!(gateway.read().is_empty());
        assert!(gateway.stable_generation().is_none());
        assert!(wake_rx.try_recv().is_ok());
        assert_eq!(publisher.events(), Vec::<String>::new());
        assert!(followers.block_log().read().is_empty());
        fence.finish()?;
        assert!(gateway.stable_generation().is_some());
        Ok(())
    }

    #[test]
    fn snapshot_retries_each_resident_orphan_once_after_settlement() -> anyhow::Result<()> {
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let followers = followers_with_gateway(&gateway);
        let now = bitcoin_rs_primitives::unix_time_secs();
        let parent = Network::Regtest.genesis_block().txs[0].txid();
        let available = orphan_child(OutPoint::new(parent, 0));
        let missing = orphan_child(OutPoint::new(Hash256::from_le_bytes(&[43; 32]).into(), 0));
        let source = PeerToken {
            endpoint: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18444)).into()),
            addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18444)).into()),
            connection_id: 7,
        };
        let replacement = PeerToken {
            connection_id: 8,
            ..source
        };
        let missing_source = PeerToken {
            endpoint: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18445)).into()),
            addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18445)).into()),
            connection_id: 9,
        };
        let chain = AdmissionCoins::default();
        for (orphan, announcer) in [
            (&available, source),
            (&available, replacement),
            (&missing, missing_source),
        ] {
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(orphan),
                    AdmissionOrigin::Peer(announcer),
                    None,
                    now,
                    &chain,
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
        }
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.orphan_count(), 2);
        assert!(!gateway.has_observer());
        let fence = gateway.begin_chain_change()?;
        gateway.chain_changed(&[missing.inputs[0].previous_output.txid]);
        *chain.prevouts.write() = vec![(
            available.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
        )];
        followers.on_snapshot();
        followers.on_snapshot();
        gateway.maintain_orphans(now, [replacement, missing_source]);
        assert_eq!(gateway.retry_orphans(&chain, now), []);
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.orphan_count(), 2);
        assert_eq!(gateway.read().sequence_number(), 0);
        fence.finish()?;

        let retries = gateway.retry_orphans(&chain, now);
        assert_eq!(retries.len(), 2, "one retry per resident witness identity");
        let accepted = retries
            .iter()
            .find(|retry| retry.wtxid == available.wtxid())
            .ok_or_else(|| anyhow::anyhow!("snapshot did not schedule the newly funded orphan"))?;
        assert_eq!(accepted.source, replacement);
        assert!(matches!(accepted.result, Ok(SubmitOutcome::Committed(_))));
        let retained = retries
            .iter()
            .find(|retry| retry.wtxid == missing.wtxid())
            .ok_or_else(|| anyhow::anyhow!("snapshot lost the still-missing orphan"))?;
        assert_eq!(retained.source, missing_source);
        assert!(matches!(retained.result, Ok(SubmitOutcome::Held { .. })));
        assert!(gateway.read().contains_txid(&available.txid()));
        assert_eq!(gateway.orphan_count(), 1);
        assert_eq!(
            gateway.get_tx_by_wtxid(missing.wtxid()).as_ref(),
            Some(missing.as_ref())
        );
        assert_eq!(gateway.read().sequence_number(), 1);
        assert_eq!(gateway.retry_orphans(&chain, now), []);
        Ok(())
    }

    fn assert_admission_followers_after_chain_change(connect: bool) -> anyhow::Result<()> {
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
        let followers = followers_with_gateway(&gateway);
        let now = bitcoin_rs_primitives::unix_time_secs();
        let block = Network::Regtest.genesis_block();
        let parent = block.txs[0].txid();
        let outpoint = OutPoint::new(parent, 0);
        let child = orphan_child(outpoint);
        let source = PeerToken {
            endpoint: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18444)).into()),
            addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18444)).into()),
            connection_id: 7,
        };
        let chain = AdmissionCoins::default();
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&child),
                AdmissionOrigin::Peer(source),
                None,
                now,
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
                now,
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
        assert_eq!(gateway.retry_orphans(&chain, now), []);
        assert_eq!(
            gateway.get_tx_by_wtxid(child.wtxid()).as_ref(),
            Some(child.as_ref())
        );
        assert_eq!(gateway.orphan_count(), 1);
        assert_eq!(gateway.read().sequence_number(), 0);

        change.finish()?;
        let retries = gateway.retry_orphans(&chain, now);
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
        assert_eq!(gateway.retry_orphans(&chain, now), []);
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
        let gateway = Arc::new(MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            None,
            ValidationEngine::Native,
            None,
        ));
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
        let genesis = BlockPayload::from_local(Network::Regtest.genesis_block());
        let hash = Hash256::from(genesis.block().block_hash());

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
    fn mining_reports_a_committed_settlement_failure_as_accepted() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        let followers = settlement_breaking_followers(state.mempool_gateway(), 3);
        let mining = crate::MiningCoordinator::new(
            state.mempool_reader(),
            state.chainstate(),
            state.stable_read(),
            followers,
            Vec::new(),
        );

        assert_eq!(
            mining.submit_block(BlockPayload::from_local(Network::Regtest.genesis_block()))?,
            BlockValidationResult::Accepted,
            "submitblock must not invite retry after authoritative commit"
        );
        assert!(
            state
                .chainstate()
                .shutdown_handle()
                .load(std::sync::atomic::Ordering::Acquire)
        );
        Ok(())
    }
}
