use crate::facts_queue::FactsQueue;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{BlockHash, BlockImage, Hash256};
use bitcoin_rs_projection::block_log::{BlockLog, BlockRecord};
use parking_lot::RwLock;

use bitcoin_rs_execution::{ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_mempool::ChainChangeGuard;
use bitcoin_rs_mempool::MempoolGateway;
use bitcoin_rs_mempool::MutationResult;
use bitcoin_rs_projection::runtime::DerivedIndexRuntime;
use bitcoin_rs_serving::zmq::{SequenceEvent, ZmqPublisher};

#[derive(Debug, thiserror::Error)]
pub enum ConnectMutationError {
    #[error("connect did not produce a committed outcome: {0}")]
    NotCommitted(#[source] bitcoin_rs_execution::ApplyError),
    #[error("authoritative connect committed, but node settlement failed: {source}")]
    CommittedButSettlementFailed {
        outcome: Box<ConnectOutcome>,
        #[source]
        source: bitcoin_rs_execution::ApplyError,
    },
    #[error("authoritative connect committed, but mempool settlement was refused: {source}")]
    CommittedButMempoolSettlementRefused {
        outcome: Box<ConnectOutcome>,
        #[source]
        source: bitcoin_rs_mempool::MempoolError,
    },
}
#[derive(Clone, Debug)]
pub struct EpochCell {
    inner: Arc<parking_lot::RwLock<Option<bitcoin_rs_execution::chain::AppliedEpoch>>>,
}

impl Default for EpochCell {
    fn default() -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(None)),
        }
    }
}

impl EpochCell {
    #[must_use]
    pub fn new(initial: Option<bitcoin_rs_execution::chain::AppliedEpoch>) -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(initial)),
        }
    }

    #[must_use]
    pub fn current(&self) -> Option<bitcoin_rs_execution::chain::AppliedEpoch> {
        self.inner.read().clone()
    }

    pub fn advance(&self, tip: bitcoin_rs_execution::chain::TipSnapshot, commit_id: u64) {
        *self.inner.write() = Some(bitcoin_rs_execution::chain::AppliedEpoch::new(
            tip, commit_id,
        ));
    }

    pub fn reset(&self) {
        *self.inner.write() = None;
    }
}

#[derive(Clone)]
pub struct ChainFollowers {
    blocks: Arc<RwLock<BlockLog>>,
    zmq: Arc<dyn ZmqPublisher>,
    derived_index: Option<Arc<DerivedIndexRuntime>>,
    facts_queue: Option<Arc<FactsQueue>>,
    mining: Arc<crate::mining::MiningGenerationSignal>,
    mempool: Option<Arc<MempoolGateway>>,
    block_announcer: Option<crate::p2p::block_announce::BlockAnnounceQueue>,
    epoch: EpochCell,
}

impl ChainFollowers {
    #[must_use]
    pub(crate) fn new(
        blocks: Arc<RwLock<BlockLog>>,
        zmq: Arc<dyn ZmqPublisher>,
        derived_index: Option<Arc<DerivedIndexRuntime>>,
        facts_queue: Option<Arc<FactsQueue>>,
        mining: Arc<crate::mining::MiningGenerationSignal>,
        mempool: Option<Arc<MempoolGateway>>,
    ) -> Self {
        Self {
            blocks,
            zmq,
            derived_index,
            facts_queue,
            mining,
            mempool,
            block_announcer: None,
            epoch: EpochCell::default(),
        }
    }

    #[must_use]
    pub fn noop() -> Self {
        Self::new(
            Arc::new(RwLock::new(BlockLog::new())),
            Arc::new(crate::NoOpZmqPublisher),
            None,
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
    pub fn epoch(&self) -> EpochCell {
        self.epoch.clone()
    }

    #[must_use]
    pub fn with_facts_queue(mut self, facts_queue: Option<Arc<FactsQueue>>) -> Self {
        self.facts_queue = facts_queue;
        self
    }

    #[must_use]
    pub fn with_block_announcer(
        mut self,
        block_announcer: Option<crate::p2p::block_announce::BlockAnnounceQueue>,
    ) -> Self {
        self.block_announcer = block_announcer;
        self
    }

    #[must_use]
    pub(crate) fn wants_committed_facts(&self) -> bool {
        self.facts_queue.is_some()
    }

    #[must_use]
    pub fn needs_rawtx(&self) -> bool {
        self.zmq.wants_rawtx()
    }

    #[must_use]
    pub fn needs_block_bytes(&self) -> bool {
        self.zmq.wants_rawblock()
    }

    #[must_use]
    pub fn block_log_reader(&self) -> bitcoin_rs_projection::BlockLogReader {
        bitcoin_rs_projection::BlockLogReader::new(Arc::clone(&self.blocks))
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
    ) -> core::result::Result<Option<ChainChangeGuard>, bitcoin_rs_execution::ApplyError> {
        self.mempool
            .as_ref()
            .map(|gateway| {
                gateway.begin_chain_change().map_err(|error| match error {
                    bitcoin_rs_mempool::ChainChangeError::AlreadyActive
                    | bitcoin_rs_mempool::ChainChangeError::GenerationMoved
                    | bitcoin_rs_mempool::ChainChangeError::ForeignGuard
                    | bitcoin_rs_mempool::ChainChangeError::DeliveryQueueFull => {
                        bitcoin_rs_execution::ApplyError::ConcurrentChainChange
                    }
                    bitcoin_rs_mempool::ChainChangeError::Overflow => {
                        bitcoin_rs_execution::ApplyError::ChainChangeGenerationOverflow
                    }
                })
            })
            .transpose()
    }

    pub(crate) fn finish_transition(
        handles: &bitcoin_rs_execution::Chainstate,
        transition: bitcoin_rs_execution::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
    ) -> core::result::Result<(), bitcoin_rs_execution::ApplyError> {
        if let Some(change) = mempool_change
            && change.finish().is_err()
        {
            handles.fail_closed_for_recovery();
            return Err(bitcoin_rs_execution::ApplyError::Shutdown);
        }
        drop(transition);
        Ok(())
    }

    pub(crate) fn on_connect(
        &self,
        payload: &BlockImage,
        outcome: &ConnectOutcome,
    ) -> Result<(), bitcoin_rs_mempool::MempoolError> {
        let on_connect_started = quanta::Instant::now();
        let block_removals = if let Some(gateway) = &self.mempool {
            let facts = match &outcome.committed_facts {
                Some(committed) => bitcoin_rs_mempool::TransitionFacts::from_committed(committed),
                None => bitcoin_rs_mempool::TransitionFacts::from_block(payload),
            };
            gateway.settle_block_facts(
                AdmissionOrigin::Block,
                &facts,
                outcome.commit_id,
                outcome.height,
                bitcoin_rs_consensus::primitives::unix_time_secs(),
            )?
        } else {
            MutationResult::empty()
        };
        self.epoch.advance(outcome.tip.clone(), outcome.commit_id);
        self.blocks
            .write()
            .push(BlockRecord::from_image(outcome.height, payload));
        self.publish_block(outcome);
        if let Some(facts_queue) = &self.facts_queue {
            if let Some(facts) = &outcome.committed_facts {
                facts_queue.try_push(Arc::clone(facts));
            }
        }
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
        Ok(())
    }

    pub(crate) fn on_disconnect(&self, outcome: &DisconnectOutcome) {
        if let Some(facts_queue) = &self.facts_queue {
            facts_queue.set_gap();
        }
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
        self.epoch.reset();
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
        handles: &bitcoin_rs_execution::Chainstate,
        payload: &BlockImage,
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
        handles: &bitcoin_rs_execution::Chainstate,
        transition: bitcoin_rs_execution::ChainTransition<'_>,
        mempool_change: Option<ChainChangeGuard>,
        payload: &BlockImage,
    ) -> core::result::Result<ConnectOutcome, ConnectMutationError> {
        match transition.connect(payload) {
            Ok(outcome) => {
                if let Err(source) = self.on_connect(payload, &outcome) {
                    handles.fail_closed_for_recovery();
                    return Err(ConnectMutationError::CommittedButMempoolSettlementRefused {
                        outcome: Box::new(outcome),
                        source,
                    });
                }
                match Self::finish_transition(handles, transition, mempool_change) {
                    Ok(()) => Ok(outcome),
                    Err(source) => Err(ConnectMutationError::CommittedButSettlementFailed {
                        outcome: Box::new(outcome),
                        source,
                    }),
                }
            }
            Err(error) => {
                if bitcoin_rs_execution::classify_apply_error(&error)
                    == bitcoin_rs_execution::WindowApplyDisposition::Fatal
                {
                    handles.fail_closed_for_recovery();
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
    handles: &bitcoin_rs_execution::Chainstate,
    followers: &ChainFollowers,
) -> Result<(), ConnectMutationError> {
    if handles.applied_tip_snapshot().is_some() {
        return Ok(());
    }
    let genesis = handles.network().genesis_block();
    let payload = BlockImage::from_local(genesis);
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
mod tests;
