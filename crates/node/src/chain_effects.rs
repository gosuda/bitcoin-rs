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
mod tests;
