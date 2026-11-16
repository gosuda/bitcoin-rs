use std::sync::Arc;

use crate::chain_effects::ChainFollowers;
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Tx, Txid};
use bitcoin_rs_execution::chain::{InvalidationOutcome, NodeId};
pub use bitcoin_rs_execution::reorg::ReorgError;
use bitcoin_rs_execution::reorg::ReorgObserver;
use bitcoin_rs_execution::{ApplyError, Chainstate, ConnectOutcome, DisconnectOutcome};
use hashbrown::HashSet;

const MAX_DISCONNECTED_TX_BYTES: usize = 20_000_000;

struct NodeReorgObserver<'a> {
    followers: &'a ChainFollowers,
    connected_body: &'a mut dyn FnMut(Hash256),
    reconnected: HashSet<Txid>,
    disconnected: Vec<Arc<Tx>>,
    disconnected_bytes: usize,
    disconnected_full: bool,
    disconnected_blocks: usize,
    connect_failed: bool,
}

impl<'a> NodeReorgObserver<'a> {
    fn new(followers: &'a ChainFollowers, connected_body: &'a mut dyn FnMut(Hash256)) -> Self {
        Self {
            followers,
            connected_body,
            reconnected: HashSet::new(),
            disconnected: Vec::new(),
            disconnected_bytes: 0,
            disconnected_full: false,
            disconnected_blocks: 0,
            connect_failed: false,
        }
    }
}

impl ReorgObserver for NodeReorgObserver<'_> {
    fn disconnected(&mut self, outcome: &DisconnectOutcome) {
        self.disconnected_blocks += 1;
        self.followers.on_disconnect(outcome);
    }

    fn connected(&mut self, block: &BlockImage, outcome: &ConnectOutcome) {
        self.reconnected
            .extend((0..block.tx_count()).map(|tx| block.identity(tx).txid()));
        if self.followers.on_connect(block, outcome).is_err() {
            self.connect_failed = true;
        }
        (self.connected_body)(outcome.hash);
    }

    fn reconsider_disconnected(&mut self, block: &BlockImage) {
        if self.disconnected_full {
            return;
        }
        for index in 0..block.tx_count() {
            let tx = block.tx(index).materialize();
            let coinbase = tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null();
            if self.reconnected.contains(&tx.txid()) || coinbase {
                continue;
            }
            let tx_size = tx.total_size();
            if self.disconnected_bytes + tx_size > MAX_DISCONNECTED_TX_BYTES {
                self.disconnected_full = true;
                return;
            }
            self.disconnected_bytes += tx_size;
            self.disconnected.push(Arc::new(tx));
        }
    }
}

fn trim_after_reorg(
    gateway: &bitcoin_rs_mempool::MempoolGateway,
) -> Result<(), bitcoin_rs_mempool::MempoolError> {
    gateway.expire(
        bitcoin_rs_mempool::AdmissionOrigin::Reorg,
        bitcoin_rs_consensus::primitives::unix_time_secs(),
    )?;
    let max_bytes = gateway.max_total_bytes();
    if max_bytes == 0 || gateway.read().dynamic_memory_usage() <= max_bytes {
        return Ok(());
    }
    gateway
        .enforce_size_limit(bitcoin_rs_mempool::AdmissionOrigin::Reorg, max_bytes)
        .map(|_| ())
}

fn settle_node_reorg(
    handles: &Chainstate,
    observer: &mut NodeReorgObserver<'_>,
    mempool_change: &mut Option<bitcoin_rs_mempool::ChainChangeGuard>,
    outcome: core::result::Result<(), ReorgError>,
) -> core::result::Result<(), ReorgError> {
    if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
        drop(mempool_change.take());
        return outcome;
    }

    let settlement_failed = (|| {
        if observer.disconnected_blocks == 0 {
            return observer.connect_failed
                || mempool_change
                    .take()
                    .is_some_and(|change| change.finish().is_err());
        }
        let mut settle_failed = observer.connect_failed;
        if let (Some(change), Some(gateway)) = (
            mempool_change.as_ref(),
            observer.followers.mempool_gateway(),
        ) {
            let chain = bitcoin_rs_serving::context::ChainAdmissionView::new(
                handles.utxo_reader(),
                handles.applied_tip_reader(),
                handles.block_tree_reader(),
                handles.network(),
            );
            let reconsidered = !outcome
                .as_ref()
                .is_err_and(ReorgError::reconsideration_failed);
            if reconsidered {
                let _ = gateway.reconsider_disconnected(
                    change,
                    &chain,
                    bitcoin_rs_consensus::primitives::unix_time_secs(),
                    observer.disconnected.drain(..),
                );
            }
            let commit_id = handles.durable_commit_id();
            if observer.connect_failed
                || gateway.remove_for_reorg(change, &chain, commit_id).is_err()
                || (reconsidered && trim_after_reorg(gateway.as_ref()).is_err())
            {
                settle_failed = true;
            } else if let Some(tip) = handles.applied_tip_snapshot() {
                observer
                    .followers
                    .epoch()
                    .advance((*tip).clone(), commit_id);
                observer.followers.mining().publish_generation();
            }
        }
        settle_failed
            || mempool_change
                .take()
                .is_some_and(|change| change.finish().is_err())
    })();
    if settlement_failed {
        return Err(ReorgError::TransitionSettlement {
            source: Box::new(ApplyError::Shutdown),
            original: outcome.err().map(Box::new),
        });
    }
    outcome
}

fn settle_checkpoint_debt<T>(
    handles: &Chainstate,
    outcome: core::result::Result<T, ReorgError>,
) -> core::result::Result<T, ReorgError> {
    if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
        return outcome;
    }
    match handles.settle_disconnect_debt() {
        Ok(true) => {
            tracing::info!("published checkpoint after branch switch");
            outcome
        }
        Ok(false) => outcome,
        Err(source) => {
            tracing::error!(%source, "reorg checkpoint debt remains unsettled");
            Err(ReorgError::CheckpointSettlement {
                source,
                original: outcome.err().map(Box::new),
            })
        }
    }
}

pub fn invalidate_block(
    handles: &Chainstate,
    followers: &ChainFollowers,
    hash: Hash256,
) -> core::result::Result<InvalidationOutcome, ReorgError> {
    let mut mempool_change = followers
        .begin_mempool_change()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;
    let mut connected_body = |_| {};
    let mut observer = NodeReorgObserver::new(followers, &mut connected_body);
    let outcome = bitcoin_rs_execution::reorg::invalidate_block(
        handles,
        &mut observer,
        hash,
        |observer, outcome| settle_node_reorg(handles, observer, &mut mempool_change, outcome),
    );
    settle_checkpoint_debt(handles, outcome)
}

pub fn switch_to_branch<F, G>(
    handles: &Chainstate,
    followers: &ChainFollowers,
    target: NodeId,
    mut staged_body: F,
    mut connected_body: G,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<bitcoin_rs_consensus::primitives::BlockImage>,
    G: FnMut(Hash256),
{
    let mut mempool_change = followers
        .begin_mempool_change()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;
    let mut observer = NodeReorgObserver::new(followers, &mut connected_body);
    let outcome = bitcoin_rs_execution::reorg::switch_to_branch(
        handles,
        target,
        &mut staged_body,
        &mut observer,
        |observer, outcome| settle_node_reorg(handles, observer, &mut mempool_change, outcome),
    );
    settle_checkpoint_debt(handles, outcome)
}
