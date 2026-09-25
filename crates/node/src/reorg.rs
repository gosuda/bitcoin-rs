//! Node-owned coordination around authoritative chainstate reorgs.

use std::sync::Arc;

use crate::chain_effects::ChainFollowers;
use bitcoin_rs_chain::NodeId;
pub use bitcoin_rs_chainstate::reorg::ReorgError;
use bitcoin_rs_chainstate::reorg::ReorgObserver;
use bitcoin_rs_chainstate::{ApplyError, Chainstate, ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_primitives::{Block, Hash256, Tx, Txid};
use hashbrown::HashSet;

/// Core's `MAX_DISCONNECTED_TX_POOL_BYTES`: the serialized-byte ceiling on
/// the reorg re-admission candidate set.
///
/// Once the cap is hit the observer stops collecting for the rest of the
/// reorg. Blocks stream oldest-first so parents arrive before their
/// descendants; the candidates dropped are therefore the newest
/// descendants, which later fail admission as missing inputs — that is the
/// defined overload outcome, never a partially admitted family root.
const MAX_DISCONNECTED_TX_BYTES: usize = 20_000_000;

struct NodeReorgObserver<'a> {
    followers: &'a ChainFollowers,
    connected_body: &'a mut dyn FnMut(Hash256),
    reconnected: HashSet<Txid>,
    disconnected: Vec<Arc<Tx>>,
    disconnected_bytes: usize,
    disconnected_full: bool,
    disconnected_blocks: usize,
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
        }
    }
}

impl ReorgObserver for NodeReorgObserver<'_> {
    fn disconnected(&mut self, outcome: &DisconnectOutcome) {
        self.disconnected_blocks += 1;
        self.followers.disconnected(outcome);
    }

    fn connected(&mut self, block: &Block, outcome: &ConnectOutcome) {
        self.reconnected
            .extend(block.txs.iter().map(bitcoin_rs_primitives::Tx::txid));
        self.followers.committed_connect(block, outcome);
        (self.connected_body)(outcome.hash);
    }

    fn reconsider_disconnected(&mut self, block: &Block) {
        if self.disconnected_full {
            return;
        }
        for tx in &block.txs {
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
            self.disconnected.push(Arc::new(tx.clone()));
        }
    }
}

/// Settles one reorg outcome while the mempool fence is held. A settle that
/// disconnected nothing leaves the pool untouched: `switch_to_branch` is
/// polled while a heavier branch is still downloading, and the resident
/// sweep costs a chain snapshot per resident entry.
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
            return mempool_change
                .take()
                .is_some_and(|change| change.finish().is_err());
        }
        if let (Some(change), Some(gateway)) = (
            mempool_change.as_ref(),
            observer.followers.mempool_gateway(),
        ) {
            let chain = bitcoin_rs_rpc::context::ChainAdmissionView::new(
                handles.utxo_handle(),
                handles.applied_tip_reader(),
                handles.block_tree_reader(),
                handles.network(),
            );
            if !outcome
                .as_ref()
                .is_err_and(ReorgError::reconsideration_failed)
            {
                let _ = gateway.reconsider_disconnected(
                    change,
                    &chain,
                    crate::tx_ingress::unix_time_secs(),
                    observer.disconnected.drain(..),
                );
            }
            if gateway.remove_for_reorg(change, &chain).is_err() {
                return true;
            }
        }
        mempool_change
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

fn settle_checkpoint_debt(
    handles: &Chainstate,
    outcome: core::result::Result<(), ReorgError>,
) -> core::result::Result<(), ReorgError> {
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

/// Invalidates one block through chainstate while node-owned followers remain fenced.
///
/// On success returns the hashes chainstate marked `Invalid`; the caller purges
/// staged and download state after the transition has settled.
pub fn invalidate_block(
    handles: &Chainstate,
    followers: &ChainFollowers,
    hash: Hash256,
) -> core::result::Result<Box<[Hash256]>, ReorgError> {
    let mut mempool_change = followers
        .begin_mempool_change()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;
    let mut connected_body = |_| {};
    let mut observer = NodeReorgObserver::new(followers, &mut connected_body);
    let outcome = bitcoin_rs_chainstate::reorg::invalidate_block(
        handles,
        &mut observer,
        hash,
        |observer, outcome| settle_node_reorg(handles, observer, &mut mempool_change, outcome),
    );
    let invalidated = outcome.as_ref().ok().cloned().unwrap_or_default();
    settle_checkpoint_debt(handles, outcome.map(|_| ())).map(|()| invalidated)
}

/// Switches the applied branch through chainstate while node-owned followers remain fenced.
pub fn switch_to_branch<F, G>(
    handles: &Chainstate,
    followers: &ChainFollowers,
    target: NodeId,
    mut staged_body: F,
    mut connected_body: G,
) -> core::result::Result<(), ReorgError>
where
    F: FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
    G: FnMut(Hash256),
{
    let mut mempool_change = followers
        .begin_mempool_change()
        .map_err(|source| ReorgError::Unavailable(Box::new(source)))?;
    let mut observer = NodeReorgObserver::new(followers, &mut connected_body);
    let outcome = bitcoin_rs_chainstate::reorg::switch_to_branch(
        handles,
        target,
        &mut staged_body,
        &mut observer,
        |observer, outcome| settle_node_reorg(handles, observer, &mut mempool_change, outcome),
    );
    settle_checkpoint_debt(handles, outcome)
}
