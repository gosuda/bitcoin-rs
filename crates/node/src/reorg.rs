//! Node-owned coordination around authoritative chainstate reorgs.

use crate::chain_effects::ChainFollowers;
use bitcoin_rs_chain::NodeId;
pub use bitcoin_rs_chainstate::reorg::ReorgError;
use bitcoin_rs_chainstate::reorg::ReorgObserver;
use bitcoin_rs_chainstate::{ApplyError, Chainstate, ConnectOutcome, DisconnectOutcome};
use bitcoin_rs_mempool::AdmissionOrigin;
use bitcoin_rs_primitives::{Block, Hash256, Txid};
use hashbrown::HashSet;

struct NodeReorgObserver<'a> {
    followers: &'a ChainFollowers,
    connected_body: &'a mut dyn FnMut(Hash256),
    reconnected: HashSet<Txid>,
    candidates: Option<bitcoin_rs_mempool::reconsider::DisconnectedCandidates>,
}

impl<'a> NodeReorgObserver<'a> {
    fn new(followers: &'a ChainFollowers, connected_body: &'a mut dyn FnMut(Hash256)) -> Self {
        Self {
            followers,
            connected_body,
            reconnected: HashSet::new(),
            candidates: None,
        }
    }

    fn finish_reconsideration(&mut self) {
        let Some(candidates) = self.candidates.take() else {
            return;
        };
        if let Some(gateway) = self.followers.mempool_gateway() {
            let _ =
                gateway.reconsider_disconnected(AdmissionOrigin::Reorg, candidates.into_entries());
        }
    }

    fn discard_reconsideration(&mut self) {
        self.candidates = None;
    }
}

impl ReorgObserver for NodeReorgObserver<'_> {
    fn disconnected(&mut self, outcome: &DisconnectOutcome) {
        self.followers.disconnected(outcome);
    }

    fn connected(&mut self, block: &Block, outcome: &ConnectOutcome) {
        self.reconnected
            .extend(block.txs.iter().map(bitcoin_rs_primitives::Tx::txid));
        self.followers.committed_connect(block, outcome);
        (self.connected_body)(outcome.hash);
    }

    fn reconsider_disconnected(
        &mut self,
        block: &Block,
        utxo: &bitcoin_rs_utxo::UtxoSet,
        height: u32,
        time: u64,
    ) {
        let candidates = self.candidates.get_or_insert_with(|| {
            bitcoin_rs_mempool::reconsider::DisconnectedCandidates::new(time, height)
        });
        for tx in &block.txs {
            if self.reconnected.contains(&tx.txid()) {
                continue;
            }
            candidates.offer(tx, |outpoint| utxo.get(outpoint));
        }
    }
}

fn settle_node_reorg(
    observer: &mut NodeReorgObserver<'_>,
    mempool_change: &mut Option<bitcoin_rs_mempool::ChainChangeGuard>,
    outcome: core::result::Result<(), ReorgError>,
) -> core::result::Result<(), ReorgError> {
    if outcome.as_ref().is_err_and(ReorgError::requires_recovery) {
        drop(mempool_change.take());
        return outcome;
    }

    if outcome
        .as_ref()
        .is_err_and(ReorgError::reconsideration_failed)
    {
        observer.discard_reconsideration();
    } else {
        observer.finish_reconsideration();
    }
    if let Some(change) = mempool_change.take()
        && change.finish().is_err()
    {
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
        |observer, outcome| settle_node_reorg(observer, &mut mempool_change, outcome),
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
        |observer, outcome| settle_node_reorg(observer, &mut mempool_change, outcome),
    );
    settle_checkpoint_debt(handles, outcome)
}
