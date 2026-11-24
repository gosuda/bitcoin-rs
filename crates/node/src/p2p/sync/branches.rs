use super::BlockSync;
use super::chain::ReorgError;
use super::chain::WindowApplyDisposition;
use bitcoin_rs_chain::chain::NodeId;
use bitcoin_rs_consensus::primitives::Hash256;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct BranchFrontier {
    applied: Hash256,
    header: Hash256,
}

impl BlockSync {
    pub(super) fn resume_stored_branch(&self) -> Option<Hash256> {
        if self.chain.closed_for_recovery() {
            return None;
        }
        let Some((target, frontier)) = self.outweighed_branch_target() else {
            self.scheduler.lock().settled_branch_frontier = None;
            return None;
        };
        if self.scheduler.lock().settled_branch_frontier == Some(frontier) {
            return None;
        }
        self.switch_branch(target, frontier)
    }

    pub(super) fn switch_branch_if_outweighed(&self) -> Option<Hash256> {
        let (target, frontier) = self.outweighed_branch_target()?;
        self.switch_branch(target, frontier)
    }

    fn switch_branch(&self, target: NodeId, frontier: BranchFrontier) -> Option<Hash256> {
        let outcome = self.chain.switch_to_branch(
            target,
            &mut |hash| self.scheduler.lock().stager.staged_body(hash),
            &mut |hash| self.retire_applied_reorg_body(hash),
        );
        self.scheduler.lock().settled_branch_frontier =
            matches!(&outcome, Ok(()) | Err(ReorgError::MissingBody { .. })).then_some(frontier);
        let mut displaced = None;
        match outcome {
            Ok(()) => {
                let height = self.chain.applied_tip().map_or(0, |tip| tip.height);
                tracing::info!(height, "block sync: switched to the heavier branch");
            }
            Err(ReorgError::MissingBody { height, .. }) => {
                tracing::trace!(height, "block sync: heavier branch still downloading");
            }
            Err(error @ (ReorgError::Fatal(_) | ReorgError::RestorationFailed { .. })) => {
                tracing::error!(
                    %error,
                    "block sync: branch switch requires chainstate recovery, shutting down"
                );
            }
            Err(error @ ReorgError::TransitionSettlement { .. }) => {
                tracing::error!(%error, "block sync: reorg generation settlement failed");
            }
            Err(error @ ReorgError::CheckpointSettlement { .. }) => {
                tracing::error!(
                    %error,
                    "block sync: reorg left checkpoint debt unsettled; a clean shutdown will retry"
                );
            }
            Err(ReorgError::ConnectFailed {
                hash,
                disposition,
                invalidated,
                demoted_tip,
                ..
            }) => {
                displaced = demoted_tip;
                let failed_source = self.scheduler.lock().stager.staged_source(&hash);
                if disposition == WindowApplyDisposition::Permanent {
                    self.punish_permanent_delivery_source(failed_source, hash);
                }
                if disposition == WindowApplyDisposition::BodyMutated {
                    let height = {
                        let tree = self.chain.block_tree();
                        tree.lookup(hash)
                            .and_then(|node_id| tree.node(node_id).ok())
                            .map(|node| node.height)
                    };
                    let mut scheduler = self.scheduler.lock();
                    scheduler.stager.retire_applied(&hash);
                    scheduler
                        .window
                        .requeue_for_retry(&hash, height, Instant::now());
                }
                self.purge_invalidated(&invalidated);
                tracing::warn!(
                    failed_hash = %hash,
                    invalidated = invalidated.len(),
                    "block sync: connect failed"
                );
            }
            Err(ReorgError::DisconnectBodyLost {
                disconnected,
                stopped_at,
                ..
            }) => {
                tracing::debug!(
                    disconnected,
                    stopped_at,
                    "block sync: disconnect body unreadable mid-rollback, coherent at reached tip"
                );
            }
            Err(ReorgError::ConnectBodyLost {
                disconnected,
                connected,
                stopped_at,
                source,
            }) if matches!(*source, ReorgError::MissingBody { .. }) => {
                tracing::debug!(
                    disconnected,
                    connected,
                    stopped_at,
                    "block sync: connect body unavailable mid-switch, coherent at reached tip"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "block sync: branch switch failed");
            }
        }
        displaced
    }

    pub(super) fn retire_applied_reorg_body(&self, hash: Hash256) {
        let mut scheduler = self.scheduler.lock();
        let source = scheduler.stager.staged_source(&hash);
        scheduler.stager.retire_applied(&hash);
        drop(scheduler);
        if let Some(source) = source {
            self.peer_table.note_useful_block(source);
        }
    }

    #[doc(hidden)]
    pub fn purge_invalidated(&self, hashes: &[Hash256]) {
        if hashes.is_empty() {
            return;
        }
        let mut scheduler = self.scheduler.lock();
        let now = Instant::now();
        for hash in hashes {
            scheduler.stager.retire_applied(hash);
            scheduler.window.release_pending(hash, now);
        }
    }

    pub(super) fn outweighed_branch_target(&self) -> Option<(NodeId, BranchFrontier)> {
        let chain_tip = self.chain.chain_tip()?;
        let applied = self.chain.applied_tip()?;
        if chain_tip.hash == applied.hash {
            return None;
        }
        let tree = self.chain.block_tree();
        let applied_id = tree.lookup(applied.hash)?;
        let applied_height = tree.node(applied_id).ok()?.height;
        if Self::is_ancestor_at_height(&tree, applied_id, applied_height, chain_tip.tip_id) {
            return None;
        }
        let ancestor = tree.find_common_ancestor(applied_id, chain_tip.tip_id)?;
        (ancestor != applied_id).then_some((
            chain_tip.tip_id,
            BranchFrontier {
                applied: applied.hash,
                header: chain_tip.hash,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::sync::test_support::{ScriptedBranchSwitch, TestChain};
    use crate::test_support::TestError;
    use arc_swap::ArcSwapOption;
    use bitcoin_rs_chain::chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
    use bitcoin_rs_consensus::primitives::Network;
    use bitcoin_rs_p2p::{InboundBlock, InboundHeaders, PeerTable};
    use crossbeam_channel::unbounded;
    use parking_lot::RwLock;
    use std::sync::Arc;

    // P2P-05, SYNC-02, SYNC-04, SYNC-06
    #[test]
    fn stored_branch_work_retries_refusal_and_waits_for_frontier_or_body_progress()
    -> Result<(), TestError> {
        let genesis = Network::Regtest.genesis_block();
        let mut side = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
        side.header.time += 1;
        side.header.nonce = 0;
        regtest_fixture::mine_block_to_declared_target(&mut side)?;
        let first = regtest_fixture::mined_regtest_child_at(genesis.block_hash(), 1)?;
        let second = regtest_fixture::mined_regtest_child_at(first.block_hash(), 2)?;
        let third = regtest_fixture::mined_regtest_child_at(second.block_hash(), 3)?;
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let side_id = tree.insert_header(side.header, NodeStatus::HeaderValid)?;
        tree.insert_header(first.header, NodeStatus::HeaderValid)?;
        tree.insert_header(second.header, NodeStatus::HeaderValid)?;
        let applied = {
            let node = tree.node(side_id)?;
            TipSnapshot {
                tip_id: side_id,
                chain_tx_count: node.chain_tx_count,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        let chain = Arc::new(TestChain::new(
            tree.tip_handle(),
            Arc::new(ArcSwapOption::from_pointee(applied)),
            Arc::new(RwLock::new(tree)),
        ));
        let (headers_tx, headers_rx) = unbounded();
        let (blocks_tx, blocks_rx) = unbounded();
        let sync = BlockSync::new(
            chain.clone(),
            Arc::new(PeerTable::new()),
            headers_rx,
            blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        );
        let set_outcome = |error| {
            *chain.scripted_branch_switch.lock() = Some(ScriptedBranchSwitch {
                connected: Vec::new(),
                error,
            });
        };
        let missing = || ReorgError::MissingBody {
            hash: Hash256::from(first.block_hash()),
            height: 1,
        };

        set_outcome(ReorgError::Unavailable(Box::new(
            bitcoin_rs_chain::ApplyError::ConcurrentChainChange,
        )));
        sync.tick();
        assert!(
            chain.scripted_branch_switch.lock().is_none(),
            "startup must drive a branch whose bodies can already be stored"
        );
        set_outcome(missing());
        sync.tick();
        assert!(
            chain.scripted_branch_switch.lock().is_none(),
            "a refused operation must remain owed on the same frontier"
        );
        set_outcome(missing());
        sync.tick();
        assert!(
            chain.scripted_branch_switch.lock().is_some(),
            "a settled missing-body probe must not repeat on an idle frontier"
        );

        headers_tx
            .send(InboundHeaders {
                headers: vec![third.header],
                source: None,
                wire_response: true,
            })
            .map_err(|_| TestError::message("header queue closed"))?;
        sync.tick();
        assert!(
            chain.scripted_branch_switch.lock().is_none(),
            "a changed header frontier must drive a fresh stored-body attempt"
        );
        set_outcome(missing());
        sync.tick();
        assert!(chain.scripted_branch_switch.lock().is_some());
        blocks_tx
            .send(InboundBlock::from_local(first))
            .map_err(|_| TestError::message("body queue closed"))?;
        sync.tick();
        assert!(
            chain.scripted_branch_switch.lock().is_none(),
            "body arrival must retry a settled branch frontier"
        );
        Ok(())
    }
}
