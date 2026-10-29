//! Heavier-branch handoff and committed reorganization body retirement.

use super::BlockSync;
use super::chain::ReorgError;
use super::chain::WindowApplyDisposition;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_primitives::Hash256;
use std::time::Instant;

impl BlockSync {
    pub(super) fn switch_branch_if_outweighed(&self) -> Option<Hash256> {
        let target = self.outweighed_branch_target()?;
        let outcome = self.chain.switch_to_branch(
            target,
            &mut |hash| self.scheduler.lock().stager.staged_body(hash),
            &mut |hash| self.retire_applied_reorg_body(hash),
        );
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

    /// Frees every bounded download slot held by an invalidated hash under
    /// one `scheduler` acquisition.
    /// INVARIANT: all releases share one `now`, so one purge stamps an
    ///      owner's queue age at a single instant.
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

    /// Returns the header tip when the applied chain is not on its branch.
    pub(super) fn outweighed_branch_target(&self) -> Option<NodeId> {
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
        (ancestor != applied_id).then_some(chain_tip.tip_id)
    }
}
