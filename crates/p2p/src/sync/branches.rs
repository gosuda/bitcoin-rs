//! Heavier-branch handoff and committed reorganization body retirement.

use super::BlockSync;
use super::chain::BranchSwitchError;
use super::chain::WindowCommitDisposition;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::plan_reorg;
use bitcoin_rs_primitives::Hash256;
use std::time::Instant;

impl BlockSync {
    /// Moves the applied chain onto the header tip's branch when it has been
    /// outweighed.
    ///
    /// `chain_tip` tracks the heaviest headers and `applied_tip` the validated
    /// chain; the two diverge exactly when a competing branch wins. Forward
    /// application cannot close that gap, because the blocks it wants to apply
    /// do not build on the applied tip.
    ///
    /// Availability is left to the implementation's switch. It may commit the
    /// contiguous winning prefix already present in bounded staging, then
    /// report `MissingBody` for the first absent suffix block. Only a
    /// zero-length available connect prefix guarantees no mutation. Keeping
    /// this as one authority avoids a pre-check that can disagree with the
    /// transition witness.
    #[doc(hidden)]
    pub fn switch_branch_if_outweighed(&self) {
        let Some(target) = self.outweighed_branch_target() else {
            return;
        };
        let outcome = self.chain.switch_to_branch(
            target,
            &mut |hash| self.scheduler.lock().stager.staged_body(hash),
            &mut |hash| self.retire_applied_reorg_body(hash),
        );
        match outcome {
            Ok(()) => {
                let height = self
                    .chain
                    .applied_tip()
                    .load_full()
                    .map_or(0, |tip| tip.height);
                tracing::info!(height, "block sync: switched to the heavier branch");
            }
            Err(BranchSwitchError::MissingBody { height }) => {
                tracing::trace!(height, "block sync: heavier branch still downloading");
            }
            Err(error @ BranchSwitchError::Fatal(_)) => {
                // The implementation has already closed admission and
                // requested shutdown.
                tracing::error!(
                    %error,
                    "block sync: chainstate torn by a failed disconnect, shutting down"
                );
            }
            Err(error @ BranchSwitchError::TransitionSettlement(_)) => {
                // The reorg owner has closed admission and requested shutdown.
                tracing::error!(%error, "block sync: reorg generation settlement failed");
            }
            Err(error @ BranchSwitchError::CheckpointSettlement(_)) => {
                tracing::error!(
                    %error,
                    "block sync: reorg left checkpoint debt unsettled; a clean shutdown will retry"
                );
            }
            Err(BranchSwitchError::ConnectFailed {
                hash,
                disposition,
                invalidated,
                ..
            }) => {
                if disposition == WindowCommitDisposition::BodyMutated {
                    // Only the delivered body is bad. Keep the header branch
                    // and its descendants, but free this slot for a new body;
                    // the tree-owned height keeps the retry cursor exact.
                    let height = {
                        let tree = self.chain.block_tree().read();
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
                // Invalid descendants cannot occupy bounded download state or
                // they can prevent the newly selected valid branch from refilling.
                self.purge_invalidated(&invalidated);
                tracing::warn!(
                    failed_hash = %hash,
                    invalidated = invalidated.len(),
                    "block sync: connect failed"
                );
            }
            Err(BranchSwitchError::DisconnectBodyLost {
                disconnected,
                stopped_at,
            }) => {
                tracing::debug!(
                    disconnected,
                    stopped_at,
                    "block sync: disconnect body unreadable mid-rollback, coherent at reached tip"
                );
            }
            Err(BranchSwitchError::ConnectBodyLost {
                disconnected,
                connected,
                stopped_at,
            }) => {
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
    }

    #[doc(hidden)]
    pub fn retire_applied_reorg_body(&self, hash: Hash256) {
        let mut scheduler = self.scheduler.lock();
        scheduler.stager.retire_applied(&hash);
    }

    /// Frees every bounded download slot held by an invalidated hash under
    /// one `scheduler` acquisition.
    #[doc(hidden)]
    pub fn purge_invalidated(&self, hashes: &[Hash256]) {
        if hashes.is_empty() {
            return;
        }
        let mut scheduler = self.scheduler.lock();
        for hash in hashes {
            scheduler.stager.retire_applied(hash);
            // Invalidated hashes are never re-requested: the pending slot is
            // released without moving the request cursor.
            scheduler
                .window
                .release_pending_without_rewind(hash, Instant::now());
        }
    }

    /// Returns the header tip when the applied chain is not on its branch.
    ///
    /// SYNC-FRONTIER-01: ancestry is identified by node identity, not height
    /// alone. An applied ancestor needs no switch; request selection starts at
    /// the first connect node of the parent-walk plan. The trusted active-height
    /// index may answer linear-sync queries without constructing that plan.
    /// Forks, disconnected roots, and invalidated indices retain parent-walk
    /// semantics. This does not change admission, request budgets, or apply.
    ///
    /// The applied tip is on the branch exactly when the header tip's ancestor
    /// at the applied height is the applied block itself.
    #[doc(hidden)]
    pub fn outweighed_branch_target(&self) -> Option<NodeId> {
        let chain_tip = self.chain.chain_tip().load_full()?;
        let applied = self.chain.applied_tip().load_full()?;
        if chain_tip.hash == applied.hash {
            return None;
        }
        let tree = self.chain.block_tree().read();
        let applied_id = tree.lookup(applied.hash)?;
        // Normal IBD extends the applied chain. Its trusted height index proves
        // ancestry without allocating a plan for the entire remaining chain.
        // Keep the parent-walk planner for actual forks and disconnected roots.
        let applied_height = tree.node(applied_id).ok()?.height;
        if Self::is_ancestor_at_height(&tree, applied_id, applied_height, chain_tip.tip_id) {
            return None;
        }
        let plan = plan_reorg(&tree, applied_id, chain_tip.tip_id).ok()?;
        (!plan.disconnect.is_empty()).then_some(chain_tip.tip_id)
    }
}
