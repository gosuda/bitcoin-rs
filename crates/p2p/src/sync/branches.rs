//! Heavier-branch handoff and committed reorganization body retirement.

use super::BlockSync;
use super::chain::ReorgError;
use super::chain::WindowApplyDisposition;
use bitcoin_rs_chain::NodeId;
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
    pub(super) fn switch_branch_if_outweighed(&self) {
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
                let height = self.chain.applied_tip().map_or(0, |tip| tip.height);
                tracing::info!(height, "block sync: switched to the heavier branch");
            }
            Err(ReorgError::MissingBody { height, .. }) => {
                tracing::trace!(height, "block sync: heavier branch still downloading");
            }
            Err(error @ (ReorgError::Fatal(_) | ReorgError::RestorationFailed { .. })) => {
                // The implementation has already closed admission and
                // requested shutdown.
                tracing::error!(
                    %error,
                    "block sync: branch switch requires chainstate recovery, shutting down"
                );
            }
            Err(error @ ReorgError::TransitionSettlement { .. }) => {
                // The reorg owner has closed admission and requested shutdown.
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
                ..
            }) => {
                // Capture the delivering connection before the purge drops
                // the staged entry that carries it.
                let failed_source = self.scheduler.lock().stager.staged_source(&hash);
                if disposition == WindowApplyDisposition::Permanent {
                    self.punish_permanent_delivery_source(failed_source, hash);
                }
                if disposition == WindowApplyDisposition::BodyMutated {
                    // Only the delivered body is bad. Keep the header branch
                    // and its descendants, but free this slot for a new body;
                    // the tree-owned height keeps the retry cursor exact.
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
                // Invalid descendants cannot occupy bounded download state or
                // they can prevent the newly selected valid branch from refilling.
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
    }

    pub(super) fn retire_applied_reorg_body(&self, hash: Hash256) {
        let mut scheduler = self.scheduler.lock();
        scheduler.stager.retire_applied(&hash);
    }

    /// Frees every bounded download slot held by an invalidated hash under
    /// one `scheduler` acquisition.
    ///
    /// PRE: `hashes` are the hashes invalidated by one settlement event.
    /// POST: every hash's pending is released with no cursor rewind; each
    ///      owner's queue start follows
    ///      [`DownloadWindow::reset_owner_queue_start`].
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
            // Invalidated hashes are never re-requested: release the pending
            // entry without rewinding the request cursor.
            scheduler.window.release_pending(hash, now);
        }
    }

    /// Returns the header tip when the applied chain is not on its branch.
    ///
    /// SYNC-FRONTIER-01: ancestry is identified by node identity, not height
    /// alone. An applied ancestor needs no switch; request selection starts at
    /// the common ancestor's child. The trusted active-height index may answer
    /// linear-sync queries directly.
    /// Forks, disconnected roots, and invalidated indices retain parent-walk
    /// semantics. This does not change admission, request budgets, or apply.
    ///
    /// The applied tip is on the branch exactly when the header tip's ancestor
    /// at the applied height is the applied block itself.
    pub(super) fn outweighed_branch_target(&self) -> Option<NodeId> {
        let chain_tip = self.chain.chain_tip()?;
        let applied = self.chain.applied_tip()?;
        if chain_tip.hash == applied.hash {
            return None;
        }
        let tree = self.chain.block_tree();
        let applied_id = tree.lookup(applied.hash)?;
        // Normal IBD extends the applied chain.
        let applied_height = tree.node(applied_id).ok()?.height;
        if Self::is_ancestor_at_height(&tree, applied_id, applied_height, chain_tip.tip_id) {
            return None;
        }
        let ancestor = tree.find_common_ancestor(applied_id, chain_tip.tip_id)?;
        (ancestor != applied_id).then_some(chain_tip.tip_id)
    }
}
