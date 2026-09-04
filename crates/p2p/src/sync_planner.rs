//! Download planner: window, staging, and conviction policy.
//!
//! Ownership boundaries are defined by the normative architecture contract
//! ([architecture contract](../../docs/contracts/architecture.md#live-gaps)).

use std::net::SocketAddr;
use std::time::Instant;

use bitcoin_rs_primitives::{Block, Hash256};

use crate::SyncBudget;
use crate::block_stager::{BlockStager, DrainedBlock, DroppedBlock, StagedBlock};
use crate::download_window::DownloadWindow;

/// Network effect the executor must perform. The planner never mutates
/// sockets, leases, or chainstate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncAction {
    /// Disconnect `addr` after window conviction.
    Disconnect {
        /// Convicted peer.
        addr: SocketAddr,
        /// Why the planner selected this peer.
        reason: SyncDisconnectReason,
    },
}

/// Why the planner asked the executor to disconnect a download peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncDisconnectReason {
    /// Window-front stall with no apply-side backpressure.
    WindowStaller {
        /// Height the stalled peer was supposed to deliver next.
        next_apply_height: u32,
    },
    /// In-flight getdata exceeded the pending timeout.
    PendingTimeout,
}

/// Optional cold-front hedge after a stall observation that did not disconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColdFrontHedge {
    /// Current window-front owner.
    pub owner: SocketAddr,
    /// Hash the owner still owes.
    pub front_hash: Hash256,
}

/// Planner-owned download state for one `BlockSync`.
#[derive(Debug)]
pub struct SyncPlanner {
    window: DownloadWindow,
    stager: BlockStager,
}

impl SyncPlanner {
    /// Empty planner sized to `budget`.
    #[must_use]
    pub fn new(budget: SyncBudget) -> Self {
        Self {
            window: DownloadWindow::new(budget),
            stager: BlockStager::new(budget),
        }
    }

    /// Replaces window and stager with a fresh pair at `budget`.
    pub fn install_budget(&mut self, budget: SyncBudget) {
        self.window = DownloadWindow::new(budget);
        self.stager = BlockStager::new(budget);
    }

    /// In-flight assignment policy.
    #[must_use]
    pub fn window(&self) -> &DownloadWindow {
        &self.window
    }

    /// Mutable in-flight assignment policy.
    pub fn window_mut(&mut self) -> &mut DownloadWindow {
        &mut self.window
    }

    /// Inbound staging set.
    #[must_use]
    pub fn stager(&self) -> &BlockStager {
        &self.stager
    }

    /// Mutable inbound staging set.
    pub fn stager_mut(&mut self) -> &mut BlockStager {
        &mut self.stager
    }

    /// Clears address-scoped window state for a replacement or ready peer.
    pub fn forget_peer(&mut self, addr: SocketAddr) {
        self.window.forget_peer(addr);
    }

    /// Drops window assignments whose peers are no longer live.
    pub fn release_disconnected_peers(&mut self, is_live_peer: impl Fn(&SocketAddr) -> bool) {
        self.window.release_disconnected_peers(is_live_peer);
    }

    /// Whether the next expected apply hash is already staged.
    #[must_use]
    pub fn apply_side_busy(&self, next_expected: Option<Hash256>) -> bool {
        next_expected.is_some_and(|hash| self.stager.contains(&hash))
    }

    /// Stages one inbound body.
    pub fn stage(
        &mut self,
        hash: Hash256,
        next_expected_hash: Option<Hash256>,
        block: Block,
        serialized: bytes::Bytes,
        now: Instant,
    ) -> StagedBlock {
        self.stager
            .insert(hash, next_expected_hash, block, serialized, now)
    }

    /// Drops expired staged bodies.
    pub fn prune_expired(&mut self, now: Instant) -> Vec<DroppedBlock> {
        self.stager.prune_expired(now)
    }

    /// Drains the contiguous staged prefix of `expected_hashes`.
    pub fn drain_expected_prefix(&mut self, expected_hashes: &[Hash256]) -> Vec<DrainedBlock> {
        self.stager.drain_expected_prefix(expected_hashes)
    }

    /// Restores a partial apply suffix.
    pub fn restore_many(&mut self, drained: impl IntoIterator<Item = DrainedBlock>) {
        self.stager.restore_many(drained);
    }

    /// Retires one committed hash from staging.
    pub fn retire_applied(&mut self, hash: &Hash256) -> bool {
        self.stager.retire_applied(hash)
    }

    /// Purges invalidated hashes from staging and the download window.
    pub fn purge_invalidated(&mut self, hashes: &[Hash256]) {
        for hash in hashes {
            self.stager.retire_applied(hash);
            self.window.drop_for_retry(hash);
        }
    }

    /// Stall then pending-timeout conviction. At most one disconnect, matching
    /// the previous `BlockSync::tick` order. A hedge is only returned when no
    /// disconnect fired.
    pub fn plan_conviction(
        &mut self,
        next_apply_height: Option<u32>,
        next_expected: Option<Hash256>,
        now: Instant,
    ) -> (Option<SyncAction>, Option<ColdFrontHedge>) {
        let apply_side_busy = self.apply_side_busy(next_expected);
        if let Some(height) = next_apply_height {
            let hedge = self.window.observe_cold_front(height, apply_side_busy, now);
            if let Some(addr) = self.window.observe_stall(height, apply_side_busy, now) {
                return (
                    Some(SyncAction::Disconnect {
                        addr,
                        reason: SyncDisconnectReason::WindowStaller {
                            next_apply_height: height,
                        },
                    }),
                    None,
                );
            }
            let timed_out = self.window.observe_pending_timeout(apply_side_busy, now);
            if let Some(addr) = timed_out {
                return (
                    Some(SyncAction::Disconnect {
                        addr,
                        reason: SyncDisconnectReason::PendingTimeout,
                    }),
                    None,
                );
            }
            if let Some((owner, front_hash)) = hedge {
                return (None, Some(ColdFrontHedge { owner, front_hash }));
            }
        } else {
            let timed_out = self.window.observe_pending_timeout(apply_side_busy, now);
            if let Some(addr) = timed_out {
                return (
                    Some(SyncAction::Disconnect {
                        addr,
                        reason: SyncDisconnectReason::PendingTimeout,
                    }),
                    None,
                );
            }
        }
        (None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPlanner;
    use crate::default_sync_budget;
    use std::time::Instant;

    /// Contract: the architecture contract's planner/executor boundary keeps
    /// conviction decisions in the planner; an empty planner emits no action.
    #[test]
    fn empty_planner_plans_no_conviction() {
        let mut planner = SyncPlanner::new(default_sync_budget());
        let now = Instant::now();
        let (action, hedge) = planner.plan_conviction(Some(1), None, now);
        assert!(action.is_none());
        assert!(hedge.is_none());
    }
}
