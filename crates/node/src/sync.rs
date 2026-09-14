//! Applied-chain seam for the block-download executor.
//!
//! The executor — download scheduling, staging, peer policy — lives in
//! [`bitcoin_rs_p2p::sync`]. This module is the [`SyncChain`] implementation
//! it drives: the applied-tip-mutating operations that stay in `node` under
//! ARCH-07 (header admission under the chain-transition lock, window commit
//! through `ChainTransition` + `ChainFollowers`, branch switch via
//! [`crate::reorg::switch_to_branch`], genesis bootstrap).

use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_p2p::sync::chain::{
    BranchSwitchError, HeaderAdmission, SyncChain, WindowCommitDisposition, WindowCommitError,
};
use bitcoin_rs_p2p::{InboundHeaders, PeerTable};
use bitcoin_rs_primitives::{Block, Hash256, Header, Network};
use crossbeam_channel::Receiver;
use parking_lot::Mutex;

pub use bitcoin_rs_p2p::sync::{BlockSync, SyncBudget, default_sync_budget};

/// The [`SyncChain`] implementation over [`crate::apply::Chainstate`]:
/// applied-tip mutation behind the chain-transition lock plus the derived
/// consumers that must fire inside it.
pub struct NodeSyncChain {
    handles: crate::apply::Chainstate,
    followers: crate::chain_effects::ChainFollowers,
}

/// Constructs the download executor over the applied-chain seam.
#[must_use]
pub fn block_sync(
    handles: crate::apply::Chainstate,
    followers: crate::chain_effects::ChainFollowers,
    peer_table: Arc<PeerTable>,
    inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
) -> BlockSync {
    BlockSync::new(
        Arc::new(NodeSyncChain { handles, followers }),
        peer_table,
        inbound_headers_rx,
        inbound_blocks_rx,
    )
}

pub(crate) fn settle_window_failure(
    transition: crate::apply::ChainTransition<'_>,
    mut error: crate::apply::WindowApplyError,
) -> crate::apply::WindowApplyError {
    if matches!(error.source, crate::apply::error::ApplyError::UtxoCommit(_)) {
        error.disposition = crate::apply::WindowApplyDisposition::Fatal;
    } else if let Err(finish_source) = transition.finish() {
        tracing::error!(
            original = %error.source,
            finish = %finish_source,
            "chain transition could not be settled after a window failure; \
             mempool admission stays closed until recovery or restart"
        );
        error.disposition = crate::apply::WindowApplyDisposition::Fatal;
    }
    error
}

/// Settles a successful window: finishes the transition, or classifies a
/// finish failure as [`WindowApplyDisposition::Fatal`] when the reserved
/// even generation could not be published.
///
/// Symmetric with [`settle_window_failure`]: both paths attempt `finish`
/// and surface a `Fatal` disposition when the CAS fails, so the caller
/// stops retrying instead of wedging on an odd generation.
#[allow(clippy::result_large_err)]
pub(crate) fn settle_window_success(
    transition: crate::apply::ChainTransition<'_>,
    applied: usize,
    committed: Vec<crate::apply::ConnectOutcome>,
) -> core::result::Result<usize, crate::apply::WindowApplyError> {
    match transition.finish() {
        Ok(()) => Ok(applied),
        Err(finish_source) => {
            tracing::error!(
                finish = %finish_source,
                "chain transition could not be settled after a committed window; \
                 mempool admission stays closed until recovery or restart"
            );
            Err(crate::apply::WindowApplyError {
                applied,
                committed,
                source: finish_source,
                disposition: crate::apply::WindowApplyDisposition::Fatal,
                invalidated: Box::default(),
            })
        }
    }
}

impl SyncChain for NodeSyncChain {
    fn network(&self) -> Network {
        self.handles.network
    }

    fn block_tree(&self) -> &parking_lot::RwLock<bitcoin_rs_chain::BlockTree> {
        &self.handles.block_tree
    }

    fn chain_tip(&self) -> &arc_swap::ArcSwapOption<TipSnapshot> {
        &self.handles.chain_tip
    }

    fn applied_tip(&self) -> &arc_swap::ArcSwapOption<TipSnapshot> {
        &self.handles.applied_tip
    }

    fn bootstrap_genesis(&self) {
        if self.handles.applied_tip.load_full().is_some() {
            return;
        }

        let had_chain_tip = self.handles.chain_tip.load_full().is_some();
        let genesis = self.handles.network.genesis_block();
        match self.followers.apply_connect(&self.handles, &genesis) {
            Ok(outcome) => {
                if !had_chain_tip {
                    self.handles.chain_tip.store(Some(Arc::new(outcome.tip)));
                }
            }
            // Genesis apply failed before an applied tip could be published.
            Err(error) => {
                tracing::warn!(%error, "block sync: failed to bootstrap genesis");
            }
        }
    }

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        // Header admission moves the header tip, which the apply path
        // reads under the transition; the lock keeps it fixed until commit.
        let transition = match self.handles.lock_transition() {
            Ok(transition) => transition,
            // The transition lock is unavailable, so admission is refused.
            Err(error) => return HeaderAdmission::Refused(Box::new(error)),
        };
        let mut tree = self.handles.block_tree.write();
        let acceptance = bitcoin_rs_chain::accept_headers(
            &mut tree,
            headers,
            self.handles.network,
            bitcoin_rs_chain::current_unix_seconds(),
        );
        match acceptance {
            Ok(node_ids) => {
                let announced_tip = node_ids
                    .last()
                    .and_then(|id| tree.node(*id).ok())
                    .map(|node| node.hash);
                let active_height = tree
                    .tip()
                    .zip(announced_tip)
                    .and_then(|(active_tip, hash)| {
                        tree.active_height_of(active_tip.tip_id, hash)
                            .and_then(|height| i32::try_from(height).ok())
                    });
                self.handles.assume_valid_gate.evaluate(&tree);
                drop(tree);
                drop(transition);
                HeaderAdmission::Accepted {
                    accepted: node_ids.len(),
                    announced_tip,
                    active_height,
                }
            }
            // Header validation rejected the batch after admission began.
            Err(error) => {
                drop(tree);
                drop(transition);
                HeaderAdmission::Rejected(error)
            }
        }
    }

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        crate::apply::window_len(serialized_sizes)
    }

    fn commit_window(
        &self,
        blocks: &[&Block],
        bodies: &[bytes::Bytes],
    ) -> Result<usize, WindowCommitError> {
        let transition = self
            .handles
            .begin_transition()
            // A closed or already-active generation refuses a new window.
            .map_err(|source| WindowCommitError {
                applied: 0,
                disposition: WindowCommitDisposition::Operational,
                invalidated: Box::default(),
                source: Box::new(source),
            })?;
        let result = match transition.connect_window(blocks, bodies) {
            Ok(outcomes) => {
                for (block, outcome) in blocks.iter().zip(&outcomes) {
                    self.followers.connected(block, outcome);
                }
                let applied = outcomes.len();
                settle_window_success(transition, applied, outcomes)
            }
            Err(error) => {
                for (block, outcome) in blocks.iter().zip(&error.committed) {
                    self.followers.connected(block, outcome);
                }
                // A connect failure settles according to its disposition.
                Err(settle_window_failure(transition, error))
            }
        };
        result.map_err(|error| WindowCommitError {
            applied: error.applied,
            disposition: match error.disposition {
                crate::apply::WindowApplyDisposition::Permanent => {
                    WindowCommitDisposition::Permanent
                }
                crate::apply::WindowApplyDisposition::Operational => {
                    WindowCommitDisposition::Operational
                }
                crate::apply::WindowApplyDisposition::Fatal => WindowCommitDisposition::Fatal,
            },
            invalidated: error.invalidated,
            source: Box::new(error.source),
        })
    }

    fn switch_to_branch(
        &self,
        target: bitcoin_rs_chain::NodeId,
        staged_body: &mut dyn FnMut(Hash256) -> Option<(Block, bytes::Bytes)>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), BranchSwitchError> {
        match crate::reorg::switch_to_branch(
            &self.handles,
            &self.followers,
            target,
            staged_body,
            connected_body,
        ) {
            Ok(()) => Ok(()),
            // A required disconnect/connect body was absent from staged storage.
            Err(crate::reorg::ReorgError::MissingBody { height, .. }) => {
                Err(BranchSwitchError::MissingBody { height })
            }
            // A disconnect failure left chainstate torn and requires shutdown.
            Err(error @ crate::reorg::ReorgError::Fatal(_)) => {
                // The disconnect died partway; chainstate is torn. Close
                // admission and request shutdown here, where the typed cause
                // still exists.
                self.handles.admission.close_permanently();
                self.handles
                    .shutdown
                    .store(true, std::sync::atomic::Ordering::Release);
                Err(BranchSwitchError::Fatal(Box::new(error)))
            }
            // The transition generation could not be settled after reorg work.
            Err(error @ crate::reorg::ReorgError::TransitionSettlement { .. }) => {
                Err(BranchSwitchError::TransitionSettlement(Box::new(error)))
            }
            // The checkpoint settlement failed after reorg mutation.
            Err(error @ crate::reorg::ReorgError::CheckpointSettlement(_)) => {
                Err(BranchSwitchError::CheckpointSettlement(Box::new(error)))
            }
            // A target-branch body failed while connecting the branch.
            Err(crate::reorg::ReorgError::ConnectFailed {
                hash, invalidated, ..
            }) => {
                if !invalidated.is_empty() {
                    // Invalidation can move the active branch away from the
                    // pinned assume-valid anchor.
                    self.handles
                        .assume_valid_gate
                        .evaluate(&self.handles.block_tree.read());
                }
                Err(BranchSwitchError::ConnectFailed {
                    hash,
                    invalidated: invalidated.into_boxed_slice(),
                })
            }
            // A disconnect body was unavailable after the disconnect started.
            Err(crate::reorg::ReorgError::DisconnectBodyLost {
                disconnected,
                stopped_at,
                ..
            }) => Err(BranchSwitchError::DisconnectBodyLost {
                disconnected,
                stopped_at,
            }),
            // An unclassified reorg error crossed the seam unchanged.
            Err(error) => Err(BranchSwitchError::Other(Box::new(error))),
        }
    }
}

#[cfg(test)]
mod tests;
