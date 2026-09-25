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
    BranchSwitchError, HeaderAdmission, SyncChain, SyncChainError, WindowCommitDisposition,
    WindowCommitError,
};
use bitcoin_rs_p2p::{InboundHeaders, PeerTable};
use bitcoin_rs_primitives::{Block, Hash256, Header, Network};
use crossbeam_channel::Receiver;
use parking_lot::Mutex;

pub use bitcoin_rs_p2p::sync::{BlockSync, SyncBudget, default_sync_budget};

/// The [`SyncChain`] implementation over [`bitcoin_rs_chainstate::Chainstate`]:
/// applied-tip mutation behind the chain-transition lock plus the derived
/// consumers that must fire inside it.
pub struct NodeSyncChain {
    handles: Arc<bitcoin_rs_chainstate::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
}

/// Constructs the download executor over the applied-chain seam.
#[must_use]
pub fn block_sync(
    handles: Arc<bitcoin_rs_chainstate::Chainstate>,
    followers: crate::chain_effects::ChainFollowers,
    peer_table: Arc<PeerTable>,
    inbound_headers_rx: Arc<Mutex<Receiver<InboundHeaders>>>,
    inbound_blocks_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundBlock>>>,
    ibd: Arc<bitcoin_rs_chain::InitialBlockDownload>,
) -> BlockSync {
    BlockSync::new(
        Arc::new(NodeSyncChain { handles, followers }),
        peer_table,
        inbound_headers_rx,
        inbound_blocks_rx,
        ibd,
    )
}

pub(crate) fn settle_window_failure(
    transition: bitcoin_rs_chainstate::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    mut error: bitcoin_rs_chainstate::WindowApplyError,
) -> bitcoin_rs_chainstate::WindowApplyError {
    let handles = transition.chainstate();
    if error.disposition == bitcoin_rs_chainstate::WindowApplyDisposition::Fatal
        || bitcoin_rs_chainstate::classify_apply_error(&error.source)
            == bitcoin_rs_chainstate::WindowApplyDisposition::Fatal
    {
        error.disposition = bitcoin_rs_chainstate::WindowApplyDisposition::Fatal;
    } else if let Err(finish_source) =
        crate::chain_effects::ChainFollowers::finish_transition(handles, transition, mempool_change)
    {
        tracing::error!(
            original = %error.source,
            finish = %finish_source,
            "chain transition could not be settled after a window failure; \
             mempool admission stays closed until recovery or restart"
        );
        error.disposition = bitcoin_rs_chainstate::WindowApplyDisposition::Fatal;
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
    transition: bitcoin_rs_chainstate::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    applied: usize,
    committed: Vec<bitcoin_rs_chainstate::ConnectOutcome>,
) -> core::result::Result<usize, bitcoin_rs_chainstate::WindowApplyError> {
    let handles = transition.chainstate();
    match crate::chain_effects::ChainFollowers::finish_transition(
        handles,
        transition,
        mempool_change,
    ) {
        Ok(()) => Ok(applied),
        Err(finish_source) => {
            tracing::error!(
                finish = %finish_source,
                "chain transition could not be settled after a committed window; \
                 mempool admission stays closed until recovery or restart"
            );
            Err(bitcoin_rs_chainstate::WindowApplyError {
                applied,
                committed,
                source: finish_source,
                disposition: bitcoin_rs_chainstate::WindowApplyDisposition::Fatal,
                invalidated: Box::default(),
            })
        }
    }
}

fn window_disposition(
    disposition: bitcoin_rs_chainstate::WindowApplyDisposition,
) -> WindowCommitDisposition {
    match disposition {
        bitcoin_rs_chainstate::WindowApplyDisposition::Permanent => {
            WindowCommitDisposition::Permanent
        }
        bitcoin_rs_chainstate::WindowApplyDisposition::BodyMutated => {
            WindowCommitDisposition::BodyMutated
        }
        bitcoin_rs_chainstate::WindowApplyDisposition::Operational => {
            WindowCommitDisposition::Operational
        }
        bitcoin_rs_chainstate::WindowApplyDisposition::Fatal => WindowCommitDisposition::Fatal,
    }
}

impl SyncChain for NodeSyncChain {
    fn network(&self) -> Network {
        self.handles.network()
    }

    fn block_tree(&self) -> &parking_lot::RwLock<bitcoin_rs_chain::BlockTree> {
        self.handles.block_tree()
    }

    fn chain_tip(&self) -> &arc_swap::ArcSwapOption<TipSnapshot> {
        self.handles.chain_tip()
    }

    fn applied_tip(&self) -> &arc_swap::ArcSwapOption<TipSnapshot> {
        self.handles.applied_tip()
    }

    fn bootstrap_genesis(&self) {
        if self.handles.applied_tip().load_full().is_some() {
            return;
        }

        let had_chain_tip = self.handles.chain_tip().load_full().is_some();
        let genesis = self.handles.network().genesis_block();
        match self.followers.apply_connect(&self.handles, &genesis) {
            Ok(outcome) => {
                if !had_chain_tip {
                    self.handles.chain_tip().store(Some(Arc::new(outcome.tip)));
                }
            }
            // Genesis apply failed before an applied tip could be published.
            Err(error) => {
                tracing::warn!(%error, "block sync: failed to bootstrap genesis");
            }
        }
    }

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        self.handles.admit_headers(headers)
    }

    fn check_body_binding(&self, block: &Block) -> Result<(), SyncChainError> {
        let hash = Hash256::from(block.block_hash());
        let segwit_active = {
            let tree = self.handles.block_tree().read();
            tree.lookup(hash)
                .and_then(|node_id| tree.node(node_id).ok())
                .is_none_or(|node| {
                    bitcoin_rs_chain::softfork_state(
                        &tree,
                        self.handles.network(),
                        node.parent,
                        node.height,
                    )
                    .segwit_active
                })
        };
        bitcoin_rs_consensus::check_block_body_binding(block, segwit_active)
            .map_err(|error| -> SyncChainError { Box::new(error) })
    }

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        bitcoin_rs_chainstate::window_len(serialized_sizes)
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
        let mempool_change =
            self.followers
                .begin_mempool_change()
                .map_err(|source| WindowCommitError {
                    applied: 0,
                    disposition: WindowCommitDisposition::Operational,
                    invalidated: Box::default(),
                    source: Box::new(source),
                })?;
        let result = match transition.connect_window(blocks, bodies) {
            Ok(outcomes) => {
                for (block, outcome) in blocks.iter().zip(&outcomes) {
                    self.followers.committed_connect(block, outcome);
                }
                let applied = outcomes.len();
                settle_window_success(transition, mempool_change, applied, outcomes)
            }
            Err(error) => {
                for (block, outcome) in blocks.iter().zip(&error.committed) {
                    self.followers.committed_connect(block, outcome);
                }
                // A connect failure settles according to its disposition.
                Err(settle_window_failure(transition, mempool_change, error))
            }
        };
        result.map_err(|error| WindowCommitError {
            applied: error.applied,
            disposition: window_disposition(error.disposition),
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
                Err(BranchSwitchError::Fatal(Box::new(error)))
            }
            // The transition generation could not be settled after reorg work.
            Err(error @ crate::reorg::ReorgError::TransitionSettlement { .. }) => {
                Err(BranchSwitchError::TransitionSettlement(Box::new(error)))
            }
            // The checkpoint settlement failed after reorg mutation.
            Err(error @ crate::reorg::ReorgError::CheckpointSettlement { .. }) => {
                Err(BranchSwitchError::CheckpointSettlement(Box::new(error)))
            }
            // A target-branch body failed while connecting the branch.
            Err(crate::reorg::ReorgError::ConnectFailed {
                hash,
                disposition,
                invalidated,
                ..
            }) => {
                if !invalidated.is_empty() {
                    // Invalidation can move the active branch away from the
                    // pinned assume-valid anchor.
                    self.handles.reevaluate_assume_valid();
                }
                Err(BranchSwitchError::ConnectFailed {
                    hash,
                    disposition: window_disposition(disposition),
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
            // A connect body absent mid-switch is retryable at the coherent
            // prefix; any other load failure keeps its causal error in `Other`.
            Err(crate::reorg::ReorgError::ConnectBodyLost {
                disconnected,
                connected,
                stopped_at,
                source,
            }) if matches!(*source, crate::reorg::ReorgError::MissingBody { .. }) => {
                Err(BranchSwitchError::ConnectBodyLost {
                    disconnected,
                    connected,
                    stopped_at,
                })
            }
            // An unclassified reorg error crossed the seam unchanged.
            Err(error) => Err(BranchSwitchError::Other(Box::new(error))),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/sync/tests/mod.rs"]
mod tests;
