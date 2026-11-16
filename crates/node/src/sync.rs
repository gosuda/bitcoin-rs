use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::p2p::sync::chain::{
    HeaderAdmission, HistoricalAdvance, ReorgError, SyncChain, SyncChainError,
    WindowApplyDisposition, WindowCommitError,
};
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Header, Network};
use bitcoin_rs_wire::{InboundHeaders, PeerTable};
use crossbeam_channel::Receiver;

pub use crate::p2p::sync::{BlockSync, default_sync_budget};

struct NodeSyncChain {
    assumeutxo: Option<Arc<bitcoin_rs_execution::AssumeUtxoManager>>,
    handles: Arc<bitcoin_rs_execution::Chainstate>,
    block_tree: bitcoin_rs_execution::chain::BlockTreeReader,
    followers: crate::chain_effects::ChainFollowers,
    budget: Arc<crate::budget::NodeBudget>,
}

#[must_use]
pub struct BlockSyncInputs {
    pub handles: Arc<bitcoin_rs_execution::Chainstate>,
    pub followers: crate::chain_effects::ChainFollowers,
    pub peer_table: Arc<PeerTable>,
    pub inbound_headers_rx: Receiver<InboundHeaders>,
    pub inbound_blocks_rx: Receiver<bitcoin_rs_wire::InboundBlock>,
    pub ibd: Arc<bitcoin_rs_execution::chain::InitialBlockDownload>,
    pub assumeutxo: Option<Arc<bitcoin_rs_execution::AssumeUtxoManager>>,
    pub budget: Arc<crate::budget::NodeBudget>,
}

fn with_historical_background_permit<T>(
    budget: &crate::budget::NodeBudget,
    validate: impl FnOnce() -> T,
) -> T {
    let _permit = budget.cpu().try_acquire_background();
    validate()
}

#[must_use]
pub fn block_sync(inputs: BlockSyncInputs) -> BlockSync {
    let block_tree = inputs.handles.block_tree_reader();
    BlockSync::new(
        Arc::new(NodeSyncChain {
            assumeutxo: inputs.assumeutxo,
            handles: Arc::clone(&inputs.handles),
            block_tree,
            followers: inputs.followers,
            budget: inputs.budget,
        }),
        inputs.peer_table,
        inputs.inbound_headers_rx,
        inputs.inbound_blocks_rx,
        inputs.ibd,
    )
}

fn settle_window_failure(
    transition: bitcoin_rs_execution::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    mut error: bitcoin_rs_execution::WindowApplyError,
) -> bitcoin_rs_execution::WindowApplyError {
    let handles = transition.chainstate();
    if error.disposition == bitcoin_rs_execution::WindowApplyDisposition::Fatal
        || bitcoin_rs_execution::classify_apply_error(&error.source)
            == bitcoin_rs_execution::WindowApplyDisposition::Fatal
    {
        handles.fail_closed_for_recovery();
        error.disposition = bitcoin_rs_execution::WindowApplyDisposition::Fatal;
    } else if let Err(finish_source) =
        crate::chain_effects::ChainFollowers::finish_transition(handles, transition, mempool_change)
    {
        tracing::error!(
            original = %error.source,
            finish = %finish_source,
            "chain transition could not be settled after a window failure; \
             mempool admission stays closed until recovery or restart"
        );
        error.disposition = bitcoin_rs_execution::WindowApplyDisposition::Fatal;
    }
    error
}

fn settle_window_refused(
    transition: bitcoin_rs_execution::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    refusal: WindowCommitError,
) -> WindowCommitError {
    let handles = transition.chainstate();
    handles.fail_closed_for_recovery();
    drop(mempool_change);
    drop(transition);
    tracing::error!(
        refusal = %refusal.source,
        "chain transition halted after a committed window: a follower refused settlement; \
         mempool admission stays closed until recovery or restart"
    );
    refusal
}

fn settle_window_success(
    transition: bitcoin_rs_execution::ChainTransition<'_>,
    mempool_change: Option<bitcoin_rs_mempool::ChainChangeGuard>,
    applied: usize,
    committed: Vec<bitcoin_rs_execution::ConnectOutcome>,
) -> core::result::Result<usize, bitcoin_rs_execution::WindowApplyError> {
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
            Err(bitcoin_rs_execution::WindowApplyError {
                applied,
                committed,
                source: Box::new(finish_source),
                disposition: bitcoin_rs_execution::WindowApplyDisposition::Fatal,
                invalidated: Box::default(),
            })
        }
    }
}

#[cfg(test)]
pub(crate) fn fixture_insert_header_node(
    handles: &bitcoin_rs_execution::Chainstate,
    parent: bitcoin_rs_execution::chain::NodeId,
    header: bitcoin_rs_consensus::primitives::Header,
    status: bitcoin_rs_execution::chain::NodeStatus,
) -> Result<bitcoin_rs_execution::chain::NodeId, bitcoin_rs_execution::chain::ChainError> {
    let mut tree = handles.block_tree().write();
    tree.insert_node(Some(parent), header, status)
}

impl SyncChain for NodeSyncChain {
    fn historical_base(&self) -> Option<Hash256> {
        match self.handles.role() {
            bitcoin_rs_execution::assumeutxo::ChainstateRole::AssumedActive {
                base_hash, ..
            } => Some(base_hash),
            _ => None,
        }
    }

    fn closed_for_recovery(&self) -> bool {
        self.handles.is_closed_for_recovery()
    }

    fn advance_historical(&self) -> Result<HistoricalAdvance, SyncChainError> {
        let Some(manager) = &self.assumeutxo else {
            return Ok(HistoricalAdvance::Complete);
        };
        manager.advance_historical().map_err(|error| {
            self.handles.fail_closed_for_recovery();
            SyncChainError::from(error)
        })
    }

    fn connect_historical(&self, payload: &BlockImage) -> Result<(), SyncChainError> {
        let manager = self
            .assumeutxo
            .as_ref()
            .ok_or("historical validation is not configured")?;
        with_historical_background_permit(&self.budget, || manager.step_historical(payload))
            .map(|_| ())
            .map_err(SyncChainError::from)
    }

    fn network(&self) -> Network {
        self.handles.network()
    }

    fn block_tree(
        &self,
    ) -> parking_lot::RwLockReadGuard<'_, bitcoin_rs_execution::chain::BlockTree> {
        self.block_tree.read()
    }

    fn chain_tip(&self) -> Option<Arc<bitcoin_rs_execution::chain::TipSnapshot>> {
        self.handles.header_tip()
    }

    fn applied_tip(&self) -> Option<Arc<bitcoin_rs_execution::chain::TipSnapshot>> {
        self.handles.applied_tip_snapshot()
    }

    fn bootstrap_genesis(&self) {
        if let Err(error) = crate::chain_effects::bootstrap_genesis(&self.handles, &self.followers)
        {
            tracing::warn!(%error, "failed to bootstrap genesis");
        }
    }

    fn admit_headers(&self, headers: &[Header]) -> HeaderAdmission {
        match self.handles.admit_headers(headers) {
            Ok(outcome) => HeaderAdmission::Accepted {
                accepted: outcome.accepted,
                announced_tip: outcome.announced_tip,
                active_height: outcome.active_height,
                demoted_tip: outcome.demoted_tip,
            },
            Err(bitcoin_rs_execution::HeaderAdmissionError::Rejected(error)) => {
                HeaderAdmission::Rejected(error)
            }
            Err(bitcoin_rs_execution::HeaderAdmissionError::Refused(error)) => {
                HeaderAdmission::Refused(bitcoin_rs_execution::chain::HeaderRefusal::from_cause(
                    &error,
                ))
            }
        }
    }

    fn check_body_binding(&self, block: &BlockImage) -> Result<(), SyncChainError> {
        let hash = Hash256::from(block.block_hash());
        let segwit_active = {
            let tree = self.block_tree.read();
            tree.lookup(hash)
                .and_then(|node_id| tree.node(node_id).ok())
                .is_none_or(|node| {
                    bitcoin_rs_execution::chain::softfork_state(
                        &tree,
                        self.handles.network(),
                        node.parent,
                        node.height,
                    )
                    .segwit_active
                })
        };
        bitcoin_rs_consensus::check_image_body_binding(
            block,
            bitcoin_rs_consensus::BlockRuleContext { segwit_active },
        )
        .map_err(SyncChainError::from)
    }

    fn window_len(&self, serialized_sizes: &mut dyn Iterator<Item = usize>) -> usize {
        bitcoin_rs_execution::window_len_within(serialized_sizes, self.budget.script_batch_limits())
    }

    fn commit_window(&self, payloads: &[&BlockImage]) -> Result<usize, WindowCommitError> {
        let transition = self
            .handles
            .begin_transition()
            .map_err(|source| WindowCommitError {
                applied: 0,
                disposition: WindowApplyDisposition::Operational,
                invalidated: Box::default(),
                source: source.into(),
            })?;
        let mempool_change =
            self.followers
                .begin_mempool_change()
                .map_err(|source| WindowCommitError {
                    applied: 0,
                    disposition: WindowApplyDisposition::Operational,
                    invalidated: Box::default(),
                    source: source.into(),
                })?;
        let _foreground = self.budget.cpu().acquire_foreground();
        match transition.connect_window(payloads) {
            Ok(outcomes) => {
                match settle_committed_followers(&self.followers, payloads, &outcomes) {
                    Ok(()) => {
                        settle_window_success(transition, mempool_change, outcomes.len(), outcomes)
                            .map_err(window_commit_error)
                    }
                    Err(refusal) => Err(settle_window_refused(
                        transition,
                        mempool_change,
                        WindowCommitError {
                            applied: outcomes.len(),
                            ..refused_window(refusal)
                        },
                    )),
                }
            }
            Err(error) => {
                let settled =
                    settle_committed_followers(&self.followers, payloads, &error.committed);
                match settled {
                    Ok(()) => Err(window_commit_error(settle_window_failure(
                        transition,
                        mempool_change,
                        error,
                    ))),
                    Err(refusal) => {
                        tracing::error!(
                            original = %error.source,
                            refusal = %refusal,
                            "window application failed before follower settlement was refused"
                        );
                        Err(settle_window_refused(
                            transition,
                            mempool_change,
                            WindowCommitError {
                                applied: error.applied,
                                invalidated: error.invalidated,
                                ..refused_window(refusal)
                            },
                        ))
                    }
                }
            }
        }
    }

    fn switch_to_branch(
        &self,
        target: bitcoin_rs_execution::chain::NodeId,
        staged_body: &mut dyn FnMut(Hash256) -> Option<BlockImage>,
        connected_body: &mut dyn FnMut(Hash256),
    ) -> Result<(), ReorgError> {
        crate::reorg::switch_to_branch(
            &self.handles,
            &self.followers,
            target,
            staged_body,
            connected_body,
        )
        .inspect_err(|error| {
            if matches!(error, ReorgError::ConnectFailed { invalidated, .. } if !invalidated.is_empty()) {
                self.handles.reevaluate_assume_valid();
            }
        })
    }
}

fn refused_window(source: bitcoin_rs_mempool::MempoolError) -> WindowCommitError {
    WindowCommitError {
        applied: 0,
        disposition: WindowApplyDisposition::Fatal,
        invalidated: Box::default(),
        source: SyncChainError::Message(format!("mempool settlement refused: {source}")),
    }
}

fn settle_committed_followers(
    followers: &crate::chain_effects::ChainFollowers,
    payloads: &[&BlockImage],
    committed: &[bitcoin_rs_execution::ConnectOutcome],
) -> core::result::Result<(), bitcoin_rs_mempool::MempoolError> {
    for (payload, outcome) in payloads.iter().zip(committed) {
        followers.on_connect(payload, outcome)?;
    }
    Ok(())
}

fn window_commit_error(error: bitcoin_rs_execution::WindowApplyError) -> WindowCommitError {
    WindowCommitError {
        applied: error.applied,
        disposition: error.disposition,
        invalidated: error.invalidated,
        source: (*error.source).into(),
    }
}

#[cfg(test)]
mod tests;
