//! Node-owned mining control facade.
//!
//! Header admission and proposal/submission projection over the authoritative
//! chainstate. Candidate lifecycle lives in `bitcoin_rs_mining`.

mod candidate;
mod control;
mod submission;

use crate::apply::Chainstate;
use crate::chain_effects::ChainFollowers;
use alloc::sync::Arc;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::accept_headers;
use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_chain::signalling_deployments;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mining::AppliedTipSource;
use bitcoin_rs_mining::AvailableMiningRule;
use bitcoin_rs_mining::ChainContextSource;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::MempoolSequenceWake;
use bitcoin_rs_mining::MempoolSnapshotSource;
use bitcoin_rs_mining::MiningChainContext;
use bitcoin_rs_mining::MiningControlError;
pub use bitcoin_rs_mining::MiningGenerationSignal;
use bitcoin_rs_mining::MiningRule;
use bitcoin_rs_mining::MiningService;
use bitcoin_rs_mining::header_reject_reason;
use bitcoin_rs_mining::snapshot_for_selection;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use compact_str::CompactString;
use parking_lot::RwLock;
use std::sync::atomic::AtomicBool;

/// Production mining coordinator owned by the node process.
pub struct MiningCoordinator {
    network: Network,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    apply_handles: Chainstate,
    followers: ChainFollowers,
    shutdown: Arc<AtomicBool>,
    service: MiningService,
}

impl MiningCoordinator {
    /// Builds a coordinator over the shared applied-chain and mempool handles.
    #[must_use]
    pub fn new(
        network: Network,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        mempool: Arc<RwLock<Mempool>>,
        apply_handles: Chainstate,
        followers: ChainFollowers,
        coinbase_script: Vec<u8>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let service = MiningService::new(
            network,
            Arc::new(AppliedTipAdapter {
                tip: Arc::clone(&applied_tip),
            }),
            Arc::new(MempoolAdapter { mempool }),
            Arc::new(ChainContextAdapter {
                block_tree: Arc::clone(&block_tree),
                network,
            }),
            coinbase_script,
            Arc::clone(&shutdown),
        );
        Self {
            network,
            applied_tip,
            block_tree,
            apply_handles,
            followers,
            shutdown,
            service,
        }
    }

    /// Reduces shutdown latency after the caller sets the shared shutdown flag.
    ///
    /// Correctness does not depend on this notification: every wait is bounded
    /// and rechecks the shutdown predicate.
    pub fn notify_shutdown(&self) {
        self.service.notify_shutdown();
    }

    /// Admits `header` through [`accept_headers`], the same gate inbound P2P uses.
    fn accept_submitted_header(&self, header: Header) -> Result<(), MiningControlError> {
        let _transition = self.apply_handles.lock_transition().map_err(|error| {
            MiningControlError::Unavailable(CompactString::from(error.to_string()))
        })?;
        let mut tree = self.block_tree.write();
        // Preserve accept_headers' idempotent duplicate path, including genesis.
        if tree.lookup(header.compute_hash().into()).is_some() {
            return accept_headers(
                &mut tree,
                std::slice::from_ref(&header),
                self.network,
                current_unix_seconds(),
            )
            .map(|_| ())
            .map_err(header_reject_reason);
        }
        let parent = tree.lookup(header.prev_blockhash.into()).ok_or_else(|| {
            header_reject_reason(ChainError::MissingParent {
                prev_hash: header.prev_blockhash.into(),
            })
        })?;
        if tree
            .node(parent)
            .is_ok_and(|node| node.status == bitcoin_rs_chain::NodeStatus::Invalid)
        {
            return Err(MiningControlError::Rejected(CompactString::from(
                "bad-prevblk",
            )));
        }
        accept_headers(
            &mut tree,
            std::slice::from_ref(&header),
            self.network,
            current_unix_seconds(),
        )
        .map(|_| ())
        .map_err(header_reject_reason)
    }
}

/// Serves the lifecycle the applied-tip snapshot the node publishes.
struct AppliedTipAdapter {
    tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl AppliedTipSource for AppliedTipAdapter {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        self.tip.load_full().map(|snapshot| (*snapshot).clone())
    }
}

/// Serves mempool reads for candidate assembly, one read lock per call.
struct MempoolAdapter {
    mempool: Arc<RwLock<Mempool>>,
}

impl MempoolSnapshotSource for MempoolAdapter {
    fn current_sequence(&self) -> u64 {
        self.mempool.read().sequence_number()
    }

    fn mining_snapshot_at(&self, expected_sequence: u64) -> Option<MempoolMiningSnapshot> {
        let mempool = self.mempool.read();
        if mempool.sequence_number() != expected_sequence {
            return None;
        }
        Some(mempool.mining_snapshot())
    }

    fn pooled_transaction_count(&self) -> u64 {
        u64::try_from(self.mempool.read().len()).unwrap_or(u64::MAX)
    }

    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
        let mempool = self.mempool.read();
        snapshot_for_selection(&mempool, selection)
    }

    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        self.mempool.read().min_relay_fee_sat_per_kvb()
    }
}

/// Resolves applied-tree facts for the lifecycle.
struct ChainContextAdapter {
    block_tree: Arc<RwLock<BlockTree>>,
    network: Network,
}

impl ChainContextSource for ChainContextAdapter {
    fn resolve_mining_context(
        &self,
        tip: &TipSnapshot,
        candidate_time: u32,
    ) -> Result<MiningChainContext, ChainError> {
        MiningChainContext::resolve(
            &self.block_tree.read(),
            self.network,
            tip.tip_id,
            candidate_time,
        )
    }

    fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
        self.block_tree
            .read()
            .node(tip.tip_id)
            .map(|node| node.header.bits)
    }

    fn signalling_rules(&self, tip: &TipSnapshot, height: u32) -> Vec<AvailableMiningRule> {
        signalling_deployments(&self.block_tree.read(), self.network, tip.tip_id, height)
            .into_iter()
            .map(|deployment| AvailableMiningRule {
                rule: MiningRule::new(deployment.name),
                bit: deployment.bit,
            })
            .collect()
    }
}

impl MempoolSequenceWake for MiningCoordinator {
    fn publish_generation_from(&self, sequence: u64) {
        self.service.publish_generation_from(sequence);
    }
}

#[cfg(test)]
mod apply_error_tests;
