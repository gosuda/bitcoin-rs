//! Node-owned mining control facade and network-hash-rate helpers.
//!
//! Candidate lifecycle state lives in [`bitcoin_rs_mining::coordinator`];
//! this module keeps the wake seam between authoritative mutations and the
//! template coordinator, plus the node-owned header admission and
//! `getnetworkhashps` estimation. Proposal mode dry-runs the ordinary apply
//! validation path without persistence; solved-block submission returns only
//! after validation, persistence, and chain-state application complete.

mod candidate;
mod control;
mod submission;

use crate::apply::Chainstate;
use crate::chain_effects::ChainFollowers;
use alloc::sync::Arc;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::accept_headers;
use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_chain::signalling_deployments;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::MempoolObserver;
use bitcoin_rs_mempool::MutationEnvelope;
use bitcoin_rs_mining::AppliedTipSource;
use bitcoin_rs_mining::AvailableMiningRule;
#[cfg(test)]
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::ChainContextSource;
use bitcoin_rs_mining::GenerateSelection;
use bitcoin_rs_mining::MempoolSequenceWake;
use bitcoin_rs_mining::MempoolSnapshotSource;
use bitcoin_rs_mining::MiningChainContext;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::MiningRule;
use bitcoin_rs_mining::MiningService;
use bitcoin_rs_mining::snapshot_for_selection;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::Network;
use compact_str::CompactString;
use core::time::Duration;
use parking_lot::RwLock;
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use submission::map_apply_error;

/// Wake seam between authoritative mutations and the template coordinator.
///
/// [`MiningCoordinator::publish_generation`] documents that every long-poll
/// waiter must observe each authoritative applied-tip or mempool mutation,
/// but the coordinator is built after node state, so it cannot be referenced
/// from the apply path or the mempool gateway directly. This signal is
/// created with the node state, wired into the gateway's mutation observer
/// and the apply-path tip publication points, and the coordinator attaches
/// itself at startup: [`Self::publish_generation`] then forwards to the live
/// coordinator. With nothing attached it is a no-op — there is no waiter to
/// wake before the coordinator exists.
#[derive(Default)]
pub struct MiningGenerationSignal {
    coordinator: RwLock<Option<std::sync::Weak<dyn MiningControl>>>,
    /// Lock-free mempool-sequence wake; set by [`Self::attach_sequence_wake`].
    sequence_wake: RwLock<Option<std::sync::Weak<dyn MempoolSequenceWake>>>,
}

impl MiningGenerationSignal {
    /// Creates a detached signal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Points the signal at `coordinator` without extending its ownership.
    ///
    /// The RPC context owns the coordinator; this wake seam must not create
    /// an ownership cycle through `MiningCoordinator::apply_handles`, which
    /// carries the same signal back. A weak reference keeps the seam
    /// observational: the coordinator's lifetime is the context's, and a
    /// wake against a torn-down coordinator is a no-op.
    pub fn attach(&self, coordinator: &Arc<dyn MiningControl>) {
        *self.coordinator.write() = Some(Arc::downgrade(coordinator));
    }

    /// Points the signal at a lock-free mempool-sequence wake.
    ///
    /// When attached, [`Self::publish_generation_from`] forwards to `wake`
    /// without taking the mempool read lock. Without it, that method falls
    /// back to [`Self::publish_generation`].
    pub fn attach_sequence_wake(&self, wake: &Arc<dyn MempoolSequenceWake>) {
        *self.sequence_wake.write() = Some(Arc::downgrade(wake));
    }

    /// Forwards one authoritative-mutation wake to the attached coordinator.
    pub fn publish_generation(&self) {
        if let Some(coordinator) = self
            .coordinator
            .read()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            coordinator.publish_generation();
        }
    }

    /// Forwards one mempool-sequence wake to the attached coordinator.
    ///
    /// Uses the lock-free [`MempoolSequenceWake`] path when attached;
    /// otherwise falls back to [`Self::publish_generation`].
    pub fn publish_generation_from(&self, sequence: u64) {
        if let Some(wake) = self
            .sequence_wake
            .read()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            wake.publish_generation_from(sequence);
        } else {
            self.publish_generation();
        }
    }
}

impl MempoolObserver for MiningGenerationSignal {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let wake_sequence = result
            .sequence_of(result.changes.len().saturating_sub(1))
            .unwrap_or(result.sequence_base);
        self.publish_generation_from(wake_sequence);
    }
}

/// Production mining coordinator owned by the node process.
///
/// `coinbase_script` is immutable coordinator configuration captured at
/// construction. There is no wallet coupling and no default miner address:
/// callers must pass the template coinbase `ScriptBuf` explicitly. Callers may
/// pass an empty script for transport-only GBT assembly (RPC exposes
/// `coinbasevalue` / `default_witness_commitment`, not a node-owned payout).
pub struct MiningCoordinator {
    network: Network,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    apply_handles: Chainstate,
    followers: ChainFollowers,
    shutdown: Arc<AtomicBool>,
    /// Mining-domain lifecycle service over the capability adapters.
    service: MiningService,
}

impl MiningCoordinator {
    /// Builds a coordinator over the shared applied-chain and mempool handles.
    ///
    /// `coinbase_script` is required and stored immutably. Pass
    /// `Vec::new()` for transport-only template assembly when the node
    /// does not own a miner payout script.
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
            MiningControlError::Rejected(missing_parent_reason(Hash256::from(
                header.prev_blockhash,
            )))
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

fn missing_parent_reason(prev_hash: Hash256) -> CompactString {
    CompactString::from(format!("Must submit previous header ({prev_hash}) first"))
}

fn header_reject_reason(error: ChainError) -> MiningControlError {
    let reason = match error {
        ChainError::InvalidPow { .. } => CompactString::from("high-hash"),
        ChainError::ZeroTarget { .. }
        | ChainError::TargetExceedsLimit { .. }
        | ChainError::NbitsMismatch { .. } => CompactString::from("bad-diffbits"),
        ChainError::TimestampTooEarly { .. } => CompactString::from("time-too-old"),
        ChainError::TimestampTooFarAhead { .. } => CompactString::from("time-too-new"),
        ChainError::MissingParent { prev_hash } => missing_parent_reason(prev_hash),
        other => CompactString::from(other.to_string()),
    };
    MiningControlError::Rejected(reason)
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

#[cfg(test)]
mod header_reject_tests;

fn hashps_missing_height() -> MiningControlError {
    MiningControlError::InvalidRequest(CompactString::from(
        "Block does not exist at specified height",
    ))
}

/// Resolves the `getnetworkhashps` start node from one tip snapshot.
///
/// This is the sole height-resolution owner for that RPC. `None` is an empty
/// chain (rate `0.0`). An explicit height that is absent from that snapshot is
/// Core's invalid-parameter error, not a zero rate.
// CONTRACT: docs/contracts/external-api.md#API-06
fn resolve_hash_ps_start(
    tree: &BlockTree,
    tip: Option<&TipSnapshot>,
    height: i64,
) -> Result<Option<NodeId>, MiningControlError> {
    let tip_height = tip.map_or(-1, |snapshot| i64::from(snapshot.height));
    if height < -1 || height > tip_height {
        return Err(hashps_missing_height());
    }
    let Some(tip) = tip else {
        return Ok(None);
    };
    if height < 0 {
        return Ok(Some(tip.tip_id));
    }
    let requested = u32::try_from(height).map_err(|_| hashps_missing_height())?;
    tree.node_at_height_from(tip.tip_id, requested)
        .map(Some)
        .ok_or_else(hashps_missing_height)
}

fn hash_ps_at(
    tree: &BlockTree,
    tip: Option<&TipSnapshot>,
    lookup: i64,
    height: i64,
    network: Network,
) -> Result<f64, MiningControlError> {
    let start = resolve_hash_ps_start(tree, tip, height)?;
    Ok(estimate_network_hashps(tree, start, lookup, network))
}

/// Estimates hashes/s over `lookup` blocks ending at an already-resolved start.
///
/// Height validation lives in [`resolve_hash_ps_start`]. The window is Core's
/// parent walk (`GetNetworkHashPS`): `lookup` parent pointers from the start
/// node, min/max header time, `chainwork` delta over that span. A missing
/// start or unwalkable window is a zero rate so `getmininginfo` can stay
/// best-effort.
// CONTRACT: docs/contracts/external-api.md#API-06
fn estimate_network_hashps(
    tree: &BlockTree,
    start_id: Option<NodeId>,
    lookup: i64,
    network: Network,
) -> f64 {
    let Some(start_id) = start_id else {
        return 0.0;
    };
    let Ok(start_node) = tree.node(start_id) else {
        return 0.0;
    };
    if start_node.height == 0 {
        return 0.0;
    }
    let mut walk = if lookup == -1 {
        let interval = i64::from(network.retarget_interval());
        if interval <= 0 {
            1
        } else {
            i64::from(start_node.height) % interval + 1
        }
    } else {
        lookup
    };
    if walk > i64::from(start_node.height) {
        walk = i64::from(start_node.height);
    }
    let walk = u32::try_from(walk).unwrap_or(u32::MAX);
    if walk == 0 {
        return 0.0;
    }

    let mut min_time = start_node.header.time;
    let mut max_time = min_time;
    let mut earliest_id = start_id;
    for _ in 0..walk {
        let Ok(node) = tree.node(earliest_id) else {
            return 0.0;
        };
        let Some(parent) = node.parent else {
            return 0.0;
        };
        earliest_id = parent;
        let Ok(parent_node) = tree.node(earliest_id) else {
            return 0.0;
        };
        min_time = min_time.min(parent_node.header.time);
        max_time = max_time.max(parent_node.header.time);
    }
    if min_time == max_time {
        return 0.0;
    }
    let Ok(earliest_node) = tree.node(earliest_id) else {
        return 0.0;
    };
    let work_delta = start_node.chainwork.saturating_sub(earliest_node.chainwork);
    let time_delta_secs = i64::from(max_time).saturating_sub(i64::from(min_time));
    let work_bytes: [u8; 32] = work_delta.to_be_bytes();
    hashes_per_second(work_bytes, time_delta_secs)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hashes_per_second(work_be_bytes: [u8; 32], time_delta_secs: i64) -> f64 {
    if time_delta_secs <= 0 {
        return 0.0;
    }
    let work = work_be_bytes
        .iter()
        .fold(0.0_f64, |acc, &byte| acc.mul_add(256.0, f64::from(byte)));
    work / f64::from(u32::try_from(time_delta_secs).unwrap_or(u32::MAX))
}

/// Oracle: Bitcoin Core `GetNetworkHashPS` in `src/rpc/mining.cpp` (kernel 31.99).
///
/// `workDiff = nChainWork[end] - nChainWork[start]` over `lookup` parent walks,
/// `timeDiff = max(GetBlockTime) - min(GetBlockTime)` in that window, result
/// `workDiff.getdouble() / timeDiff`. Non-monotonic timestamps use min/max, not
/// first/last. `lookup == -1` walks `height % DifficultyAdjustmentInterval + 1`.
#[cfg(test)]
mod network_hashps_oracle_tests;

#[cfg(test)]
mod generation_signal_tests;
