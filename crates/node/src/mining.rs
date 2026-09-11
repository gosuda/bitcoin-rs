//! Node-owned mining candidate lifecycle coordinator.
//!
//! Generation is keyed by `(applied_tip_hash, mempool_sequence)`. Template
//! assembly is single-flight per key, cached by [`TemplateId`], and woken by
//! explicit generation publication. Proposal mode dry-runs the ordinary apply
//! validation path without persistence; solved-block submission returns only
//! after validation, persistence, and chain-state application complete.

mod candidate;
mod control;
mod long_poll;
mod submission;

use crate::apply::Chainstate;
use crate::chain_effects::ChainFollowers;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolObserver;
use bitcoin_rs_mempool::MutationEnvelope;
#[cfg(test)]
use bitcoin_rs_mining::BlockValidationResult;
use bitcoin_rs_mining::Candidate;
use bitcoin_rs_mining::LastCandidateInfo;
use bitcoin_rs_mining::MiningControl;
use bitcoin_rs_mining::MiningControlError;
use bitcoin_rs_mining::TemplateId;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use compact_str::CompactString;
use core::time::Duration;
use hashbrown::HashMap;
#[cfg(test)]
use long_poll::parse_long_poll_id;
use parking_lot::Condvar;
use parking_lot::Mutex;
use parking_lot::RwLock;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
#[cfg(test)]
use submission::map_apply_error;

/// Default number of cached candidates retained by template id.
const CANDIDATE_CACHE_LIMIT: usize = 8;
/// Finite bound on generation-key races during candidate assembly.
const CANDIDATE_GENERATION_RETRIES: usize = 8;
const GENERATION_RACE: &str = "generation key changed during candidate assembly";
/// Bitcoin Core's mempool-only long-poll cooldown before returning a new template.
const DEFAULT_MEMPOOL_UPDATE_WAIT: Duration = Duration::from_secs(10);
/// Upper bound for a single long-poll wait slice while rechecking predicates.
const LONG_POLL_SLICE: Duration = Duration::from_secs(1);
/// Consensus maximum block weight / serialized size.
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
const MAX_BLOCK_SIZE: u64 = 4_000_000;

/// Applied-tip hash plus mempool sequence that identify one candidate generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GenerationKey {
    /// Applied tip hash in consensus little-endian storage order.
    pub tip_hash: Hash256,
    /// Mempool sequence captured with the tip.
    pub mempool_sequence: u64,
}

impl GenerationKey {
    /// Opaque BIP22/BIP23 long-poll identity for this generation.
    #[must_use]
    pub fn template_id(self) -> TemplateId {
        TemplateId::new(&self.tip_hash, self.mempool_sequence)
    }
}

#[derive(Debug)]
struct InFlight {
    key: GenerationKey,
    result: Option<Result<Arc<Candidate>, MiningControlError>>,
}

struct CoordinatorState {
    /// Last generation published to long-poll waiters.
    published: Option<GenerationKey>,
    /// Bounded LRU of assembled candidates keyed by template id.
    cache: HashMap<TemplateId, Arc<Candidate>>,
    /// Insertion order for deterministic eviction of the oldest entry.
    cache_order: VecDeque<TemplateId>,
    /// Single in-flight assembly, if any.
    in_flight: Option<InFlight>,
    /// Facts from the most recently assembled candidate.
    last_candidate: Option<LastCandidateInfo>,
}

impl CoordinatorState {
    fn new() -> Self {
        Self {
            published: None,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            in_flight: None,
            last_candidate: None,
        }
    }

    fn cache_get(&self, id: &TemplateId) -> Option<Arc<Candidate>> {
        self.cache.get(id).cloned()
    }

    fn cache_insert(&mut self, id: TemplateId, candidate: Arc<Candidate>) {
        if self.cache.contains_key(&id) {
            self.cache.insert(id, candidate);
            return;
        }
        while self.cache.len() >= CANDIDATE_CACHE_LIMIT {
            let Some(oldest) = self.cache_order.pop_front() else {
                break;
            };
            self.cache.remove(&oldest);
        }
        self.cache_order.push_back(id.clone());
        self.cache.insert(id, candidate);
    }

    fn invalidate_key(&mut self, key: GenerationKey) {
        let id = key.template_id();
        if self.cache.remove(&id).is_some() {
            self.cache_order.retain(|cached| cached != &id);
        }
        if self
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == key)
        {
            self.in_flight = None;
        }
    }
}
/// Mempool-sequence wake that avoids the mempool read lock.
///
/// The mempool observer fires under the gateway's publish mutex; taking the
/// pool read lock from that path can deadlock or contend with an in-flight
/// writer. Implementations build the generation key from `applied_tip` plus
/// the caller-supplied sequence instead.
pub trait MempoolSequenceWake: Send + Sync {
    /// Publishes a generation key built from `applied_tip` and `sequence`
    /// without taking the mempool read lock, then wakes all waiters.
    fn publish_generation_from(&self, sequence: u64);
}

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
    mempool: Arc<RwLock<Mempool>>,
    apply_handles: Chainstate,
    followers: ChainFollowers,
    coinbase_script: Vec<u8>,
    shutdown: Arc<AtomicBool>,
    /// Wall clock used for long-poll cooldowns.
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    /// Controllable mempool-only long-poll cooldown (Core default: 10s).
    mempool_update_wait: Duration,
    state: Mutex<CoordinatorState>,
    wake: Condvar,
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
        Self {
            network,
            applied_tip,
            block_tree,
            mempool,
            apply_handles,
            followers,
            coinbase_script,
            shutdown,
            clock: Arc::new(Instant::now),
            mempool_update_wait: DEFAULT_MEMPOOL_UPDATE_WAIT,
            state: Mutex::new(CoordinatorState::new()),
            wake: Condvar::new(),
        }
    }

    /// Overrides the wall clock. Intended for deterministic tests.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Overrides the mempool-only long-poll cooldown. Tests may set this to zero.
    #[must_use]
    pub const fn with_mempool_update_wait(mut self, wait: Duration) -> Self {
        self.mempool_update_wait = wait;
        self
    }

    fn current_time_secs() -> u32 {
        u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
        )
        .unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod apply_error_tests;

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
/// Height validation lives in [`resolve_hash_ps_start`]. A missing start or
/// unwalkable window is a zero rate so `getmininginfo` can stay best-effort.
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
    let walk = if lookup == -1 {
        let interval = i64::from(network.retarget_interval());
        if interval <= 0 {
            1
        } else {
            i64::from(start_node.height) % interval + 1
        }
    } else {
        lookup
    };
    let walk = u32::try_from(walk).unwrap_or(u32::MAX);
    let walk = walk.min(start_node.height);
    if walk == 0 {
        return 0.0;
    }
    let target_height = start_node.height.saturating_sub(walk);
    let Some(earliest_id) = tree.node_at_height_from(start_id, target_height) else {
        return 0.0;
    };
    let Ok(earliest_node) = tree.node(earliest_id) else {
        return 0.0;
    };
    if earliest_node.height == start_node.height {
        return 0.0;
    }
    let mut min_time = start_node.header.time;
    let mut max_time = min_time;
    for window_height in target_height..=start_node.height {
        let Some(id) = tree.node_at_height_from(start_id, window_height) else {
            continue;
        };
        let Ok(node) = tree.node(id) else {
            continue;
        };
        min_time = min_time.min(node.header.time);
        max_time = max_time.max(node.header.time);
    }
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

/// Decodes a lowercase hex string to bytes. Returns `None` on invalid input.
fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.as_bytes().iter();
    while let Some(&hi) = chars.next() {
        let &lo = chars.next()?;
        let high = decode_nibble(hi)?;
        let low = decode_nibble(lo)?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod generation_key_tests;

/// Oracle: Bitcoin Core `GetNetworkHashPS` in `src/rpc/mining.cpp` (kernel 31.99).
///
/// `workDiff = nChainWork[end] - nChainWork[start]` over `lookup` parent walks,
/// `timeDiff = max(GetBlockTime) - min(GetBlockTime)` in that window, result
/// `workDiff.getdouble() / timeDiff`. Non-monotonic timestamps use min/max, not
/// first/last. `lookup == -1` walks `height % DifficultyAdjustmentInterval + 1`.
#[cfg(test)]
mod network_hashps_oracle_tests;

#[cfg(test)]
mod candidate_template_tests;

#[cfg(test)]
mod generation_signal_tests;
