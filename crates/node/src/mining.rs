//! Node-owned mining candidate lifecycle coordinator.
//!
//! Generation is keyed by `(applied_tip_hash, mempool_sequence)`. Template
//! assembly is single-flight per key, cached by [`TemplateId`], and woken by
//! explicit generation publication. Proposal mode dry-runs the ordinary apply
//! validation path without persistence; solved-block submission returns only
//! after validation, persistence, and chain-state application complete.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_mempool::{Mempool, MempoolObserver, MutationEnvelope};
use bitcoin_rs_mining::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, Candidate, CandidateContext, LastCandidateInfo,
    MiningCapability, MiningChainContext, MiningControl, MiningControlError, MiningInfo,
    MiningRule, SignetMiningInfo, TemplateId, TemplateMutation, assemble_candidate,
    difficulty_for_bits,
};
use bitcoin_rs_primitives::{Block, Hash256, Network};
use compact_str::CompactString;
use hashbrown::HashMap;
use parking_lot::{Condvar, Mutex, RwLock};

use crate::ApplyError;
use crate::apply::{self, Chainstate};
use crate::chain_effects::ChainFollowers;

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

    /// Publishes the live generation key and wakes every long-poll / single-flight waiter.
    ///
    /// Callers must invoke this after every authoritative applied-tip or mempool
    /// mutation and before any dependent notification. The published key is
    /// captured from live applied-tip / mempool state under the coordinator lock.
    pub fn publish_generation(&self) {
        let key = self.live_generation_key();
        let mut state = self.state.lock();
        if let Some(previous) = state.published
            && previous != key
        {
            state.invalidate_key(previous);
        }
        state.published = Some(key);
        self.wake.notify_all();
    }

    /// Publishes a generation key built from `applied_tip` and `sequence`
    /// without taking the mempool read lock, then wakes all waiters.
    ///
    /// The mempool observer calls this with the sequence the mutation already
    /// produced, avoiding a reentrant pool read that can deadlock under the
    /// gateway's publish mutex. Tip-move callers should use
    /// [`Self::publish_generation`] instead, which captures the live sequence
    /// safely (no write lock is held on that path).
    pub fn publish_generation_from(&self, sequence: u64) {
        let tip_hash = self
            .applied_tip
            .load_full()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        let key = GenerationKey {
            tip_hash,
            mempool_sequence: sequence,
        };
        let mut state = self.state.lock();
        if let Some(previous) = state.published
            && previous != key
        {
            state.invalidate_key(previous);
        }
        state.published = Some(key);
        self.wake.notify_all();
    }

    /// Reduces shutdown latency after the caller sets the shared shutdown flag.
    ///
    /// Correctness does not depend on this notification: every wait is bounded
    /// and rechecks the shutdown predicate.
    pub fn notify_shutdown(&self) {
        self.wake.notify_all();
    }

    fn live_generation_key(&self) -> GenerationKey {
        let tip_hash = self
            .applied_tip
            .load_full()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        let mempool_sequence = self.mempool.read().sequence_number();
        GenerationKey {
            tip_hash,
            mempool_sequence,
        }
    }

    fn current_time_secs() -> u32 {
        u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
        )
        .unwrap_or(u32::MAX)
    }

    fn ensure_published(&self, state: &mut CoordinatorState) -> GenerationKey {
        let live = self.live_generation_key();
        if state.published != Some(live) {
            if let Some(previous) = state.published
                && previous != live
            {
                state.invalidate_key(previous);
            }
            state.published = Some(live);
        }
        live
    }

    fn wait_for_generation_change(
        &self,
        waited: GenerationKey,
    ) -> Result<GenerationKey, MiningControlError> {
        let mut state = self.state.lock();
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let live = self.ensure_published(&mut state);
            if live != waited {
                return Ok(live);
            }
            let _ = self.wake.wait_for(&mut state, LONG_POLL_SLICE);
        }
    }

    fn live_candidate(&self) -> Result<Arc<Candidate>, MiningControlError> {
        let mut last_race = None;
        for attempt in 0..CANDIDATE_GENERATION_RETRIES {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let key = {
                let mut state = self.state.lock();
                self.ensure_published(&mut state)
            };
            match self.candidate_for_key(key) {
                Ok(candidate) => {
                    if self.live_generation_key() == key {
                        return Ok(candidate);
                    }
                    last_race = Some(generation_race());
                }
                Err(error) if is_generation_race(&error) => last_race = Some(error),
                Err(error) => return Err(error),
            }
            let _ = attempt;
        }
        Err(last_race.unwrap_or_else(generation_race))
    }

    fn candidate_for_key(&self, key: GenerationKey) -> Result<Arc<Candidate>, MiningControlError> {
        let template_id = key.template_id();
        let mut state = self.state.lock();
        if let Some(cached) = state.cache_get(&template_id) {
            return Ok(cached);
        }

        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let Some(flight) = state.in_flight.as_ref() else {
                break;
            };
            if flight.key != key {
                break;
            }
            if let Some(result) = flight.result.clone() {
                return result;
            }
            let _ = self.wake.wait_for(&mut state, LONG_POLL_SLICE);
        }
        if let Some(cached) = state.cache_get(&template_id) {
            return Ok(cached);
        }

        state.in_flight = Some(InFlight { key, result: None });
        drop(state);

        let assembled = self.assemble_for_key(key);
        let mut state = self.state.lock();
        let returned = match &assembled {
            Ok(candidate) => {
                let live = self.live_generation_key();
                if live == key {
                    state.cache_insert(template_id, Arc::clone(candidate));
                    state.last_candidate = Some(LastCandidateInfo {
                        weight: candidate.weight,
                        transactions: u64::try_from(candidate.transactions.len())
                            .unwrap_or(u64::MAX)
                            .saturating_add(1),
                    });
                    state.published = Some(key);
                    Ok(Arc::clone(candidate))
                } else {
                    Err(generation_race())
                }
            }
            Err(error) => Err(error.clone()),
        };
        if let Some(flight) = state.in_flight.as_mut()
            && flight.key == key
        {
            flight.result = Some(returned.clone());
        }
        self.wake.notify_all();
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == key && flight.result.is_some())
        {
            state.in_flight = None;
        }
        returned
    }

    fn assemble_for_key(&self, key: GenerationKey) -> Result<Arc<Candidate>, MiningControlError> {
        let tip = self.applied_tip.load_full().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        if tip.hash != key.tip_hash {
            return Err(generation_race());
        }
        let snapshot = {
            let mempool = self.mempool.read();
            if mempool.sequence_number() != key.mempool_sequence {
                return Err(generation_race());
            }
            mempool.mining_snapshot()
        };
        let current_time = Self::current_time_secs().max(1);
        let chain = {
            let tree = self.block_tree.read();
            MiningChainContext::resolve(&tree, self.network, tip.tip_id, current_time).map_err(
                |error| MiningControlError::Failed(CompactString::from(error.to_string())),
            )?
        };
        let context = CandidateContext {
            previous_block_hash: chain.previous_block_hash,
            height: chain.height,
            version: chain.version,
            bits: chain.bits,
            min_time: chain.min_time,
            current_time: current_time.max(chain.min_time),
            locktime_cutoff: chain.locktime_cutoff(current_time.max(chain.min_time)),
            network: self.network,
            csv_active: chain.csv_active,
            segwit_active: chain.segwit_active,
            max_weight: MAX_BLOCK_WEIGHT,
            max_size: MAX_BLOCK_SIZE,
            max_sigops: u64::from(bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST),
        };
        let candidate = assemble_candidate(&context, &snapshot, &self.coinbase_script)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        if candidate.template_id != key.template_id() {
            return Err(MiningControlError::Failed(CompactString::from(
                "assembled candidate template id does not match generation key",
            )));
        }
        Ok(Arc::new(candidate))
    }

    fn template_from_candidate(
        network: Network,
        candidate: Arc<Candidate>,
        request: &BlockTemplateRequest,
        submit_old: Option<bool>,
        version_bits_available: Vec<AvailableMiningRule>,
        version_bits_required: u32,
    ) -> BlockTemplate {
        let mut rules = Vec::new();
        if candidate.segwit_active {
            rules.push(MiningRule::new("segwit"));
        }
        if candidate.csv_active {
            rules.push(MiningRule::new("csv"));
        }
        if network.is_taproot_active(candidate.height) {
            rules.push(MiningRule::new("taproot"));
        }
        let mut capabilities = vec![
            MiningCapability::new("proposal"),
            MiningCapability::new("longpoll"),
        ];
        for capability in &request.capabilities {
            if !capabilities
                .iter()
                .any(|known| known.as_str() == capability.as_str())
            {
                capabilities.push(capability.clone());
            }
        }
        BlockTemplate {
            candidate,
            rules,
            version_bits_available,
            version_bits_required,
            capabilities,
            mutable: vec![
                TemplateMutation::Time,
                TemplateMutation::Transactions,
                TemplateMutation::PreviousBlock,
            ],
            submit_old,
            work_id: None,
        }
    }

    fn version_bits_for(&self, candidate: &Candidate) -> (Vec<AvailableMiningRule>, u32) {
        let Some(tip) = self.applied_tip.load_full() else {
            return (Vec::new(), 0);
        };
        if tip.hash != candidate.previous_block_hash {
            return (Vec::new(), 0);
        }
        let tree = self.block_tree.read();
        let signalling = bitcoin_rs_chain::signalling_deployments(
            &tree,
            self.network,
            tip.tip_id,
            candidate.height,
        );
        let mut required = 0_u32;
        let available = signalling
            .into_iter()
            .map(|deployment| {
                if deployment.locked_in {
                    required |= 1_u32 << u32::from(deployment.bit);
                }
                AvailableMiningRule {
                    rule: MiningRule::new(deployment.name),
                    bit: deployment.bit,
                }
            })
            .collect();
        (available, required)
    }

    fn propose(&self, block: &Block) -> BlockValidationResult {
        match apply::validate_block(&self.apply_handles, block) {
            Ok(()) => BlockValidationResult::Accepted,
            Err(error) => map_apply_error(error),
        }
    }

    fn submit(&self, block: &Block) -> Result<BlockValidationResult, MiningControlError> {
        let block_hash: Hash256 = block.block_hash().into();
        {
            let tree = self.block_tree.read();
            if let Some(node_id) = tree.lookup(block_hash) {
                let node = tree.node(node_id).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
                if node.status == bitcoin_rs_chain::NodeStatus::Invalid {
                    return Ok(BlockValidationResult::DuplicateInvalid);
                }
                let on_applied = self.applied_tip.load_full().is_some_and(|tip| {
                    tree.node_at_height_from(tip.tip_id, node.height) == Some(node_id)
                });
                if on_applied {
                    return Ok(BlockValidationResult::Duplicate);
                }
                return Ok(BlockValidationResult::DuplicateInconclusive);
            }
        }

        match self.followers.apply_connect(&self.apply_handles, block) {
            Ok(outcome) => {
                let tip = outcome.tip;
                let visible = self.applied_tip.load_full().ok_or_else(|| {
                    MiningControlError::Failed(CompactString::from(
                        "applied tip missing after accepted submission",
                    ))
                })?;
                if visible.hash != tip.hash {
                    return Err(MiningControlError::Failed(CompactString::from(
                        "applied tip was not published before submit_block returned",
                    )));
                }
                Ok(BlockValidationResult::Accepted)
            }
            Err(error) => Ok(map_apply_error(error)),
        }
    }

    fn mining_info_snapshot(&self) -> Result<MiningInfo, MiningControlError> {
        let tip = self.applied_tip.load_full();
        let blocks = tip.as_ref().map_or(0, |tip| tip.height);
        let (bits, difficulty, next_bits, next_difficulty) = match tip.as_ref() {
            Some(tip) => {
                let tree = self.block_tree.read();
                let tip_bits =
                    tree.node(tip.tip_id)
                        .map(|node| node.header.bits)
                        .map_err(|error| {
                            MiningControlError::Failed(CompactString::from(error.to_string()))
                        })?;
                let current_time = Self::current_time_secs().max(1);
                let next =
                    MiningChainContext::resolve(&tree, self.network, tip.tip_id, current_time)
                        .map_err(|error| {
                            MiningControlError::Failed(CompactString::from(error.to_string()))
                        })?;
                (
                    tip_bits,
                    difficulty_for_bits(tip_bits),
                    next.bits,
                    difficulty_for_bits(next.bits),
                )
            }
            None => (0, 0.0, 0, 0.0),
        };
        let pooled_transactions = u64::try_from(self.mempool.read().len()).unwrap_or(u64::MAX);
        let minimum_fee_rate = self.mempool.read().min_relay_fee_sat_per_kvb();
        let last_candidate = self.state.lock().last_candidate;
        let network_hashes_per_second =
            estimate_network_hashps(&self.block_tree, tip.as_deref(), 120, -1, self.network);
        Ok(MiningInfo {
            blocks,
            last_candidate,
            bits,
            difficulty,
            network_hashes_per_second,
            pooled_transactions,
            network: self.network,
            next_bits,
            next_difficulty,
            minimum_fee_rate,
            signet: signet_info(self.network),
            warnings: crate::metrics::node_warnings()
                .messages()
                .into_iter()
                .map(CompactString::from)
                .collect(),
        })
    }
}

impl MiningControl for MiningCoordinator {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        match request.mode {
            BlockTemplateMode::Proposal(block) => {
                Ok(BlockTemplateResult::Proposal(self.propose(&block)))
            }
            BlockTemplateMode::Template => {
                let waited = if let Some(long_poll_id) = request.long_poll_id.as_deref() {
                    let waited = parse_long_poll_id(long_poll_id).ok_or_else(|| {
                        MiningControlError::InvalidRequest(CompactString::from(
                            "longpollid is malformed",
                        ))
                    })?;
                    let live = {
                        let mut state = self.state.lock();
                        self.ensure_published(&mut state)
                    };
                    if live == waited {
                        self.wait_for_generation_change(waited)?;
                    }
                    Some(waited)
                } else {
                    None
                };
                if self.applied_tip.load_full().is_none() {
                    return Err(MiningControlError::Unavailable(CompactString::from(
                        "applied tip is not available",
                    )));
                }
                let candidate = self.live_candidate()?;
                let submit_old =
                    waited.map(|waited| candidate.previous_block_hash == waited.tip_hash);
                let (version_bits_available, version_bits_required) =
                    self.version_bits_for(&candidate);
                let template = Self::template_from_candidate(
                    self.network,
                    candidate,
                    &request,
                    submit_old,
                    version_bits_available,
                    version_bits_required,
                );
                Ok(BlockTemplateResult::Template(template))
            }
        }
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        self.mining_info_snapshot()
    }

    fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError> {
        if lookup < -1 || lookup == 0 {
            return Err(MiningControlError::InvalidRequest(CompactString::from(
                "Invalid nblocks. Must be a positive number or -1.",
            )));
        }
        let tip = self.applied_tip.load_full();
        let tip_height = tip
            .as_ref()
            .map_or(-1, |snapshot| i64::from(snapshot.height));
        if height < -1 || height > tip_height {
            return Err(MiningControlError::InvalidRequest(CompactString::from(
                "Block does not exist at specified height",
            )));
        }
        Ok(estimate_network_hashps(
            &self.block_tree,
            tip.as_deref(),
            lookup,
            height,
            self.network,
        ))
    }

    fn submit_block(&self, block: Block) -> Result<BlockValidationResult, MiningControlError> {
        self.submit(&block)
    }

    fn publish_generation(&self) {
        Self::publish_generation(self);
    }
}

impl MempoolSequenceWake for MiningCoordinator {
    fn publish_generation_from(&self, sequence: u64) {
        Self::publish_generation_from(self, sequence);
    }
}

fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    if id.len() < 65 {
        return None;
    }
    let (hash_hex, sequence) = id.split_at(64);
    let tip_hash = Hash256::from_str_be(hash_hex).ok()?;
    let mempool_sequence = sequence.parse().ok()?;
    Some(GenerationKey {
        tip_hash,
        mempool_sequence,
    })
}

fn map_apply_error(error: ApplyError) -> BlockValidationResult {
    match error {
        ApplyError::ProofOfWork { .. } => {
            BlockValidationResult::Rejected(CompactString::from("high-hash"))
        }
        ApplyError::PrevHashMismatch { .. } => {
            BlockValidationResult::Rejected(CompactString::from("inconclusive-not-best-prevblk"))
        }
        ApplyError::TargetAboveLimit | ApplyError::NbitsNonRetargetMismatch { .. } => {
            BlockValidationResult::Rejected(CompactString::from("bad-diffbits"))
        }
        ApplyError::BlockOutputsExceedInputs
        | ApplyError::BlockValueOverflow
        | ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { .. }) => {
            BlockValidationResult::Rejected(CompactString::from("bad-cb-amount"))
        }
        ApplyError::Shutdown | ApplyError::JournalBackpressure(_) => {
            BlockValidationResult::Inconclusive
        }
        other => BlockValidationResult::Rejected(CompactString::from(other.to_string())),
    }
}

#[cfg(test)]
mod apply_error_tests {
    use super::{BlockValidationResult, map_apply_error};
    use crate::state::ApplyError;

    #[test]
    fn journal_backpressure_is_operational() {
        assert!(matches!(
            map_apply_error(ApplyError::JournalBackpressure("test pressure".to_owned())),
            BlockValidationResult::Inconclusive
        ));
    }

    #[test]
    fn coinbase_amount_is_bad_cb_amount() {
        assert!(matches!(
            map_apply_error(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseAmount {
                    paid: 1,
                    allowed: 0,
                }
            )),
            BlockValidationResult::Rejected(reason) if reason == "bad-cb-amount"
        ));
    }
}

fn estimate_network_hashps(
    block_tree: &RwLock<BlockTree>,
    tip: Option<&TipSnapshot>,
    lookup: i64,
    height: i64,
    network: Network,
) -> f64 {
    let Some(tip) = tip else {
        return 0.0;
    };
    let tree = block_tree.read();
    let start_id = if height < 0 {
        tip.tip_id
    } else {
        let Ok(requested) = u32::try_from(height) else {
            return 0.0;
        };
        let Some(id) = tree.node_at_height_from(tip.tip_id, requested) else {
            return 0.0;
        };
        id
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
    hashes_per_second(work_delta.to_be_bytes(), time_delta_secs)
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

fn generation_race() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from(GENERATION_RACE))
}

fn is_generation_race(error: &MiningControlError) -> bool {
    matches!(error, MiningControlError::Unavailable(message) if message.as_str() == GENERATION_RACE)
}

fn signet_info(network: Network) -> Option<SignetMiningInfo> {
    const DEFAULT_SIGNET_CHALLENGE: &str = concat!(
        "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430",
        "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
    );

    if network != Network::Signet {
        return None;
    }
    let challenge = hex_decode(DEFAULT_SIGNET_CHALLENGE)
        .unwrap_or_else(|| panic!("Bitcoin Core's default Signet challenge is invalid hex"));
    Some(SignetMiningInfo { challenge })
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
mod generation_key_tests {
    use super::{GenerationKey, parse_long_poll_id};
    use bitcoin_rs_mining::TemplateId;
    use bitcoin_rs_primitives::Hash256;

    #[test]
    fn long_poll_round_trips_template_id() {
        let tip = Hash256::from_le_bytes(&[0x11; 32]);
        let key = GenerationKey {
            tip_hash: tip,
            mempool_sequence: 7,
        };
        let id = key.template_id();
        let Some(parsed) = parse_long_poll_id(id.as_str()) else {
            panic!("generated long-poll id did not parse");
        };
        assert_eq!(parsed, key);
        assert_eq!(TemplateId::new(&tip, 7).as_str(), id.as_str());
    }

    #[test]
    fn hashes_per_second_divides_work_by_elapsed_seconds() {
        let mut work = [0_u8; 32];
        work[31] = 120;
        let rate = super::hashes_per_second(work, 60);
        assert!(
            (rate - 2.0).abs() < f64::EPSILON,
            "120 work over 60s must be 2.0 hashes/s, got {rate}"
        );
        let zero_elapsed = super::hashes_per_second(work, 0);
        assert!(
            zero_elapsed.abs() < f64::EPSILON,
            "zero elapsed must report 0.0 hashes/s, got {zero_elapsed}"
        );
        let negative_elapsed = super::hashes_per_second(work, -1);
        assert!(
            negative_elapsed.abs() < f64::EPSILON,
            "negative elapsed must report 0.0 hashes/s, got {negative_elapsed}"
        );
    }
}

/// Oracle: Bitcoin Core `GetNetworkHashPS` in `src/rpc/mining.cpp` (kernel 31.99).
///
/// `workDiff = nChainWork[end] - nChainWork[start]` over `lookup` parent walks,
/// `timeDiff = max(GetBlockTime) - min(GetBlockTime)` in that window, result
/// `workDiff.getdouble() / timeDiff`. Non-monotonic timestamps use min/max, not
/// first/last. `lookup == -1` walks `height % DifficultyAdjustmentInterval + 1`.
#[cfg(test)]
mod network_hashps_oracle_tests {
    use super::estimate_network_hashps;
    use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::{BlockHash, Hash256, Header, Network};
    use parking_lot::RwLock;

    const BITS: u32 = 0x207f_ffff;

    fn header(prev: BlockHash, time: u32) -> Header {
        Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: BITS,
            nonce: 0,
        }
    }

    fn append(tree: &mut BlockTree, prev: BlockHash, time: u32) -> NodeId {
        tree.insert_header(header(prev, time), NodeStatus::HeaderValid)
            .unwrap_or_else(|err| panic!("insert header at time {time}: {err}"))
    }

    fn snapshot(tree: &BlockTree, tip_id: NodeId) -> TipSnapshot {
        let node = tree
            .node(tip_id)
            .unwrap_or_else(|err| panic!("missing tip {tip_id:?}: {err}"));
        TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    }

    fn work_to_f64(work: bitcoin_rs_chain::ChainWork) -> f64 {
        let bytes: [u8; 32] = work.to_be_bytes();
        bytes
            .iter()
            .fold(0.0_f64, |acc, &byte| acc.mul_add(256.0, f64::from(byte)))
    }

    /// Independent Core parent-walk, not the height-range implementation under test.
    fn core_getnetworkhashps(
        tree: &BlockTree,
        start_id: NodeId,
        lookup: i64,
        network: Network,
    ) -> f64 {
        let start = tree
            .node(start_id)
            .unwrap_or_else(|err| panic!("missing start: {err}"));
        if start.height == 0 {
            return 0.0;
        }
        let mut walk = if lookup == -1 {
            i64::from(start.height) % i64::from(network.retarget_interval()) + 1
        } else {
            lookup
        };
        if walk > i64::from(start.height) {
            walk = i64::from(start.height);
        }
        let walk = u32::try_from(walk).unwrap_or_else(|_| panic!("walk fits u32"));
        let mut min_time = start.header.time;
        let mut max_time = min_time;
        let mut earliest_id = start_id;
        for _ in 0..walk {
            earliest_id = tree
                .node(earliest_id)
                .unwrap_or_else(|err| panic!("missing walked node: {err}"))
                .parent
                .unwrap_or_else(|| panic!("Core walks `lookup` parents; chain too short"));
            let time = tree
                .node(earliest_id)
                .unwrap_or_else(|err| panic!("missing parent: {err}"))
                .header
                .time;
            min_time = min_time.min(time);
            max_time = max_time.max(time);
        }
        if min_time == max_time {
            return 0.0;
        }
        let earliest = tree
            .node(earliest_id)
            .unwrap_or_else(|err| panic!("missing earliest: {err}"));
        let work = work_to_f64(start.chainwork.saturating_sub(earliest.chainwork));
        work / f64::from(max_time.saturating_sub(min_time))
    }

    fn assert_matches_core(
        tree: &RwLock<BlockTree>,
        tip: &TipSnapshot,
        lookup: i64,
        height: i64,
        network: Network,
    ) {
        let expected = {
            let guard = tree.read();
            let start_id = if height < 0 {
                tip.tip_id
            } else {
                let requested = u32::try_from(height).unwrap_or_else(|_| panic!("height fits u32"));
                guard
                    .node_at_height_from(tip.tip_id, requested)
                    .unwrap_or_else(|| panic!("missing height {height}"))
            };
            core_getnetworkhashps(&guard, start_id, lookup, network)
        };
        let got = estimate_network_hashps(tree, Some(tip), lookup, height, network);
        assert!(
            (got - expected).abs() < 1e-9,
            "lookup={lookup} height={height}: got {got}, Core oracle {expected}"
        );
    }

    #[test]
    fn estimate_network_hashps_matches_core_getnetworkhashps() {
        let mut tree = BlockTree::new();
        // Non-monotonic times: height 2 goes backwards so min/max ≠ first/last.
        let times = [1_000_000_u32, 1_000_600, 1_000_300, 1_001_200, 1_001_800];
        let mut prev = BlockHash::default();
        let mut tip_id = None;
        for &time in &times {
            let id = append(&mut tree, prev, time);
            prev = tree
                .node(id)
                .unwrap_or_else(|err| panic!("inserted node: {err}"))
                .header
                .compute_hash();
            tip_id = Some(id);
        }
        let tip_id = tip_id.unwrap_or_else(|| panic!("chain has a tip"));
        let tip = snapshot(&tree, tip_id);
        let tree = RwLock::new(tree);
        let network = Network::Regtest;

        assert_matches_core(&tree, &tip, 2, -1, network);
        assert_matches_core(&tree, &tip, 1, 3, network);
        assert_matches_core(&tree, &tip, -1, -1, network);
        assert_matches_core(&tree, &tip, 120, -1, network);

        let genesis = estimate_network_hashps(&tree, Some(&tip), 120, 0, network);
        assert!(
            genesis.abs() < f64::EPSILON,
            "Core returns 0 at genesis, got {genesis}"
        );

        let retarget_lookup = i64::from(tip.height) % i64::from(network.retarget_interval()) + 1;
        let via_minus_one = estimate_network_hashps(&tree, Some(&tip), -1, -1, network);
        let via_explicit = estimate_network_hashps(&tree, Some(&tip), retarget_lookup, -1, network);
        assert!(
            (via_minus_one - via_explicit).abs() < 1e-9,
            "-1 lookback must equal height % interval + 1 ({retarget_lookup})"
        );
    }
}

#[cfg(test)]
mod candidate_template_tests {
    use alloc::sync::Arc;
    use bitcoin_rs_mining::{Candidate, TemplateId};
    use bitcoin_rs_primitives::{Hash256, Network, Tx, TxOut};

    #[test]
    fn candidate_cache_evicts_the_oldest_entry_at_the_bound() {
        use alloc::sync::Arc;
        use bitcoin_rs_mining::Candidate;

        let mut state = super::CoordinatorState::new();
        let coinbase = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 50,
                script_pubkey: Vec::new(),
            }],
        };
        let mut first_id = None;
        for seq in 0..=super::CANDIDATE_CACHE_LIMIT {
            let seq = u64::try_from(seq).unwrap_or(u64::MAX);
            let hash = Hash256::from_le_bytes(&[u8::try_from(seq).unwrap_or(0xff); 32]);
            let id = TemplateId::new(&hash, seq);
            if seq == 0 {
                first_id = Some(id.clone());
            }
            let candidate = Arc::new(Candidate {
                template_id: id.clone(),
                previous_block_hash: hash,
                height: 1,
                version: 1,
                bits: 0x207f_ffff,
                min_time: 1,
                current_time: 1,
                csv_active: false,
                segwit_active: false,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
                mempool_sequence: seq,
                coinbase: coinbase.clone(),
                coinbase_value: 50,
                fees: 0,
                weight: 800,
                size: 200,
                sigop_cost: 0,
                transactions: Vec::new(),
                witness_merkle_root: None,
                witness_reserved_value: None,
                witness_commitment: None,
            });
            state.cache_insert(id, candidate);
        }
        assert_eq!(state.cache.len(), super::CANDIDATE_CACHE_LIMIT);
        assert!(
            !state
                .cache
                .contains_key(first_id.as_ref().unwrap_or_else(|| panic!("first id"))),
            "oldest cached candidate must be evicted at the bound"
        );
    }

    fn sample_candidate(previous: Hash256, csv_active: bool, segwit_active: bool) -> Candidate {
        Candidate {
            template_id: TemplateId::new(&previous, 1),
            previous_block_hash: previous,
            height: 1,
            version: 1,
            bits: 0x207f_ffff,
            min_time: 1,
            current_time: 1,
            csv_active,
            segwit_active,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
            mempool_sequence: 1,
            coinbase: Tx {
                version: 2,
                lock_time: 0,
                inputs: Vec::new(),
                outputs: vec![TxOut {
                    value: 50,
                    script_pubkey: Vec::new(),
                }],
            },
            coinbase_value: 50,
            fees: 0,
            weight: 800,
            size: 200,
            sigop_cost: 0,
            transactions: Vec::new(),
            witness_merkle_root: None,
            witness_reserved_value: None,
            witness_commitment: None,
        }
    }

    fn empty_request() -> bitcoin_rs_mining::BlockTemplateRequest {
        bitcoin_rs_mining::BlockTemplateRequest {
            mode: bitcoin_rs_mining::BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        }
    }

    fn template_for(
        candidate: Candidate,
        submit_old: Option<bool>,
    ) -> bitcoin_rs_mining::BlockTemplate {
        super::MiningCoordinator::template_from_candidate(
            Network::Regtest,
            Arc::new(candidate),
            &empty_request(),
            submit_old,
            Vec::new(),
            0,
        )
    }

    #[test]
    fn template_facts_follow_mutated_candidate_generation() {
        use bitcoin_rs_mining::MiningRule;

        let first_prev = Hash256::from_le_bytes(&[0x11; 32]);
        let first = template_for(sample_candidate(first_prev, false, true), Some(true));
        assert_eq!(first.candidate.previous_block_hash, first_prev);
        assert_eq!(
            first
                .rules
                .iter()
                .map(MiningRule::as_str)
                .collect::<Vec<_>>(),
            vec!["segwit", "taproot"]
        );

        let mutated_prev = Hash256::from_le_bytes(&[0x22; 32]);
        let mutated = template_for(sample_candidate(mutated_prev, true, false), Some(false));
        assert_eq!(mutated.candidate.previous_block_hash, mutated_prev);
        assert_ne!(mutated.candidate.template_id, first.candidate.template_id);
        assert_eq!(
            mutated
                .rules
                .iter()
                .map(MiningRule::as_str)
                .collect::<Vec<_>>(),
            vec!["csv", "taproot"]
        );
        assert_eq!(mutated.submit_old, Some(false));
    }

    #[test]
    fn deployment_boundary_rules_follow_candidate_flags() {
        use bitcoin_rs_mining::MiningRule;

        let prev = Hash256::from_le_bytes(&[0x33; 32]);
        let cases = [
            (false, false, vec!["taproot"]),
            (true, false, vec!["csv", "taproot"]),
            (false, true, vec!["segwit", "taproot"]),
            (true, true, vec!["segwit", "csv", "taproot"]),
        ];
        for (csv_active, segwit_active, expected) in cases {
            let template = template_for(sample_candidate(prev, csv_active, segwit_active), None);
            assert_eq!(template.candidate.csv_active, csv_active);
            assert_eq!(template.candidate.segwit_active, segwit_active);
            assert_eq!(
                template
                    .rules
                    .iter()
                    .map(MiningRule::as_str)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}

#[cfg(test)]
mod generation_signal_tests {
    use super::{MempoolSequenceWake, MiningGenerationSignal};
    use bitcoin_rs_mining::{
        BlockTemplateRequest, BlockTemplateResult, MiningControl, MiningControlError,
    };
    use bitcoin_rs_primitives::Block;
    use compact_str::CompactString;
    use parking_lot::Mutex;
    use std::sync::Arc;

    /// Records `publish_generation` and `publish_generation_from` calls; every
    /// other control operation is unsupported in these tests.
    #[derive(Default)]
    struct RecordingControl {
        published: Mutex<usize>,
        published_from: Mutex<Vec<u64>>,
    }

    fn unavailable() -> MiningControlError {
        MiningControlError::Unavailable(CompactString::from("not wired in this test"))
    }

    impl MiningControl for RecordingControl {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Err(unavailable())
        }

        fn mining_info(&self) -> Result<bitcoin_rs_mining::MiningInfo, MiningControlError> {
            Err(unavailable())
        }

        fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
            Err(unavailable())
        }

        fn submit_block(
            &self,
            _block: Block,
        ) -> Result<bitcoin_rs_mining::BlockValidationResult, MiningControlError> {
            Err(unavailable())
        }

        fn publish_generation(&self) {
            *self.published.lock() += 1;
        }
    }

    impl MempoolSequenceWake for RecordingControl {
        fn publish_generation_from(&self, sequence: u64) {
            self.published_from.lock().push(sequence);
        }
    }

    #[test]
    fn detached_signal_is_a_noop() {
        let signal = MiningGenerationSignal::new();
        // No coordinator attached: nothing to wake, nothing panics.
        signal.publish_generation();
        signal.publish_generation();
        signal.publish_generation_from(1);
    }

    #[test]
    fn attached_signal_forwards_every_generation_publication() {
        let signal = MiningGenerationSignal::new();
        let control = Arc::new(RecordingControl::default());
        let control_dyn: Arc<dyn MiningControl> = control.clone();
        signal.attach(&control_dyn);

        assert_eq!(*control.published.lock(), 0);
        signal.publish_generation();
        signal.publish_generation();
        assert_eq!(
            *control.published.lock(),
            2,
            "every authoritative-mutation wake must reach the coordinator"
        );
    }

    #[test]
    fn attached_signal_forwards_sequence_wake_without_mempool_lock() {
        let signal = MiningGenerationSignal::new();
        let control = Arc::new(RecordingControl::default());
        let control_dyn: Arc<dyn MiningControl> = control.clone();
        let wake_dyn: Arc<dyn MempoolSequenceWake> = control.clone();
        signal.attach(&control_dyn);
        signal.attach_sequence_wake(&wake_dyn);

        assert!(control.published_from.lock().is_empty());
        signal.publish_generation_from(7);
        signal.publish_generation_from(8);
        assert_eq!(
            *control.published_from.lock(),
            vec![7, 8],
            "sequence wakes must reach the lock-free path"
        );
        assert_eq!(
            *control.published.lock(),
            0,
            "sequence wakes must not fall back to publish_generation"
        );
    }

    #[test]
    fn sequence_wake_falls_back_when_not_attached() {
        let signal = MiningGenerationSignal::new();
        let control = Arc::new(RecordingControl::default());
        let control_dyn: Arc<dyn MiningControl> = control.clone();
        signal.attach(&control_dyn);

        signal.publish_generation_from(1);
        assert_eq!(
            *control.published.lock(),
            1,
            "without attach_sequence_wake, publish_generation_from falls back"
        );
        assert!(
            control.published_from.lock().is_empty(),
            "the lock-free path is not taken without attach_sequence_wake"
        );
    }
}
