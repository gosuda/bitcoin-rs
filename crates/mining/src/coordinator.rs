//! Candidate lifecycle state and pure mining-domain projections.
//!
//! Generation is keyed by `(applied_tip_hash, mempool_sequence)`. Template
//! assembly is single-flight per key, cached by [`TemplateId`], and woken by
//! explicit generation publication. [`MiningService`] drives this state
//! through capability sources implemented by the node; proposal validation
//! and solved-block submission stay on `node`'s authoritative apply path.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_consensus::{MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT};
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::SnapshotEntry;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::count_tx_legacy;
use compact_str::CompactString;
use core::time::Duration;
use hashbrown::HashMap;
use parking_lot::Condvar;
use parking_lot::Mutex;

use crate::context::MiningChainContext;
use crate::control::AvailableMiningRule;
use crate::control::BlockTemplate;
use crate::control::GenerateSelection;
use crate::control::GenerateTx;
use crate::control::LastCandidateInfo;
use crate::control::MiningCapability;
use crate::control::MiningControlError;
use crate::control::MiningInfo;
use crate::control::MiningRule;
use crate::control::SignetMiningInfo;
use crate::control::TemplateMutation;
use crate::control::difficulty_for_bits;
use crate::template::Candidate;
use crate::template::CandidateContext;
use crate::template::TemplateId;
use crate::template::assemble_candidate;
use crate::template::assemble_ordered_candidate;

/// Default number of cached candidates retained by template id.
const CANDIDATE_CACHE_LIMIT: usize = 8;
/// Finite bound on generation-key races during candidate assembly.
const CANDIDATE_GENERATION_RETRIES: usize = 8;
/// Error message identifying a generation-key race during candidate assembly.
const GENERATION_RACE: &str = "generation key changed during candidate assembly";
/// Bitcoin Core's mempool-only long-poll cooldown before returning a new template.
pub const DEFAULT_MEMPOOL_UPDATE_WAIT: Duration = Duration::from_secs(10);
/// Upper bound for a single long-poll wait slice while rechecking predicates.
const LONG_POLL_SLICE: Duration = Duration::from_secs(1);

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

/// Single in-flight assembly record.
#[derive(Debug)]
struct InFlight {
    /// Generation key the flight assembles for.
    key: GenerationKey,
    /// Monotonic identity assigned when the flight was installed.
    id: u64,
    /// Result shared with same-key waiters once assembly finishes.
    result: Option<Result<Arc<Candidate>, MiningControlError>>,
}

/// Bounded template cache, single-flight guard, and published generation.
#[derive(Debug, Default)]
struct CoordinatorState {
    /// Last generation published to long-poll waiters.
    published: Option<GenerationKey>,
    /// Bounded LRU of assembled candidates keyed by template id.
    cache: HashMap<TemplateId, Arc<Candidate>>,
    /// Insertion order for deterministic eviction of the oldest entry.
    cache_order: VecDeque<TemplateId>,
    /// Single in-flight assembly, if any.
    in_flight: Option<InFlight>,
    /// Monotonically increasing identity for each installed flight.
    next_flight_id: u64,
    /// Facts from the most recently assembled candidate.
    last_candidate: Option<LastCandidateInfo>,
}

impl CoordinatorState {
    /// Creates the empty lifecycle state.
    #[must_use]
    fn new() -> Self {
        Self {
            published: None,
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            in_flight: None,
            next_flight_id: 0,
            last_candidate: None,
        }
    }

    /// Returns the cached candidate for `id`, if one is retained.
    fn cache_get(&self, id: &TemplateId) -> Option<Arc<Candidate>> {
        self.cache.get(id).cloned()
    }

    /// Inserts or refreshes `id`, evicting the oldest entry at the bound.
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

    /// Drops the cached candidate and any matching in-flight assembly for `key`.
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

/// Applied-chain tip the lifecycle reads instead of node state.
pub trait AppliedTipSource: Send + Sync {
    /// Snapshot of the current applied tip, if any block has committed.
    fn applied_tip(&self) -> Option<TipSnapshot>;
}

/// Read-only mempool facts for candidate assembly and long-poll waits.
pub trait MempoolSnapshotSource: Send + Sync {
    /// Monotonic mutation sequence of the pool.
    fn current_sequence(&self) -> u64;
    /// Captures the mining snapshot if the pool is still at `expected_sequence`.
    ///
    /// The comparison and the capture share one pool read lock: a snapshot is
    /// only valid for the sequence it was taken at, so generation-key
    /// coherence is checked and captured atomically.
    fn mining_snapshot_at(&self, expected_sequence: u64) -> Option<MempoolMiningSnapshot>;
    /// Captures the mining snapshot an explicit generate selection assembles from.
    ///
    /// `Ordered` selections re-index the pool snapshot to the caller's
    /// transaction order under one pool read lock; unknown mempool txids are
    /// a request error.
    ///
    /// # Errors
    ///
    /// Returns [`MiningControlError::InvalidRequest`] when an `Ordered`
    /// selection names a transaction that is not in the mempool.
    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
    ) -> Result<MempoolMiningSnapshot, MiningControlError>;
    /// Number of pooled transactions.
    fn pooled_transaction_count(&self) -> u64;
    /// Minimum relay fee in sat/kvB.
    fn min_relay_fee_sat_per_kvb(&self) -> u64;
}

/// Applied-tree facts the candidate lifecycle resolves per generation.
pub trait ChainContextSource: Send + Sync {
    /// Resolves candidate context for a block extending `tip` at `candidate_time`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] when the tree cannot resolve `tip`'s ancestry.
    fn resolve_mining_context(
        &self,
        tip: &TipSnapshot,
        candidate_time: u32,
    ) -> Result<MiningChainContext, ChainError>;

    /// Header bits declared by `tip`'s own header.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] when `tip` is not in the tree.
    fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError>;

    /// Versionbit deployments signalling for a candidate at `height` on `tip`.
    fn signalling_rules(&self, tip: &TipSnapshot, height: u32) -> Vec<AvailableMiningRule>;
}

/// Mining-domain candidate lifecycle service driven by capability sources.
///
/// Owns the template cache, single-flight assembly, and long-poll
/// publication state. The node facade constructs it with adapters over the
/// applied tip, the mempool, and the block tree, and keeps proposal
/// validation and solved-block submission on the authoritative apply path.
pub struct MiningService {
    /// Network whose genesis anchors an empty applied chain.
    network: Network,
    /// Immutable coinbase payout script for assembled candidates.
    coinbase_script: Vec<u8>,
    /// Shared shutdown flag checked by every unbounded wait.
    shutdown: Arc<AtomicBool>,
    /// Applied-chain tip publisher.
    applied_tip: Arc<dyn AppliedTipSource>,
    /// Read-only mempool facts.
    mempool: Arc<dyn MempoolSnapshotSource>,
    /// Applied-tree facts.
    chain: Arc<dyn ChainContextSource>,
    /// Cache, single-flight, and publication state.
    state: Mutex<CoordinatorState>,
    /// Wake for long-poll and single-flight waiters.
    wake: Condvar,
}

impl MiningService {
    /// Builds a service over node-owned capability sources.
    ///
    /// `coinbase_script` is required and stored immutably. Pass
    /// `Vec::new()` for transport-only template assembly when the node
    /// does not own a miner payout script.
    #[must_use]
    pub fn new(
        network: Network,
        applied_tip: Arc<dyn AppliedTipSource>,
        mempool: Arc<dyn MempoolSnapshotSource>,
        chain: Arc<dyn ChainContextSource>,
        coinbase_script: Vec<u8>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            network,
            applied_tip,
            mempool,
            chain,
            coinbase_script,
            shutdown,
            state: Mutex::new(CoordinatorState::new()),
            wake: Condvar::new(),
        }
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
            .applied_tip()
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
            .applied_tip()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash);
        let mempool_sequence = self.mempool.current_sequence();
        GenerationKey {
            tip_hash,
            mempool_sequence,
        }
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

    /// Assembles the BIP22/BIP23 template for the live (or long-polled) generation.
    ///
    /// Long-poll callers pass the `longpollid` they are still working; the call
    /// blocks until the published generation changes or the node shuts down.
    ///
    /// # Errors
    ///
    /// [`MiningControlError::InvalidRequest`] for a malformed long-poll id;
    /// [`MiningControlError::Unavailable`] while no tip is applied, on
    /// shutdown, or when the generation raced during assembly.
    pub fn get_block_template(
        &self,
        long_poll_id: Option<&str>,
    ) -> Result<BlockTemplate, MiningControlError> {
        let waited = if let Some(long_poll_id) = long_poll_id {
            let waited = parse_long_poll_id(long_poll_id).ok_or_else(|| {
                MiningControlError::InvalidRequest(CompactString::from("longpollid is malformed"))
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
        // Candidate assembly may retry after a tip move.  Pair the deployment
        // snapshot with the candidate it describes, rather than with a stale
        // snapshot captured before assembly.
        for _ in 0..CANDIDATE_GENERATION_RETRIES {
            let candidate = self.live_candidate()?;
            let Some(tip) = self.applied_tip.applied_tip() else {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "applied tip is not available",
                )));
            };
            if tip.hash != candidate.previous_block_hash {
                continue;
            }
            let submit_old = waited.map(|waited| candidate.previous_block_hash == waited.tip_hash);
            let (version_bits_available, version_bits_required) =
                self.version_bits_for(&candidate, &tip);
            return Ok(template_from_candidate(
                self.network,
                candidate,
                submit_old,
                version_bits_available,
                version_bits_required,
            ));
        }
        Err(generation_race())
    }

    /// Captures one coherent mining-state report.
    ///
    /// `network_hashes_per_second` and `warnings` are node-owned facts
    /// (the applied-tree hashrate walk and node metrics); everything else is
    /// derived from the applied tip, the mempool, and the lifecycle state.
    ///
    /// # Errors
    ///
    /// [`MiningControlError::Failed`] when the applied tip cannot be resolved
    /// in the tree.
    pub fn mining_info(
        &self,
        network_hashes_per_second: f64,
        warnings: Vec<CompactString>,
        tip: Option<&TipSnapshot>,
    ) -> Result<MiningInfo, MiningControlError> {
        let blocks = tip.map_or(0, |tip| tip.height);
        let (bits, difficulty, next_bits, next_difficulty) = match tip {
            Some(tip) => {
                let tip_bits = self.chain.tip_bits(tip).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
                let current_time = current_unix_seconds().max(1);
                let next = self
                    .chain
                    .resolve_mining_context(tip, current_time)
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
            None => (
                CompactTarget::from_consensus(0),
                0.0,
                CompactTarget::from_consensus(0),
                0.0,
            ),
        };
        let pooled_transactions = self.mempool.pooled_transaction_count();
        let minimum_fee_rate = self.mempool.min_relay_fee_sat_per_kvb();
        let last_candidate = self.state.lock().last_candidate;
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
            warnings,
        })
    }

    /// Returns the live candidate, retrying bounded generation-key races.
    fn live_candidate(&self) -> Result<Arc<Candidate>, MiningControlError> {
        let mut last_race = None;
        for _attempt in 0..CANDIDATE_GENERATION_RETRIES {
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
        }
        Err(last_race.unwrap_or_else(generation_race))
    }

    /// Cache lookup or single-flight assembly for one generation key.
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

        state.next_flight_id = state.next_flight_id.wrapping_add(1);
        let flight_id = state.next_flight_id;
        state.in_flight = Some(InFlight {
            key,
            id: flight_id,
            result: None,
        });
        drop(state);
        let mut flight_guard = InFlightAssemblyGuard {
            service: self,
            key,
            id: flight_id,
            armed: true,
        };

        let assembled = self.assemble_for_key(key);
        let mut state = self.state.lock();
        // Recheck after acquiring the lifecycle mutex: a publication may
        // have won while assembly was completing.
        let live = self.live_generation_key();
        let returned = match &assembled {
            Ok(candidate) => {
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
            && flight.id == flight_id
        {
            flight.result = Some(returned.clone());
        }
        self.wake.notify_all();
        if state.in_flight.as_ref().is_some_and(|flight| {
            flight.key == key && flight.id == flight_id && flight.result.is_some()
        }) {
            state.in_flight = None;
        }
        flight_guard.armed = false;
        returned
    }

    /// Assembles the candidate for `key`, refusing a raced tip or mempool.
    fn assemble_for_key(&self, key: GenerationKey) -> Result<Arc<Candidate>, MiningControlError> {
        let tip = self.applied_tip.applied_tip().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        if tip.hash != key.tip_hash {
            return Err(generation_race());
        }
        let Some(snapshot) = self.mempool.mining_snapshot_at(key.mempool_sequence) else {
            return Err(generation_race());
        };
        let context = self.candidate_context(&tip)?;
        let candidate = assemble_candidate(&context, &snapshot, &self.coinbase_script)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        if candidate.template_id != key.template_id() {
            return Err(MiningControlError::Failed(CompactString::from(
                "assembled candidate template id does not match generation key",
            )));
        }
        Ok(Arc::new(candidate))
    }

    /// Resolves the candidate context for a block extending `tip`.
    fn candidate_context(&self, tip: &TipSnapshot) -> Result<CandidateContext, MiningControlError> {
        let current_time = current_unix_seconds().max(1);
        let chain = self
            .chain
            .resolve_mining_context(tip, current_time)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        Ok(CandidateContext {
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
            max_size: MAX_BLOCK_SERIALIZED_SIZE,
            max_sigops: u64::from(MAX_BLOCK_SIGOPS_COST),
        })
    }

    /// Assembles a fresh candidate for an explicit generate request.
    ///
    /// Unlike [`Self::get_block_template`] this does not consult the cache or
    /// the published generation: `generate` assembles, solves, and submits
    /// one block at a time against the live tip.
    ///
    /// # Errors
    ///
    /// [`MiningControlError::Unavailable`] when no tip is applied;
    /// [`MiningControlError::InvalidRequest`] for selections the pool cannot
    /// resolve; [`MiningControlError::Failed`] on assembly refusal.
    pub fn assemble_fresh(
        &self,
        payout: &[u8],
        selection: &GenerateSelection,
    ) -> Result<Candidate, MiningControlError> {
        let tip = self.applied_tip.applied_tip().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        let snapshot = self.mempool.selection_snapshot(selection)?;
        let context = self.candidate_context(&tip)?;
        match selection {
            GenerateSelection::Mempool => assemble_candidate(&context, &snapshot, payout),
            GenerateSelection::Ordered(_) => {
                assemble_ordered_candidate(&context, &snapshot, payout)
            }
        }
        .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))
    }

    fn version_bits_for(
        &self,
        candidate: &Candidate,
        tip: &TipSnapshot,
    ) -> (Vec<AvailableMiningRule>, u32) {
        if tip.hash != candidate.previous_block_hash {
            return (Vec::new(), 0);
        }
        // Core v31 `getblocktemplate` hardcodes `vbrequired` to 0.
        (self.chain.signalling_rules(tip, candidate.height), 0)
    }
}

impl MempoolSequenceWake for MiningService {
    fn publish_generation_from(&self, sequence: u64) {
        Self::publish_generation_from(self, sequence);
    }
}

/// Clears an abandoned single-flight slot if candidate assembly unwinds.
///
/// Release/quickstart builds abort on panic, but test, development, and other
/// unwind-enabled profiles must not leave same-key callers blocked behind a
/// permanently in-flight generation.
struct InFlightAssemblyGuard<'a> {
    service: &'a MiningService,
    key: GenerationKey,
    id: u64,
    armed: bool,
}

impl Drop for InFlightAssemblyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.service.state.lock();
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == self.key && flight.id == self.id)
        {
            state.in_flight = None;
            drop(state);
            self.service.wake.notify_all();
        }
    }
}

/// Projects an assembled candidate into a BIP22/BIP23 block template.
///
/// Rule advertisement follows the candidate's own deployment facts and
/// producer capabilities, never caller-requested names.
fn template_from_candidate(
    network: Network,
    candidate: Arc<Candidate>,
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
    let signet = signet_info(network);
    if signet.is_some() {
        rules.push(MiningRule::new("signet"));
    }
    // API-11 advertises producer capabilities, never client-requested names.
    BlockTemplate {
        rules,
        candidate,
        version_bits_available,
        version_bits_required,
        capabilities: vec![
            MiningCapability::new("proposal"),
            MiningCapability::new("longpoll"),
        ],
        mutable: vec![
            TemplateMutation::Time,
            TemplateMutation::Transactions,
            TemplateMutation::PreviousBlock,
        ],
        submit_old,
        signet,
        work_id: None,
    }
}

/// Builds the mining snapshot a generate selection assembles from.
///
/// `Ordered` selections re-index the mempool snapshot to the caller's
/// explicit transaction order; unknown mempool txids are request errors.
///
/// # Errors
///
/// Returns [`MiningControlError::InvalidRequest`] when an `Ordered`
/// selection names a transaction that is not in the mempool.
pub fn snapshot_for_selection(
    mempool: &Mempool,
    selection: &GenerateSelection,
) -> Result<MempoolMiningSnapshot, MiningControlError> {
    match selection {
        GenerateSelection::Mempool => Ok(mempool.mining_snapshot()),
        GenerateSelection::Ordered(items) => {
            let full = mempool.mining_snapshot();
            let mut by_txid = HashMap::with_capacity(full.entries.len());
            for (index, entry) in full.entries.iter().enumerate() {
                let position = u32::try_from(index).unwrap_or(u32::MAX);
                by_txid.insert(entry.txid, position);
            }
            let mut selected = Vec::with_capacity(items.len());
            let mut old_to_new = HashMap::with_capacity(items.len());
            for item in items {
                match item {
                    GenerateTx::Mempool(txid) => {
                        let Some(&old) = by_txid.get(txid) else {
                            return Err(MiningControlError::InvalidRequest(CompactString::from(
                                "transaction not in mempool",
                            )));
                        };
                        let new_index = u32::try_from(selected.len()).unwrap_or(u32::MAX);
                        old_to_new.insert(old, new_index);
                        let old_usize = usize::try_from(old).unwrap_or(usize::MAX);
                        selected.push(full.entries[old_usize].clone());
                    }
                    GenerateTx::ResolvedMempool(entry) => {
                        let mut entry = entry.clone();
                        entry.ancestors.clear();
                        selected.push(entry);
                    }
                    GenerateTx::Raw(tx) => selected.push(snapshot_entry_from_raw(tx)),
                }
            }
            for entry in &mut selected {
                entry.ancestors.retain_mut(|ancestor| {
                    if let Some(&new_index) = old_to_new.get(ancestor) {
                        *ancestor = new_index;
                        true
                    } else {
                        false
                    }
                });
            }
            Ok(MempoolMiningSnapshot {
                sequence: full.sequence,
                entries: selected,
            })
        }
    }
}

fn snapshot_entry_from_raw(tx: &Tx) -> SnapshotEntry {
    let tx = Arc::new(tx.clone());
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    let size = u32::try_from(tx.total_size()).unwrap_or(u32::MAX);
    SnapshotEntry {
        txid: tx.txid(),
        wtxid: tx.wtxid(),
        vsize,
        bip141_vsize: vsize,
        size,
        weight: tx.weight(),
        sigop_cost: count_tx_legacy(&tx),
        fee: 0,
        fee_delta: 0,
        time: 0,
        height: 0,
        ancestor_size: u64::from(vsize),
        ancestor_fee: 0,
        ancestor_fee_delta: 0,
        ancestors: Vec::new(),
        tx,
    }
}

/// Constructs the generation-race error callers retry against.
fn generation_race() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from(GENERATION_RACE))
}

/// Reports whether `error` is the generation-race error.
fn is_generation_race(error: &MiningControlError) -> bool {
    matches!(error, MiningControlError::Unavailable(message) if message.as_str() == GENERATION_RACE)
}

/// Parses a BIP22/BIP23 long-poll id into its generation key.
#[must_use]
fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    let hash_hex = id.get(..64)?;
    let sequence = id.get(64..)?;
    if sequence.is_empty() {
        return None;
    }
    let tip_hash = Hash256::from_str_be(hash_hex).ok()?;
    let mempool_sequence = sequence.parse().ok()?;
    Some(GenerationKey {
        tip_hash,
        mempool_sequence,
    })
}

/// Signet challenge and flag for `network`, or `None` off signet.
#[must_use]
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
mod candidate_template_tests;

#[cfg(test)]
mod generation_key_tests;
