//! Candidate lifecycle state and pure mining-domain projections.
//!
//! Generation is keyed by `(applied_tip_hash, mempool_sequence,
//! fee_delta_sequence)`. Template
//! assembly is single-flight per key, cached by [`TemplateId`], and woken by
//! explicit generation publication. [`MiningService`] drives this state
//! through capability sources implemented by the node; proposal validation
//! and solved-block submission stay on `node`'s authoritative apply path.

use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use std::time::Instant;

use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_chain::current_unix_seconds;
use bitcoin_rs_consensus::transaction_sigop_cost;
use bitcoin_rs_consensus::{MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT};
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::MutationOutcome;
use bitcoin_rs_mempool::MutationResult;
use bitcoin_rs_mempool::RemovalReason;
use bitcoin_rs_mempool::SnapshotEntry;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_script::VerifyFlags;
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
use crate::template::SelectedBody;
use crate::template::TemplateId;
use crate::template::assemble_ordered_candidate;
use crate::template::finish_candidate;

/// Default number of cached candidates retained by template id.
const CANDIDATE_CACHE_LIMIT: usize = 8;
/// Finite bound on generation-key races during candidate assembly.
const CANDIDATE_GENERATION_RETRIES: usize = 8;
/// Error message identifying a generation-key race during candidate assembly.
const GENERATION_RACE: &str = "generation key changed during candidate assembly";
/// Upper bound for a single long-poll wait slice while rechecking predicates.
const LONG_POLL_SLICE: Duration = Duration::from_secs(1);

/// Applied-tip hash plus the mempool membership and fee-delta sequences that
/// identify one candidate generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenerationKey {
    /// Applied tip hash in consensus little-endian storage order.
    tip_hash: Hash256,
    /// Mempool membership-mutation sequence captured with the tip.
    mempool_sequence: u64,
    /// Mempool fee-delta (prioritisation) sequence captured with the tip.
    fee_delta_sequence: u64,
}

impl GenerationKey {
    /// Opaque BIP22/BIP23 long-poll identity for this generation.
    #[must_use]
    fn template_id(self) -> TemplateId {
        TemplateId::with_fee_revision(
            &self.tip_hash,
            self.mempool_sequence,
            self.fee_delta_sequence,
        )
    }
}

/// Single in-flight assembly record.
struct InFlight {
    key: GenerationKey,
    /// Monotonic identity assigned when the flight was installed.
    id: u64,
    /// Shared with same-key waiters once assembly finishes.
    result: Option<Result<Arc<Candidate>, MiningControlError>>,
}

/// Bounded template cache, single-flight guard, and published generation.
#[derive(Default)]
struct CoordinatorState {
    published: Option<GenerationKey>,
    /// Pool membership sequence captured at construction, used to compose a
    /// full key for a fee-sequence publication before any generation is
    /// published.
    seed: u64,
    /// Test-seam probe: long-poll waiters parked on the wake condvar.
    #[cfg(any(test, feature = "test-seam"))]
    parked_long_poll_waiters: usize,
    cache: HashMap<TemplateId, Arc<Candidate>>,
    /// Insertion order for deterministic eviction of the oldest entry.
    cache_order: VecDeque<TemplateId>,
    /// Last resolved signalling-rule snapshot. The template path serves only
    /// the current candidate tip and height, so one entry is enough and a tip
    /// move naturally invalidates it; no history is retained.
    signalling_rules: Option<(Hash256, u32, Vec<AvailableMiningRule>)>,
    in_flight: Option<InFlight>,
    next_flight_id: u64,
    last_candidate: Option<LastCandidateInfo>,
}

impl CoordinatorState {
    /// Membership sequence a fee-sequence publication carries: the published
    /// generation's component, or the construction seed when nothing is
    /// published (including after a membership invalidation cleared it).
    fn retained_mempool_sequence(&self) -> u64 {
        self.published.map_or(self.seed, |key| key.mempool_sequence)
    }

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

    fn signalling_cache_get(&self, tip: &Hash256, height: u32) -> Option<Vec<AvailableMiningRule>> {
        let (cached_tip, cached_height, rules) = self.signalling_rules.as_ref()?;
        if cached_tip == tip && *cached_height == height {
            Some(rules.clone())
        } else {
            None
        }
    }

    /// Installs the resolved rules, replacing whatever tip they describe.
    fn signalling_cache_insert(
        &mut self,
        tip: Hash256,
        height: u32,
        rules: Vec<AvailableMiningRule>,
    ) {
        self.signalling_rules = Some((tip, height, rules));
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

/// Template body selected against a staged block's projected removals.
///
/// [`MempoolSnapshotSource::select_template_after`] captures the source pool
/// sequences, the removal plan's stable identities, and the projected body
/// under one pool read. The install check matches `removals` against the
/// committed receipt and the body's predicted sequences against the live
/// generation; `EntryId` never leaves the pool.
#[derive(Debug)]
pub struct PreparedTemplateBody {
    /// Body selected from the projected pool, carrying the predicted
    /// post-removal sequences.
    pub body: SelectedBody,
    /// Pool membership and fee-delta sequences the projection read.
    pub source_sequences: (u64, u64),
    /// Planned removals as stable transaction ids with their exact reasons.
    pub removals: Vec<(Txid, RemovalReason)>,
}

/// Mempool-sequence wake that avoids the mempool read lock.
///
/// Membership notifications carry no fee revision. Avoid a second pool view
/// or contention with an in-flight writer on that path. Implementations invalidate
/// membership generations using the supplied sequence; the next template read
/// captures both live pool revisions. The staged-tip hook path also
/// avoids the pool lock: it only enqueues, and installation waits for the
/// committed receipt.
pub trait MempoolSequenceWake: Send + Sync {
    /// Invalidates an older membership generation without a pool read, then wakes waiters.
    fn publish_generation_from(&self, sequence: u64);
    /// Stages a tip-child block for background template preparation.
    ///
    /// Hook-only: enqueues the staged tip and returns at once. Never
    /// publishes a tip, a generation, or a candidate; installation waits for
    /// the committed receipt. Repeated stages for one tip are idempotent.
    fn stage_tip(&self, tip: &TipSnapshot, block: &Block);
    /// Publishes a committed block generation with its actual removal receipt.
    ///
    /// The receipt is retained so a still-finishing preparation can install
    /// against it; the generation key and waiter wake follow the ordinary
    /// [`MiningService::publish_generation`] path.
    fn publish_block_generation(&self, tip_hash: Hash256, removals: &MutationResult);
}

/// Applied-chain tip the lifecycle reads instead of node state.
pub trait AppliedTipSource: Send + Sync {
    /// Snapshot of the current applied tip, if any block has committed.
    fn applied_tip(&self) -> Option<TipSnapshot>;
}

/// Read-only mempool facts for candidate assembly and long-poll waits.
pub trait MempoolSnapshotSource: Send + Sync {
    /// Membership and fee-priority revisions captured under one pool read lock.
    fn current_revisions(&self) -> (u64, u64);
    /// Selects the template body only if both pool revisions still match.
    ///
    /// Both sequence checks and the selection share one pool read lock, so the
    /// body always matches the generation key it is assembled for. The guard
    /// is released before the candidate finishes: only the selected
    /// transactions leave the pool. Returns `None` when the pool moved past
    /// `expected_sequences`, which the caller retries as a generation race.
    fn select_template(
        &self,
        expected_sequences: Option<(u64, u64)>,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<Option<SelectedBody>, MiningControlError>;
    /// Selects the template body as if `block` had applied, without mutating
    /// the pool.
    ///
    /// The source sequences, the removal plan's stable txid-and-reason
    /// identities, and the projected selection share one pool read lock, so
    /// the returned [`PreparedTemplateBody`] always describes the pool state
    /// it was read at. The guard is released before the candidate finishes:
    /// only owned copies leave the pool.
    ///
    /// # Errors
    ///
    /// Returns [`MiningControlError::Failed`] when the projected selection
    /// refuses the candidate context's limits.
    fn select_template_after(
        &self,
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError>;
    /// Captures the mining snapshot an explicit generate selection assembles from.
    ///
    /// Pool facts are captured under one read lock; `Ordered` selections
    /// re-index the captured snapshot to the caller's transaction order.
    /// Unknown mempool txids are a request error. Raw transaction costs use copied prevouts from the
    /// candidate's applied tip and its effective witness-activation flag.
    ///
    /// # Errors
    ///
    /// Returns [`MiningControlError::InvalidRequest`] when an `Ordered`
    /// selection names a transaction that is not in the mempool, or
    /// [`MiningControlError::Unavailable`] when the candidate tip changed
    /// before copying raw transaction prevouts.
    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
        context: &CandidateContext,
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
/// Owns the template cache, single-flight assembly, long-poll publication
/// state, and the staged-template preparation worker. The node facade
/// constructs it with adapters over the applied tip, the mempool, and the
/// block tree, and keeps proposal validation and solved-block submission on
/// the authoritative apply path.
///
/// Consistency: pool selection runs under one read guard (snapshot
/// isolation); accepted-generation and cache publication are linearizable
/// under the coordinator mutex. Repeated identical stage and publication
/// notifications are idempotent.
pub struct MiningService {
    /// Network whose genesis anchors an empty applied chain.
    network: Network,
    coinbase_script: Vec<u8>,
    /// Shared shutdown flag checked by every unbounded wait.
    shutdown: bitcoin_rs_chain::LatchReader,
    /// Applied-chain tip publisher.
    applied_tip: Arc<dyn AppliedTipSource>,
    mempool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    state: Mutex<CoordinatorState>,
    /// Wake for long-poll and single-flight waiters.
    wake: Condvar,
    /// Staged-template preparation worker and its shared mailbox.
    prep: PrepWorker,
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
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    ) -> Self {
        // Seed the retained membership sequence from the actual pool state so
        // the first fee-sequence publication composes a full key without a
        // zero fallback.
        let seed = mempool.current_revisions().0;
        let shutdown = shutdown.into();
        let shared = Arc::new(PrepShared {
            network,
            coinbase_script: coinbase_script.clone(),
            shutdown: shutdown.clone(),
            mempool: Arc::clone(&mempool),
            chain: Arc::clone(&chain),
            mailbox: parking_lot::Mutex::new(PrepMailbox::default()),
            wake: parking_lot::Condvar::new(),
        });
        Self {
            network,
            applied_tip,
            mempool,
            chain,
            coinbase_script,
            shutdown,
            state: Mutex::new(CoordinatorState {
                seed,
                ..CoordinatorState::default()
            }),
            wake: Condvar::new(),
            prep: PrepWorker::spawn(shared),
        }
    }

    /// Stages a tip-child block for background template preparation.
    ///
    /// Hook-only: enqueues the staged tip and returns at once, copying the
    /// block into an `Arc` only for an eligible tip the worker has not seen.
    /// Never publishes a tip, a generation, or a candidate; installation
    /// waits for the committed receipt. Repeated stages for one tip are
    /// idempotent.
    pub fn stage_tip(&self, tip: &TipSnapshot, block: &Block) {
        if self.prep.owns_tip(tip.hash) {
            return;
        }
        // The block copy happens outside the mailbox lock: holding the mutex
        // across a multi-megabyte clone would delay worker and waiter
        // wakeups. A raced duplicate stage drops its copy below.
        let staged = StagedPrep {
            tip: tip.clone(),
            block: Arc::new(block.clone()),
        };
        let mut mailbox = self.prep.mailbox();
        if mailbox.stopped {
            return;
        }
        if PrepWorker::owns_tip_inner(&mailbox, tip.hash) {
            return;
        }
        mailbox.pending = Some(staged);
        drop(mailbox);
        self.prep.notify();
    }

    /// Test seam: waits for the preparation targeting `tip_hash` to finish,
    /// returning the existing ready candidate without publishing or
    /// assembling anything.
    ///
    /// Parks on the mailbox condvar (never sleeps or polls) until the worker
    /// finishes exactly this tip, or until `timeout`, stop, shutdown, or a
    /// preparation failure. Only a `Ready` candidate for the exact tip is
    /// returned, as the stored `Arc`; every other outcome is `None`. The
    /// timeout is a deadlock bound, never a performance assertion.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn wait_for_prepared_candidate(
        &self,
        tip_hash: Hash256,
        timeout: Duration,
    ) -> Option<Arc<Candidate>> {
        let deadline = Instant::now() + timeout;
        let mut mailbox = self.prep.mailbox();
        loop {
            if mailbox.stopped || self.shutdown.is_triggered() {
                return None;
            }
            match mailbox.active.as_ref() {
                Some(active) if active.target_tip == tip_hash => match &active.progress {
                    PrepProgress::Ready { candidate, .. } => {
                        return Some(Arc::clone(candidate));
                    }
                    PrepProgress::Failed => return None,
                    PrepProgress::Selecting | PrepProgress::Finishing => {}
                },
                _ => {}
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            self.prep.wait_for(&mut mailbox, deadline - now);
        }
    }

    /// Publishes a committed block generation with its actual removal receipt.
    ///
    /// The receipt is retained before waking so a foreground request for this
    /// tip joins a still-finishing preparation against exactly these
    /// identities and reasons instead of abandoning it. The generation key
    /// and waiter wake follow the ordinary [`Self::publish_generation`] path,
    /// so disconnects and other mutations keep their generic publication.
    pub fn publish_block_generation(&self, tip_hash: Hash256, removals: &MutationResult) {
        let receipt = BlockReceipt::from_result(tip_hash, removals);
        {
            let mut mailbox = self.prep.mailbox();
            mailbox.receipt = Some(receipt);
        }
        // Wake joined foregrounds parked on a Ready preparation: the receipt
        // they wait for is now stored, before the generic publication below.
        self.prep.notify();
        self.publish_generation();
    }

    /// Publishes the live generation key and wakes every long-poll / single-flight waiter.
    ///
    /// Callers must invoke this after every authoritative applied-tip or mempool
    /// mutation and before any dependent notification. The published key is
    /// captured from live applied-tip / mempool state; installing it and waking
    /// waiters share one coordinator-lock critical section.
    pub fn publish_generation(&self) {
        // Baseline order: the live key is read before the state lock is taken;
        // only the two sequence-based publishers must keep their retained
        // component reads and the publication in one critical section. A key
        // that raced a newer publication heals through `ensure_published`'s
        // live re-derivation.
        let key = self.live_generation_key();
        let mut state = self.state.lock();
        self.publish_locked(&mut state, key);
    }

    /// Invalidates an older membership generation and wakes waiters without a pool read.
    ///
    /// The mempool observer supplies only the sequence the mutation produced.
    /// Do not read the pool here or invent its fee revision. Tip/fee callers use
    /// [`Self::publish_generation`] instead, which captures the live sequence
    /// safely (no write lock is held on that path).
    pub fn publish_generation_from(&self, sequence: u64) {
        let mut state = self.state.lock();
        if let Some(key) = state.published
            && key.mempool_sequence != sequence
        {
            state.invalidate_key(key);
            state.published = None;
        }
        // Use the same mutex as the wait predicate so a wake cannot be lost.
        // Do not invent a fee revision from a membership-only notification.
        self.wake.notify_all();
    }

    /// Publishes a fee-priority (prioritisation) generation change and wakes
    /// every waiter without taking the mempool read lock.
    ///
    /// The `prioritisetransaction` path calls this after a successful
    /// prioritisation, passing the pool's post-change fee-delta sequence
    /// captured under a short pool read that has already been released. The
    /// published key preserves the last published membership sequence. The
    /// retained-component read, the state update, and the wake share one
    /// coordinator-state critical section, so a concurrent membership
    /// publication cannot interleave between the read and the overwrite and no
    /// fee component is lost.
    pub fn publish_fee_delta_generation(&self, fee_delta_sequence: u64) {
        let mut state = self.state.lock();
        let key = GenerationKey {
            tip_hash: self.live_tip_hash(),
            mempool_sequence: state.retained_mempool_sequence(),
            fee_delta_sequence,
        };
        self.publish_locked(&mut state, key);
    }

    #[cfg(any(test, feature = "test-seam"))]
    /// Test-seam probe: long-poll waiters currently parked in
    /// [`Self::wait_for_generation_change`].
    ///
    /// A reader that observes a count of at least one knows a waiter has read
    /// `live == waited` under the state mutex and registered on the wake
    /// condvar (`wait_for` releases the mutex only after enqueueing), so any
    /// later publication's notify reaches it.
    #[must_use]
    pub fn parked_long_poll_waiters(&self) -> usize {
        self.state.lock().parked_long_poll_waiters
    }

    fn live_tip_hash(&self) -> Hash256 {
        self.applied_tip
            .applied_tip()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash)
    }

    fn live_generation_key(&self) -> GenerationKey {
        let tip_hash = self.live_tip_hash();
        let (mempool_sequence, fee_delta_sequence) = self.mempool.current_revisions();
        GenerationKey {
            tip_hash,
            mempool_sequence,
            fee_delta_sequence,
        }
    }

    /// Installs `key` and wakes every waiter under an already-held state lock,
    /// so a retained-component read and its publication share one critical
    /// section and cannot interleave with another sequence-based publication.
    fn publish_locked(&self, state: &mut CoordinatorState, key: GenerationKey) {
        if let Some(previous) = state.published
            && previous != key
        {
            state.invalidate_key(previous);
        }
        state.published = Some(key);
        self.wake.notify_all();
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
            if self.shutdown.is_triggered() {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let live = self.ensure_published(&mut state);
            if live != waited {
                return Ok(live);
            }
            #[cfg(any(test, feature = "test-seam"))]
            {
                state.parked_long_poll_waiters += 1;
            }
            let _ = self.wake.wait_for(&mut state, LONG_POLL_SLICE);
            #[cfg(any(test, feature = "test-seam"))]
            {
                state.parked_long_poll_waiters -= 1;
            }
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
            let version_bits_available = self.signalling_rules_for(&tip, candidate.height);
            return Ok(template_from_candidate(
                self.network,
                candidate,
                submit_old,
                version_bits_available,
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
            if self.shutdown.is_triggered() {
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
                Err(error) if error.is_template_generation_race() => {
                    last_race = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_race.unwrap_or_else(generation_race))
    }

    /// Joins the preparation targeting `key`'s tip: returns its finished data
    /// once ready, waits in bounded slices while it is queued, selecting, or
    /// finishing, and releases the waiter (fall back, never a duplicate
    /// finish) when no job targets this tip, the preparation failed, the
    /// worker stopped, or the chain moved on. Shutdown releases the waiter
    /// with `Unavailable`.
    ///
    /// A still-pending match waits too: the worker owns that tip and will
    /// start it, so a foreground request must not run a duplicate lazy
    /// finish beside it.
    ///
    /// A `Ready` match whose live key equals the key it predicted waits for
    /// the committed receipt of its tip. That state exists only after the
    /// pool removal committed (the gateway observer wakes foregrounds before
    /// the connect effects publish the receipt), so the receipt is imminent
    /// and joining beats a duplicate lazy finish. The tip leg is what makes
    /// this sound: the staged target is the connecting block's own tip, so a
    /// foreground key can equal the prediction only once that tip applied —
    /// a staged block refused before its commit keeps the applied tip on the
    /// parent, which never targets the preparation and serves lazily. A
    /// `Ready` match whose key the live pool no longer predicts (for example
    /// a later prioritisation) has no receipt coming for it and returns at
    /// once, so a stale preparation can never park a foreground. Receipt
    /// content mismatch is decided by the install check, not here.
    fn join_preparation(
        &self,
        key: GenerationKey,
    ) -> Result<Option<ReadyPreparation>, MiningControlError> {
        let mut mailbox = self.prep.mailbox();
        loop {
            if self.shutdown.is_triggered() {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            if mailbox.stopped {
                return Ok(None);
            }
            let targeted = mailbox
                .active
                .as_ref()
                .is_some_and(|active| active.target_tip == key.tip_hash)
                || mailbox
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.tip.hash == key.tip_hash);
            if !targeted {
                return Ok(None);
            }
            let failed = mailbox.active.as_ref().is_some_and(|active| {
                active.target_tip == key.tip_hash && matches!(active.progress, PrepProgress::Failed)
            });
            if failed {
                mailbox.active = None;
                return Ok(None);
            }
            let ready = match mailbox.active.as_ref() {
                Some(active) if active.target_tip == key.tip_hash => match &active.progress {
                    PrepProgress::Ready {
                        source_sequences,
                        expected_removals,
                        candidate,
                    } => {
                        let committed = mailbox
                            .receipt
                            .as_ref()
                            .is_some_and(|receipt| receipt.tip_hash == key.tip_hash);
                        let predicted = candidate.template_id == key.template_id();
                        (committed || !predicted).then(|| ReadyPreparation {
                            source_sequences: *source_sequences,
                            expected_removals: expected_removals.clone(),
                            candidate: Arc::clone(candidate),
                        })
                    }
                    // Selecting, Finishing, or a defensively rechecked Failed
                    // (the `failed` guard above already released that case):
                    // keep waiting for progress.
                    PrepProgress::Selecting | PrepProgress::Finishing | PrepProgress::Failed => {
                        None
                    }
                },
                _ => None,
            };
            if let Some(ready) = ready {
                return Ok(Some(ready));
            }
            #[cfg(test)]
            {
                mailbox.parked_joins += 1;
            }
            self.prep.wait_for(&mut mailbox, LONG_POLL_SLICE);
            #[cfg(test)]
            {
                mailbox.parked_joins -= 1;
            }
            if self.live_tip_hash() != key.tip_hash {
                return Ok(None);
            }
            // The pool read runs with the mailbox released: a key the live
            // pool moved off can never receive its receipt, so the waiter
            // falls back instead of parking behind it.
            let live =
                parking_lot::MutexGuard::unlocked(&mut mailbox, || self.live_generation_key());
            if live != key {
                return Ok(None);
            }
        }
    }

    /// Discards the preparation targeting `tip` when it still owns the slot,
    /// waking any joined waiter to fall back to lazy assembly.
    fn discard_preparation(&self, tip: Hash256) {
        let mut mailbox = self.prep.mailbox();
        let current = mailbox
            .active
            .as_ref()
            .is_some_and(|active| active.target_tip == tip);
        if current {
            mailbox.active = None;
        }
        drop(mailbox);
        self.prep.notify();
    }

    /// Installs the staged preparation for `key` when the committed receipt
    /// and the live generation match its expectations.
    ///
    /// A successful install matches, in order: the committed target, the
    /// exact removal identities and reasons, the wrapping membership advance
    /// (one step per actual removal), the predicted body sequences, and the
    /// live generation. A delayed worker that selected post-removal state
    /// carries an empty expectation that cannot match a nonempty receipt. No
    /// candidate is exposed before the committed receipt is accepted. Returns
    /// `Ok(None)` when no preparation targets this tip or the check refuses
    /// it; the caller falls back to lazy assembly.
    fn prepared_candidate_for_key(
        &self,
        key: GenerationKey,
    ) -> Result<Option<Arc<Candidate>>, MiningControlError> {
        let Some(ready) = self.join_preparation(key)? else {
            return Ok(None);
        };
        if self.live_generation_key() != key {
            return Ok(None);
        }
        // A receipt for another tip is stale, not a refusal: keep the slot
        // and let the matching publication decide. A same-tip receipt with
        // different removals is definitive and discards the preparation.
        let receipt_matches = {
            let mailbox = self.prep.mailbox();
            match &mailbox.receipt {
                None => None,
                Some(receipt) if receipt.tip_hash != key.tip_hash => None,
                Some(receipt) => Some(receipt.removals == ready.expected_removals),
            }
        };
        match receipt_matches {
            None => return Ok(None),
            Some(false) => {
                self.discard_preparation(key.tip_hash);
                return Ok(None);
            }
            Some(true) => {}
        }
        let removals = u64::try_from(ready.expected_removals.len()).unwrap_or(u64::MAX);
        if ready.source_sequences.0.wrapping_add(removals) != key.mempool_sequence {
            self.discard_preparation(key.tip_hash);
            return Ok(None);
        }
        // The installed candidate's identity already encodes the predicted
        // post-removal membership and fee sequences: an unrelated
        // prioritisation moves the live key off it and refuses the install.
        if ready.candidate.template_id != key.template_id() {
            self.discard_preparation(key.tip_hash);
            return Ok(None);
        }
        let template_id = key.template_id();
        let mut state = self.state.lock();
        if let Some(cached) = state.cache_get(&template_id) {
            return Ok(Some(cached));
        }
        // Recheck under the state lock: the tip may have moved while the pool
        // read ran. A stale install never publishes a speculative tip.
        if self.live_generation_key() != key {
            return Ok(None);
        }
        state.cache_insert(template_id, Arc::clone(&ready.candidate));
        state.last_candidate = Some(last_candidate_info(&ready.candidate));
        state.published = Some(key);
        drop(state);
        // The installed job owns nothing further: release the single slot so
        // a stale Ready never outlives its generation. Same-key foregrounds
        // already share the cached candidate above.
        self.discard_preparation(key.tip_hash);
        self.wake.notify_all();
        Ok(Some(ready.candidate))
    }

    /// Cache lookup or single-flight assembly for one generation key.
    fn candidate_for_key(&self, key: GenerationKey) -> Result<Arc<Candidate>, MiningControlError> {
        let template_id = key.template_id();
        {
            let state = self.state.lock();
            if let Some(cached) = state.cache_get(&template_id) {
                return Ok(cached);
            }
        }
        // A staged preparation for this tip installs without a second
        // finish; a still-running one is joined, never duplicated.
        if let Some(candidate) = self.prepared_candidate_for_key(key)? {
            return Ok(candidate);
        }
        let mut state = self.state.lock();

        loop {
            if self.shutdown.is_triggered() {
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
                    state.last_candidate = Some(last_candidate_info(candidate));
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
        if state
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.id == flight_id)
        {
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
        let context = self.candidate_context(&tip)?;
        let Some(body) = self.mempool.select_template(
            Some((key.mempool_sequence, key.fee_delta_sequence)),
            &context,
            &self.coinbase_script,
        )?
        else {
            return Err(generation_race());
        };
        let candidate = finish_candidate(&context, &body, &self.coinbase_script)
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
        candidate_context_for(self.network, &self.chain, tip)
    }

    /// Cached deployment facts for `tip` at `height`: hits reuse the stored
    /// vector, misses resolve outside the coordinator lock and then install,
    /// so chain-tree reads never nest inside coordinator state.
    fn signalling_rules_for(&self, tip: &TipSnapshot, height: u32) -> Vec<AvailableMiningRule> {
        let cached = self.state.lock().signalling_cache_get(&tip.hash, height);
        if let Some(cached) = cached {
            return cached;
        }
        let resolved = self.chain.signalling_rules(tip, height);
        self.state
            .lock()
            .signalling_cache_insert(tip.hash, height, resolved.clone());
        resolved
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
        let context = self.candidate_context(&tip)?;
        match selection {
            GenerateSelection::Mempool => {
                let body = self
                    .mempool
                    .select_template(None, &context, payout)?
                    .ok_or_else(generation_race)?;
                finish_candidate(&context, &body, payout)
            }
            GenerateSelection::Ordered(_) => {
                let snapshot = self.mempool.selection_snapshot(selection, &context)?;
                assemble_ordered_candidate(&context, &snapshot, payout)
            }
        }
        .map_err(|error| match selection {
            GenerateSelection::Ordered(_) => crate::bip22::ordered_assembly_error(&error),
            GenerateSelection::Mempool => {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            }
        })
    }
}

/// Clears an abandoned single-flight slot when assembly unwinds, so
/// unwind-enabled profiles cannot leave same-key callers blocked forever.
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
/// Staged tip and block handed to the preparation worker.
struct StagedPrep {
    tip: TipSnapshot,
    block: Arc<Block>,
}

/// One preparation's progress from enqueue to finished candidate.
enum PrepProgress {
    /// The worker has not selected yet; source sequences are unknown.
    Selecting,
    /// Selected under the pool read; finishing the candidate without any lock.
    Finishing,
    /// Candidate finished; installable once the committed receipt matches.
    Ready {
        source_sequences: (u64, u64),
        expected_removals: Vec<(Txid, RemovalReason)>,
        candidate: Arc<Candidate>,
    },
    /// Selection or finishing failed; foreground falls back to lazy assembly.
    Failed,
}

/// The single preparation the worker owns, if any.
struct ActivePrep {
    target_tip: Hash256,
    progress: PrepProgress,
}

/// Committed block-removal receipt retained while a preparation finishes.
struct BlockReceipt {
    tip_hash: Hash256,
    removals: Vec<(Txid, RemovalReason)>,
}

impl BlockReceipt {
    /// Keeps every committed removal's stable identity and exact reason, in
    /// commit order. Admissions carry no removal and contribute nothing.
    fn from_result(tip_hash: Hash256, removals: &MutationResult) -> Self {
        let removals = removals
            .changes
            .iter()
            .filter_map(|change| match change.outcome {
                MutationOutcome::Removed(reason) => Some((Txid::from(change.txid), reason)),
                MutationOutcome::Accepted => None,
            })
            .collect();
        Self { tip_hash, removals }
    }
}

/// Bounded preparation mailbox shared by the service and its worker: one
/// pending newest job plus at most one owned job.
#[derive(Default)]
struct PrepMailbox {
    /// Newest unstarted staged tip; a newer stage replaces it.
    pending: Option<StagedPrep>,
    /// The job the worker owns; at most one.
    active: Option<ActivePrep>,
    /// Latest committed removal receipt, retained for a finishing preparation.
    receipt: Option<BlockReceipt>,
    /// Test probe: foreground joins parked on the mailbox condvar. A reader
    /// that observes a count of at least one knows a waiter evaluated its
    /// predicate under the mailbox mutex and registered on the condvar
    /// (`wait_for` releases the mutex only after enqueueing), so any later
    /// notify reaches it.
    #[cfg(test)]
    parked_joins: usize,
    /// Set by stop; the worker exits and waiters release.
    stopped: bool,
}

/// Capability sources plus the preparation mailbox owned by both the service
/// and its worker. Never points back at the service: the worker cannot join
/// itself and dropping the last service reference still stops the thread.
struct PrepShared {
    network: Network,
    coinbase_script: Vec<u8>,
    shutdown: bitcoin_rs_chain::LatchReader,
    mempool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    mailbox: parking_lot::Mutex<PrepMailbox>,
    wake: parking_lot::Condvar,
}

/// The service's one preparation thread over shared mailbox state.
///
/// The worker owns capability sources and mailbox state only — never the
/// service — so drops cannot self-join and no reference cycle forms.
/// `std::thread::JoinHandle` is `Sync`, so the plain `Option` keeps the
/// service `Send + Sync` with no wrapper.
struct PrepWorker {
    shared: Arc<PrepShared>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PrepWorker {
    /// Spawns the service's one preparation thread over `shared`.
    ///
    /// A refused spawn logs the exact OS error and degrades to no worker
    /// instead of panicking: the slot is marked stopped, stages no-op, and
    /// every foreground request falls back to lazy assembly. Correctness
    /// never depends on the thread.
    fn spawn(shared: Arc<PrepShared>) -> Self {
        let worker = Arc::clone(&shared);
        let handle = match std::thread::Builder::new()
            .name("btcrs-template-prep".into())
            .spawn(move || {
                let _exit = WorkerExitGuard::new(Arc::clone(&worker));
                preparation_loop(&worker);
            }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "template preparation worker spawn failed; continuing without background preparation"
                );
                {
                    let mut mailbox = shared.mailbox.lock();
                    mailbox.stopped = true;
                }
                None
            }
        };
        Self { shared, handle }
    }

    /// Whether the worker already owns a job for `target`.
    fn owns_tip(&self, target: Hash256) -> bool {
        Self::owns_tip_inner(&self.mailbox(), target)
    }

    fn owns_tip_inner(mailbox: &parking_lot::MutexGuard<'_, PrepMailbox>, target: Hash256) -> bool {
        mailbox
            .active
            .as_ref()
            .is_some_and(|active| active.target_tip == target)
            || mailbox
                .pending
                .as_ref()
                .is_some_and(|pending| pending.tip.hash == target)
    }

    fn mailbox(&self) -> parking_lot::MutexGuard<'_, PrepMailbox> {
        self.shared.mailbox.lock()
    }

    fn notify(&self) {
        self.shared.wake.notify_all();
    }

    fn wait_for(&self, guard: &mut parking_lot::MutexGuard<'_, PrepMailbox>, timeout: Duration) {
        self.shared.wake.wait_for(guard, timeout);
    }

    /// Signals the worker to exit and joins it. Holds no pool lock: a
    /// selecting worker finishes its bounded read, a parked one wakes. A
    /// panicked join logs the exact payload message instead of propagating:
    /// `Drop` cannot fail, but the failure stays visible.
    fn stop(&mut self) {
        {
            let mut mailbox = self.mailbox();
            mailbox.stopped = true;
        }
        self.notify();
        if let Some(handle) = self.handle.take() {
            if let Err(payload) = handle.join() {
                let message = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("unknown panic payload");
                tracing::warn!(
                    message,
                    "template preparation worker panicked; preparation is disabled"
                );
            }
        }
    }
}

impl Drop for PrepWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Releases every preparation waiter when the worker exits for any reason,
/// including an unwinding panic. Owned by the worker closure; the panic
/// itself is never caught or suppressed, only cleaned up after, and its
/// payload is logged by the joining `stop`.
struct WorkerExitGuard {
    shared: Arc<PrepShared>,
}

impl WorkerExitGuard {
    fn new(shared: Arc<PrepShared>) -> Self {
        Self { shared }
    }
}

impl Drop for WorkerExitGuard {
    fn drop(&mut self) {
        let mut mailbox = self.shared.mailbox.lock();
        mailbox.stopped = true;
        mailbox.pending = None;
        mailbox.active = None;
        // The panic payload is not visible here; the joining `stop` logs the
        // exact message. Log the fact of the unwind immediately so the
        // failure is visible even while the service lives.
        let unwinding = std::thread::panicking();
        drop(mailbox);
        if unwinding {
            tracing::warn!(
                "template preparation worker panicked; waiters released, payload follows at join"
            );
        }
        self.shared.wake.notify_all();
    }
}

/// Finished preparation data copied out of the mailbox for the install check.
struct ReadyPreparation {
    source_sequences: (u64, u64),
    expected_removals: Vec<(Txid, RemovalReason)>,
    candidate: Arc<Candidate>,
}

/// Takes the newest staged job, or `None` on stop or shutdown.
///
/// An owned job for the staged tip stays: repeated stage notifications are
/// idempotent and never disturb running or finished work. A newer tip
/// replaces only the unstarted pending slot.
fn wait_for_staged_job(shared: &PrepShared) -> Option<StagedPrep> {
    let mut mailbox = shared.mailbox.lock();
    loop {
        if mailbox.stopped || shared.shutdown.is_triggered() {
            return None;
        }
        if let Some(job) = mailbox.pending.take() {
            let owned = mailbox
                .active
                .as_ref()
                .is_some_and(|active| active.target_tip == job.tip.hash);
            if owned {
                continue;
            }
            mailbox.active = Some(ActivePrep {
                target_tip: job.tip.hash,
                progress: PrepProgress::Selecting,
            });
            // Wake joined foreground waiters: a pending match they waited on
            // is now owned and progressing.
            shared.wake.notify_all();
            return Some(job);
        }
        // Bounded slice, not an unbounded park: a latch-only shutdown that
        // never drops the service still releases the worker within one slice.
        shared.wake.wait_for(&mut mailbox, LONG_POLL_SLICE);
    }
}

/// Records a failed preparation for `target` when it still owns the slot,
/// then wakes any joined foreground waiter to fall back to lazy assembly.
fn mark_prep_failed(shared: &PrepShared, target: Hash256) {
    let mut mailbox = shared.mailbox.lock();
    let current = mailbox
        .active
        .as_ref()
        .is_some_and(|active| active.target_tip == target);
    if current {
        mailbox.active = Some(ActivePrep {
            target_tip: target,
            progress: PrepProgress::Failed,
        });
    }
    drop(mailbox);
    shared.wake.notify_all();
}

/// The worker's one loop: select the staged tip's projection under the pool
/// read, finish the candidate after releasing it, and publish the finished
/// preparation for the install check. No candidate is exposed before the
/// committed receipt arrives; the install path owns that gate.
fn preparation_loop(shared: &PrepShared) {
    loop {
        let Some(job) = wait_for_staged_job(shared) else {
            return;
        };
        let Ok(context) = candidate_context_for(shared.network, &shared.chain, &job.tip) else {
            mark_prep_failed(shared, job.tip.hash);
            continue;
        };
        let Ok(prepared) =
            shared
                .mempool
                .select_template_after(&job.block, &context, &shared.coinbase_script)
        else {
            mark_prep_failed(shared, job.tip.hash);
            continue;
        };
        {
            let mut mailbox = shared.mailbox.lock();
            let current = mailbox
                .active
                .as_ref()
                .is_some_and(|active| active.target_tip == job.tip.hash);
            if !current {
                // Superseded while selecting: drop the projection, keep the
                // newer job's slot untouched.
                continue;
            }
            mailbox.active = Some(ActivePrep {
                target_tip: job.tip.hash,
                progress: PrepProgress::Finishing,
            });
        }
        let Ok(candidate) = finish_candidate(&context, &prepared.body, &shared.coinbase_script)
        else {
            mark_prep_failed(shared, job.tip.hash);
            continue;
        };
        {
            let mut mailbox = shared.mailbox.lock();
            let current = mailbox
                .active
                .as_ref()
                .is_some_and(|active| active.target_tip == job.tip.hash);
            if current {
                mailbox.active = Some(ActivePrep {
                    target_tip: job.tip.hash,
                    progress: PrepProgress::Ready {
                        source_sequences: prepared.source_sequences,
                        expected_removals: prepared.removals,
                        candidate: Arc::new(candidate),
                    },
                });
            }
            // Else superseded while finishing: drop the finished work, keep
            // the newer job's slot untouched.
        }
        shared.wake.notify_all();
    }
}

/// Resolves the candidate context for a block extending `tip` at the current
/// time. Shared by foreground assembly and the preparation worker so both
/// describe the same candidate shape.
fn candidate_context_for(
    network: Network,
    chain: &Arc<dyn ChainContextSource>,
    tip: &TipSnapshot,
) -> Result<CandidateContext, MiningControlError> {
    let current_time = current_unix_seconds().max(1);
    let chain = chain
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
        network,
        csv_active: chain.csv_active,
        segwit_active: chain.segwit_active,
        max_weight: MAX_BLOCK_WEIGHT,
        max_size: MAX_BLOCK_SERIALIZED_SIZE,
        max_sigops: u64::from(MAX_BLOCK_SIGOPS_COST),
    })
}

/// Builds the cached-candidate report line the lazy and prepared install
/// paths share, so both publications describe the same candidate shape.
fn last_candidate_info(candidate: &Candidate) -> LastCandidateInfo {
    LastCandidateInfo {
        weight: candidate.weight,
        transactions: u64::try_from(candidate.transactions.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1),
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
    // Core v31 `getblocktemplate` hardcodes `vbrequired` to 0.
    BlockTemplate {
        rules,
        candidate,
        version_bits_available,
        version_bits_required: 0,
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
    }
}

/// Builds the mining snapshot a generate selection assembles from.
///
/// `Ordered` selections re-index the mempool snapshot to the caller's
/// explicit transaction order; unknown mempool txids are request errors.
/// `prevouts` must come from the candidate's applied-chain view. Raw transaction
/// costs also resolve outputs of earlier listed transactions, using the same
/// consensus owner as admitted entries. Later or unselected pool outputs are
/// not spendable inputs. Missing inputs are retained for block validation.
///
/// # Errors
///
/// Returns [`MiningControlError::InvalidRequest`] when an `Ordered`
/// selection names a transaction that is not in the mempool.
pub fn snapshot_for_selection(
    full: MempoolMiningSnapshot,
    selection: &GenerateSelection,
    prevouts: &[(OutPoint, TxOut)],
    segwit_active: bool,
) -> Result<MempoolMiningSnapshot, MiningControlError> {
    match selection {
        GenerateSelection::Mempool => Ok(full),
        GenerateSelection::Ordered(items) => {
            let flags = if segwit_active {
                VerifyFlags::WITNESS
            } else {
                VerifyFlags::NONE
            };
            let prevouts: HashMap<_, _> =
                prevouts.iter().map(|(key, value)| (*key, value)).collect();
            let mut selected_positions = HashMap::with_capacity(items.len());
            let mut by_txid = HashMap::with_capacity(full.entries.len());
            for (index, entry) in full.entries.iter().enumerate() {
                let position = u32::try_from(index).unwrap_or(u32::MAX);
                by_txid.insert(entry.txid, position);
            }
            let mut selected: Vec<SnapshotEntry> = Vec::with_capacity(items.len());
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
                    GenerateTx::Raw(tx) => {
                        let resolved = tx
                            .inputs
                            .iter()
                            .filter_map(|input| {
                                let outpoint = input.previous_output;
                                let earlier_output = selected_positions
                                    .get(&outpoint.txid)
                                    .and_then(|&index: &usize| selected.get(index))
                                    .and_then(|entry| {
                                        usize::try_from(outpoint.vout)
                                            .ok()
                                            .and_then(|vout| entry.tx.outputs.get(vout))
                                    });
                                earlier_output
                                    .or_else(|| prevouts.get(&outpoint).copied())
                                    .map(|output| (outpoint, output.clone()))
                            })
                            .collect::<Vec<_>>();
                        selected.push(snapshot_entry_from_raw(tx, &resolved, flags));
                    }
                }
                if let Some(entry) = selected.last() {
                    selected_positions.insert(entry.txid, selected.len() - 1);
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
                fee_delta_sequence: full.fee_delta_sequence,
                entries: selected,
            })
        }
    }
}

/// Counts a raw transaction against copied chain outputs and earlier ordered outputs.
/// Missing inputs remain missing; authoritative block validation owns their rejection.
fn snapshot_entry_from_raw(
    tx: &Tx,
    prevouts: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
) -> SnapshotEntry {
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
        sigop_cost: transaction_sigop_cost(&tx, prevouts, flags),
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

impl MiningControlError {
    /// Whether candidate acquisition failed because its tip or mempool generation changed.
    ///
    /// Callers may retry this race after a delay. Other unavailable states,
    /// including shutdown, are not classified as generation races.
    #[must_use]
    pub fn is_template_generation_race(&self) -> bool {
        matches!(self, Self::Unavailable(message) if message == GENERATION_RACE)
    }
}

/// Parses a BIP22/BIP23 long-poll id into its generation key.
///
/// At fee revision zero the id retains Core's hash plus decimal membership
/// sequence; later fee revisions append `:<revision>`. Both forms parse;
/// legacy ids imply fee revision zero.
#[must_use]
fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    let hash_hex = id.get(..64)?;
    let sequence = id.get(64..)?;
    if sequence.is_empty() {
        return None;
    }
    let tip_hash = Hash256::from_str_be(hash_hex).ok()?;
    let (sequence, fee_revision) = sequence.split_once(':').unwrap_or((sequence, "0"));
    let mempool_sequence = sequence.parse().ok()?;
    let fee_delta_sequence = fee_revision.parse().ok()?;
    Some(GenerationKey {
        tip_hash,
        mempool_sequence,
        fee_delta_sequence,
    })
}

/// Signet challenge and flag for `network`, or `None` off signet. The
/// challenge is the one `Network::signet_challenge` that block validation
/// also reads.
#[must_use]
fn signet_info(network: Network) -> Option<SignetMiningInfo> {
    network
        .signet_challenge()
        .map(|challenge| SignetMiningInfo {
            challenge: challenge.to_vec(),
        })
}

#[cfg(test)]
mod tests;
