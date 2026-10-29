//! Candidate lifecycle state and pure mining-domain projections.

use std::collections::VecDeque;
use std::sync::Arc;
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
use crate::template::CoinbaseBudget;
use crate::template::SelectedBody;
use crate::template::TemplateId;
use crate::template::assemble_ordered_candidate;
use crate::template::finish_candidate;

const CANDIDATE_CACHE_LIMIT: usize = 8;
const CANDIDATE_GENERATION_RETRIES: usize = 8;
const GENERATION_RACE: &str = "generation key changed during candidate assembly";
const ASSEMBLY_BUSY: &str = "budgeted candidate assembly is busy";
const LONG_POLL_SLICE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct GenerationKey {
    tip_hash: Hash256,
    mempool_sequence: u64,
    fee_delta_sequence: u64,
}

impl GenerationKey {
    #[must_use]
    fn template_id(self) -> TemplateId {
        TemplateId::with_fee_revision(
            &self.tip_hash,
            self.mempool_sequence,
            self.fee_delta_sequence,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct CandidateKey {
    generation: GenerationKey,
    budget: Option<CoinbaseBudget>,
}

impl CandidateKey {
    #[must_use]
    fn ordinary(generation: GenerationKey) -> Self {
        Self {
            generation,
            budget: None,
        }
    }

    #[must_use]
    fn template_id(self) -> TemplateId {
        self.generation.template_id().qualified(self.budget)
    }
}

struct InFlight {
    key: GenerationKey,
    id: u64,
    result: Option<Result<Arc<Candidate>, MiningControlError>>,
}

#[derive(Default)]
struct CoordinatorState {
    published: Option<GenerationKey>,
    seed: u64,
    #[cfg(any(test, feature = "test-seam"))]
    parked_long_poll_waiters: usize,
    cache: HashMap<CandidateKey, Arc<Candidate>>,
    cache_order: VecDeque<CandidateKey>,
    signalling_rules: Option<(Hash256, u32, Vec<AvailableMiningRule>)>,
    in_flight: Option<InFlight>,
    budgeted: Option<u64>,
    next_flight_id: u64,
    last_candidate: Option<LastCandidateInfo>,
}

impl CoordinatorState {
    fn retained_mempool_sequence(&self) -> u64 {
        self.published.map_or(self.seed, |key| key.mempool_sequence)
    }

    fn cache_get(&self, key: &CandidateKey) -> Option<Arc<Candidate>> {
        self.cache.get(key).cloned()
    }

    fn cache_insert(&mut self, key: CandidateKey, candidate: Arc<Candidate>) {
        if self.cache.contains_key(&key) {
            self.cache.insert(key, candidate);
            return;
        }
        while self.cache.len() >= CANDIDATE_CACHE_LIMIT {
            let Some(oldest) = self.cache_order.pop_front() else {
                break;
            };
            self.cache.remove(&oldest);
        }
        self.cache_order.push_back(key);
        self.cache.insert(key, candidate);
    }

    fn signalling_cache_get(&self, tip: &Hash256, height: u32) -> Option<Vec<AvailableMiningRule>> {
        let (cached_tip, cached_height, rules) = self.signalling_rules.as_ref()?;
        if cached_tip == tip && *cached_height == height {
            Some(rules.clone())
        } else {
            None
        }
    }

    fn signalling_cache_insert(
        &mut self,
        tip: Hash256,
        height: u32,
        rules: Vec<AvailableMiningRule>,
    ) {
        self.signalling_rules = Some((tip, height, rules));
    }

    fn invalidate_key(&mut self, generation: GenerationKey) {
        self.cache.retain(|key, _| key.generation != generation);
        self.cache_order.retain(|key| key.generation != generation);
        if self
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.key == generation)
        {
            self.in_flight = None;
        }
    }
}

#[derive(Debug)]
pub struct PreparedTemplateBody {
    pub body: SelectedBody,
    pub source_sequences: (u64, u64),
    pub removals: Vec<(Txid, RemovalReason)>,
}

pub trait MempoolSequenceWake: Send + Sync {
    fn publish_generation_from(&self, sequence: u64);
    fn stage_tip(&self, tip: &TipSnapshot, block: &Block);
    fn publish_block_generation(&self, tip_hash: Hash256, removals: &MutationResult);
}

pub trait AppliedTipSource: Send + Sync {
    fn applied_tip(&self) -> Option<TipSnapshot>;
}

pub trait MempoolSnapshotSource: Send + Sync {
    fn current_revisions(&self) -> (u64, u64);
    /// Returns [`MiningControlError::Failed`] when selection refuses the
    /// context's limits, including an unsatisfiable `budget`.
    fn select_template(
        &self,
        expected_sequences: Option<(u64, u64)>,
        context: &CandidateContext,
        payout: &[u8],
        budget: Option<CoinbaseBudget>,
    ) -> Result<Option<SelectedBody>, MiningControlError>;
    fn select_template_after(
        &self,
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError>;
    /// Returns [`MiningControlError::InvalidRequest`] when an `Ordered`
    /// selection names a transaction that is not in the mempool, or
    /// [`MiningControlError::Unavailable`] when the candidate tip changed
    /// before copying raw transaction prevouts.
    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
        context: &CandidateContext,
    ) -> Result<MempoolMiningSnapshot, MiningControlError>;
    fn pooled_transaction_count(&self) -> u64;
    fn min_relay_fee_sat_per_kvb(&self) -> u64;
}

pub trait ChainContextSource: Send + Sync {
    fn resolve_mining_context(
        &self,
        tip: &TipSnapshot,
        candidate_time: u32,
    ) -> Result<MiningChainContext, ChainError>;

    fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError>;

    fn signalling_rules(&self, tip: &TipSnapshot, height: u32) -> Vec<AvailableMiningRule>;
}

pub struct MiningService {
    network: Network,
    coinbase_script: Vec<u8>,
    shutdown: bitcoin_rs_chain::LatchReader,
    applied_tip: Arc<dyn AppliedTipSource>,
    mempool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    state: Mutex<CoordinatorState>,
    wake: Condvar,
    prep: PrepWorker,
}

impl MiningService {
    #[must_use]
    pub fn new(
        network: Network,
        applied_tip: Arc<dyn AppliedTipSource>,
        mempool: Arc<dyn MempoolSnapshotSource>,
        chain: Arc<dyn ChainContextSource>,
        coinbase_script: Vec<u8>,
        shutdown: impl Into<bitcoin_rs_chain::LatchReader>,
    ) -> Self {
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

    pub fn stage_tip(&self, tip: &TipSnapshot, block: &Block) {
        if self.prep.owns_tip(tip.hash) {
            return;
        }
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

    pub fn publish_block_generation(&self, tip_hash: Hash256, removals: &MutationResult) {
        let receipt = BlockReceipt::from_result(tip_hash, removals);
        {
            let mut mailbox = self.prep.mailbox();
            mailbox.receipt = Some(receipt);
        }
        self.prep.notify();
        self.publish_generation();
    }

    pub fn publish_generation(&self) {
        let key = self.live_generation_key();
        let mut state = self.state.lock();
        self.publish_locked(&mut state, key);
    }

    pub fn publish_generation_from(&self, sequence: u64) {
        let mut state = self.state.lock();
        if let Some(key) = state.published
            && key.mempool_sequence != sequence
        {
            state.invalidate_key(key);
            state.published = None;
        }
        self.wake.notify_all();
    }

    pub fn publish_fee_delta_generation(&self, fee_delta_sequence: u64) {
        let mut state = self.state.lock();
        let key = GenerationKey {
            tip_hash: self.live_tip_hash(),
            mempool_sequence: state.retained_mempool_sequence(),
            fee_delta_sequence,
        };
        if let Some(published) = state.published
            && published.tip_hash == key.tip_hash
            && published.mempool_sequence == key.mempool_sequence
            && published.fee_delta_sequence > fee_delta_sequence
        {
            return;
        }
        self.publish_locked(&mut state, key);
    }

    #[cfg(any(test, feature = "test-seam"))]
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

    /// [`MiningControlError::Failed`] when the budget cannot fit even an empty
    /// block.
    pub fn get_block_template(
        &self,
        long_poll_id: Option<&str>,
        coinbase_budget: Option<CoinbaseBudget>,
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
        for _ in 0..CANDIDATE_GENERATION_RETRIES {
            let candidate = self.live_candidate(coinbase_budget)?;
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

    fn live_candidate(
        &self,
        budget: Option<CoinbaseBudget>,
    ) -> Result<Arc<Candidate>, MiningControlError> {
        let mut last_race = None;
        for _attempt in 0..CANDIDATE_GENERATION_RETRIES {
            if self.shutdown.is_triggered() {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            let generation = {
                let mut state = self.state.lock();
                self.ensure_published(&mut state)
            };
            let served = match budget {
                None => self.candidate_for_key(generation),
                Some(budget) => self.budgeted_candidate(generation, budget),
            };
            match served {
                Ok(candidate) => {
                    if self.live_generation_key() == generation {
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
            let live =
                parking_lot::MutexGuard::unlocked(&mut mailbox, || self.live_generation_key());
            if live != key {
                return Ok(None);
            }
        }
    }

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
        if ready.candidate.template_id != key.template_id() {
            self.discard_preparation(key.tip_hash);
            return Ok(None);
        }
        let cache_key = CandidateKey::ordinary(key);
        let mut state = self.state.lock();
        if let Some(cached) = state.cache_get(&cache_key) {
            return Ok(Some(cached));
        }
        if self.live_generation_key() != key {
            return Ok(None);
        }
        state.cache_insert(cache_key, Arc::clone(&ready.candidate));
        state.last_candidate = Some(last_candidate_info(&ready.candidate));
        state.published = Some(key);
        drop(state);
        self.discard_preparation(key.tip_hash);
        self.wake.notify_all();
        Ok(Some(ready.candidate))
    }

    fn candidate_for_key(&self, key: GenerationKey) -> Result<Arc<Candidate>, MiningControlError> {
        let cache_key = CandidateKey::ordinary(key);
        {
            let state = self.state.lock();
            if let Some(cached) = state.cache_get(&cache_key) {
                return Ok(cached);
            }
        }
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
        if let Some(cached) = state.cache_get(&cache_key) {
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

        let assembled = self.assemble_for_key(cache_key);
        let mut state = self.state.lock();
        let live = self.live_generation_key();
        let returned = match &assembled {
            Ok(candidate) => {
                if live == key {
                    state.cache_insert(cache_key, Arc::clone(candidate));
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

    fn assemble_for_key(&self, key: CandidateKey) -> Result<Arc<Candidate>, MiningControlError> {
        let generation = key.generation;
        let tip = self.applied_tip.applied_tip().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        if tip.hash != generation.tip_hash {
            return Err(generation_race());
        }
        let context = self.candidate_context(&tip)?;
        let Some(body) = self.mempool.select_template(
            Some((generation.mempool_sequence, generation.fee_delta_sequence)),
            &context,
            &self.coinbase_script,
            key.budget,
        )?
        else {
            return Err(generation_race());
        };
        let candidate = finish_candidate(&context, &body, &self.coinbase_script)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        if candidate.template_id != key.template_id() {
            return Err(MiningControlError::Failed(CompactString::from(
                "assembled candidate template id does not match candidate key",
            )));
        }
        Ok(Arc::new(candidate))
    }

    fn budgeted_candidate(
        &self,
        generation: GenerationKey,
        budget: CoinbaseBudget,
    ) -> Result<Arc<Candidate>, MiningControlError> {
        let key = CandidateKey {
            generation,
            budget: Some(budget),
        };
        let mut deadline = None;
        let flight_id = loop {
            if self.shutdown.is_triggered() {
                return Err(MiningControlError::Unavailable(CompactString::from(
                    "node is shutting down",
                )));
            }
            if let Some(candidate) = self.reusable_candidate(key, budget)? {
                return Ok(candidate);
            }
            let mut state = self.state.lock();
            if let Some(cached) = state.cache_get(&key) {
                return Ok(cached);
            }
            if state.budgeted.is_none() {
                state.next_flight_id = state.next_flight_id.wrapping_add(1);
                let flight_id = state.next_flight_id;
                state.budgeted = Some(flight_id);
                break flight_id;
            }
            let until = *deadline.get_or_insert_with(|| Instant::now() + LONG_POLL_SLICE);
            let now = Instant::now();
            if now >= until {
                return Err(assembly_busy());
            }
            let _ = self.wake.wait_for(&mut state, until - now);
        };
        let _slot = BudgetedSlot {
            service: self,
            id: flight_id,
        };

        let assembled = self.assemble_for_key(key)?;
        let mut state = self.state.lock();
        if self.live_generation_key() != generation {
            return Err(generation_race());
        }
        state.cache_insert(key, Arc::clone(&assembled));
        state.last_candidate = Some(last_candidate_info(&assembled));
        Ok(assembled)
    }

    fn reusable_candidate(
        &self,
        key: CandidateKey,
        budget: CoinbaseBudget,
    ) -> Result<Option<Arc<Candidate>>, MiningControlError> {
        let ordinary_key = CandidateKey::ordinary(key.generation);
        let (exact, ordinary) = {
            let state = self.state.lock();
            (state.cache_get(&key), state.cache_get(&ordinary_key))
        };
        if exact.is_some() {
            return Ok(exact);
        }
        let ordinary = match ordinary {
            Some(ordinary) => Some(ordinary),
            None if self.preparation_installable(key.generation.tip_hash) => {
                self.prepared_candidate_for_key(key.generation)?
            }
            None => None,
        };
        Ok(ordinary.filter(|candidate| candidate.admits(budget).is_ok()))
    }

    fn preparation_installable(&self, tip: Hash256) -> bool {
        let mailbox = self.prep.mailbox();
        let finished = mailbox.active.as_ref().is_some_and(|active| {
            active.target_tip == tip && matches!(active.progress, PrepProgress::Ready { .. })
        });
        finished
            && mailbox
                .receipt
                .as_ref()
                .is_some_and(|receipt| receipt.tip_hash == tip)
    }

    fn candidate_context(&self, tip: &TipSnapshot) -> Result<CandidateContext, MiningControlError> {
        candidate_context_for(self.network, &self.chain, tip)
    }

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
                    .select_template(None, &context, payout, None)?
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

struct BudgetedSlot<'a> {
    service: &'a MiningService,
    id: u64,
}

impl Drop for BudgetedSlot<'_> {
    fn drop(&mut self) {
        let mut state = self.service.state.lock();
        if state.budgeted == Some(self.id) {
            state.budgeted = None;
        }
        drop(state);
        self.service.wake.notify_all();
    }
}

struct StagedPrep {
    tip: TipSnapshot,
    block: Arc<Block>,
}

enum PrepProgress {
    Selecting,
    Finishing,
    Ready {
        source_sequences: (u64, u64),
        expected_removals: Vec<(Txid, RemovalReason)>,
        candidate: Arc<Candidate>,
    },
    Failed,
}

struct ActivePrep {
    target_tip: Hash256,
    progress: PrepProgress,
}

struct BlockReceipt {
    tip_hash: Hash256,
    removals: Vec<(Txid, RemovalReason)>,
}

impl BlockReceipt {
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

#[derive(Default)]
struct PrepMailbox {
    pending: Option<StagedPrep>,
    active: Option<ActivePrep>,
    receipt: Option<BlockReceipt>,
    #[cfg(test)]
    parked_joins: usize,
    stopped: bool,
}

struct PrepShared {
    network: Network,
    coinbase_script: Vec<u8>,
    shutdown: bitcoin_rs_chain::LatchReader,
    mempool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    mailbox: parking_lot::Mutex<PrepMailbox>,
    wake: parking_lot::Condvar,
}

struct PrepWorker {
    shared: Arc<PrepShared>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PrepWorker {
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

struct ReadyPreparation {
    source_sequences: (u64, u64),
    expected_removals: Vec<(Txid, RemovalReason)>,
    candidate: Arc<Candidate>,
}

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
            shared.wake.notify_all();
            return Some(job);
        }
        shared.wake.wait_for(&mut mailbox, LONG_POLL_SLICE);
    }
}

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
        }
        shared.wake.notify_all();
    }
}

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
        staged_parent_mtp: chain.parent_median_time_past,
        network,
        csv_active: chain.csv_active,
        segwit_active: chain.segwit_active,
        max_weight: MAX_BLOCK_WEIGHT,
        max_size: MAX_BLOCK_SERIALIZED_SIZE,
        max_sigops: u64::from(MAX_BLOCK_SIGOPS_COST),
    })
}

fn last_candidate_info(candidate: &Candidate) -> LastCandidateInfo {
    LastCandidateInfo {
        weight: candidate.weight,
        transactions: u64::try_from(candidate.transactions.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    }
}

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

fn generation_race() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from(GENERATION_RACE))
}

fn assembly_busy() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from(ASSEMBLY_BUSY))
}

impl MiningControlError {
    #[must_use]
    pub fn is_template_generation_race(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(message) if message == GENERATION_RACE || message == ASSEMBLY_BUSY
        )
    }
}

#[must_use]
fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
    let (id, _budget) = CoinbaseBudget::split_qualifier(id)?;
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
