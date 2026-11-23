use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_chain::chain::TipSnapshot;
use bitcoin_rs_chain::chain::current_unix_seconds;
use bitcoin_rs_consensus::latch::HookGuard;
use bitcoin_rs_consensus::primitives::BlockImage;
use bitcoin_rs_consensus::primitives::CompactTarget;
use bitcoin_rs_consensus::primitives::Hash256;
use bitcoin_rs_consensus::primitives::Network;
use bitcoin_rs_consensus::primitives::Txid;
use bitcoin_rs_consensus::primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_consensus::script::VerifyFlags;
use bitcoin_rs_consensus::transaction_sigop_cost;
use bitcoin_rs_consensus::{MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT};
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mempool::MutationOutcome;
use bitcoin_rs_mempool::MutationResult;
use bitcoin_rs_mempool::RemovalReason;
use bitcoin_rs_mempool::SnapshotEntry;
use bitcoin_rs_wire::mining::{
    AppliedTipSource, AvailableMiningRule, BlockTemplate, Candidate, CandidateContext,
    ChainContextSource, CoinbaseBudget, CoinbaseReserve, GenerateSelection, GenerateTx,
    LastCandidateInfo, MempoolSnapshotSource, MiningCapability, MiningControlError, MiningInfo,
    MiningRule, SignetMiningInfo, TemplateId, TemplateMutation, assemble_ordered_candidate,
    difficulty_for_bits, finish_candidate,
};
use compact_str::CompactString;
use core::time::Duration;
use hashbrown::HashMap;
use parking_lot::Condvar;
use parking_lot::Mutex;

const CANDIDATE_CACHE_LIMIT: usize = 8;
const CANDIDATE_GENERATION_RETRIES: usize = 8;
const GENERATION_RACE: &str = "generation key changed during candidate assembly";
const ASSEMBLY_BUSY: &str = "budgeted candidate assembly is busy";
const LONG_POLL_SLICE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct GenerationKey {
    tip_hash: Hash256,
    commit_id: u64,
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

    #[must_use]
    fn matches_template(self, other: Self) -> bool {
        self.tip_hash == other.tip_hash
            && self.mempool_sequence == other.mempool_sequence
            && self.fee_delta_sequence == other.fee_delta_sequence
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
    #[cfg(any(test, feature = "test-seam"))]
    budgeted_waiters: usize,
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

pub struct MiningService {
    network: Network,
    coinbase_script: Vec<u8>,
    coinbase_reserve: CoinbaseReserve,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    applied_tip: Arc<dyn AppliedTipSource>,
    mempool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    state: Mutex<CoordinatorState>,
    wake: Arc<Condvar>,
    _wake_guard: HookGuard,
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
        coinbase_reserve: CoinbaseReserve,
        shutdown: bitcoin_rs_consensus::latch::LatchReader,
    ) -> Self {
        let seed = mempool.current_revisions().0;
        let wake = Arc::new(Condvar::new());
        let wake_hook = Arc::clone(&wake);
        let wake_guard = shutdown.on_cancel(move || {
            wake_hook.notify_all();
        });
        let shared = Arc::new(PrepShared {
            network,
            coinbase_script: coinbase_script.clone(),
            coinbase_reserve,
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
            coinbase_reserve,
            shutdown,
            state: Mutex::new(CoordinatorState {
                seed,
                ..CoordinatorState::default()
            }),
            wake,
            _wake_guard: wake_guard,
            prep: PrepWorker::spawn(shared),
        }
    }

    pub fn stage_tip(&self, tip: &TipSnapshot, block: &BlockImage) {
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
        let commit_id = self
            .applied_tip
            .applied_epoch()
            .map_or(0, |epoch| epoch.commit_id);
        let key = GenerationKey {
            tip_hash: self.live_tip_hash(),
            commit_id,
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

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn budgeted_waiters(&self) -> usize {
        self.state.lock().budgeted_waiters
    }

    fn live_tip_hash(&self) -> Hash256 {
        self.applied_tip
            .applied_tip()
            .map_or_else(|| self.network.genesis_block_hash(), |tip| tip.hash)
    }

    fn live_generation_key(&self) -> GenerationKey {
        let (tip_hash, epoch_commit) = self
            .applied_tip
            .applied_epoch()
            .map(|epoch| (epoch.tip.hash, epoch.commit_id))
            .unwrap_or_else(|| (self.live_tip_hash(), 0));
        let (settled_commit, mempool_sequence, fee_delta_sequence) =
            self.mempool.settled_generation();
        let commit_id = if epoch_commit != 0 {
            epoch_commit
        } else {
            settled_commit
        };
        GenerationKey {
            tip_hash,
            commit_id,
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
            if !live.matches_template(waited) {
                return Ok(live);
            }
            #[cfg(any(test, feature = "test-seam"))]
            {
                state.parked_long_poll_waiters += 1;
            }
            let _timed_out = self.wake.wait_for(&mut state, LONG_POLL_SLICE);
            #[cfg(any(test, feature = "test-seam"))]
            {
                state.parked_long_poll_waiters -= 1;
            }
        }
    }

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
            if live.matches_template(waited) {
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
        self.validate_candidate_for_key(key, &ready.candidate)?;
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

    fn await_flight(
        &self,
        key: GenerationKey,
        state: &mut parking_lot::MutexGuard<'_, CoordinatorState>,
    ) -> Result<Option<Arc<Candidate>>, MiningControlError> {
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
                return result.map(Some);
            }
            let _timed_out = self.wake.wait_for(state, LONG_POLL_SLICE);
        }
        Ok(None)
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
        if let Some(candidate) = self.await_flight(key, &mut state)? {
            return Ok(candidate);
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
        let epoch = self.applied_tip.applied_epoch().ok_or_else(|| {
            MiningControlError::Unavailable(CompactString::from("applied tip is not available"))
        })?;
        if epoch.tip.hash != generation.tip_hash {
            return Err(generation_race());
        }
        let (settled_commit, _mempool_seq, _fee_delta_seq) = self.mempool.settled_generation();
        if (generation.commit_id != 0
            && (epoch.commit_id != generation.commit_id || settled_commit != generation.commit_id))
            || (epoch.commit_id != 0 && settled_commit != 0 && epoch.commit_id != settled_commit)
        {
            return Err(generation_race());
        }
        let context = self.candidate_context(&epoch.tip)?;
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
        self.validate_candidate_for_key(generation, &candidate)?;
        Ok(Arc::new(candidate))
    }

    fn validate_candidate_for_key(
        &self,
        key: GenerationKey,
        candidate: &Candidate,
    ) -> Result<(), MiningControlError> {
        let validated = self.chain.validate_candidate(candidate);
        if self.live_generation_key() != key {
            return Err(generation_race());
        }
        validated
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
            #[cfg(any(test, feature = "test-seam"))]
            {
                state.budgeted_waiters += 1;
            }
            let _timed_out = self.wake.wait_for(&mut state, until - now);
            #[cfg(any(test, feature = "test-seam"))]
            {
                state.budgeted_waiters -= 1;
            }
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
        candidate_context_for(self.network, &self.chain, tip, self.coinbase_reserve)
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
        let candidate = match selection {
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
            GenerateSelection::Ordered(_) => {
                bitcoin_rs_wire::mining::ordered_assembly_error(&error)
            }
            GenerateSelection::Mempool => {
                MiningControlError::Failed(CompactString::from(error.to_string()))
            }
        })?;
        if matches!(selection, GenerateSelection::Mempool) {
            let validated = self.chain.validate_candidate(&candidate);
            if self
                .applied_tip
                .applied_tip()
                .is_none_or(|current| current.hash != tip.hash)
            {
                return Err(generation_race());
            }
            validated?;
        }
        Ok(candidate)
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
    block: Arc<BlockImage>,
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
    coinbase_reserve: CoinbaseReserve,
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
    mempool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    mailbox: parking_lot::Mutex<PrepMailbox>,
    wake: parking_lot::Condvar,
}

struct PrepWorker {
    shared: Arc<PrepShared>,
    handle: Option<std::thread::JoinHandle<()>>,
    _wake_guard: HookGuard,
}

impl PrepWorker {
    fn spawn(shared: Arc<PrepShared>) -> Self {
        let worker = Arc::clone(&shared);
        let weak_shared = Arc::downgrade(&shared);
        let wake_guard = shared.shutdown.on_cancel(move || {
            if let Some(shared) = weak_shared.upgrade() {
                shared.wake.notify_all();
            }
        });
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
        Self {
            shared,
            handle,
            _wake_guard: wake_guard,
        }
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
        let Ok(context) = candidate_context_for(
            shared.network,
            &shared.chain,
            &job.tip,
            shared.coinbase_reserve,
        ) else {
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
    coinbase_reserve: CoinbaseReserve,
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
        coinbase_reserve,
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
    full: Arc<MempoolMiningSnapshot>,
    selection: &GenerateSelection,
    prevouts: &[(OutPoint, TxOut)],
    segwit_active: bool,
) -> Result<Arc<MempoolMiningSnapshot>, MiningControlError> {
    match selection {
        GenerateSelection::Mempool => Ok(full),
        GenerateSelection::Ordered(items) => {
            ordered_snapshot(&full, items, prevouts, segwit_active).map(Arc::new)
        }
    }
}

fn ordered_snapshot(
    full: &MempoolMiningSnapshot,
    items: &[GenerateTx],
    prevouts: &[(OutPoint, TxOut)],
    segwit_active: bool,
) -> Result<MempoolMiningSnapshot, MiningControlError> {
    let flags = if segwit_active {
        VerifyFlags::P2SH.union(VerifyFlags::WITNESS)
    } else {
        VerifyFlags::P2SH
    };
    let prevouts: HashMap<_, _> = prevouts.iter().map(|(key, value)| (*key, value)).collect();
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
        commit_id: 0,
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
mod tests {
    use super::*;
    use bitcoin_rs_chain::chain::{ChainError, ChainTxCount, NodeId};
    use bitcoin_rs_consensus::header_rules::ChainWork;
    use bitcoin_rs_consensus::primitives::Amount;
    use bitcoin_rs_consensus::primitives::BlockImage;
    use bitcoin_rs_consensus::primitives::LockTime;
    use bitcoin_rs_consensus::primitives::Script;
    use bitcoin_rs_consensus::primitives::Tx;
    use bitcoin_rs_consensus::primitives::TxOut;
    use bitcoin_rs_mempool::Mempool;
    use bitcoin_rs_mempool::MempoolLimits;
    use bitcoin_rs_mempool::MutationChange;
    use bitcoin_rs_mempool::MutationOutcome;
    use bitcoin_rs_mempool::RemovalReason;
    use bitcoin_rs_wire::mining::{
        BlockTemplate, Candidate, MiningCapability, MiningChainContext, MiningRule,
        PreparedTemplateBody, SelectedBody, SelectedTx, TemplateId, select_template_body,
        select_template_body_after,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    use crate::test_support::TestError;

    type TestResult = Result<(), TestError>;

    mod coinbase_budget {
        use super::fee_revision::service_over;
        use super::*;
        use bitcoin_rs_consensus::primitives::{BlockImage, Sequence, TxIn, Witness};
        use bitcoin_rs_mempool::MempoolEntry;
        use bitcoin_rs_wire::mining::{MiningError, SelectedBody, assemble_candidate};
        use std::thread::JoinHandle;

        type TestResult<T = ()> = Result<T, TestError>;

        const HEAVY_SIGOPS: u32 = 72_155;

        const FITS: CoinbaseBudget = CoinbaseBudget {
            additional_size: 100,
            additional_sigops: 5,
        };
        const TIGHT: CoinbaseBudget = CoinbaseBudget {
            additional_size: 100,
            additional_sigops: 6,
        };

        fn tx(label: u8) -> Tx {
            Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Hash256::from_le_bytes(&[label; 32]).into(), 0),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: vec![0x51].into(),
                }],
            }
        }

        fn heavy_pool() -> TestResult<(Mempool, Txid, Txid)> {
            let mut pool = Mempool::new(MempoolLimits::default());
            let heavy = tx(1);
            let light = tx(2);
            let (heavy_id, light_id) = (heavy.txid(), light.txid());
            pool.insert_entry(MempoolEntry::new(
                Arc::new(heavy),
                100,
                10_000,
                1,
                0,
                HEAVY_SIGOPS,
            ))?;
            pool.insert_entry(MempoolEntry::new(Arc::new(light), 100, 10_000, 1, 0, 0))?;
            Ok((pool, heavy_id, light_id))
        }

        fn txids(candidate: &Candidate) -> Vec<Txid> {
            candidate.transactions.iter().map(|tx| tx.txid).collect()
        }

        fn block_sigops(candidate: &Candidate) -> u64 {
            u64::from(transaction_sigop_cost(
                &candidate.coinbase,
                &[],
                VerifyFlags::NONE,
            )) + candidate
                .transactions
                .iter()
                .map(|tx| u64::from(tx.sigop_cost))
                .sum::<u64>()
        }

        fn sorted(mut ids: Vec<Txid>) -> Vec<Txid> {
            ids.sort_unstable_by_key(|id| *id.as_bytes());
            ids
        }

        // API-11
        #[test]
        fn ordinary_service_reserves_coinbase_weight_and_sigops() -> TestResult {
            let mut pool = Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            });
            for label in 1..=5 {
                let transaction = tx(label);
                let vsize = u32::try_from(transaction.vsize())?;
                pool.insert_entry(MempoolEntry::new(
                    Arc::new(transaction),
                    vsize,
                    10_000,
                    0,
                    0,
                    16_000,
                ))?;
            }
            let (_, service) = service_over(pool)?;
            let candidate = service.get_block_template(None, None)?.candidate;
            assert_eq!(candidate.transactions.len(), 4);
            assert!(block_sigops(&candidate) + 400 <= 80_000);

            let mut pool = Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                ..MempoolLimits::default()
            });
            let mut reference_weight = 0;
            for label in 1..=50 {
                let mut transaction = tx(label);
                transaction.inputs[0].witness = vec![vec![0x42; 79_650]].into();
                let reference: bitcoin::Transaction = bitcoin::consensus::deserialize(
                    &bitcoin_rs_consensus::primitives::consensus_bytes(&transaction),
                )?;
                reference_weight = reference.weight().to_wu();
                let vsize = u32::try_from(transaction.vsize())?;
                pool.insert_entry(MempoolEntry::new(
                    Arc::new(transaction),
                    vsize,
                    100_000,
                    0,
                    0,
                    0,
                ))?;
            }
            let expected = usize::try_from((4_000_000 - 8_000) / reference_weight)?;
            assert_eq!(expected, 49);
            let (_, service) = service_over(pool)?;
            let candidate = service.get_block_template(None, None)?.candidate;
            assert_eq!(candidate.transactions.len(), expected);
            Ok(())
        }

        #[test]
        fn tight_budget_gets_a_fitting_selection_not_a_post_selection_refusal() -> TestResult {
            let (pool, heavy, light) = heavy_pool()?;
            let (source, service) = service_over(pool)?;
            let ordinary = service.get_block_template(None, None)?.candidate;
            assert_eq!(sorted(txids(&ordinary)), sorted(vec![heavy, light]));
            ordinary.admits(FITS)?;
            assert!(matches!(
                ordinary.admits(TIGHT),
                Err(MiningError::CapacityExhausted { field: "sigops" })
            ));

            let served = service.get_block_template(None, Some(TIGHT))?.candidate;
            served.admits(TIGHT)?;
            assert_eq!(txids(&served), vec![light]);
            assert!(
                block_sigops(&served) + u64::from(TIGHT.additional_sigops) <= served.max_sigops
            );
            let live = service.live_generation_key();
            assert_eq!(
                served.template_id,
                CandidateKey {
                    generation: live,
                    budget: Some(TIGHT)
                }
                .template_id()
            );
            assert_ne!(served.template_id, ordinary.template_id);
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 1);

            let again = service.get_block_template(None, Some(TIGHT))?.candidate;
            assert_eq!(again.template_id, served.template_id);
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 1);
            let other = CoinbaseBudget {
                additional_size: 100,
                additional_sigops: 7,
            };
            let other = service.get_block_template(None, Some(other))?.candidate;
            assert_ne!(other.template_id, served.template_id);
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 2);
            Ok(())
        }

        #[test]
        fn ordinary_request_is_never_served_a_budgeted_candidate_and_is_unchanged() -> TestResult {
            let (pool, heavy, light) = heavy_pool()?;
            let (source, service) = service_over(pool)?;
            let budgeted = service.get_block_template(None, Some(TIGHT))?.candidate;
            assert_eq!(txids(&budgeted), vec![light]);
            let reported = service
                .state
                .lock()
                .last_candidate
                .ok_or("a budgeted assembly must report the candidate it installed")?;
            assert_eq!(reported.weight, budgeted.weight);
            assert_eq!(
                reported.transactions,
                u64::try_from(budgeted.transactions.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1)
            );
            let info = service.mining_info(0.0, Vec::new(), None)?;
            assert_eq!(
                info.last_candidate.map(|known| known.weight),
                Some(budgeted.weight)
            );

            let stricter = CoinbaseBudget {
                additional_size: 100,
                additional_sigops: 7,
            };
            let restrained = service.get_block_template(None, Some(stricter))?.candidate;
            assert_ne!(restrained.template_id, budgeted.template_id);
            let reported = service
                .state
                .lock()
                .last_candidate
                .ok_or("a stricter budgeted assembly must replace the reported candidate")?;
            assert_eq!(reported.weight, restrained.weight);

            let ordinary = service.get_block_template(None, None)?.candidate;
            assert_ne!(ordinary.template_id, budgeted.template_id);
            assert_eq!(sorted(txids(&ordinary)), sorted(vec![heavy, light]));
            assert!(service.state.lock().last_candidate.is_some());
            let tip = source.tip.clone();
            let context = service.candidate_context(&tip)?;
            let expected = assemble_candidate(&context, &source.pool.lock(), &[0x51])?;
            assert_eq!(txids(&ordinary), txids(&expected));
            assert_eq!(ordinary.weight, expected.weight);
            assert_eq!(ordinary.coinbase_value, expected.coinbase_value);
            assert_eq!(ordinary.template_id, expected.template_id);
            Ok(())
        }

        #[test]
        fn budgeted_request_reuses_the_ordinary_candidate_when_it_admits_the_budget() -> TestResult
        {
            let (pool, _, _) = heavy_pool()?;
            let (source, service) = service_over(pool)?;
            let ordinary = service.get_block_template(None, None)?.candidate;
            let served = service.get_block_template(None, Some(FITS))?.candidate;
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 0);
            assert_eq!(served.template_id, ordinary.template_id);
            served.admits(FITS)?;
            assert_eq!(txids(&served), txids(&ordinary));
            Ok(())
        }

        #[test]
        fn publication_drops_every_budget_of_the_old_generation_and_the_cache_stays_bounded()
        -> TestResult {
            let (pool, _, _) = heavy_pool()?;
            let (source, service) = service_over(pool)?;
            let old = service.live_generation_key();
            let distinct = u16::try_from(CANDIDATE_CACHE_LIMIT)?.saturating_add(1);
            for extra in 0..distinct {
                let budget = CoinbaseBudget {
                    additional_size: 100,
                    additional_sigops: 6 + extra,
                };
                let candidate = service.get_block_template(None, Some(budget))?.candidate;
                candidate.admits(budget)?;
            }
            let walks = source.budgeted_walks.load(Ordering::SeqCst);
            assert_eq!(walks, usize::from(distinct));
            assert_eq!(service.state.lock().cache.len(), CANDIDATE_CACHE_LIMIT);
            let first = CoinbaseBudget {
                additional_size: 100,
                additional_sigops: 6,
            };
            service
                .get_block_template(None, Some(first))?
                .candidate
                .admits(first)?;
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), walks + 1);

            source.pool.lock().insert_entry(MempoolEntry::new(
                Arc::new(tx(3)),
                100,
                10_000,
                1,
                0,
                0,
            ))?;
            service.publish_generation();
            assert!(
                service
                    .state
                    .lock()
                    .cache
                    .keys()
                    .all(|key| key.generation != old)
            );
            let fresh = service.get_block_template(None, Some(TIGHT))?.candidate;
            assert_ne!(fresh.mempool_sequence, old.mempool_sequence);
            assert_eq!(
                fresh.mempool_sequence,
                service.live_generation_key().mempool_sequence
            );
            fresh.admits(TIGHT)?;
            Ok(())
        }

        #[test]
        fn unsatisfiable_budget_fails_typed_and_leaves_the_slot_free() -> TestResult {
            let tip = Hash256::from_le_bytes(&[0x72; 32]);
            let service = service_with_chain(
                Some(tip_snapshot(tip)),
                Arc::new(StaticPool::new(5, 2)),
                Arc::new(ResolvedChain),
            );
            let impossible = CoinbaseBudget {
                additional_size: u32::MAX,
                additional_sigops: 0,
            };
            let refused = service.get_block_template(None, Some(impossible));
            assert!(
                matches!(
                    &refused,
                    Err(MiningControlError::Failed(message))
                        if message.as_str() == "coinbase reservation exhausts the weight limit"
                ),
                "{refused:?}"
            );
            if let Err(error) = &refused {
                assert!(!error.is_template_generation_race());
            }
            let state = service.state.lock();
            assert!(state.budgeted.is_none());
            assert!(state.cache.is_empty());
            drop(state);
            service
                .get_block_template(None, None)?
                .candidate
                .admits(FITS)?;
            Ok(())
        }

        #[test]
        fn long_poll_accepts_a_budget_qualified_id_and_rejects_malformed_qualifiers() {
            let key = GenerationKey {
                tip_hash: Hash256::from_le_bytes(&[0x33; 32]),
                commit_id: 0,
                mempool_sequence: 9,
                fee_delta_sequence: 4,
            };
            let budget = CoinbaseBudget {
                additional_size: 1_000,
                additional_sigops: 7,
            };
            let qualified = CandidateKey {
                generation: key,
                budget: Some(budget),
            }
            .template_id();
            assert_eq!(parse_long_poll_id(qualified.as_str()), Some(key));
            assert_eq!(parse_long_poll_id(key.template_id().as_str()), Some(key));
            for malformed in [
                "@cb",
                "@cb1000",
                "@cb1000.",
                "@cb.7",
                "@cb01000.7",
                "@cb1000.07",
                "@cb+1000.7",
                "@cb1000.7x",
                "@cb4294967296.7",
                "@cb1000.65536",
                "@cb1000.7@cb1.1",
                "@xx1000.7",
            ] {
                let id = format!("{}{malformed}", key.template_id().as_str());
                assert!(parse_long_poll_id(&id).is_none(), "must reject {malformed}");
            }
        }

        #[test]
        fn budgeted_request_serves_an_installable_preparation_without_discarding_it() -> TestResult
        {
            let (pool, _, _) = heavy_pool()?;
            let (source, service) = service_over(pool)?;
            let tip = source.tip.clone();
            service.stage_tip(
                &tip,
                &BlockImage::from_local(Network::Regtest.genesis_block()),
            );
            wait_until_ready(&service, tip.hash);
            service.publish_block_generation(tip.hash, &MutationResult::empty());

            let served = service.get_block_template(None, Some(FITS))?.candidate;
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 0);
            assert_eq!(source.ordinary_walks.load(Ordering::SeqCst), 0);
            served.admits(FITS)?;
            assert_eq!(
                served.template_id,
                service.live_generation_key().template_id()
            );
            let ordinary = service.get_block_template(None, None)?.candidate;
            assert_eq!(ordinary.template_id, served.template_id);
            assert_eq!(source.ordinary_walks.load(Ordering::SeqCst), 0);
            Ok(())
        }

        #[test]
        fn budgeted_request_before_the_receipt_leaves_the_preparation_for_the_ordinary_caller()
        -> TestResult {
            let (pool, heavy, light) = heavy_pool()?;
            let (source, service) = service_over(pool)?;
            let tip = source.tip.clone();
            service.stage_tip(
                &tip,
                &BlockImage::from_local(Network::Regtest.genesis_block()),
            );
            wait_until_ready(&service, tip.hash);

            let served = service.get_block_template(None, Some(TIGHT))?.candidate;
            served.admits(TIGHT)?;
            assert_eq!(txids(&served), vec![light]);
            assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 1);
            let still_ready = service
                .prep
                .mailbox()
                .active
                .as_ref()
                .is_some_and(|active| {
                    active.target_tip == tip.hash
                        && matches!(active.progress, PrepProgress::Ready { .. })
                });
            assert!(
                still_ready,
                "the budgeted request must not touch the preparation"
            );

            service.publish_block_generation(tip.hash, &MutationResult::empty());
            let ordinary = service.get_block_template(None, None)?.candidate;
            assert_eq!(sorted(txids(&ordinary)), sorted(vec![heavy, light]));
            assert_eq!(source.ordinary_walks.load(Ordering::SeqCst), 0);
            assert!(service.prep.mailbox().active.is_none());
            Ok(())
        }

        struct BudgetGate {
            inner: StaticPool,
            budgeted_calls: AtomicUsize,
            ordinary_calls: AtomicUsize,
            hold: AtomicBool,
            entered: AtomicBool,
            release: AtomicBool,
            panic_next: AtomicBool,
        }

        impl BudgetGate {
            fn new(sequence: u64, fee_delta_sequence: u64) -> Self {
                Self {
                    inner: StaticPool::new(sequence, fee_delta_sequence),
                    budgeted_calls: AtomicUsize::new(0),
                    ordinary_calls: AtomicUsize::new(0),
                    hold: AtomicBool::new(false),
                    entered: AtomicBool::new(false),
                    release: AtomicBool::new(false),
                    panic_next: AtomicBool::new(false),
                }
            }

            fn park(&self) {
                if !self.hold.load(Ordering::SeqCst) {
                    return;
                }
                self.entered.store(true, Ordering::SeqCst);
                let deadline = Instant::now() + WAKE_PROOF_TIMEOUT * 3;
                while !self.release.load(Ordering::SeqCst) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }

            fn budgeted_calls(&self) -> usize {
                self.budgeted_calls.load(Ordering::SeqCst)
            }
        }

        impl MempoolSnapshotSource for BudgetGate {
            fn current_revisions(&self) -> (u64, u64) {
                self.inner.current_revisions()
            }

            fn settled_generation(&self) -> (u64, u64, u64) {
                self.inner.settled_generation()
            }

            fn select_template(
                &self,
                expected_sequences: Option<(u64, u64)>,
                context: &CandidateContext,
                payout: &[u8],
                budget: Option<CoinbaseBudget>,
            ) -> Result<Option<SelectedBody>, MiningControlError> {
                if budget.is_none() {
                    self.ordinary_calls.fetch_add(1, Ordering::SeqCst);
                    return self
                        .inner
                        .select_template(expected_sequences, context, payout, budget);
                }
                self.budgeted_calls.fetch_add(1, Ordering::SeqCst);
                assert!(
                    !self.panic_next.swap(false, Ordering::SeqCst),
                    "adversarial assembler panic inside the budgeted selection"
                );
                let selected =
                    self.inner
                        .select_template(expected_sequences, context, payout, budget);
                self.park();
                selected
            }

            fn select_template_after(
                &self,
                block: &BlockImage,
                context: &CandidateContext,
                payout: &[u8],
            ) -> Result<PreparedTemplateBody, MiningControlError> {
                self.inner.select_template_after(block, context, payout)
            }

            fn selection_snapshot(
                &self,
                selection: &GenerateSelection,
                context: &CandidateContext,
            ) -> Result<Arc<MempoolMiningSnapshot>, MiningControlError> {
                self.inner.selection_snapshot(selection, context)
            }

            fn pooled_transaction_count(&self) -> u64 {
                self.inner.pooled_transaction_count()
            }

            fn min_relay_fee_sat_per_kvb(&self) -> u64 {
                self.inner.min_relay_fee_sat_per_kvb()
            }
        }

        const BUDGET_A: CoinbaseBudget = CoinbaseBudget {
            additional_size: 100,
            additional_sigops: 6,
        };
        const BUDGET_B: CoinbaseBudget = CoinbaseBudget {
            additional_size: 200,
            additional_sigops: 6,
        };

        fn gated_service() -> (
            Arc<MiningService>,
            Arc<BudgetGate>,
            GenerationKey,
            bitcoin_rs_consensus::latch::LatchWriter,
        ) {
            let tip = Hash256::from_le_bytes(&[0x71; 32]);
            let pool = Arc::new(BudgetGate::new(5, 2));
            let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
            let service = Arc::new(service_with_source(
                Some(tip_snapshot(tip)),
                pool.clone(),
                Arc::new(ResolvedChain),
                shutdown.reader(),
            ));
            let generation = GenerationKey {
                tip_hash: tip,
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 2,
            };
            (service, pool, generation, shutdown)
        }

        fn spawn_budgeted(
            service: &Arc<MiningService>,
            generation: GenerationKey,
            budget: CoinbaseBudget,
        ) -> JoinHandle<Result<Arc<Candidate>, MiningControlError>> {
            let worker = Arc::clone(service);
            std::thread::spawn(move || worker.budgeted_candidate(generation, budget))
        }

        fn wait_until_held(pool: &BudgetGate) {
            let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
            while !pool.entered.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "no assembler reached the gated budgeted selection"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        #[test]
        fn budgeted_walks_are_serialized_and_a_blocked_caller_gives_up_after_one_slice()
        -> TestResult {
            let (service, pool, generation, _shutdown) = gated_service();
            pool.hold.store(true, Ordering::SeqCst);
            let holder = spawn_budgeted(&service, generation, BUDGET_A);
            wait_until_held(&pool);

            let started = Instant::now();
            let blocked = service.budgeted_candidate(generation, BUDGET_B);
            assert!(
                matches!(&blocked, Err(error) if error.is_template_generation_race()),
                "{blocked:?}"
            );
            assert!(started.elapsed() < WAKE_PROOF_TIMEOUT);
            assert_eq!(pool.budgeted_calls(), 1);

            let ordinary = service.candidate_for_key(generation)?;
            assert_eq!(ordinary.template_id, generation.template_id());
            assert_eq!(pool.ordinary_calls.load(Ordering::SeqCst), 1);
            assert!(service.state.lock().budgeted.is_some());

            pool.release.store(true, Ordering::SeqCst);
            let held = holder.join().map_err(|_| "the holder panicked")??;
            held.admits(BUDGET_A)?;
            assert_eq!(
                held.template_id,
                CandidateKey {
                    generation,
                    budget: Some(BUDGET_A)
                }
                .template_id()
            );
            assert!(service.state.lock().budgeted.is_none());

            let reused = service.budgeted_candidate(generation, BUDGET_B)?;
            assert_eq!(reused.template_id, generation.template_id());
            reused.admits(BUDGET_B)?;
            assert_eq!(pool.budgeted_calls(), 1);
            Ok(())
        }

        #[test]
        fn a_caller_behind_a_held_slot_ends_with_a_retryable_error_not_a_hang() -> TestResult {
            let (service, pool, generation, _shutdown) = gated_service();
            pool.hold.store(true, Ordering::SeqCst);
            let holder = spawn_budgeted(&service, generation, BUDGET_A);
            wait_until_held(&pool);

            let started = Instant::now();
            let outcome = service.live_candidate(Some(BUDGET_B));
            assert!(
                matches!(&outcome, Err(error) if error.is_template_generation_race()),
                "{outcome:?}"
            );
            assert!(started.elapsed() >= LONG_POLL_SLICE, "it must have waited");
            assert_eq!(
                pool.budgeted_calls(),
                1,
                "and it never walked beside the holder"
            );

            pool.release.store(true, Ordering::SeqCst);
            holder.join().map_err(|_| "the holder panicked")??;
            let served = service.live_candidate(Some(BUDGET_B))?;
            served.admits(BUDGET_B)?;
            Ok(())
        }

        #[test]
        fn same_budget_callers_share_one_walk() -> TestResult {
            let (service, pool, generation, _shutdown) = gated_service();
            pool.hold.store(true, Ordering::SeqCst);
            let holder = spawn_budgeted(&service, generation, BUDGET_A);
            wait_until_held(&pool);
            let joiner = spawn_budgeted(&service, generation, BUDGET_A);
            let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
            while service.budgeted_waiters() == 0 {
                assert!(
                    Instant::now() < deadline,
                    "the joiner never reached the occupied budget slot"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(pool.budgeted_calls(), 1, "a same-key caller must not walk");
            pool.release.store(true, Ordering::SeqCst);
            let first = holder.join().map_err(|_| "the holder panicked")??;
            let second = joiner.join().map_err(|_| "the joiner panicked")??;
            assert_eq!(first.template_id, second.template_id);
            assert_eq!(txids(&first), txids(&second));
            assert_eq!(pool.budgeted_calls(), 1);
            Ok(())
        }

        #[test]
        fn publication_neither_frees_the_slot_nor_lets_a_stale_install_through() -> TestResult {
            let (service, pool, generation, _shutdown) = gated_service();
            pool.hold.store(true, Ordering::SeqCst);
            let holder = spawn_budgeted(&service, generation, BUDGET_A);
            wait_until_held(&pool);

            pool.inner.set(6, 2);
            service.publish_generation();
            assert!(
                service.state.lock().budgeted.is_some(),
                "publication must not free the slot while its assembler runs"
            );
            let next = GenerationKey {
                mempool_sequence: 6,
                ..generation
            };
            let blocked = service.budgeted_candidate(next, BUDGET_A);
            assert!(
                matches!(&blocked, Err(error) if error.is_template_generation_race()),
                "{blocked:?}"
            );
            assert_eq!(
                pool.budgeted_calls(),
                1,
                "no second walk while the slot is held"
            );

            pool.release.store(true, Ordering::SeqCst);
            let stale = holder.join().map_err(|_| "the holder panicked")?;
            assert!(
                matches!(&stale, Err(error) if error.is_template_generation_race()),
                "the stale assembly must be refused: {stale:?}"
            );
            {
                let state = service.state.lock();
                assert!(
                    state.budgeted.is_none(),
                    "the assembler's guard releases the slot"
                );
                assert!(
                    state.cache.keys().all(|key| key.generation != generation),
                    "a stale install must not populate the cache"
                );
            }

            let fresh = service.live_candidate(Some(BUDGET_A))?;
            assert_eq!(fresh.mempool_sequence, 6);
            fresh.admits(BUDGET_A)?;
            assert_eq!(pool.budgeted_calls(), 2);
            Ok(())
        }

        #[test]
        fn shutdown_ends_a_budgeted_wait() -> TestResult {
            let (service, pool, generation, shutdown) = gated_service();
            pool.hold.store(true, Ordering::SeqCst);
            let holder = spawn_budgeted(&service, generation, BUDGET_A);
            wait_until_held(&pool);
            let waiter = spawn_budgeted(&service, generation, BUDGET_B);
            std::thread::sleep(Duration::from_millis(50));
            shutdown.trigger();
            let outcome = waiter.join().map_err(|_| "the waiter panicked")?;
            assert!(
                matches!(&outcome, Err(MiningControlError::Unavailable(_))),
                "{outcome:?}"
            );
            assert_eq!(pool.budgeted_calls(), 1);
            pool.release.store(true, Ordering::SeqCst);
            holder.join().map_err(|_| "the holder panicked")??;
            assert!(service.state.lock().budgeted.is_none());
            Ok(())
        }

        #[test]
        fn a_panicking_assembler_releases_the_slot() -> TestResult {
            let (service, pool, generation, _shutdown) = gated_service();
            pool.panic_next.store(true, Ordering::SeqCst);
            let crashed = spawn_budgeted(&service, generation, BUDGET_A).join();
            assert!(crashed.is_err(), "the armed selection must unwind");
            assert!(
                service.state.lock().budgeted.is_none(),
                "unwinding must release the slot"
            );
            let served = service.budgeted_candidate(generation, BUDGET_A)?;
            served.admits(BUDGET_A)?;
            assert_eq!(pool.budgeted_calls(), 2);
            Ok(())
        }
    }
    mod fee_revision {
        use super::*;
        use bitcoin_rs_chain::chain::{BlockTree, ChainError, ChainTxCount, NodeStatus};
        use bitcoin_rs_consensus::latch::LatchReader;
        use bitcoin_rs_consensus::primitives::{BlockImage, Sequence, TxIn, Txid, Witness};
        use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
        use bitcoin_rs_wire::mining::{
            MiningChainContext, SelectedBody, select_template_body, select_template_body_after,
        };
        use compact_str::CompactString;
        use std::sync::atomic::AtomicUsize;
        use std::sync::mpsc::{Sender, channel};
        use std::thread;

        type TestResult<T = ()> = Result<T, TestError>;

        pub(super) struct Sources {
            tree: BlockTree,
            pub(super) tip: TipSnapshot,
            pub(super) pool: Mutex<Mempool>,
            wait_probe: Mutex<Option<(usize, Sender<()>)>>,
            pub(super) ordinary_walks: AtomicUsize,
            pub(super) budgeted_walks: AtomicUsize,
        }

        impl AppliedTipSource for Sources {
            fn applied_tip(&self) -> Option<TipSnapshot> {
                Some(self.tip.clone())
            }
        }

        impl ChainContextSource for Sources {
            fn validate_candidate(&self, _candidate: &Candidate) -> Result<(), MiningControlError> {
                Ok(())
            }

            fn resolve_mining_context(
                &self,
                tip: &TipSnapshot,
                time: u32,
            ) -> Result<MiningChainContext, ChainError> {
                MiningChainContext::resolve(&self.tree, Network::Regtest, tip.tip_id, time)
            }
            fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
                Ok(self.tree.node(tip.tip_id)?.header.bits)
            }
            fn signalling_rules(&self, _: &TipSnapshot, _: u32) -> Vec<AvailableMiningRule> {
                Vec::new()
            }
        }

        impl MempoolSnapshotSource for Sources {
            fn current_revisions(&self) -> (u64, u64) {
                let mut probe = self.wait_probe.lock();
                if let Some((remaining, signal)) = probe.as_mut() {
                    *remaining -= 1;
                    if *remaining == 0 {
                        let _ = signal.send(());
                        *probe = None;
                    }
                }
                let pool = self.pool.lock();
                (pool.sequence_number(), pool.fee_delta_sequence_number())
            }
            fn select_template(
                &self,
                expected_sequences: Option<(u64, u64)>,
                context: &CandidateContext,
                payout: &[u8],
                budget: Option<CoinbaseBudget>,
            ) -> Result<Option<SelectedBody>, MiningControlError> {
                let pool = self.pool.lock();
                if expected_sequences.is_some_and(|(sequence, fee_revision)| {
                    pool.sequence_number() != sequence
                        || pool.fee_delta_sequence_number() != fee_revision
                }) {
                    return Ok(None);
                }
                let walks = if budget.is_some() {
                    &self.budgeted_walks
                } else {
                    &self.ordinary_walks
                };
                walks.fetch_add(1, Ordering::SeqCst);
                select_template_body(&pool, context, payout, budget)
                    .map(Some)
                    .map_err(|error| {
                        MiningControlError::Failed(CompactString::from(error.to_string()))
                    })
            }
            fn select_template_after(
                &self,
                block: &BlockImage,
                context: &CandidateContext,
                payout: &[u8],
            ) -> Result<PreparedTemplateBody, MiningControlError> {
                let pool = self.pool.lock();
                let source_sequences = (pool.sequence_number(), pool.fee_delta_sequence_number());
                let plan = pool
                    .plan_block_removals(&bitcoin_rs_mempool::TransitionFacts::from_block(block));
                let body =
                    select_template_body_after(&pool, &plan, context, payout).map_err(|error| {
                        MiningControlError::Failed(CompactString::from(error.to_string()))
                    })?;
                let removals = plan
                    .removals
                    .iter()
                    .filter_map(|(id, reason)| pool.entry(*id).map(|entry| (entry.txid, *reason)))
                    .collect();
                Ok(PreparedTemplateBody {
                    body,
                    source_sequences,
                    removals,
                })
            }
            fn selection_snapshot(
                &self,
                selection: &GenerateSelection,
                context: &CandidateContext,
            ) -> Result<Arc<MempoolMiningSnapshot>, MiningControlError> {
                snapshot_for_selection(
                    self.pool.lock().mining_snapshot(),
                    selection,
                    &[],
                    context.segwit_active,
                )
            }
            fn pooled_transaction_count(&self) -> u64 {
                u64::try_from(self.pool.lock().len()).unwrap_or(u64::MAX)
            }
            fn min_relay_fee_sat_per_kvb(&self) -> u64 {
                self.pool.lock().min_relay_fee_sat_per_kvb()
            }
        }

        pub(super) fn service_over(
            pool: Mempool,
        ) -> TestResult<(Arc<Sources>, Arc<MiningService>)> {
            let mut tree = BlockTree::new();
            let genesis = Network::Regtest.genesis_block();
            let tip_id = tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
            let node = tree.node(tip_id)?;
            let tip = TipSnapshot {
                tip_id,
                height: node.height,
                hash: node.hash,
                chainwork: node.chainwork,
                chain_tx_count: ChainTxCount::established(1),
            };
            let source = Arc::new(Sources {
                tree,
                tip,
                pool: Mutex::new(pool),
                wait_probe: Mutex::new(None),
                ordinary_walks: AtomicUsize::new(0),
                budgeted_walks: AtomicUsize::new(0),
            });
            let service = Arc::new(MiningService::new(
                Network::Regtest,
                source.clone(),
                source.clone(),
                source.clone(),
                vec![0x51],
                CoinbaseReserve::default(),
                LatchReader::fixture_never(),
            ));
            Ok((source, service))
        }

        fn fixture() -> TestResult<(Arc<Sources>, Arc<MiningService>, Txid)> {
            let mut pool = Mempool::new(MempoolLimits::default());
            let mut low = Txid::default();
            for (label, fee) in [(1_u8, 1_000), (2, 10_000)] {
                let tx = Arc::new(Tx {
                    version: 2,
                    lock_time: LockTime::ZERO,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(
                            Hash256::from_le_bytes(&[label; 32]).into(),
                            0,
                        ),
                        script_sig: Script::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    outputs: vec![TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: vec![0x51].into(),
                    }],
                });
                if label == 1 {
                    low = tx.txid();
                }
                pool.insert_entry(MempoolEntry::new(tx, 100, fee, 1, 0, 0))?;
            }
            let (source, service) = service_over(pool)?;
            Ok((source, service, low))
        }

        #[test]
        fn prioritisation_rebuilds_cached_order_and_wakes_a_waiting_long_poll() -> TestResult {
            let (source, service, low) = fixture()?;
            let first = service.get_block_template(None, None)?.candidate;
            assert_ne!(first.transactions[0].txid, low);
            assert!(Arc::ptr_eq(
                &first,
                &service.get_block_template(None, None)?.candidate
            ));
            let original = source.current_revisions();
            let legacy_id = TemplateId::new(&source.tip.hash, original.0);
            assert_eq!(first.template_id, legacy_id);

            let (entered_tx, entered_rx) = channel();
            *source.wait_probe.lock() = Some((2, entered_tx));
            let (done_tx, done_rx) = channel();
            let waiting = Arc::clone(&service);
            let poll = thread::spawn(move || {
                let _ = done_tx.send(waiting.get_block_template(Some(legacy_id.as_str()), None));
            });
            entered_rx.recv_timeout(Duration::from_secs(2))?;
            drop(service.state.lock());
            assert!(done_rx.try_recv().is_err());
            source.pool.lock().prioritise(low, 100_000)?;
            assert_eq!(source.current_revisions(), (original.0, original.1 + 1));
            service.publish_generation();
            let next = done_rx.recv_timeout(Duration::from_millis(500))??.candidate;
            poll.join().map_err(|_| "long-poll worker panicked")?;
            assert_eq!(next.transactions[0].txid, low);
            assert_ne!(next.template_id, first.template_id);
            assert!(!Arc::ptr_eq(&first, &next));
            assert!(Arc::ptr_eq(
                &next,
                &service.get_block_template(None, None)?.candidate
            ));
            Ok(())
        }

        #[test]
        fn stale_fee_snapshot_cannot_populate_the_candidate_cache() -> TestResult {
            let (source, service, low) = fixture()?;
            let stale = service.live_generation_key();
            source.pool.lock().prioritise(low, 100_000)?;
            assert!(matches!(
                service.candidate_for_key(stale),
                Err(MiningControlError::Unavailable(_))
            ));
            assert!(
                service
                    .state
                    .lock()
                    .cache_get(&CandidateKey::ordinary(stale))
                    .is_none()
            );
            let full = source.pool.lock().mining_snapshot();
            let ordered = snapshot_for_selection(
                full.clone(),
                &GenerateSelection::Ordered(Vec::new()),
                &[],
                true,
            )?;
            assert_eq!(
                (ordered.sequence, ordered.fee_delta_sequence),
                (full.sequence, full.fee_delta_sequence)
            );
            assert_eq!(
                service
                    .get_block_template(None, None)?
                    .candidate
                    .transactions[0]
                    .txid,
                low
            );
            Ok(())
        }
    }

    fn sample_candidate(
        previous: Hash256,
        sequence: u64,
        fee_delta_sequence: u64,
        csv_active: bool,
        segwit_active: bool,
    ) -> Candidate {
        Candidate {
            template_id: TemplateId::with_fee_revision(&previous, sequence, fee_delta_sequence),
            previous_block_hash: previous,
            height: 1,
            version: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1,
            current_time: 1,
            csv_active,
            segwit_active,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
            mempool_sequence: sequence,
            coinbase: Tx {
                version: 2,
                lock_time: LockTime::ZERO,
                inputs: Vec::new(),
                outputs: vec![TxOut {
                    value: Amount::from_sat(50),
                    script_pubkey: Script::new(),
                }],
            },
            coinbase_value: 50,
            weight: 800,
            transactions: Vec::new(),
            witness_commitment: None,
        }
    }

    fn rule_names(template: &BlockTemplate) -> Vec<&str> {
        template.rules.iter().map(MiningRule::as_str).collect()
    }

    #[test]
    fn candidate_cache_evicts_the_oldest_entry_at_the_bound() {
        let mut state = CoordinatorState::default();
        let mut first_key = None;
        for seq in 0..=CANDIDATE_CACHE_LIMIT {
            let seq = u64::try_from(seq).unwrap_or(u64::MAX);
            let hash = Hash256::from_le_bytes(&[u8::try_from(seq).unwrap_or(0xff); 32]);
            let candidate = sample_candidate(hash, seq, seq, false, false);
            let key = CandidateKey::ordinary(GenerationKey {
                tip_hash: hash,
                commit_id: 0,
                mempool_sequence: seq,
                fee_delta_sequence: seq,
            });
            if seq == 0 {
                first_key = Some(key);
            }
            state.cache_insert(key, Arc::new(candidate));
        }
        assert_eq!(state.cache.len(), CANDIDATE_CACHE_LIMIT);
        assert!(
            !state
                .cache
                .contains_key(first_key.as_ref().unwrap_or_else(|| panic!("first key"))),
            "oldest cached candidate must be evicted at the bound"
        );
    }

    // API-11
    #[test]
    fn template_projects_candidate_generation_and_deployment_flags() {
        let cases = [
            (
                Network::Regtest,
                0x11,
                Some(true),
                false,
                true,
                vec!["segwit", "taproot"],
            ),
            (
                Network::Regtest,
                0x22,
                Some(false),
                true,
                false,
                vec!["csv", "taproot"],
            ),
            (Network::Regtest, 0x33, None, false, false, vec!["taproot"]),
            (
                Network::Regtest,
                0x33,
                None,
                true,
                false,
                vec!["csv", "taproot"],
            ),
            (
                Network::Regtest,
                0x33,
                None,
                false,
                true,
                vec!["segwit", "taproot"],
            ),
            (
                Network::Regtest,
                0x33,
                None,
                true,
                true,
                vec!["segwit", "csv", "taproot"],
            ),
            (
                Network::Signet,
                0x44,
                None,
                true,
                true,
                vec!["segwit", "csv", "taproot", "signet"],
            ),
        ];
        let mut generations: Vec<(Hash256, TemplateId)> = Vec::new();
        for (network, label, submit_old, csv_active, segwit_active, expected) in cases {
            let prev = Hash256::from_le_bytes(&[label; 32]);
            let candidate = sample_candidate(prev, 1, 1, csv_active, segwit_active);
            let expected_id = candidate.template_id.clone();
            let template =
                template_from_candidate(network, Arc::new(candidate), submit_old, Vec::new());
            assert_eq!(template.candidate.previous_block_hash, prev);
            assert_eq!(template.candidate.csv_active, csv_active);
            assert_eq!(template.candidate.segwit_active, segwit_active);
            assert_eq!(template.submit_old, submit_old);
            assert_eq!(rule_names(&template), expected);
            assert_eq!(template.candidate.template_id, expected_id);
            for (other_prev, other_id) in &generations {
                assert_eq!(
                    prev == *other_prev,
                    template.candidate.template_id == *other_id
                );
            }
            generations.push((prev, template.candidate.template_id.clone()));
            assert_eq!(
                template
                    .capabilities
                    .iter()
                    .map(MiningCapability::as_str)
                    .collect::<Vec<_>>(),
                vec!["proposal", "longpoll"]
            );
            let challenge = template.signet.map(|signet| signet.challenge);
            assert_eq!(
                challenge.as_deref(),
                network.signet_challenge(),
                "the template carries the network's one signet challenge, and only signet has it"
            );
        }
    }

    // API-11
    #[test]
    fn long_poll_round_trips_template_id() {
        let tip = Hash256::from_le_bytes(&[0x11; 32]);
        let key = GenerationKey {
            tip_hash: tip,
            commit_id: 0,
            mempool_sequence: 7,
            fee_delta_sequence: 0,
        };
        let id = key.template_id();
        let Some(parsed) = parse_long_poll_id(id.as_str()) else {
            panic!("generated long-poll id did not parse");
        };
        assert_eq!(parsed, key);
        assert_eq!(TemplateId::new(&tip, 7).as_str(), id.as_str());
        for revision in [1, 12, u64::MAX] {
            let key = GenerationKey {
                fee_delta_sequence: revision,
                ..key
            };
            assert_eq!(parse_long_poll_id(key.template_id().as_str()), Some(key));
        }
        for suffix in [
            "7:",
            "7:1:2",
            "7:no",
            "18446744073709551616",
            "7:18446744073709551616",
        ] {
            assert!(parse_long_poll_id(&format!("{}{suffix}", tip.to_string_be())).is_none());
        }
    }

    #[test]
    fn long_poll_rejects_non_ascii_split_boundary_without_panicking() {
        let malformed = format!("{}é:1", "0".repeat(63));
        assert_eq!(malformed.len(), 67);
        assert!(parse_long_poll_id(&malformed).is_none());
    }

    #[test]
    fn long_poll_rejects_malformed_components_without_panicking() {
        let tip_hex = Hash256::from_le_bytes(&[0x34; 32]).to_string_be();
        let cases = [
            format!("{tip_hex}:9"),
            format!("{tip_hex}x:9"),
            format!("{tip_hex}-7:9"),
            format!("{}.:9", "a".repeat(63)),
        ];
        for case in &cases {
            assert!(parse_long_poll_id(case).is_none(), "must reject {case}");
        }
    }

    #[test]
    fn template_generation_race_classification_excludes_other_failures() {
        assert!(generation_race().is_template_generation_race());
        assert!(assembly_busy().is_template_generation_race());
        for error in [
            MiningControlError::Unavailable("node is shutting down".into()),
            MiningControlError::Unavailable("applied tip is not available".into()),
            MiningControlError::InvalidRequest(GENERATION_RACE.into()),
            MiningControlError::Failed(GENERATION_RACE.into()),
            MiningControlError::Rejected(GENERATION_RACE.into()),
            MiningControlError::InvalidRequest(ASSEMBLY_BUSY.into()),
            MiningControlError::Failed(ASSEMBLY_BUSY.into()),
            MiningControlError::Rejected(ASSEMBLY_BUSY.into()),
        ] {
            assert!(!error.is_template_generation_race(), "{error:?}");
        }
    }

    struct StaticTip {
        tip: Mutex<Option<TipSnapshot>>,
        commit: Mutex<u64>,
    }

    impl StaticTip {
        fn new(tip: Option<TipSnapshot>) -> Self {
            Self {
                tip: Mutex::new(tip),
                commit: Mutex::new(0),
            }
        }

        fn set(&self, tip: Option<TipSnapshot>) {
            *self.tip.lock() = tip;
        }

        fn set_epoch(&self, tip: Option<TipSnapshot>, commit: u64) {
            *self.tip.lock() = tip;
            *self.commit.lock() = commit;
        }
    }

    impl AppliedTipSource for StaticTip {
        fn applied_tip(&self) -> Option<TipSnapshot> {
            self.tip.lock().clone()
        }

        fn applied_epoch(&self) -> Option<bitcoin_rs_chain::chain::AppliedEpoch> {
            self.applied_tip()
                .map(|tip| bitcoin_rs_chain::chain::AppliedEpoch::new(tip, *self.commit.lock()))
        }
    }

    struct StaticPool {
        counters: Mutex<(u64, u64)>,
        pool_reads: AtomicUsize,
        settled_commit: Mutex<u64>,
        gated: Mutex<bool>,
    }

    fn gated_tx() -> Arc<Tx> {
        Arc::new(Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::new(),
            }],
        })
    }

    impl StaticPool {
        fn new(sequence: u64, fee_delta_sequence: u64) -> Self {
            Self {
                counters: Mutex::new((sequence, fee_delta_sequence)),
                pool_reads: AtomicUsize::new(0),
                settled_commit: Mutex::new(0),
                gated: Mutex::new(false),
            }
        }

        fn set(&self, sequence: u64, fee_delta_sequence: u64) {
            *self.counters.lock() = (sequence, fee_delta_sequence);
        }

        fn set_settled_commit(&self, commit: u64) {
            *self.settled_commit.lock() = commit;
        }

        fn admit_gated(&self) {
            *self.gated.lock() = true;
        }
    }

    impl MempoolSnapshotSource for StaticPool {
        fn current_revisions(&self) -> (u64, u64) {
            self.pool_reads.fetch_add(1, Ordering::Relaxed);
            *self.counters.lock()
        }
        fn settled_generation(&self) -> (u64, u64, u64) {
            let (seq, fee) = self.current_revisions();
            (*self.settled_commit.lock(), seq, fee)
        }

        fn select_template(
            &self,
            expected_sequences: Option<(u64, u64)>,
            context: &CandidateContext,
            payout: &[u8],
            budget: Option<CoinbaseBudget>,
        ) -> Result<Option<SelectedBody>, MiningControlError> {
            self.pool_reads.fetch_add(1, Ordering::Relaxed);
            let (sequence, fee_delta_sequence) = *self.counters.lock();
            if expected_sequences.is_some_and(|(expected_sequence, expected_fee_delta_sequence)| {
                sequence != expected_sequence || fee_delta_sequence != expected_fee_delta_sequence
            }) {
                return Ok(None);
            }
            let fixture = Mempool::new(MempoolLimits::default());
            let mut body =
                select_template_body(&fixture, context, payout, budget).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
            body.sequence = sequence;
            body.fee_delta_sequence = fee_delta_sequence;
            if *self.gated.lock() {
                let tx = gated_tx();
                let weight = tx.weight();
                let fee = 1_000;
                body.transactions.push(SelectedTx {
                    txid: tx.txid(),
                    wtxid: tx.wtxid(),
                    fee,
                    sigop_cost: 0,
                    weight,
                    tx,
                });
                body.fees = body.fees.saturating_add(fee);
                body.weight = body.weight.saturating_add(weight);
            }
            Ok(Some(body))
        }

        fn select_template_after(
            &self,
            block: &BlockImage,
            context: &CandidateContext,
            payout: &[u8],
        ) -> Result<PreparedTemplateBody, MiningControlError> {
            self.pool_reads.fetch_add(1, Ordering::Relaxed);
            let source_sequences = *self.counters.lock();
            let fixture = Mempool::new(MempoolLimits::default());
            let plan = fixture
                .plan_block_removals(&bitcoin_rs_mempool::TransitionFacts::from_block(block));
            assert!(
                plan.removals.is_empty(),
                "the fixture pool holds nothing to project"
            );
            let mut body =
                select_template_body_after(&fixture, &plan, context, payout).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
            body.sequence = source_sequences.0;
            body.fee_delta_sequence = source_sequences.1;
            Ok(PreparedTemplateBody {
                body,
                source_sequences,
                removals: Vec::new(),
            })
        }

        fn selection_snapshot(
            &self,
            _selection: &GenerateSelection,
            _context: &CandidateContext,
        ) -> Result<Arc<MempoolMiningSnapshot>, MiningControlError> {
            let (sequence, fee_delta_sequence) = *self.counters.lock();
            Ok(Arc::new(MempoolMiningSnapshot {
                sequence,
                fee_delta_sequence,
                entries: Vec::new(),
            }))
        }

        fn pooled_transaction_count(&self) -> u64 {
            0
        }

        fn min_relay_fee_sat_per_kvb(&self) -> u64 {
            1_000
        }
    }

    struct UnresolvedChain;

    impl ChainContextSource for UnresolvedChain {
        fn validate_candidate(&self, _candidate: &Candidate) -> Result<(), MiningControlError> {
            Ok(())
        }

        fn resolve_mining_context(
            &self,
            _tip: &TipSnapshot,
            _candidate_time: u32,
        ) -> Result<MiningChainContext, ChainError> {
            Err(ChainError::UnknownNode { id: NodeId::new(0) })
        }

        fn tip_bits(&self, _tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
            Err(ChainError::UnknownNode { id: NodeId::new(0) })
        }

        fn signalling_rules(&self, _tip: &TipSnapshot, _height: u32) -> Vec<AvailableMiningRule> {
            Vec::new()
        }
    }

    fn tip_snapshot(hash: Hash256) -> TipSnapshot {
        TipSnapshot {
            tip_id: NodeId::new(0),
            height: 1,
            chainwork: ChainWork::from(1_u64),
            hash,
            chain_tx_count: ChainTxCount::established(1),
        }
    }

    struct ResolvedChain;

    impl ChainContextSource for ResolvedChain {
        fn validate_candidate(&self, _candidate: &Candidate) -> Result<(), MiningControlError> {
            Ok(())
        }

        fn resolve_mining_context(
            &self,
            tip: &TipSnapshot,
            _candidate_time: u32,
        ) -> Result<MiningChainContext, ChainError> {
            Ok(MiningChainContext {
                previous_block_hash: tip.hash,
                height: tip.height.saturating_add(1),
                version: 0x2000_0000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                min_time: 1,
                prev_median_time_past: 0,
                parent_median_time_past: 0,
                csv_active: false,
                segwit_active: false,
            })
        }

        fn tip_bits(&self, _tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
            Ok(CompactTarget::from_consensus(0x207f_ffff))
        }

        fn signalling_rules(&self, _tip: &TipSnapshot, _height: u32) -> Vec<AvailableMiningRule> {
            Vec::new()
        }
    }

    struct ValidationChain<F>(F);

    impl<F> ChainContextSource for ValidationChain<F>
    where
        F: Fn(&Candidate) -> Result<(), MiningControlError> + Send + Sync,
    {
        fn validate_candidate(&self, candidate: &Candidate) -> Result<(), MiningControlError> {
            (self.0)(candidate)
        }

        fn resolve_mining_context(
            &self,
            tip: &TipSnapshot,
            candidate_time: u32,
        ) -> Result<MiningChainContext, ChainError> {
            ResolvedChain.resolve_mining_context(tip, candidate_time)
        }

        fn tip_bits(&self, tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
            ResolvedChain.tip_bits(tip)
        }

        fn signalling_rules(&self, tip: &TipSnapshot, height: u32) -> Vec<AvailableMiningRule> {
            ResolvedChain.signalling_rules(tip, height)
        }
    }

    fn service_with(tip: Option<TipSnapshot>, pool: Arc<StaticPool>) -> MiningService {
        service_with_chain(tip, pool, Arc::new(UnresolvedChain))
    }

    fn service_with_chain(
        tip: Option<TipSnapshot>,
        pool: Arc<StaticPool>,
        chain: Arc<dyn ChainContextSource>,
    ) -> MiningService {
        service_with_source(
            tip,
            pool,
            chain,
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        )
    }

    fn service_with_source(
        tip: Option<TipSnapshot>,
        pool: Arc<dyn MempoolSnapshotSource>,
        chain: Arc<dyn ChainContextSource>,
        shutdown: bitcoin_rs_consensus::latch::LatchReader,
    ) -> MiningService {
        MiningService::new(
            Network::Regtest,
            Arc::new(StaticTip::new(tip)),
            pool,
            chain,
            Vec::new(),
            CoinbaseReserve::default(),
            shutdown,
        )
    }

    const WAKE_PROOF_TIMEOUT: Duration = Duration::from_secs(10);

    #[test]
    fn publish_fee_delta_generation_wakes_a_registered_waiter() {
        let tip = Hash256::from_le_bytes(&[0x27; 32]);
        let service = Arc::new(service_with(
            Some(tip_snapshot(tip)),
            Arc::new(StaticPool::new(5, 2)),
        ));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (result_tx, result_rx) = std::sync::mpsc::channel::<Option<GenerationKey>>();
        let stop = Arc::new(AtomicBool::new(false));
        let waiter = {
            let service = Arc::clone(&service);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut state = service.state.lock();
                let waited = state.published;
                let _ = ready_tx.send(());
                loop {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if state.published != waited {
                        let _ = result_tx.send(state.published);
                        return;
                    }
                    service.wake.wait(&mut state);
                }
            })
        };
        assert!(
            ready_rx.recv().is_ok(),
            "waiter exited before signalling readiness"
        );
        service.publish_fee_delta_generation(9);
        let Ok(published) = result_rx.recv_timeout(WAKE_PROOF_TIMEOUT) else {
            {
                let _guard = service.state.lock();
                stop.store(true, Ordering::SeqCst);
                service.wake.notify_all();
            }
            let _ = waiter.join();
            panic!("publish_fee_delta_generation did not wake a registered waiter");
        };
        assert_eq!(
            published,
            Some(GenerationKey {
                tip_hash: tip,
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 9,
            })
        );
        assert!(waiter.join().is_ok(), "waiter thread panicked");
    }

    #[test]
    fn publish_fee_delta_generation_drops_a_stale_fee_revision() {
        let tip = Hash256::from_le_bytes(&[0x27; 32]);
        let service = service_with(Some(tip_snapshot(tip)), Arc::new(StaticPool::new(5, 2)));
        let newer = GenerationKey {
            tip_hash: tip,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        };
        service.publish_fee_delta_generation(9);
        assert_eq!(service.state.lock().published, Some(newer));
        service.state.lock().cache_insert(
            CandidateKey::ordinary(newer),
            Arc::new(sample_candidate(tip, 5, 9, false, false)),
        );
        service.publish_fee_delta_generation(4);
        assert_eq!(
            service.state.lock().published,
            Some(newer),
            "a stale fee revision must not regress the published key"
        );
        assert!(
            service
                .state
                .lock()
                .cache_get(&CandidateKey::ordinary(newer))
                .is_some(),
            "a stale fee revision must not invalidate the newer candidate"
        );
    }

    #[test]
    fn sequence_based_publications_do_not_read_the_pool() {
        let tip = Hash256::from_le_bytes(&[0x26; 32]);
        let pool = Arc::new(StaticPool::new(5, 2));
        let service = service_with(Some(tip_snapshot(tip)), Arc::clone(&pool));
        assert_eq!(pool.pool_reads.load(Ordering::Relaxed), 1);
        service.publish_generation_from(6);
        service.publish_fee_delta_generation(9);
        assert_eq!(
            pool.pool_reads.load(Ordering::Relaxed),
            1,
            "sequence-based publishers must compose their keys from retained state"
        );
    }

    fn published_key(service: &MiningService) -> Option<GenerationKey> {
        service.state.lock().published
    }

    #[test]
    fn fee_publication_preserves_the_published_membership_sequence() {
        let tip = Hash256::from_le_bytes(&[0x22; 32]);
        let service = service_with(Some(tip_snapshot(tip)), Arc::new(StaticPool::new(5, 2)));
        service.publish_fee_delta_generation(9);
        assert_eq!(
            published_key(&service),
            Some(GenerationKey {
                tip_hash: tip,
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 9,
            })
        );
    }

    #[test]
    fn membership_publication_invalidates_without_inventing_a_fee_revision() {
        let tip = Hash256::from_le_bytes(&[0x23; 32]);
        let service = service_with(Some(tip_snapshot(tip)), Arc::new(StaticPool::new(5, 2)));
        service.publish_generation_from(6);
        assert_eq!(published_key(&service), None);
        service.publish_fee_delta_generation(9);
        assert_eq!(
            published_key(&service),
            Some(GenerationKey {
                tip_hash: tip,
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 9,
            })
        );
        service.publish_generation_from(5);
        assert_eq!(
            published_key(&service),
            Some(GenerationKey {
                tip_hash: tip,
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 9,
            })
        );
        service.publish_generation_from(7);
        assert_eq!(published_key(&service), None);
    }

    #[test]
    fn first_sequence_publication_seeds_from_the_construction_pool_state() {
        let service = service_with(None, Arc::new(StaticPool::new(5, 2)));
        service.publish_fee_delta_generation(4);
        assert_eq!(
            published_key(&service),
            Some(GenerationKey {
                tip_hash: Network::Regtest.genesis_block_hash(),
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 4,
            })
        );
    }

    #[test]
    fn assemble_refuses_when_either_pool_counter_moves() {
        let tip = Hash256::from_le_bytes(&[0x25; 32]);
        let pool = Arc::new(StaticPool::new(5, 2));
        let service = service_with_chain(
            Some(tip_snapshot(tip)),
            Arc::clone(&pool),
            Arc::new(ResolvedChain),
        );
        let key = GenerationKey {
            tip_hash: tip,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let ordinary = CandidateKey::ordinary(key);
        let assembled = service
            .assemble_for_key(ordinary)
            .unwrap_or_else(|error| panic!("matching counters must assemble: {error}"));
        assert_eq!(assembled.template_id, key.template_id());
        assert_eq!(assembled.previous_block_hash, tip);
        assert_eq!(assembled.mempool_sequence, 5);
        pool.set(5, 3);
        assert!(
            matches!(
                service.assemble_for_key(ordinary),
                Err(MiningControlError::Unavailable(message))
                    if message.as_str() == GENERATION_RACE
            ),
            "a moved fee sequence must refuse assembly"
        );
        pool.set(6, 2);
        assert!(
            matches!(
                service.assemble_for_key(ordinary),
                Err(MiningControlError::Unavailable(message))
                    if message.as_str() == GENERATION_RACE
            ),
            "a moved membership sequence must refuse assembly"
        );
        assert!(service.state.lock().cache.is_empty());
    }

    struct GatedPool {
        counters: Mutex<(u64, u64)>,
        entered_projection: AtomicBool,
        release_projection: AtomicBool,
        panic_projection: AtomicBool,
        projection_calls: AtomicUsize,
        live_calls: AtomicUsize,
    }

    impl GatedPool {
        fn new(sequence: u64, fee_delta_sequence: u64) -> Self {
            Self {
                counters: Mutex::new((sequence, fee_delta_sequence)),
                entered_projection: AtomicBool::new(false),
                release_projection: AtomicBool::new(false),
                panic_projection: AtomicBool::new(false),
                projection_calls: AtomicUsize::new(0),
                live_calls: AtomicUsize::new(0),
            }
        }

        fn release(&self) {
            self.release_projection.store(true, Ordering::SeqCst);
        }

        fn arm_panic(&self) {
            self.panic_projection.store(true, Ordering::SeqCst);
        }
    }

    impl MempoolSnapshotSource for GatedPool {
        fn current_revisions(&self) -> (u64, u64) {
            *self.counters.lock()
        }

        fn select_template(
            &self,
            expected_sequences: Option<(u64, u64)>,
            context: &CandidateContext,
            payout: &[u8],
            budget: Option<CoinbaseBudget>,
        ) -> Result<Option<SelectedBody>, MiningControlError> {
            self.live_calls.fetch_add(1, Ordering::Relaxed);
            let (sequence, fee_delta_sequence) = *self.counters.lock();
            if expected_sequences.is_some_and(|(expected_sequence, expected_fee_delta_sequence)| {
                sequence != expected_sequence || fee_delta_sequence != expected_fee_delta_sequence
            }) {
                return Ok(None);
            }
            let fixture = Mempool::new(MempoolLimits::default());
            let mut body =
                select_template_body(&fixture, context, payout, budget).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
            body.sequence = sequence;
            body.fee_delta_sequence = fee_delta_sequence;
            Ok(Some(body))
        }

        fn select_template_after(
            &self,
            block: &BlockImage,
            context: &CandidateContext,
            payout: &[u8],
        ) -> Result<PreparedTemplateBody, MiningControlError> {
            self.projection_calls.fetch_add(1, Ordering::Relaxed);
            self.entered_projection.store(true, Ordering::SeqCst);
            assert!(
                !self.panic_projection.load(Ordering::SeqCst),
                "adversarial worker panic inside the projected selection"
            );
            let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
            while !self.release_projection.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                !self.panic_projection.load(Ordering::SeqCst),
                "adversarial worker panic on projection release"
            );
            let source_sequences = *self.counters.lock();
            let fixture = Mempool::new(MempoolLimits::default());
            let plan = fixture
                .plan_block_removals(&bitcoin_rs_mempool::TransitionFacts::from_block(block));
            let mut body =
                select_template_body_after(&fixture, &plan, context, payout).map_err(|error| {
                    MiningControlError::Failed(CompactString::from(error.to_string()))
                })?;
            body.sequence = source_sequences.0;
            body.fee_delta_sequence = source_sequences.1;
            Ok(PreparedTemplateBody {
                body,
                source_sequences,
                removals: Vec::new(),
            })
        }

        fn selection_snapshot(
            &self,
            _selection: &GenerateSelection,
            _context: &CandidateContext,
        ) -> Result<Arc<MempoolMiningSnapshot>, MiningControlError> {
            let (sequence, fee_delta_sequence) = *self.counters.lock();
            Ok(Arc::new(MempoolMiningSnapshot {
                sequence,
                fee_delta_sequence,
                entries: Vec::new(),
            }))
        }

        fn pooled_transaction_count(&self) -> u64 {
            0
        }

        fn min_relay_fee_sat_per_kvb(&self) -> u64 {
            1_000
        }
    }

    struct CountingChain {
        rules_calls: AtomicUsize,
    }

    impl ChainContextSource for CountingChain {
        fn validate_candidate(&self, _candidate: &Candidate) -> Result<(), MiningControlError> {
            Ok(())
        }

        fn resolve_mining_context(
            &self,
            tip: &TipSnapshot,
            _candidate_time: u32,
        ) -> Result<MiningChainContext, ChainError> {
            Ok(MiningChainContext {
                previous_block_hash: tip.hash,
                height: tip.height.saturating_add(1),
                version: 0x2000_0000,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                min_time: 1,
                prev_median_time_past: 0,
                parent_median_time_past: 0,
                csv_active: false,
                segwit_active: false,
            })
        }

        fn tip_bits(&self, _tip: &TipSnapshot) -> Result<CompactTarget, ChainError> {
            Ok(CompactTarget::from_consensus(0x207f_ffff))
        }

        fn signalling_rules(&self, _tip: &TipSnapshot, _height: u32) -> Vec<AvailableMiningRule> {
            self.rules_calls.fetch_add(1, Ordering::Relaxed);
            vec![AvailableMiningRule {
                rule: MiningRule::new("segwit"),
                bit: 1,
            }]
        }
    }

    fn wait_until_ready(service: &MiningService, target: Hash256) {
        let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
        loop {
            let ready = service
                .prep
                .mailbox()
                .active
                .as_ref()
                .is_some_and(|active| {
                    active.target_tip == target
                        && matches!(active.progress, PrepProgress::Ready { .. })
                });
            if ready {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "staged preparation did not finish"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn ready_candidate(service: &MiningService, target: Hash256) -> Arc<Candidate> {
        let mailbox = service.prep.mailbox();
        match mailbox.active.as_ref() {
            Some(ActivePrep {
                target_tip,
                progress: PrepProgress::Ready { candidate, .. },
            }) if *target_tip == target => Arc::clone(candidate),
            _ => panic!("no ready preparation for the target tip"),
        }
    }

    fn wait_until_parked(service: &MiningService) {
        let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
        while service.prep.mailbox().parked_joins == 0 {
            assert!(
                Instant::now() < deadline,
                "the foreground never parked on the preparation condvar"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_until_entered(pool: &GatedPool) {
        let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
        while !pool.entered_projection.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "worker did not enter the projected selection"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn stage_tip_is_idempotent_and_publishes_nothing() {
        let tip_hash = Hash256::from_le_bytes(&[0x61; 32]);
        let tip = tip_snapshot(tip_hash);
        let pool = Arc::new(GatedPool::new(5, 2));
        let service = service_with_source(
            Some(tip.clone()),
            pool.clone(),
            Arc::new(ResolvedChain),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        );
        let block = BlockImage::from_local(Network::Regtest.genesis_block());
        service.stage_tip(&tip, &block);
        wait_until_entered(&pool);
        service.stage_tip(&tip, &block);
        assert_eq!(
            pool.projection_calls.load(Ordering::Relaxed),
            1,
            "one owned tip runs exactly one projection"
        );
        assert!(
            published_key(&service).is_none(),
            "staging must never publish a generation"
        );
        pool.release();
    }

    #[test]
    fn publish_block_generation_retains_receipt_and_publishes() {
        let tip_hash = Hash256::from_le_bytes(&[0x62; 32]);
        let service = service_with(
            Some(tip_snapshot(tip_hash)),
            Arc::new(StaticPool::new(5, 2)),
        );
        let removed = Txid::from(Hash256::from_le_bytes(&[0x63; 32]));
        let removals = MutationResult {
            changes: vec![MutationChange {
                txid: Hash256::from(removed),
                outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
            }],
            sequence_base: 6,
        };
        service.publish_block_generation(tip_hash, &removals);
        assert_eq!(
            published_key(&service),
            Some(GenerationKey {
                tip_hash,
                commit_id: 0,
                mempool_sequence: 5,
                fee_delta_sequence: 2,
            }),
            "block publication still publishes the live generation key"
        );
        let receipt = service
            .prep
            .mailbox()
            .receipt
            .take()
            .unwrap_or_else(|| panic!("the committed receipt must be retained"));
        assert_eq!(receipt.tip_hash, tip_hash);
        assert_eq!(
            receipt.removals,
            vec![(removed, RemovalReason::BlockInclusion)],
            "the receipt keeps stable identities with exact reasons"
        );
    }

    // API-11, SYNC-05
    #[test]
    fn prepared_candidate_validation_refusal_does_not_fill_cache() -> TestResult {
        let tip_hash = Hash256::from_le_bytes(&[0x75; 32]);
        let tip = tip_snapshot(tip_hash);
        let calls = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicBool::new(true));
        let chain = {
            let calls = Arc::clone(&calls);
            let rejected = Arc::clone(&rejected);
            Arc::new(ValidationChain(move |_candidate: &Candidate| {
                calls.fetch_add(1, Ordering::Relaxed);
                if rejected.load(Ordering::Relaxed) {
                    Err(MiningControlError::Rejected(CompactString::from(
                        "prepared candidate is invalid",
                    )))
                } else {
                    Ok(())
                }
            }))
        };
        let service = service_with_chain(Some(tip.clone()), Arc::new(StaticPool::new(5, 2)), chain);
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_ready(&service, tip_hash);
        let prepared = ready_candidate(&service, tip_hash);
        service.publish_block_generation(tip_hash, &MutationResult::empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        assert!(matches!(
            service.get_block_template(None, None),
            Err(MiningControlError::Rejected(reason))
                if reason.as_str() == "prepared candidate is invalid"
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        {
            let state = service.state.lock();
            assert!(state.cache.is_empty());
            assert!(state.last_candidate.is_none());
        }

        rejected.store(false, Ordering::Relaxed);
        let accepted = service.get_block_template(None, None)?.candidate;
        assert!(Arc::ptr_eq(&prepared, &accepted));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let cached = service.get_block_template(None, None)?.candidate;
        assert!(Arc::ptr_eq(&accepted, &cached));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        Ok(())
    }

    // API-11, SYNC-05
    #[test]
    fn validation_generation_change_retries_before_propagating_rejection() -> TestResult {
        for (prepared, budget) in [
            (false, None),
            (true, None),
            (
                false,
                Some(CoinbaseBudget {
                    additional_size: 100,
                    additional_sigops: 0,
                }),
            ),
        ] {
            let tip_hash = Hash256::from_le_bytes(&[0x76; 32]);
            let tip = tip_snapshot(tip_hash);
            let pool = Arc::new(StaticPool::new(5, 2));
            let calls = Arc::new(AtomicUsize::new(0));
            let chain = {
                let pool = Arc::clone(&pool);
                let calls = Arc::clone(&calls);
                Arc::new(ValidationChain(move |_candidate: &Candidate| {
                    if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                        pool.set(6, 3);
                        Err(MiningControlError::Rejected(CompactString::from(
                            "previous generation is invalid",
                        )))
                    } else {
                        Ok(())
                    }
                }))
            };
            let service = service_with_chain(Some(tip.clone()), pool, chain);
            if prepared {
                service.stage_tip(
                    &tip,
                    &BlockImage::from_local(Network::Regtest.genesis_block()),
                );
                wait_until_ready(&service, tip_hash);
                service.publish_block_generation(tip_hash, &MutationResult::empty());
            }

            let candidate = service.get_block_template(None, budget)?.candidate;
            let expected = TemplateId::with_fee_revision(&tip_hash, 6, 3).qualified(budget);
            assert_eq!(candidate.template_id, expected);
            assert_eq!(calls.load(Ordering::Relaxed), 2);
            {
                let state = service.state.lock();
                assert_eq!(state.cache.len(), 1);
                assert!(state.cache.keys().all(|key| {
                    key.generation.mempool_sequence == 6 && key.generation.fee_delta_sequence == 3
                }));
            }

            let cached = service.get_block_template(None, budget)?.candidate;
            assert!(Arc::ptr_eq(&candidate, &cached));
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
        Ok(())
    }

    #[test]
    fn empty_preparation_installs_against_matching_receipt() {
        let tip_hash = Hash256::from_le_bytes(&[0x64; 32]);
        let tip = tip_snapshot(tip_hash);
        let service = service_with_chain(
            Some(tip.clone()),
            Arc::new(StaticPool::new(5, 2)),
            Arc::new(ResolvedChain),
        );
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_ready(&service, tip_hash);
        service.publish_block_generation(tip_hash, &MutationResult::empty());
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let installed = service
            .candidate_for_key(key)
            .unwrap_or_else(|error| panic!("a matching receipt must install: {error}"));
        assert_eq!(installed.template_id, key.template_id());
        let cached = service
            .state
            .lock()
            .cache_get(&CandidateKey::ordinary(key))
            .unwrap_or_else(|| panic!("the install must fill the template cache"));
        assert!(
            Arc::ptr_eq(&installed, &cached),
            "foreground callers share the installed candidate"
        );
        let last = service.state.lock().last_candidate.unwrap_or_else(|| {
            panic!("the install updates the candidate report as lazy assembly does")
        });
        assert_eq!(last.weight, installed.weight);
        assert_eq!(
            last.transactions, 1,
            "the empty body carries only its count line"
        );
    }

    #[test]
    fn empty_preparation_cannot_install_against_nonempty_receipt() {
        let tip_hash = Hash256::from_le_bytes(&[0x65; 32]);
        let tip = tip_snapshot(tip_hash);
        let service = service_with_chain(
            Some(tip.clone()),
            Arc::new(StaticPool::new(5, 2)),
            Arc::new(ResolvedChain),
        );
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_ready(&service, tip_hash);
        let prepared = service
            .prep
            .mailbox()
            .active
            .as_ref()
            .and_then(|active| match &active.progress {
                PrepProgress::Ready { candidate, .. } => Some(Arc::clone(candidate)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the preparation must be ready"));
        let removed = Txid::from(Hash256::from_le_bytes(&[0x66; 32]));
        service.publish_block_generation(
            tip_hash,
            &MutationResult {
                changes: vec![MutationChange {
                    txid: Hash256::from(removed),
                    outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
                }],
                sequence_base: 6,
            },
        );
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let served = service
            .candidate_for_key(key)
            .unwrap_or_else(|error| panic!("the refusal must fall back to lazy assembly: {error}"));
        assert!(
            !Arc::ptr_eq(&prepared, &served),
            "the empty expectation must not install over the actual receipt"
        );
        assert!(
            service.prep.mailbox().active.is_none(),
            "a definitive receipt mismatch discards the preparation"
        );
        assert!(
            service
                .state
                .lock()
                .cache_get(&CandidateKey::ordinary(key))
                .is_some(),
            "lazy assembly still serves the live generation"
        );
    }

    #[test]
    fn fee_moved_preparation_discards_and_serves_live() {
        let tip_hash = Hash256::from_le_bytes(&[0x67; 32]);
        let tip = tip_snapshot(tip_hash);
        let pool = Arc::new(StaticPool::new(5, 2));
        let service = service_with_chain(
            Some(tip.clone()),
            Arc::clone(&pool),
            Arc::new(ResolvedChain),
        );
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_ready(&service, tip_hash);
        pool.set(5, 9);
        service.publish_block_generation(tip_hash, &MutationResult::empty());
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        };
        let served = service
            .candidate_for_key(key)
            .unwrap_or_else(|error| panic!("the refusal must fall back to lazy assembly: {error}"));
        assert_eq!(
            served.template_id,
            key.template_id(),
            "the reply reflects the live fee sequence"
        );
        assert!(
            service.prep.mailbox().active.is_none(),
            "a stale fee prediction is discarded"
        );
    }

    #[test]
    fn matching_foreground_joins_running_preparation_without_duplicate_finish() {
        let tip_hash = Hash256::from_le_bytes(&[0x68; 32]);
        let tip = tip_snapshot(tip_hash);
        let pool = Arc::new(GatedPool::new(5, 2));
        let service = Arc::new(service_with_source(
            Some(tip.clone()),
            pool.clone(),
            Arc::new(ResolvedChain),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_entered(&pool);
        service.publish_block_generation(tip_hash, &MutationResult::empty());
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let waiter_service = Arc::clone(&service);
        let waiter = std::thread::spawn(move || waiter_service.candidate_for_key(key));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            0,
            "the joined waiter must not start a duplicate finish"
        );
        pool.release();
        let installed = waiter
            .join()
            .unwrap_or_else(|_| panic!("the waiter thread panicked"))
            .unwrap_or_else(|error| panic!("the joined preparation must install: {error}"));
        assert_eq!(installed.template_id, key.template_id());
        assert_eq!(
            pool.projection_calls.load(Ordering::Relaxed),
            1,
            "one projection serves the worker and the joined waiter"
        );
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            0,
            "no lazy finish ran for the joined key"
        );
    }

    #[test]
    fn shutdown_releases_a_preparation_waiter() {
        let tip_hash = Hash256::from_le_bytes(&[0x69; 32]);
        let tip = tip_snapshot(tip_hash);
        let pool = Arc::new(GatedPool::new(5, 2));
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let service = Arc::new(service_with_source(
            Some(tip.clone()),
            pool.clone(),
            Arc::new(ResolvedChain),
            shutdown.reader(),
        ));
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_entered(&pool);
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let waiter_service = Arc::clone(&service);
        let waiter = std::thread::spawn(move || waiter_service.candidate_for_key(key));
        std::thread::sleep(Duration::from_millis(50));
        shutdown.trigger();
        let outcome = waiter
            .join()
            .unwrap_or_else(|_| panic!("the waiter thread panicked"));
        assert!(
            matches!(
                outcome,
                Err(MiningControlError::Unavailable(message))
                    if message.as_str() == "node is shutting down"
            ),
            "shutdown must release the joined waiter"
        );
        pool.release();
    }

    #[test]
    fn pending_stage_foreground_joins_without_duplicate_finish() {
        let first_hash = Hash256::from_le_bytes(&[0x71; 32]);
        let second_hash = Hash256::from_le_bytes(&[0x72; 32]);
        let pool = Arc::new(GatedPool::new(5, 2));
        let tip_source = Arc::new(StaticTip::new(Some(tip_snapshot(first_hash))));
        let service = Arc::new(MiningService::new(
            Network::Regtest,
            tip_source.clone(),
            pool.clone(),
            Arc::new(ResolvedChain),
            Vec::new(),
            CoinbaseReserve::default(),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        service.stage_tip(
            &tip_snapshot(first_hash),
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_entered(&pool);
        tip_source.set(Some(tip_snapshot(second_hash)));
        service.stage_tip(
            &tip_snapshot(second_hash),
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        service.publish_block_generation(second_hash, &MutationResult::empty());
        let key = GenerationKey {
            tip_hash: second_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let waiter_service = Arc::clone(&service);
        let waiter = std::thread::spawn(move || waiter_service.candidate_for_key(key));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            0,
            "a foreground for a pending tip must join, never duplicate the finish"
        );
        pool.release();
        let installed = waiter
            .join()
            .unwrap_or_else(|_| panic!("the waiter thread panicked"))
            .unwrap_or_else(|error| {
                panic!("the pending preparation must install once the worker reaches it: {error}")
            });
        assert_eq!(installed.template_id, key.template_id());
        assert_eq!(
            pool.projection_calls.load(Ordering::Relaxed),
            2,
            "both staged tips run exactly one projection each"
        );
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            0,
            "no lazy finish ran for the joined key"
        );
    }

    #[test]
    fn worker_panic_releases_joined_waiter_to_lazy_fallback() {
        let tip_hash = Hash256::from_le_bytes(&[0x73; 32]);
        let pool = Arc::new(GatedPool::new(5, 2));
        let service = Arc::new(service_with_source(
            Some(tip_snapshot(tip_hash)),
            pool.clone(),
            Arc::new(ResolvedChain),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        service.stage_tip(
            &tip_snapshot(tip_hash),
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_entered(&pool);
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let waiter_service = Arc::clone(&service);
        let waiter = std::thread::spawn(move || waiter_service.candidate_for_key(key));
        wait_until_parked(&service);
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            0,
            "a parked waiter must not run a duplicate lazy finish"
        );
        assert!(
            !waiter.is_finished(),
            "the waiter must still be parked when the panic lands"
        );
        pool.arm_panic();
        pool.release();
        let served = waiter
            .join()
            .unwrap_or_else(|_| panic!("the waiter thread panicked"))
            .unwrap_or_else(|error| {
                panic!("the released waiter must fall back to lazy assembly: {error}")
            });
        assert_eq!(served.template_id, key.template_id());
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            1,
            "the released waiter serves the live generation lazily"
        );
    }

    #[test]
    fn ready_preparation_parks_until_the_receipt_and_serves_the_prepared_arc() {
        let tip_hash = Hash256::from_le_bytes(&[0x74; 32]);
        let tip = tip_snapshot(tip_hash);
        let pool = Arc::new(GatedPool::new(5, 2));
        pool.release();
        let service = Arc::new(service_with_source(
            Some(tip.clone()),
            pool.clone(),
            Arc::new(ResolvedChain),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        ));
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_ready(&service, tip_hash);
        let prepared = ready_candidate(&service, tip_hash);
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 2,
        };
        let foreground_service = Arc::clone(&service);
        let foreground = std::thread::spawn(move || foreground_service.candidate_for_key(key));
        wait_until_parked(&service);
        assert_eq!(
            pool.live_calls.load(Ordering::Relaxed),
            0,
            "a parked foreground must not run a duplicate lazy finish"
        );
        assert!(
            !foreground.is_finished(),
            "no candidate may be exposed before the committed receipt arrives"
        );
        service.publish_block_generation(tip_hash, &MutationResult::empty());
        let served = foreground
            .join()
            .unwrap_or_else(|_| panic!("the foreground thread panicked"))
            .unwrap_or_else(|error| {
                panic!("the receipt must release the parked foreground into the install: {error}")
            });
        assert!(
            Arc::ptr_eq(&served, &prepared),
            "the receipt installs the prepared candidate, not a rebuilt one"
        );
        assert_eq!(pool.live_calls.load(Ordering::Relaxed), 0);
        assert_eq!(pool.projection_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stale_ready_without_a_receipt_serves_lazily_instead_of_parking() {
        let tip_hash = Hash256::from_le_bytes(&[0x75; 32]);
        let tip = tip_snapshot(tip_hash);
        let pool = Arc::new(GatedPool::new(5, 2));
        pool.release();
        let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
        let service = Arc::new(service_with_source(
            Some(tip.clone()),
            pool.clone(),
            Arc::new(ResolvedChain),
            shutdown.reader(),
        ));
        service.stage_tip(
            &tip,
            &BlockImage::from_local(Network::Regtest.genesis_block()),
        );
        wait_until_ready(&service, tip_hash);
        let prepared = ready_candidate(&service, tip_hash);
        *pool.counters.lock() = (5, 9);
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        };
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let foreground_service = Arc::clone(&service);
        let foreground = std::thread::spawn(move || {
            let _ = result_tx.send(foreground_service.candidate_for_key(key));
        });
        let Ok(outcome) = result_rx.recv_timeout(WAKE_PROOF_TIMEOUT) else {
            shutdown.trigger();
            let _ = foreground.join();
            panic!("a stale Ready parked a foreground that no receipt can ever release");
        };
        assert!(foreground.join().is_ok(), "the foreground thread panicked");
        let served = outcome.unwrap_or_else(|error| {
            panic!("the stale preparation must fall back to lazy assembly: {error}")
        });
        assert_eq!(served.template_id, key.template_id());
        assert!(
            !Arc::ptr_eq(&served, &prepared),
            "the stale candidate must never serve the moved generation"
        );
        assert_eq!(pool.live_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn nonempty_preparation_installs_against_matching_receipt() {
        let tip_hash = Hash256::from_le_bytes(&[0x6c; 32]);
        let tip = tip_snapshot(tip_hash);
        let service = service_with(Some(tip), Arc::new(StaticPool::new(7, 3)));
        let first = Txid::from(Hash256::from_le_bytes(&[0x6d; 32]));
        let second = Txid::from(Hash256::from_le_bytes(&[0x6e; 32]));
        let expected = vec![
            (first, RemovalReason::BlockInclusion),
            (second, RemovalReason::Conflict),
        ];
        let candidate = Arc::new(sample_candidate(tip_hash, 7, 3, false, false));
        {
            let mut mailbox = service.prep.mailbox();
            mailbox.active = Some(ActivePrep {
                target_tip: tip_hash,
                progress: PrepProgress::Ready {
                    source_sequences: (5, 2),
                    expected_removals: expected,
                    candidate: Arc::clone(&candidate),
                },
            });
        }
        service.publish_block_generation(
            tip_hash,
            &MutationResult {
                changes: vec![
                    MutationChange {
                        txid: Hash256::from(first),
                        outcome: MutationOutcome::Removed(RemovalReason::BlockInclusion),
                    },
                    MutationChange {
                        txid: Hash256::from(second),
                        outcome: MutationOutcome::Removed(RemovalReason::Conflict),
                    },
                ],
                sequence_base: 6,
            },
        );
        let key = GenerationKey {
            tip_hash,
            commit_id: 0,
            mempool_sequence: 7,
            fee_delta_sequence: 3,
        };
        let installed = service
            .candidate_for_key(key)
            .unwrap_or_else(|error| panic!("a matching nonempty receipt must install: {error}"));
        assert!(
            Arc::ptr_eq(&installed, &candidate),
            "the install serves the prepared candidate, not a duplicate finish"
        );
        assert!(
            service.prep.mailbox().active.is_none(),
            "a successful install releases the single slot"
        );
    }

    #[test]
    fn signalling_rules_resolve_once_per_tip_and_height() -> TestResult {
        let chain = Arc::new(CountingChain {
            rules_calls: AtomicUsize::new(0),
        });
        let tip_source = Arc::new(StaticTip::new(Some(tip_snapshot(Hash256::from_le_bytes(
            &[0x6a; 32],
        )))));
        let service = MiningService::new(
            Network::Regtest,
            tip_source.clone(),
            Arc::new(StaticPool::new(5, 2)),
            chain.clone(),
            Vec::new(),
            CoinbaseReserve::default(),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        );
        service.get_block_template(None, None)?;
        assert_eq!(
            chain.rules_calls.load(Ordering::Relaxed),
            1,
            "the first template resolves its signalling rules"
        );
        service.get_block_template(None, None)?;
        assert_eq!(
            chain.rules_calls.load(Ordering::Relaxed),
            1,
            "the same tip and height must reuse the cached rules"
        );
        tip_source.set(Some(tip_snapshot(Hash256::from_le_bytes(&[0x6b; 32]))));
        service.get_block_template(None, None)?;
        assert_eq!(
            chain.rules_calls.load(Ordering::Relaxed),
            2,
            "a moved tip resolves its own rules once"
        );
        Ok(())
    }

    // MPS-03
    #[test]
    fn mining_template_never_references_unsettled_transaction() {
        let tip_a = tip_snapshot(Hash256::from_le_bytes(&[0x11; 32]));
        let tip_source = Arc::new(StaticTip::new(Some(tip_a.clone())));
        tip_source.set_epoch(Some(tip_a.clone()), 1);
        let pool = Arc::new(StaticPool::new(1, 0));
        pool.set_settled_commit(1);

        let service = MiningService::new(
            Network::Regtest,
            tip_source.clone(),
            pool.clone(),
            Arc::new(ResolvedChain),
            Vec::new(),
            CoinbaseReserve::default(),
            bitcoin_rs_consensus::latch::LatchReader::fixture_never(),
        );

        let key_epoch_1 = GenerationKey {
            tip_hash: tip_a.hash,
            commit_id: 1,
            mempool_sequence: 1,
            fee_delta_sequence: 0,
        };
        let candidate = service.candidate_for_key(key_epoch_1);
        assert!(candidate.is_ok());
        let Ok(candidate) = candidate else {
            panic!("a settled generation must produce a candidate");
        };
        assert_eq!(candidate.previous_block_hash, tip_a.hash);
        assert!(candidate.transactions.is_empty());

        pool.set(2, 0);
        pool.admit_gated();
        let tip_b = tip_snapshot(Hash256::from_le_bytes(&[0x22; 32]));
        tip_source.set_epoch(Some(tip_b.clone()), 2);

        let key_epoch_2 = GenerationKey {
            tip_hash: tip_b.hash,
            commit_id: 2,
            mempool_sequence: 2,
            fee_delta_sequence: 0,
        };
        let unsettled_candidate = service.candidate_for_key(key_epoch_2);
        assert!(matches!(
            &unsettled_candidate,
            Err(e) if e.is_template_generation_race()
        ));

        pool.set_settled_commit(2);
        let settled_candidate = service.candidate_for_key(key_epoch_2);
        assert!(settled_candidate.is_ok());
        let Ok(settled_candidate) = settled_candidate else {
            panic!("a newly settled generation must produce a candidate");
        };
        assert_eq!(settled_candidate.previous_block_hash, tip_b.hash);
        let gated_txid = gated_tx().txid();
        assert!(
            settled_candidate
                .transactions
                .iter()
                .any(|transaction| transaction.txid == gated_txid)
        );
    }
}
