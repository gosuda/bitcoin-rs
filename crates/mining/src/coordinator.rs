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
use std::time::Instant;

use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::TipSnapshot;
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

use crate::control::AvailableMiningRule;
use crate::control::BlockTemplate;
use crate::control::GenerateSelection;
use crate::control::GenerateTx;
use crate::control::LastCandidateInfo;
use crate::control::MiningCapability;
use crate::control::MiningControlError;
use crate::control::MiningRule;
use crate::control::SignetMiningInfo;
use crate::control::TemplateMutation;
use crate::context::MiningChainContext;
use crate::template::Candidate;
use crate::template::TemplateId;

/// Default number of cached candidates retained by template id.
pub const CANDIDATE_CACHE_LIMIT: usize = 8;
/// Finite bound on generation-key races during candidate assembly.
pub const CANDIDATE_GENERATION_RETRIES: usize = 8;
/// Error message identifying a generation-key race during candidate assembly.
pub const GENERATION_RACE: &str = "generation key changed during candidate assembly";
/// Bitcoin Core's mempool-only long-poll cooldown before returning a new template.
pub const DEFAULT_MEMPOOL_UPDATE_WAIT: Duration = Duration::from_secs(10);
/// Upper bound for a single long-poll wait slice while rechecking predicates.
pub const LONG_POLL_SLICE: Duration = Duration::from_secs(1);

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
pub struct InFlight {
    /// Generation key the flight assembles for.
    pub key: GenerationKey,
    /// Monotonic identity assigned when the flight was installed.
    pub id: u64,
    /// Result shared with same-key waiters once assembly finishes.
    pub result: Option<Result<Arc<Candidate>, MiningControlError>>,
}

/// Bounded template cache, single-flight guard, and published generation.
#[derive(Debug, Default)]
pub struct CoordinatorState {
    /// Last generation published to long-poll waiters.
    pub published: Option<GenerationKey>,
    /// Bounded LRU of assembled candidates keyed by template id.
    pub cache: HashMap<TemplateId, Arc<Candidate>>,
    /// Insertion order for deterministic eviction of the oldest entry.
    pub cache_order: VecDeque<TemplateId>,
    /// Single in-flight assembly, if any.
    pub in_flight: Option<InFlight>,
    /// Monotonically increasing identity for each installed flight.
    pub next_flight_id: u64,
    /// Facts from the most recently assembled candidate.
    pub last_candidate: Option<LastCandidateInfo>,
}

impl CoordinatorState {
    /// Creates the empty lifecycle state.
    #[must_use]
    pub fn new() -> Self {
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
    pub fn cache_get(&self, id: &TemplateId) -> Option<Arc<Candidate>> {
        self.cache.get(id).cloned()
    }

    /// Inserts or refreshes `id`, evicting the oldest entry at the bound.
    pub fn cache_insert(&mut self, id: TemplateId, candidate: Arc<Candidate>) {
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
    pub fn invalidate_key(&mut self, key: GenerationKey) {
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
    /// Mining view of the pool's current transactions.
    fn mining_snapshot(&self) -> MempoolMiningSnapshot;
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
    fn signalling_rules(&self, tip: &TipSnapshot, height: u32)
    -> Vec<AvailableMiningRule>;
}

/// Mining-domain candidate lifecycle service driven by capability sources.
///
/// Owns the template cache, single-flight assembly, and long-poll
/// publication state. The node facade constructs it with adapters over the
/// applied tip, the mempool, and the block tree, and keeps proposal
/// validation and solved-block submission on the authoritative apply path.
#[expect(dead_code, reason = "stub; the lifecycle methods land with the candidate-lifecycle move")]
pub struct MiningService {
    /// Network whose genesis anchors an empty applied chain.
    network: Network,
    /// Immutable coinbase payout script for assembled candidates.
    coinbase_script: Vec<u8>,
    /// Shared shutdown flag checked by every unbounded wait.
    shutdown: Arc<AtomicBool>,
    /// Wall clock used for long-poll cooldowns.
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    /// Controllable mempool-only long-poll cooldown (Core default: 10s).
    mempool_update_wait: Duration,
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
}

/// Projects an assembled candidate into a BIP22/BIP23 block template.
///
/// Rule advertisement follows the candidate's own deployment facts and
/// producer capabilities, never caller-requested names.
pub fn template_from_candidate(
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
pub fn generation_race() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from(GENERATION_RACE))
}

/// Reports whether `error` is the generation-race error.
pub fn is_generation_race(error: &MiningControlError) -> bool {
    matches!(error, MiningControlError::Unavailable(message) if message.as_str() == GENERATION_RACE)
}

/// Parses a BIP22/BIP23 long-poll id into its generation key.
#[must_use]
pub fn parse_long_poll_id(id: &str) -> Option<GenerationKey> {
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
pub fn signet_info(network: Network) -> Option<SignetMiningInfo> {
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
