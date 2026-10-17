// CONTRACT: `crates/mining/README.md` owns the node-facing BIP22/BIP23
// long-poll identity contract; `docs/contracts/external-api.md#API-11` owns
// BIP22/BIP23 template capabilities, submitold, signet projection, template
// rules, and the corresponding `getblocktemplate` long-poll surface.
use super::*;
use crate::control::BlockTemplate;
use crate::control::MiningCapability;
use crate::control::MiningRule;
use crate::template::Candidate;
use crate::template::TemplateId;
use crate::template::select_template_body;
use crate::template::select_template_body_after;
use bitcoin_rs_chain::ChainTxCount;
use bitcoin_rs_chain::ChainWork;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_mempool::MempoolLimits;
use bitcoin_rs_mempool::MutationChange;
use bitcoin_rs_mempool::MutationOutcome;
use bitcoin_rs_mempool::RemovalReason;
use bitcoin_rs_primitives::Amount;
use bitcoin_rs_primitives::LockTime;
use bitcoin_rs_primitives::Script;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxOut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod fee_revision;

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
    let mut first_id = None;
    for seq in 0..=CANDIDATE_CACHE_LIMIT {
        let seq = u64::try_from(seq).unwrap_or(u64::MAX);
        let hash = Hash256::from_le_bytes(&[u8::try_from(seq).unwrap_or(0xff); 32]);
        let candidate = sample_candidate(hash, seq, seq, false, false);
        let id = candidate.template_id.clone();
        if seq == 0 {
            first_id = Some(id.clone());
        }
        state.cache_insert(id, Arc::new(candidate));
    }
    assert_eq!(state.cache.len(), CANDIDATE_CACHE_LIMIT);
    assert!(
        !state
            .cache
            .contains_key(first_id.as_ref().unwrap_or_else(|| panic!("first id"))),
        "oldest cached candidate must be evicted at the bound"
    );
}

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

#[test]
fn long_poll_round_trips_template_id() {
    let tip = Hash256::from_le_bytes(&[0x11; 32]);
    let key = GenerationKey {
        tip_hash: tip,
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
    // API-11 requires malformed longpollids, including invalid UTF-8 split
    // boundaries, to be rejected without panicking. 63 ASCII bytes followed by
    // a two-byte UTF-8 scalar puts byte 64 - the hex/sequence split point -
    // inside that scalar; the fee revision keeps `split_once(':')` from
    // rejecting first, so the slice guard itself is exercised.
    let malformed = format!("{}é:1", "0".repeat(63));
    assert_eq!(malformed.len(), 67);
    assert!(parse_long_poll_id(&malformed).is_none());
}

#[test]
fn long_poll_rejects_malformed_components_without_panicking() {
    // Colon-form near misses the revision loop does not cover: an empty
    // membership sequence, a non-decimal membership sequence, and a signed
    // membership sequence must all fail without panicking. (A leading `+`
    // parses as decimal, so it is not a malformed case.)
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
    for error in [
        MiningControlError::Unavailable("node is shutting down".into()),
        MiningControlError::Unavailable("applied tip is not available".into()),
        MiningControlError::InvalidRequest(GENERATION_RACE.into()),
        MiningControlError::Failed(GENERATION_RACE.into()),
        MiningControlError::Rejected(GENERATION_RACE.into()),
    ] {
        assert!(!error.is_template_generation_race(), "{error:?}");
    }
}

/// Applied tip behind a test-controlled cell.
struct StaticTip(Mutex<Option<TipSnapshot>>);

impl StaticTip {
    fn set(&self, tip: Option<TipSnapshot>) {
        *self.0.lock() = tip;
    }
}

impl AppliedTipSource for StaticTip {
    fn applied_tip(&self) -> Option<TipSnapshot> {
        self.0.lock().clone()
    }
}

/// Pool counter double backing [`MempoolSnapshotSource`] for publication and
/// snapshot-gate probes. `pool_reads` counts every pool-lock acquisition so
/// tests can prove the sequence-based publishers never take one.
struct StaticPool {
    counters: Mutex<(u64, u64)>,
    pool_reads: AtomicUsize,
}

impl StaticPool {
    fn new(sequence: u64, fee_delta_sequence: u64) -> Self {
        Self {
            counters: Mutex::new((sequence, fee_delta_sequence)),
            pool_reads: AtomicUsize::new(0),
        }
    }

    fn set(&self, sequence: u64, fee_delta_sequence: u64) {
        *self.counters.lock() = (sequence, fee_delta_sequence);
    }
}

impl MempoolSnapshotSource for StaticPool {
    fn current_revisions(&self) -> (u64, u64) {
        self.pool_reads.fetch_add(1, Ordering::Relaxed);
        *self.counters.lock()
    }

    fn select_template(
        &self,
        expected_sequences: Option<(u64, u64)>,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<Option<SelectedBody>, MiningControlError> {
        self.pool_reads.fetch_add(1, Ordering::Relaxed);
        let (sequence, fee_delta_sequence) = *self.counters.lock();
        if expected_sequences.is_some_and(|(expected_sequence, expected_fee_delta_sequence)| {
            sequence != expected_sequence || fee_delta_sequence != expected_fee_delta_sequence
        }) {
            return Ok(None);
        }
        // Real selection over an empty fixture pool: the solver walks the
        // maintained chunk index and reserves the header and coinbase, so the
        // body contents are produced, not echoed. The sequences are the live
        // fixture counters read under the same check, mirroring the
        // production adapter stamping the pool state it selected under.
        let fixture = Mempool::new(MempoolLimits::default());
        let mut body = select_template_body(&fixture, context, payout)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        body.sequence = sequence;
        body.fee_delta_sequence = fee_delta_sequence;
        Ok(Some(body))
    }

    fn select_template_after(
        &self,
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError> {
        self.pool_reads.fetch_add(1, Ordering::Relaxed);
        let source_sequences = *self.counters.lock();
        // Real projection over an empty fixture pool: the plan is empty and
        // the predicted sequences advance past nothing, so the body is
        // stamped with the live fixture counters exactly as the production
        // adapter stamps the pool state it projected under.
        let fixture = Mempool::new(MempoolLimits::default());
        let plan = fixture.plan_block_removals(block);
        assert!(
            plan.removals.is_empty(),
            "the fixture pool holds nothing to project"
        );
        let mut body = select_template_body_after(&fixture, &plan, context, payout)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
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
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
        let (sequence, fee_delta_sequence) = *self.counters.lock();
        Ok(MempoolMiningSnapshot {
            sequence,
            fee_delta_sequence,
            entries: Vec::new(),
        })
    }

    fn pooled_transaction_count(&self) -> u64 {
        0
    }

    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        1_000
    }
}

/// Chain double that refuses every resolution: publication tests never assemble.
struct UnresolvedChain;

impl ChainContextSource for UnresolvedChain {
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

/// Chain double resolving every tip to a fixed regtest context echoing the
/// tip hash, so assembly probes reach the pool selection gate instead of
/// failing on context resolution first.
struct ResolvedChain;

impl ChainContextSource for ResolvedChain {
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

fn service_with(tip: Option<TipSnapshot>, pool: Arc<StaticPool>) -> MiningService {
    service_with_chain(tip, pool, Arc::new(UnresolvedChain))
}

fn service_with_chain(
    tip: Option<TipSnapshot>,
    pool: Arc<StaticPool>,
    chain: Arc<dyn ChainContextSource>,
) -> MiningService {
    service_with_source(tip, pool, chain, Arc::new(AtomicBool::new(false)))
}

fn service_with_source(
    tip: Option<TipSnapshot>,
    pool: Arc<dyn MempoolSnapshotSource>,
    chain: Arc<dyn ChainContextSource>,
    shutdown: Arc<AtomicBool>,
) -> MiningService {
    MiningService::new(
        Network::Regtest,
        Arc::new(StaticTip(Mutex::new(tip))),
        pool,
        chain,
        Vec::new(),
        shutdown,
    )
}

/// Failure-only deadline for the wake proof: generous enough that a healthy
/// wake never approaches it, and never used as a latency threshold.
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
            // The state mutex is held across the readiness signal and the
            // condvar registration: the publisher can only acquire the mutex
            // after `wait` atomically releases it with this thread parked, so
            // wake registration provably precedes publication.
            let mut state = service.state.lock();
            let waited = state.published;
            let _ = ready_tx.send(());
            loop {
                // Stop is checked before the predicate: the cleanup path's
                // direct notify must terminate the waiter even when a mutated
                // publisher already changed `published` without waking anyone.
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if state.published != waited {
                    let _ = result_tx.send(state.published);
                    return;
                }
                // Unconditional wait: only a notify can wake this thread, so a
                // suppressed fee-path notify is not masked by a timer recheck.
                service.wake.wait(&mut state);
            }
        })
    };
    assert!(
        ready_rx.recv().is_ok(),
        "waiter exited before signalling readiness"
    );
    // Real publisher on the real service: it must acquire the state mutex the
    // parked waiter released, then notify the condvar.
    service.publish_fee_delta_generation(9);
    let Ok(published) = result_rx.recv_timeout(WAKE_PROOF_TIMEOUT) else {
        // Suppressed-notify mutation: wake the parked thread directly so
        // cleanup cannot hang, then fail.
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
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        })
    );
    assert!(waiter.join().is_ok(), "waiter thread panicked");
}

#[test]
fn sequence_based_publications_do_not_read_the_pool() {
    let tip = Hash256::from_le_bytes(&[0x26; 32]);
    let pool = Arc::new(StaticPool::new(5, 2));
    let service = service_with(Some(tip_snapshot(tip)), Arc::clone(&pool));
    // Construction seeds the retained membership sequence with exactly one pool read.
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
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        })
    );
}

#[test]
fn membership_publication_invalidates_without_inventing_a_fee_revision() {
    let tip = Hash256::from_le_bytes(&[0x23; 32]);
    let service = service_with(Some(tip_snapshot(tip)), Arc::new(StaticPool::new(5, 2)));
    // A membership-only notification carries no fee revision: with nothing
    // published it publishes nothing and only wakes waiters.
    service.publish_generation_from(6);
    assert_eq!(published_key(&service), None);
    // The fee publisher composes its key from the retained membership
    // sequence without a pool read.
    service.publish_fee_delta_generation(9);
    assert_eq!(
        published_key(&service),
        Some(GenerationKey {
            tip_hash: tip,
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        })
    );
    // A membership notification for the published sequence keeps the
    // fee-carrying key; a newer sequence invalidates it instead of composing
    // a key with an invented fee revision. The next template read captures
    // both live pool revisions.
    service.publish_generation_from(5);
    assert_eq!(
        published_key(&service),
        Some(GenerationKey {
            tip_hash: tip,
            mempool_sequence: 5,
            fee_delta_sequence: 9,
        })
    );
    service.publish_generation_from(7);
    assert_eq!(published_key(&service), None);
}

#[test]
fn first_sequence_publication_seeds_from_the_construction_pool_state() {
    // No tip applied: the published key falls back to the genesis anchor, and
    // the retained membership component comes from the pool counters read at
    // construction, never a zero fallback.
    let service = service_with(None, Arc::new(StaticPool::new(5, 2)));
    service.publish_fee_delta_generation(4);
    assert_eq!(
        published_key(&service),
        Some(GenerationKey {
            tip_hash: Network::Regtest.genesis_block_hash(),
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
        mempool_sequence: 5,
        fee_delta_sequence: 2,
    };
    // Matching counters pass the selection gate and assemble a real candidate
    // whose identity carries both sequences.
    let assembled = service
        .assemble_for_key(key)
        .unwrap_or_else(|error| panic!("matching counters must assemble: {error}"));
    assert_eq!(assembled.template_id, key.template_id());
    assert_eq!(assembled.previous_block_hash, tip);
    assert_eq!(assembled.mempool_sequence, 5);
    pool.set(5, 3);
    assert!(
        matches!(
            service.assemble_for_key(key),
            Err(MiningControlError::Unavailable(message))
                if message.as_str() == GENERATION_RACE
        ),
        "a moved fee sequence must refuse assembly"
    );
    pool.set(6, 2);
    assert!(
        matches!(
            service.assemble_for_key(key),
            Err(MiningControlError::Unavailable(message))
                if message.as_str() == GENERATION_RACE
        ),
        "a moved membership sequence must refuse assembly"
    );
    // Direct assembly never caches: the cache fills only through the
    // single-flight candidate path, so a refused selection leaves nothing behind.
    assert!(service.state.lock().cache.is_empty());
}

/// Pool double with a gated projected selection: the worker enters
/// `select_template_after` and parks until the test releases it, so the
/// same-key single-flight join is deterministic. Live selections are counted
/// to prove a joined waiter never duplicates the finish.
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

    /// Arms a panic inside the next projected selection, so the test can
    /// prove the worker's exit guard releases joined waiters.
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
    ) -> Result<Option<SelectedBody>, MiningControlError> {
        self.live_calls.fetch_add(1, Ordering::Relaxed);
        let (sequence, fee_delta_sequence) = *self.counters.lock();
        if expected_sequences.is_some_and(|(expected_sequence, expected_fee_delta_sequence)| {
            sequence != expected_sequence || fee_delta_sequence != expected_fee_delta_sequence
        }) {
            return Ok(None);
        }
        let fixture = Mempool::new(MempoolLimits::default());
        let mut body = select_template_body(&fixture, context, payout)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
        body.sequence = sequence;
        body.fee_delta_sequence = fee_delta_sequence;
        Ok(Some(body))
    }

    fn select_template_after(
        &self,
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError> {
        self.projection_calls.fetch_add(1, Ordering::Relaxed);
        self.entered_projection.store(true, Ordering::SeqCst);
        assert!(
            !self.panic_projection.load(Ordering::SeqCst),
            "adversarial worker panic inside the projected selection"
        );
        // Bounded park: the test releases the gate; the deadline only fires
        // on test failure, and proceeding then still terminates the worker so
        // the service drop can join it.
        let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
        while !self.release_projection.load(Ordering::SeqCst) {
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let source_sequences = *self.counters.lock();
        let fixture = Mempool::new(MempoolLimits::default());
        let plan = fixture.plan_block_removals(block);
        let mut body = select_template_body_after(&fixture, &plan, context, payout)
            .map_err(|error| MiningControlError::Failed(CompactString::from(error.to_string())))?;
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
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
        let (sequence, fee_delta_sequence) = *self.counters.lock();
        Ok(MempoolMiningSnapshot {
            sequence,
            fee_delta_sequence,
            entries: Vec::new(),
        })
    }

    fn pooled_transaction_count(&self) -> u64 {
        0
    }

    fn min_relay_fee_sat_per_kvb(&self) -> u64 {
        1_000
    }
}

/// Chain double resolving every tip like [`ResolvedChain`] while counting
/// signalling-rule resolutions, so the metadata cache test observes hits.
struct CountingChain {
    rules_calls: AtomicUsize,
}

impl ChainContextSource for CountingChain {
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

/// Failure-only deadline for a background preparation: generous enough that
/// a healthy worker never approaches it, and never a latency threshold.
fn wait_until_ready(service: &MiningService, target: Hash256) {
    let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
    loop {
        let ready = service
            .prep
            .mailbox()
            .active
            .as_ref()
            .is_some_and(|active| {
                active.target_tip == target && matches!(active.progress, PrepProgress::Ready { .. })
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

/// The finished candidate the worker stored for `target`.
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

/// Blocks until a foreground join is registered on the mailbox condvar. The
/// probe is incremented under the mailbox mutex before the wait releases it,
/// so a later notify provably reaches the parked waiter; the deadline only
/// fires on failure.
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
        Arc::new(AtomicBool::new(false)),
    );
    let block = Network::Regtest.genesis_block();
    service.stage_tip(&tip, &block);
    wait_until_entered(&pool);
    // A repeated stage for the owned tip replaces nothing: the pending slot
    // stays empty and the worker still runs its single projection.
    service.stage_tip(&tip, &block);
    assert!(service.prep.mailbox().pending.is_none());
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

#[test]
fn empty_preparation_installs_against_matching_receipt() {
    let tip_hash = Hash256::from_le_bytes(&[0x64; 32]);
    let tip = tip_snapshot(tip_hash);
    let service = service_with_chain(
        Some(tip.clone()),
        Arc::new(StaticPool::new(5, 2)),
        Arc::new(ResolvedChain),
    );
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_ready(&service, tip_hash);
    service.publish_block_generation(tip_hash, &MutationResult::empty());
    let key = GenerationKey {
        tip_hash,
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
        .cache_get(&key.template_id())
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
    // A delayed worker that selected post-removal state carries an empty
    // expectation; it must not install against the nonempty actual receipt,
    // and the foreground falls back to lazy assembly for the live key.
    let tip_hash = Hash256::from_le_bytes(&[0x65; 32]);
    let tip = tip_snapshot(tip_hash);
    let service = service_with_chain(
        Some(tip.clone()),
        Arc::new(StaticPool::new(5, 2)),
        Arc::new(ResolvedChain),
    );
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
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
        service.state.lock().cache_get(&key.template_id()).is_some(),
        "lazy assembly still serves the live generation"
    );
}

#[test]
fn fee_moved_preparation_discards_and_serves_live() {
    // An unrelated prioritisation between staging and publication moves the
    // live fee sequence off the predicted body: the install refuses and the
    // reply reflects the live sequences, not the stale prediction.
    let tip_hash = Hash256::from_le_bytes(&[0x67; 32]);
    let tip = tip_snapshot(tip_hash);
    let pool = Arc::new(StaticPool::new(5, 2));
    let service = service_with_chain(
        Some(tip.clone()),
        Arc::clone(&pool),
        Arc::new(ResolvedChain),
    );
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_ready(&service, tip_hash);
    pool.set(5, 9);
    service.publish_block_generation(tip_hash, &MutationResult::empty());
    let key = GenerationKey {
        tip_hash,
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
        Arc::new(AtomicBool::new(false)),
    ));
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_entered(&pool);
    // The commit arrives while the worker still selects: the receipt is
    // retained and the matching foreground joins the same flight.
    service.publish_block_generation(tip_hash, &MutationResult::empty());
    let key = GenerationKey {
        tip_hash,
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
    let shutdown = Arc::new(AtomicBool::new(false));
    let service = Arc::new(service_with_source(
        Some(tip.clone()),
        pool.clone(),
        Arc::new(ResolvedChain),
        Arc::clone(&shutdown),
    ));
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_entered(&pool);
    let key = GenerationKey {
        tip_hash,
        mempool_sequence: 5,
        fee_delta_sequence: 2,
    };
    let waiter_service = Arc::clone(&service);
    let waiter = std::thread::spawn(move || waiter_service.candidate_for_key(key));
    std::thread::sleep(Duration::from_millis(50));
    shutdown.store(true, Ordering::SeqCst);
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
    // The worker is occupied with the first tip behind the closed gate while
    // the second tip waits in the pending slot: a foreground request for the
    // pending tip must join instead of running a duplicate lazy finish.
    let first_hash = Hash256::from_le_bytes(&[0x71; 32]);
    let second_hash = Hash256::from_le_bytes(&[0x72; 32]);
    let pool = Arc::new(GatedPool::new(5, 2));
    let tip_source = Arc::new(StaticTip(Mutex::new(Some(tip_snapshot(first_hash)))));
    let service = Arc::new(MiningService::new(
        Network::Regtest,
        tip_source.clone(),
        pool.clone(),
        Arc::new(ResolvedChain),
        Vec::new(),
        Arc::new(AtomicBool::new(false)),
    ));
    service.stage_tip(&tip_snapshot(first_hash), &Network::Regtest.genesis_block());
    wait_until_entered(&pool);
    tip_source.set(Some(tip_snapshot(second_hash)));
    service.stage_tip(
        &tip_snapshot(second_hash),
        &Network::Regtest.genesis_block(),
    );
    assert!(
        service
            .prep
            .mailbox()
            .pending
            .as_ref()
            .is_some_and(|pending| pending.tip.hash == second_hash),
        "the second stage must wait in the pending slot while the worker is occupied"
    );
    service.publish_block_generation(second_hash, &MutationResult::empty());
    let key = GenerationKey {
        tip_hash: second_hash,
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
    // A panic inside the projected selection unwinds through the worker's
    // exit guard: the mailbox releases and the joined waiter falls back to
    // lazy assembly, while the unwind and the join payload are logged.
    let tip_hash = Hash256::from_le_bytes(&[0x73; 32]);
    let pool = Arc::new(GatedPool::new(5, 2));
    pool.arm_panic();
    pool.release();
    let service = Arc::new(service_with_source(
        Some(tip_snapshot(tip_hash)),
        pool.clone(),
        Arc::new(ResolvedChain),
        Arc::new(AtomicBool::new(false)),
    ));
    service.stage_tip(&tip_snapshot(tip_hash), &Network::Regtest.genesis_block());
    let deadline = Instant::now() + WAKE_PROOF_TIMEOUT;
    loop {
        if service.prep.mailbox().stopped {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the panicking worker did not release the mailbox"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let key = GenerationKey {
        tip_hash,
        mempool_sequence: 5,
        fee_delta_sequence: 2,
    };
    let waiter_service = Arc::clone(&service);
    let served = std::thread::spawn(move || waiter_service.candidate_for_key(key))
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
    assert!(
        service.prep.mailbox().stopped,
        "the exit guard stops the mailbox when the worker dies"
    );
}

#[test]
fn ready_preparation_parks_until_the_receipt_and_serves_the_prepared_arc() {
    // The reachable race: the pool removal committed and the gateway observer
    // woke a foreground, but the connect effects have not published the
    // receipt yet. The live key equals the key the preparation predicted, so
    // the foreground must join it on the mailbox condvar instead of running a
    // duplicate lazy finish, then receive the very candidate the worker built.
    let tip_hash = Hash256::from_le_bytes(&[0x74; 32]);
    let tip = tip_snapshot(tip_hash);
    let pool = Arc::new(GatedPool::new(5, 2));
    pool.release();
    let service = Arc::new(service_with_source(
        Some(tip.clone()),
        pool.clone(),
        Arc::new(ResolvedChain),
        Arc::new(AtomicBool::new(false)),
    ));
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_ready(&service, tip_hash);
    let prepared = ready_candidate(&service, tip_hash);
    let key = GenerationKey {
        tip_hash,
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
    // A same-tip prioritisation moved the live fee sequence off the
    // preparation's prediction, and no receipt will ever arrive for it: the
    // foreground must fall back at once, and the stale Ready stays in place.
    let tip_hash = Hash256::from_le_bytes(&[0x75; 32]);
    let tip = tip_snapshot(tip_hash);
    let pool = Arc::new(GatedPool::new(5, 2));
    pool.release();
    let shutdown = Arc::new(AtomicBool::new(false));
    let service = Arc::new(service_with_source(
        Some(tip.clone()),
        pool.clone(),
        Arc::new(ResolvedChain),
        Arc::clone(&shutdown),
    ));
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_ready(&service, tip_hash);
    let prepared = ready_candidate(&service, tip_hash);
    *pool.counters.lock() = (5, 9);
    let key = GenerationKey {
        tip_hash,
        mempool_sequence: 5,
        fee_delta_sequence: 9,
    };
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let foreground_service = Arc::clone(&service);
    let foreground = std::thread::spawn(move || {
        let _ = result_tx.send(foreground_service.candidate_for_key(key));
    });
    let Ok(outcome) = result_rx.recv_timeout(WAKE_PROOF_TIMEOUT) else {
        // A wrongly parked foreground: release it through shutdown so the
        // failure cannot hang the harness, then fail.
        shutdown.store(true, Ordering::SeqCst);
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
    assert!(
        service
            .prep
            .mailbox()
            .active
            .as_ref()
            .is_some_and(|active| {
                active.target_tip == tip_hash
                    && matches!(active.progress, PrepProgress::Ready { .. })
            }),
        "the stale Ready is preserved until a newer tip releases it"
    );
}

#[test]
fn nonempty_preparation_installs_against_matching_receipt() {
    // A worker that projected two removals and one cleared overlay predicts
    // membership 5 + 2 and fee 2 + 1: the install matches the wrapping
    // advances, the exact identities and reasons, and the live generation.
    // The Ready state is installed by hand (no worker timing); the install
    // path under test is identical to the worker-fed one.
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
    let tip = tip_snapshot(Hash256::from_le_bytes(&[0x6a; 32]));
    let service = service_with_source(
        Some(tip),
        Arc::new(StaticPool::new(5, 2)),
        chain.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    service.get_block_template(None)?;
    assert_eq!(
        chain.rules_calls.load(Ordering::Relaxed),
        1,
        "the first template resolves its signalling rules"
    );
    service.get_block_template(None)?;
    assert_eq!(
        chain.rules_calls.load(Ordering::Relaxed),
        1,
        "the same tip and height must reuse the cached rules"
    );
    let next_tip = tip_snapshot(Hash256::from_le_bytes(&[0x6b; 32]));
    let next_service = service_with_source(
        Some(next_tip),
        Arc::new(StaticPool::new(5, 2)),
        chain.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    next_service.get_block_template(None)?;
    assert_eq!(
        chain.rules_calls.load(Ordering::Relaxed),
        2,
        "a new tip resolves its own rules once"
    );
    Ok(())
}
