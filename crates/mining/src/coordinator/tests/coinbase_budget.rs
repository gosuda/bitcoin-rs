// CONTRACT: `crates/mining/README.md` owns budgeted template acquisition:
// identity, reuse, finite admission, and the retryable failure classes.
//
// A real pool and block tree prove fit and reuse; a gated capability source
// holds a budgeted walk after it ran, so publication, cancellation, and
// unwinding are observed while the single budgeted slot is occupied.
use super::fee_revision::service_over;
use super::*;
use crate::MiningError;
use crate::template::assemble_candidate;
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::{Sequence, TxIn, Witness};
use std::thread::JoinHandle;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Leaves room for the 98-byte input extension (80 cost units per byte),
/// plus exactly five additional output cost units.
const HEAVY_SIGOPS: u32 = 72_155;

const FITS: CoinbaseBudget = CoinbaseBudget {
    additional_size: 100,
    additional_sigops: 5,
};
/// One sigop cost unit more than the ordinary candidate has room for.
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

/// A pool of one sigop-heavy transaction and one ordinary one paying the same
/// rate. Returns the pool with the heavy and the light txids.
fn heavy_pool() -> TestResult<(Mempool, Txid, Txid)> {
    let mut pool = Mempool::new(MempoolLimits::default());
    let heavy = tx(1);
    let light = tx(2);
    let (heavy_id, light_id) = (heavy.txid(), light.txid());
    // Entries supply admitted mining facts; this is not a consensus-spend test.
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

/// Sigop cost of the whole block: the coinbase and every selected transaction.
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

#[test]
fn tight_budget_gets_a_fitting_selection_not_a_post_selection_refusal() -> TestResult {
    let (pool, heavy, light) = heavy_pool()?;
    let (source, service) = service_over(pool)?;
    let ordinary = service.get_block_template(None, None)?.candidate;
    assert_eq!(sorted(txids(&ordinary)), sorted(vec![heavy, light]));
    // The ordinary candidate leaves exactly five sigop cost units of room.
    ordinary.admits(FITS)?;
    assert!(matches!(
        ordinary.admits(TIGHT),
        Err(MiningError::CapacityExhausted { field: "sigops" })
    ));

    let served = service.get_block_template(None, Some(TIGHT))?.candidate;
    // The selector dropped the heavy transaction; nothing was refused after it.
    served.admits(TIGHT)?;
    assert_eq!(txids(&served), vec![light]);
    assert!(block_sigops(&served) + u64::from(TIGHT.additional_sigops) <= served.max_sigops);
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

    // The same budget in the same generation is answered from the cache.
    let again = service.get_block_template(None, Some(TIGHT))?.candidate;
    assert_eq!(again.template_id, served.template_id);
    assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 1);
    // A different budget is a different candidate with its own walk.
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
    // A fresh budgeted assembly is the newest candidate the node served, so
    // the mining-info observation must describe it, not stay absent.
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

    // A subsequent stricter budget walks again under a new key and the
    // observation follows the newest install.
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
    // The standalone assembler over the same pool and context agrees with what
    // the service served, byte for byte where identity is concerned.
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
fn budgeted_request_reuses_the_ordinary_candidate_when_it_admits_the_budget() -> TestResult {
    let (pool, _, _) = heavy_pool()?;
    let (source, service) = service_over(pool)?;
    let ordinary = service.get_block_template(None, None)?.candidate;
    let served = service.get_block_template(None, Some(FITS))?.candidate;
    // No budgeted selection ran: the ordinary candidate already admits FITS,
    // and the returned id says so.
    assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 0);
    assert_eq!(served.template_id, ordinary.template_id);
    served.admits(FITS)?;
    assert_eq!(txids(&served), txids(&ordinary));
    Ok(())
}

#[test]
fn publication_drops_every_budget_of_the_old_generation_and_the_cache_stays_bounded() -> TestResult
{
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
    // The oldest budget was evicted; asking again reassembles it correctly.
    let first = CoinbaseBudget {
        additional_size: 100,
        additional_sigops: 6,
    };
    service
        .get_block_template(None, Some(first))?
        .candidate
        .admits(first)?;
    assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), walks + 1);

    // A membership change publishes a new generation: every budgeted entry of
    // the old one goes with it.
    source
        .pool
        .lock()
        .insert_entry(MempoolEntry::new(Arc::new(tx(3)), 100, 10_000, 1, 0, 0))?;
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
    // The ordinary template is unaffected.
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
fn budgeted_request_serves_an_installable_preparation_without_discarding_it() -> TestResult {
    let (pool, _, _) = heavy_pool()?;
    let (source, service) = service_over(pool)?;
    let tip = source.tip.clone();
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_ready(&service, tip.hash);
    service.publish_block_generation(tip.hash, &MutationResult::empty());

    let served = service.get_block_template(None, Some(FITS))?.candidate;
    // The preparation answered: the pool was not walked for this request.
    assert_eq!(source.budgeted_walks.load(Ordering::SeqCst), 0);
    assert_eq!(source.ordinary_walks.load(Ordering::SeqCst), 0);
    served.admits(FITS)?;
    assert_eq!(
        served.template_id,
        service.live_generation_key().template_id()
    );
    // It now also serves the ordinary caller; nothing was discarded and
    // reassembled.
    let ordinary = service.get_block_template(None, None)?.candidate;
    assert_eq!(ordinary.template_id, served.template_id);
    assert_eq!(source.ordinary_walks.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn budgeted_request_before_the_receipt_leaves_the_preparation_for_the_ordinary_caller() -> TestResult
{
    let (pool, heavy, light) = heavy_pool()?;
    let (source, service) = service_over(pool)?;
    let tip = source.tip.clone();
    service.stage_tip(&tip, &Network::Regtest.genesis_block());
    wait_until_ready(&service, tip.hash);

    // No committed receipt yet, and the prepared candidate does not admit
    // TIGHT: the request must not park on the preparation or discard it.
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
            active.target_tip == tip.hash && matches!(active.progress, PrepProgress::Ready { .. })
        });
    assert!(
        still_ready,
        "the budgeted request must not touch the preparation"
    );

    // The commit arrives: the ordinary caller installs the very preparation.
    service.publish_block_generation(tip.hash, &MutationResult::empty());
    let ordinary = service.get_block_template(None, None)?.candidate;
    assert_eq!(sorted(txids(&ordinary)), sorted(vec![heavy, light]));
    assert_eq!(source.ordinary_walks.load(Ordering::SeqCst), 0);
    assert!(service.prep.mailbox().active.is_none());
    Ok(())
}

/// Capability source that runs a budgeted selection and then holds its
/// result, so the walk is finished while the slot is still occupied.
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

    /// Parks until released. The deadline fires only on test failure, and
    /// proceeding then still ends the assembler so the service can drop. It
    /// outlasts a caller's whole retry budget (eight one-second slices).
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
        let selected = self
            .inner
            .select_template(expected_sequences, context, payout, budget);
        self.park();
        selected
    }

    fn select_template_after(
        &self,
        block: &Block,
        context: &CandidateContext,
        payout: &[u8],
    ) -> Result<PreparedTemplateBody, MiningControlError> {
        self.inner.select_template_after(block, context, payout)
    }

    fn selection_snapshot(
        &self,
        selection: &GenerateSelection,
        context: &CandidateContext,
    ) -> Result<MempoolMiningSnapshot, MiningControlError> {
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

/// A service over a gated pool at generation `(tip, 5, 2)`.
fn gated_service() -> (
    Arc<MiningService>,
    Arc<BudgetGate>,
    GenerationKey,
    Arc<AtomicBool>,
) {
    let tip = Hash256::from_le_bytes(&[0x71; 32]);
    let pool = Arc::new(BudgetGate::new(5, 2));
    let shutdown = Arc::new(AtomicBool::new(false));
    let service = Arc::new(service_with_source(
        Some(tip_snapshot(tip)),
        pool.clone(),
        Arc::new(ResolvedChain),
        Arc::clone(&shutdown),
    ));
    let generation = GenerationKey {
        tip_hash: tip,
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

/// Blocks until an assembler is parked inside the gated selection. The
/// deadline fires only on failure.
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
fn budgeted_walks_are_serialized_and_a_blocked_caller_gives_up_after_one_slice() -> TestResult {
    let (service, pool, generation, _shutdown) = gated_service();
    pool.hold.store(true, Ordering::SeqCst);
    let holder = spawn_budgeted(&service, generation, BUDGET_A);
    wait_until_held(&pool);

    // A different budget cannot start a second walk. It waits one bounded
    // slice and then fails with a retryable error.
    let started = Instant::now();
    let blocked = service.budgeted_candidate(generation, BUDGET_B);
    assert!(
        matches!(&blocked, Err(error) if error.is_template_generation_race()),
        "{blocked:?}"
    );
    assert!(started.elapsed() < WAKE_PROOF_TIMEOUT);
    assert_eq!(pool.budgeted_calls(), 1);

    // The ordinary template neither waits for the held walk nor displaces it.
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

    // With the slot free, the other budget is answered by the cached ordinary
    // candidate, which admits it: no further walk.
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

    // The whole call, with its eight attempts of one bounded wait each, ends
    // by itself while the walk is still held.
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

    // The holder is untouched, and the same caller succeeds once it releases.
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
    std::thread::sleep(Duration::from_millis(50));
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

    // The generation moves while the walk is held.
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

    // A fresh attempt serves the live generation.
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
    shutdown.store(true, Ordering::SeqCst);
    let outcome = waiter.join().map_err(|_| "the waiter panicked")?;
    assert!(
        matches!(
            &outcome,
            Err(MiningControlError::Unavailable(message))
                if message.as_str() == "node is shutting down"
        ),
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
