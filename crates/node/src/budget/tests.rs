use super::{BudgetCaps, NodeBudget, STAGED_IMAGE_BUDGET_BYTES};
use crate::budget_model::{self, Action, AllocationOwner};
use bitcoin_rs_execution::WindowLimits;
use bitcoin_rs_storage::budget::{BudgetError, BudgetOwner, BudgetRefusal, ChargeHandle};
use bitcoin_rs_storage::{CoinKey, CoinStore, MemoryKvStore, WindowDelta};
use bytes::Bytes;
use std::sync::Arc;

const AMOUNT_CAP: u32 = 20_000;
const OWNER_CAP: u64 = 20_000;
const MODEL_TOTAL: u32 = 7 * 20_000;
const MODEL_FOREGROUND: u32 = 64_000;
const DIFFERENTIAL_STEPS: usize = 4_000;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn amount(&mut self) -> u32 {
        u32::try_from(self.next() % u64::from(AMOUNT_CAP)).unwrap_or(1) + 1
    }
}

fn differential_caps() -> BudgetCaps {
    BudgetCaps {
        staged_images: OWNER_CAP,
        engine_cache: OWNER_CAP,
        coin_cache: OWNER_CAP,
        facts_queue: OWNER_CAP,
        index_builder: OWNER_CAP,
        query_views: OWNER_CAP,
        peer_outbound: OWNER_CAP,
        foreground_reserve: 64_000,
    }
}

fn owner_of_model(owner: crate::budget_model::AllocationOwner) -> BudgetOwner {
    match owner {
        crate::budget_model::AllocationOwner::CoinCache => BudgetOwner::CoinCache,
        crate::budget_model::AllocationOwner::EngineCache => BudgetOwner::EngineCache,
        crate::budget_model::AllocationOwner::FactsQueue => BudgetOwner::FactsQueue,
        crate::budget_model::AllocationOwner::IndexBuilder => BudgetOwner::IndexBuilder,
        crate::budget_model::AllocationOwner::StagedImages => BudgetOwner::StagedImages,
        crate::budget_model::AllocationOwner::QueryViews => BudgetOwner::QueryViews,
        crate::budget_model::AllocationOwner::PeerOutbound => BudgetOwner::PeerOutbound,
    }
}

const ALL_OWNERS: [BudgetOwner; 7] = [
    BudgetOwner::CoinCache,
    BudgetOwner::EngineCache,
    BudgetOwner::FactsQueue,
    BudgetOwner::IndexBuilder,
    BudgetOwner::StagedImages,
    BudgetOwner::QueryViews,
    BudgetOwner::PeerOutbound,
];

fn ledger_of(budget: &NodeBudget) -> ([u64; 7], [u64; 7], bool) {
    let charges = ALL_OWNERS.map(|owner| budget.available_of_charges(owner));
    let reserved = ALL_OWNERS.map(|owner| budget.available_of_reservations(owner));
    (charges, reserved, budget.ingress_refused())
}

fn assert_ledger_matches(budget: &NodeBudget, state: &budget_model::BudgetState, site: &str) {
    let (charges, reserved, refused) = ledger_of(budget);
    for index in 0..ALL_OWNERS.len() {
        assert_eq!(
            charges[index],
            u64::from(state.charges[index]),
            "charges diverge at owner {index} after {site}"
        );
        assert_eq!(
            reserved[index],
            u64::from(state.reserved[index]),
            "reserved diverges at owner {index} after {site}"
        );
    }
    let _ = (charges, reserved, refused);
    assert_eq!(
        refused, state.block_refused,
        "refusal flag diverges after {site}"
    );
    assert!(
        !state.consensus_invalid,
        "a budget step marked a block consensus-invalid at {site}"
    );
    assert!(budget.is_safe(), "budget invariant broke after {site}");
    assert!(
        budget_model::safety(state),
        "model invariant broke after {site}"
    );
}

fn random_action(rng: &mut XorShift, background: bool) -> Action {
    let pick = rng.next() % 14;
    let amount = rng.amount();
    match pick {
        0 => Action::ReserveIngress(amount),
        1 => Action::RefuseIngress(amount),
        2 => Action::AllocateIngress(amount),
        3 => Action::ApplyBlock(amount),
        4 => {
            let owner = match rng.next() % 3 {
                0 => AllocationOwner::FactsQueue,
                1 => AllocationOwner::IndexBuilder,
                _ => AllocationOwner::QueryViews,
            };
            match rng.next() % 3 {
                0 => Action::ReserveBackground(owner, amount),
                1 => Action::AllocateBackground(owner, amount),
                _ => Action::ReleaseBackground(owner, amount),
            }
        }
        5 => Action::ReserveCoinCache(amount),
        6 => Action::AllocateCoinCache(amount),
        7 => Action::ReleaseCoinCache(amount),
        8 => Action::GrowEngineCache(amount),
        9 => Action::ShrinkEngineCache(amount),
        10 => Action::ReservePeerOutbound(amount),
        11 => Action::AllocatePeerOutbound(amount),
        12 => Action::ReleasePeerOutbound(amount),
        _ if background => Action::Stutter,
        _ => match rng.next() % 2 {
            0 => Action::Stutter,
            _ => Action::ReserveIngress(amount),
        },
    }
}

fn apply_action(budget: &NodeBudget, action: &Action) {
    match *action {
        Action::ReserveIngress(amount) => {
            reserve(budget, BudgetOwner::StagedImages, amount);
        }
        Action::RefuseIngress(amount) => {
            budget.note_ingress_refusal_when_exhausted(u64::from(amount));
        }
        Action::AllocateIngress(amount) => {
            allocate(budget, BudgetOwner::StagedImages, amount);
        }
        Action::ApplyBlock(amount) => {
            release(budget, BudgetOwner::StagedImages, amount);
        }
        Action::ReserveBackground(owner, amount) => {
            reserve(budget, owner_of_model(owner), amount);
        }
        Action::AllocateBackground(owner, amount) => {
            allocate(budget, owner_of_model(owner), amount);
        }
        Action::ReleaseBackground(owner, amount) => {
            release(budget, owner_of_model(owner), amount);
        }
        Action::ReserveCoinCache(amount) => {
            reserve(budget, BudgetOwner::CoinCache, amount);
        }
        Action::AllocateCoinCache(amount) => {
            allocate(budget, BudgetOwner::CoinCache, amount);
        }
        Action::ReleaseCoinCache(amount) => {
            release(budget, BudgetOwner::CoinCache, amount);
        }
        Action::GrowEngineCache(amount) => budget.grow_engine_cache(u64::from(amount)),
        Action::ShrinkEngineCache(amount) => budget.shrink_engine_cache(u64::from(amount)),
        Action::ReserveEngineCache(amount) => {
            reserve(budget, BudgetOwner::EngineCache, amount);
        }
        Action::AllocateEngineCache(amount) => {
            allocate(budget, BudgetOwner::EngineCache, amount);
        }
        Action::ReleaseEngineCache(amount) => {
            release(budget, BudgetOwner::EngineCache, amount);
        }
        Action::ReservePeerOutbound(amount) => {
            reserve(budget, BudgetOwner::PeerOutbound, amount);
        }
        Action::AllocatePeerOutbound(amount) => {
            allocate(budget, BudgetOwner::PeerOutbound, amount);
        }
        Action::ReleasePeerOutbound(amount) => {
            release(budget, BudgetOwner::PeerOutbound, amount);
        }
        Action::Stutter => {}
    }
}

fn reserve(budget: &NodeBudget, owner: BudgetOwner, amount: u32) {
    let _ = budget.reserve(owner, u64::from(amount));
}

fn allocate(budget: &NodeBudget, owner: BudgetOwner, amount: u32) {
    let _ = budget.allocate(owner, u64::from(amount));
}

fn release(budget: &NodeBudget, owner: BudgetOwner, amount: u32) {
    let _ = budget.release(owner, u64::from(amount));
}

fn run_byte_differential(seed: u64) {
    run_model_differential(&NodeBudget::new(differential_caps(), 4), seed, false);
}

fn run_mdbx_differential(seed: u64) {
    run_model_differential(&NodeBudget::new(differential_caps(), 4), seed, true);
}

fn run_model_differential(budget: &NodeBudget, seed: u64, is_mdbx: bool) {
    budget.set_mdbx(is_mdbx);
    let mut state = if is_mdbx {
        budget_model::BudgetState::init_mdbx(MODEL_TOTAL, MODEL_FOREGROUND)
    } else {
        budget_model::BudgetState::init(MODEL_TOTAL, MODEL_FOREGROUND)
    };
    let mut rng = XorShift(seed);
    let mut trace: Vec<String> = Vec::new();
    for step in 0..DIFFERENTIAL_STEPS {
        let action = random_action(&mut rng, is_mdbx);
        trace.push(format!("{action:?}"));
        state = budget_model::step(&state, action);
        apply_action(budget, &action);
        assert_ledger_matches(
            budget,
            &state,
            &format!("seed {seed} step {step} trace {}", trace.join(" | ")),
        );
    }
}

// BUD-01, BUD-02, BUD-05, BUD-06
#[test]
fn implementation_tracks_the_reference_model_step_for_step() {
    for seed in [0x2A_1C, 0xDEAD_BEEF, 0x5EED_5EED] {
        run_byte_differential(seed);
        run_mdbx_differential(seed);
    }
}

// BUD-03
#[test]
fn exhausted_ingress_refuses_without_consent_invalidation() {
    let budget = NodeBudget::from_dbcache_bytes(64, 4);
    let oversized = STAGED_IMAGE_BUDGET_BYTES + 1;
    assert_eq!(
        budget.reserve(BudgetOwner::StagedImages, oversized),
        Err(BudgetError::BudgetExhausted)
    );
    assert!(budget.ingress_refused());
    let Err(error) = budget.reserve(BudgetOwner::StagedImages, oversized) else {
        panic!("an oversized reservation must be refused");
    };
    assert_eq!(error.refusal(), Some(BudgetRefusal::RetryLater));
    assert!(budget.is_safe());
    assert_eq!(
        budget.total_committed(),
        0,
        "a refused reservation must not consume budget"
    );
}

// BUD-05
#[test]
fn background_reservations_stop_at_the_foreground_reserve() {
    let mut caps = differential_caps();
    caps.facts_queue = 60_000;
    caps.foreground_reserve = 130_000;
    let budget = NodeBudget::new(caps, 4);
    let ceiling = caps.total().saturating_sub(caps.foreground_reserve);
    let beyond = ceiling.saturating_add(1);
    assert_eq!(
        budget.reserve(BudgetOwner::FactsQueue, beyond),
        Err(BudgetError::BudgetExhausted)
    );
    assert!(
        budget.reserve(BudgetOwner::FactsQueue, ceiling).is_ok(),
        "background share up to the reserve ceiling must be granted"
    );
    assert_eq!(
        budget.reserve(BudgetOwner::FactsQueue, 1),
        Err(BudgetError::BudgetExhausted)
    );
    assert!(budget.is_safe());
}

// BUD-06
#[test]
fn engine_cache_charge_follows_the_model_gate_and_cap() {
    let caps = differential_caps();
    let budget = NodeBudget::new(caps, 4);
    budget.grow_engine_cache(1_500);
    assert_eq!(budget.available_of_charges(BudgetOwner::EngineCache), 1_500);
    budget.grow_engine_cache(caps.total());
    assert_eq!(
        budget.available_of_charges(BudgetOwner::EngineCache),
        1_500,
        "engine growth past the total budget must be rejected"
    );
    budget.set_engine_cache_source(Some(Box::new(|| OWNER_CAP + 1)));
    budget.sample_engine_cache();
    assert_eq!(
        budget.available_of_charges(BudgetOwner::EngineCache),
        OWNER_CAP,
        "engine sampling clamps at the owner cap"
    );
    budget.shrink_engine_cache(500);
    assert_eq!(
        budget.available_of_charges(BudgetOwner::EngineCache),
        OWNER_CAP - 500
    );
    assert!(budget.is_safe());
}

// BUD-06
#[test]
fn mdbx_reports_a_zero_engine_cache_charge() {
    let budget = NodeBudget::new(differential_caps(), 4);
    budget.set_mdbx(true);
    budget.grow_engine_cache(4_096);
    assert_eq!(budget.available_of_charges(BudgetOwner::EngineCache), 0);
    assert_eq!(
        budget.reserve(BudgetOwner::EngineCache, 1),
        Err(BudgetError::EngineCacheUnsupported)
    );
    assert!(budget.is_safe());
}

#[test]
fn window_limits_shrink_with_staged_headroom() {
    let budget = NodeBudget::from_dbcache_bytes(16, 4);
    assert_eq!(
        budget.window_limits(),
        WindowLimits::durable_head_defaults()
    );
    assert!(
        budget
            .reserve(BudgetOwner::StagedImages, STAGED_IMAGE_BUDGET_BYTES - 1)
            .is_ok(),
        "reservation inside the staged cap must be granted"
    );
    assert_eq!(
        budget.window_limits(),
        WindowLimits {
            max_blocks: 64,
            max_bytes: 1,
        }
    );
}

#[test]
fn background_cpu_permits_stop_at_the_foreground_share() {
    let budget = NodeBudget::from_dbcache_bytes(16, 4);
    let cpu = budget.cpu();
    let Some(first) = cpu.try_acquire_background() else {
        panic!("one background permit inside the share must be granted");
    };
    let second = cpu.try_acquire_background();
    let third = cpu.try_acquire_background();
    let fourth = cpu.try_acquire_background();
    assert!(second.is_some() && third.is_some());
    assert!(
        fourth.is_none(),
        "a four worker pool with one reserved share grants at most three background permits"
    );
    drop(third);
    assert!(
        cpu.try_acquire_background().is_some(),
        "released background share must be reusable"
    );
    drop(first);
    drop(second);
    let guard = cpu.acquire_foreground();
    assert_eq!(cpu.foreground_active(), 1);
    drop(guard);
    assert_eq!(cpu.foreground_active(), 0);
}

// BUD-06
#[test]
#[expect(clippy::expect_used)]
fn coin_cache_fill_charges_the_coin_cache_owner_and_wipe_returns_it() {
    let budget = Arc::new(NodeBudget::from_dbcache_bytes(64 * 1024 * 1024, 4));
    let charge = ChargeHandle::new(budget.clone(), BudgetOwner::CoinCache);
    let coins = CoinStore::open_with_charge(
        Arc::new(MemoryKvStore::new()),
        64 * 1024 * 1024,
        Some(charge),
    );
    let key = CoinKey([7; 32]);
    let value = Bytes::from(vec![0xab_u8; 1024]);
    let mut delta = WindowDelta::default();
    delta.push_final(key, Some(value));
    coins.ingest_chunk(&delta).expect("ingest succeeds");
    assert_eq!(
        budget.available_of_charges(BudgetOwner::CoinCache),
        0,
        "a durable write alone does not fill the cache"
    );
    coins.get(&key).expect("read succeeds");
    assert_eq!(
        budget.available_of_charges(BudgetOwner::CoinCache),
        1024,
        "the read fill charges the coin cache"
    );
    coins.wipe().expect("wipe succeeds");
    assert_eq!(
        budget.available_of_charges(BudgetOwner::CoinCache),
        0,
        "wipe returns the coin cache charge"
    );
}
