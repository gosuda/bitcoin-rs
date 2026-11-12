use super::{
    Action, AllocationOwner, BudgetError, BudgetState, safety, step,
    step_mutant_ingress_invalidation, step_mutant_mdbx_engine_cache,
};

fn any_budget_state() -> BudgetState {
    let mut charges = [0u32; 7];
    let mut reserved = [0u32; 7];
    let mut i = 0;
    while i < 7 {
        let c: u32 = kani::any();
        let r: u32 = kani::any();
        kani::assume(c <= 4);
        kani::assume(r <= 4);
        charges[i] = c;
        reserved[i] = r;
        i += 1;
    }
    let block_staged: bool = kani::any();
    let block_refused: bool = kani::any();
    let is_mdbx: bool = kani::any();
    let total_budget: u32 = 4;
    let foreground_reserve: u32 = 1;
    let consensus_invalid: bool = kani::any();
    kani::assume(!consensus_invalid);

    BudgetState {
        charges,
        reserved,
        block_staged,
        block_refused,
        consensus_invalid,
        is_mdbx,
        total_budget,
        foreground_reserve,
        owner_caps: [total_budget; 7],
    }
}

fn any_owner() -> AllocationOwner {
    let tag: u8 = kani::any();
    kani::assume(tag < 7);
    match tag {
        0 => AllocationOwner::CoinCache,
        1 => AllocationOwner::EngineCache,
        2 => AllocationOwner::FactsQueue,
        3 => AllocationOwner::IndexBuilder,
        4 => AllocationOwner::StagedImages,
        5 => AllocationOwner::QueryViews,
        _ => AllocationOwner::PeerOutbound,
    }
}

fn any_bg_owner() -> AllocationOwner {
    let tag: u8 = kani::any();
    kani::assume(tag < 3);
    match tag {
        0 => AllocationOwner::FactsQueue,
        1 => AllocationOwner::IndexBuilder,
        _ => AllocationOwner::QueryViews,
    }
}

fn any_action() -> Action {
    let tag: u8 = kani::any();
    let amt: u32 = kani::any();
    kani::assume(tag < 18);
    kani::assume(amt <= 2);
    match tag {
        0 => Action::ReserveIngress(amt),
        1 => Action::RefuseIngress(amt),
        2 => Action::AllocateIngress(amt),
        3 => Action::ApplyBlock(amt),
        4 => Action::ReserveBackground(any_bg_owner(), amt),
        5 => Action::AllocateBackground(any_bg_owner(), amt),
        6 => Action::ReleaseBackground(any_bg_owner(), amt),
        7 => Action::ReserveCoinCache(amt),
        8 => Action::AllocateCoinCache(amt),
        9 => Action::ReleaseCoinCache(amt),
        10 => Action::GrowEngineCache(amt),
        11 => Action::ShrinkEngineCache(amt),
        12 => Action::ReserveEngineCache(amt),
        13 => Action::AllocateEngineCache(amt),
        14 => Action::ReleaseEngineCache(amt),
        15 => Action::ReservePeerOutbound(amt),
        16 => Action::AllocatePeerOutbound(amt),
        17 => Action::ReleasePeerOutbound(amt),
        _ => Action::Stutter,
    }
}

// BUD-01, BUD-02, BUD-05, BUD-06, BUD-07
#[kani::proof]
fn harness_budget_step_inductive_safety() {
    let s = any_budget_state();
    kani::assume(safety(&s));
    let a = any_action();
    let s_next = step(&s, a);
    assert!(safety(&s_next));
}

// BUD-01
#[kani::proof]
fn harness_reservation_before_allocation() {
    let mut s = any_budget_state();
    kani::assume(safety(&s));
    let owner = any_owner();
    s.reserved[owner.index()] = 0;
    let amt: u32 = kani::any();
    kani::assume(amt > 0 && amt <= 2);
    let original_charge = s.charges[owner.index()];
    let res = s.allocate(owner, amt);
    assert_eq!(res, Err(BudgetError::UnreservedAllocation));
    assert_eq!(s.charges[owner.index()], original_charge);
}

// BUD-03
#[kani::proof]
fn harness_ingress_refusal_never_invalidates_consensus() {
    let s = any_budget_state();
    kani::assume(safety(&s));
    let req: u32 = kani::any();
    kani::assume(req > 0 && req <= 4);
    kani::assume(s.total_committed() + u64::from(req) > u64::from(s.total_budget));
    let mut s_mut = s.clone();
    let res = s_mut.reserve_ingress(req);
    assert_eq!(res, Err(BudgetError::BudgetExhausted));
    let s_next = step(&s, Action::ReserveIngress(req));
    assert!(s_next.block_refused);
    assert!(!s_next.consensus_invalid);
}

// BUD-05
#[kani::proof]
fn harness_foreground_capacity_preserved() {
    let mut s = any_budget_state();
    kani::assume(safety(&s));
    let owner = any_bg_owner();
    let amt: u32 = kani::any();
    kani::assume(amt <= 2);
    let _ = s.reserve(owner, amt);
    assert!(
        s.background_committed() <= u64::from(s.total_budget.saturating_sub(s.foreground_reserve))
    );
}

// BUD-06, BUD-07
#[kani::proof]
fn harness_total_charges_and_reservations_bounded() {
    let s = any_budget_state();
    kani::assume(safety(&s));
    let a = any_action();
    let s_next = step(&s, a);
    assert!(s_next.total_committed() <= u64::from(s_next.total_budget));
}

// BUD-06
#[kani::proof]
fn harness_mdbx_zero_engine_cache_reporting() {
    let s = any_budget_state();
    kani::assume(s.is_mdbx);
    kani::assume(safety(&s));
    let a = any_action();
    let s_next = step(&s, a);
    assert_eq!(s_next.charges[AllocationOwner::EngineCache.index()], 0);
    assert_eq!(s_next.reserved[AllocationOwner::EngineCache.index()], 0);
}

// BUD-06
#[kani::proof]
#[kani::should_panic]
fn harness_negative_control_mdbx_engine_cache_reporting() {
    let s = any_budget_state();
    kani::assume(s.is_mdbx);
    kani::assume(safety(&s));
    let amt: u32 = kani::any();
    kani::assume(amt > 0 && amt <= 2);
    let s_next = step_mutant_mdbx_engine_cache(&s, Action::GrowEngineCache(amt));
    assert_eq!(s_next.charges[AllocationOwner::EngineCache.index()], 0);
    assert_eq!(s_next.reserved[AllocationOwner::EngineCache.index()], 0);
}

// BUD-03
#[kani::proof]
#[kani::should_panic]
fn harness_negative_control_ingress_refusal_invalidation() {
    let s = any_budget_state();
    kani::assume(safety(&s));
    let req: u32 = kani::any();
    kani::assume(req > 0 && req <= 4);
    kani::assume(s.total_committed() + u64::from(req) > u64::from(s.total_budget));
    let s_next = step_mutant_ingress_invalidation(&s, Action::ReserveIngress(req));
    assert!(!s_next.consensus_invalid);
}
