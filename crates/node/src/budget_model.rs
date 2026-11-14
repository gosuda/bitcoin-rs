//! Executable reference model for node-wide budget accounting and resource reservation.

#[cfg(kani)]
mod proofs;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationOwner {
    CoinCache = 0,
    EngineCache = 1,
    FactsQueue = 2,
    IndexBuilder = 3,
    StagedImages = 4,
    QueryViews = 5,
    PeerOutbound = 6,
}

impl AllocationOwner {
    #[inline]
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::CoinCache => 0,
            Self::EngineCache => 1,
            Self::FactsQueue => 2,
            Self::IndexBuilder => 3,
            Self::StagedImages => 4,
            Self::QueryViews => 5,
            Self::PeerOutbound => 6,
        }
    }

    #[inline]
    #[must_use]
    pub(crate) const fn is_background(self) -> bool {
        matches!(
            self,
            Self::FactsQueue | Self::IndexBuilder | Self::QueryViews
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BudgetError {
    #[error("allocation attempted without prior reservation")]
    UnreservedAllocation,
    #[error("budget exhausted; request refused")]
    BudgetExhausted,
    #[error("insufficient charge to release")]
    InsufficientCharge,
    #[error("engine cache accounting is unsupported for this backend")]
    EngineCacheUnsupported,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BudgetState {
    pub(crate) charges: [u32; 7],
    pub(crate) reserved: [u32; 7],
    pub(crate) block_staged: bool,
    pub(crate) block_refused: bool,
    pub(crate) consensus_invalid: bool,
    pub(crate) is_mdbx: bool,
    pub(crate) total_budget: u32,
    pub(crate) foreground_reserve: u32,
    pub(crate) owner_caps: [u32; 7],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    ReserveIngress(u32),
    RefuseIngress(u32),
    AllocateIngress(u32),
    ApplyBlock(u32),
    ReserveBackground(AllocationOwner, u32),
    AllocateBackground(AllocationOwner, u32),
    ReleaseBackground(AllocationOwner, u32),
    ReserveCoinCache(u32),
    AllocateCoinCache(u32),
    ReleaseCoinCache(u32),
    GrowEngineCache(u32),
    ShrinkEngineCache(u32),
    ReserveEngineCache(u32),
    AllocateEngineCache(u32),
    ReleaseEngineCache(u32),
    ReservePeerOutbound(u32),
    AllocatePeerOutbound(u32),
    ReleasePeerOutbound(u32),
    Stutter,
}

impl BudgetState {
    #[must_use]
    pub(crate) const fn init(total_budget: u32, foreground_reserve: u32) -> Self {
        Self {
            charges: [0; 7],
            reserved: [0; 7],
            block_staged: false,
            block_refused: false,
            consensus_invalid: false,
            is_mdbx: false,
            total_budget,
            foreground_reserve,
            owner_caps: [total_budget; 7],
        }
    }

    #[must_use]
    pub(crate) const fn init_mdbx(total_budget: u32, foreground_reserve: u32) -> Self {
        Self {
            charges: [0; 7],
            reserved: [0; 7],
            block_staged: false,
            block_refused: false,
            consensus_invalid: false,
            is_mdbx: true,
            total_budget,
            foreground_reserve,
            owner_caps: [total_budget; 7],
        }
    }

    #[must_use]
    pub(crate) fn total_charges(&self) -> u64 {
        self.charges.iter().copied().map(u64::from).sum()
    }

    #[must_use]
    pub(crate) fn total_reserved(&self) -> u64 {
        self.reserved.iter().copied().map(u64::from).sum()
    }

    #[must_use]
    pub(crate) fn total_committed(&self) -> u64 {
        self.total_charges() + self.total_reserved()
    }

    #[must_use]
    pub(crate) fn background_committed(&self) -> u64 {
        u64::from(self.charges[AllocationOwner::FactsQueue.index()])
            + u64::from(self.charges[AllocationOwner::IndexBuilder.index()])
            + u64::from(self.charges[AllocationOwner::QueryViews.index()])
            + u64::from(self.reserved[AllocationOwner::FactsQueue.index()])
            + u64::from(self.reserved[AllocationOwner::IndexBuilder.index()])
            + u64::from(self.reserved[AllocationOwner::QueryViews.index()])
    }

    pub(crate) fn reserve(&mut self, owner: AllocationOwner, amt: u32) -> Result<(), BudgetError> {
        let total = self.total_committed();
        let amt_u64 = u64::from(amt);
        let idx = owner.index();
        if total + amt_u64 > u64::from(self.total_budget)
            || u64::from(self.charges[idx]) + u64::from(self.reserved[idx]) + amt_u64
                > u64::from(self.owner_caps[idx])
        {
            if owner == AllocationOwner::StagedImages {
                self.block_refused = true;
            }
            return Err(BudgetError::BudgetExhausted);
        }
        if owner.is_background() {
            let bg_max = u64::from(self.total_budget.saturating_sub(self.foreground_reserve));
            if self.background_committed() + amt_u64 > bg_max {
                return Err(BudgetError::BudgetExhausted);
            }
        }
        if self.is_mdbx && owner == AllocationOwner::EngineCache {
            return Err(BudgetError::EngineCacheUnsupported);
        }
        self.reserved[idx] = self.reserved[idx].saturating_add(amt);
        Ok(())
    }

    pub(crate) fn allocate(&mut self, owner: AllocationOwner, amt: u32) -> Result<(), BudgetError> {
        if amt == 0 {
            return Ok(());
        }
        let idx = owner.index();
        let res = &mut self.reserved[idx];
        if *res < amt {
            return Err(BudgetError::UnreservedAllocation);
        }
        *res -= amt;
        self.charges[idx] = self.charges[idx].saturating_add(amt);
        if owner == AllocationOwner::StagedImages {
            self.block_staged = true;
        }
        Ok(())
    }

    pub(crate) fn release(&mut self, owner: AllocationOwner, amt: u32) -> Result<(), BudgetError> {
        if amt == 0 {
            return Ok(());
        }
        let idx = owner.index();
        let chg = &mut self.charges[idx];
        if *chg < amt {
            return Err(BudgetError::InsufficientCharge);
        }
        *chg -= amt;
        if owner == AllocationOwner::StagedImages && *chg == 0 {
            self.block_staged = false;
        }
        Ok(())
    }

    pub(crate) fn reserve_ingress(&mut self, amt: u32) -> Result<(), BudgetError> {
        self.reserve(AllocationOwner::StagedImages, amt)
    }

    pub(crate) fn allocate_ingress(&mut self, amt: u32) -> Result<(), BudgetError> {
        self.allocate(AllocationOwner::StagedImages, amt)
    }

    pub(crate) fn apply_block(&mut self, amt: u32) -> Result<(), BudgetError> {
        self.release(AllocationOwner::StagedImages, amt)
    }
}

// BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
#[must_use]
pub(crate) fn step(s: &BudgetState, a: Action) -> BudgetState {
    let mut next = s.clone();
    match a {
        Action::ReserveIngress(amt) => {
            let _ = next.reserve_ingress(amt);
        }
        Action::RefuseIngress(amt) => {
            if next.total_committed() + u64::from(amt) > u64::from(next.total_budget) {
                next.block_refused = true;
            }
        }
        Action::AllocateIngress(amt) => {
            let _ = next.allocate_ingress(amt);
        }
        Action::ApplyBlock(amt) => {
            let _ = next.apply_block(amt);
        }
        Action::ReserveBackground(owner, amt) => {
            if owner.is_background() {
                let _ = next.reserve(owner, amt);
            }
        }
        Action::AllocateBackground(owner, amt) => {
            if owner.is_background() {
                let _ = next.allocate(owner, amt);
            }
        }
        Action::ReleaseBackground(owner, amt) => {
            if owner.is_background() {
                let _ = next.release(owner, amt);
            }
        }
        Action::ReserveCoinCache(amt) => {
            let _ = next.reserve(AllocationOwner::CoinCache, amt);
        }
        Action::AllocateCoinCache(amt) => {
            let _ = next.allocate(AllocationOwner::CoinCache, amt);
        }
        Action::ReleaseCoinCache(amt) => {
            let _ = next.release(AllocationOwner::CoinCache, amt);
        }
        Action::GrowEngineCache(amt) => {
            if !next.is_mdbx {
                let idx = AllocationOwner::EngineCache.index();
                if next.total_committed() + u64::from(amt) <= u64::from(next.total_budget)
                    && u64::from(next.charges[idx]) + u64::from(next.reserved[idx]) + u64::from(amt)
                        <= u64::from(next.owner_caps[idx])
                {
                    next.charges[idx] = next.charges[idx].saturating_add(amt);
                }
            }
        }
        Action::ShrinkEngineCache(amt) => {
            if !next.is_mdbx {
                let idx = AllocationOwner::EngineCache.index();
                let chg = &mut next.charges[idx];
                if *chg >= amt {
                    *chg -= amt;
                }
            }
        }
        Action::ReserveEngineCache(amt) => {
            let _ = next.reserve(AllocationOwner::EngineCache, amt);
        }
        Action::AllocateEngineCache(amt) => {
            let _ = next.allocate(AllocationOwner::EngineCache, amt);
        }
        Action::ReleaseEngineCache(amt) => {
            let _ = next.release(AllocationOwner::EngineCache, amt);
        }
        Action::ReservePeerOutbound(amt) => {
            let _ = next.reserve(AllocationOwner::PeerOutbound, amt);
        }
        Action::AllocatePeerOutbound(amt) => {
            let _ = next.allocate(AllocationOwner::PeerOutbound, amt);
        }
        Action::ReleasePeerOutbound(amt) => {
            let _ = next.release(AllocationOwner::PeerOutbound, amt);
        }
        Action::Stutter => {}
    }
    next
}

// BUD-03
#[must_use]
pub(crate) fn step_mutant_ingress_invalidation(s: &BudgetState, a: Action) -> BudgetState {
    let mut next = s.clone();
    match a {
        Action::ReserveIngress(amt) => {
            if next.total_committed() + u64::from(amt) > u64::from(next.total_budget) {
                next.block_refused = true;
                next.consensus_invalid = true;
            } else {
                let _ = next.reserve_ingress(amt);
            }
        }
        Action::RefuseIngress(amt) => {
            if next.total_committed() + u64::from(amt) > u64::from(next.total_budget) {
                next.block_refused = true;
                next.consensus_invalid = true;
            }
        }
        _ => return step(s, a),
    }
    next
}

// BUD-06
#[must_use]
pub(crate) fn step_mutant_mdbx_engine_cache(s: &BudgetState, a: Action) -> BudgetState {
    let mut next = s.clone();
    match a {
        Action::GrowEngineCache(amt) => {
            let idx = AllocationOwner::EngineCache.index();
            next.charges[idx] = next.charges[idx].saturating_add(amt);
        }
        Action::AllocateEngineCache(amt) => {
            let idx = AllocationOwner::EngineCache.index();
            next.charges[idx] = next.charges[idx].saturating_add(amt);
        }
        _ => return step(s, a),
    }
    next
}

/// Safety invariant for NodeBudget.
// BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
#[must_use]
pub(crate) fn safety(s: &BudgetState) -> bool {
    let total_committed = s.total_committed();
    let bg_committed = s.background_committed();
    let engine_idx = AllocationOwner::EngineCache.index();

    total_committed <= u64::from(s.total_budget)
        && bg_committed <= u64::from(s.total_budget.saturating_sub(s.foreground_reserve))
        && (0..7).all(|idx| {
            u64::from(s.charges[idx]) + u64::from(s.reserved[idx]) <= u64::from(s.owner_caps[idx])
        })
        && (!s.block_refused || !s.consensus_invalid)
        && (!s.is_mdbx || (s.charges[engine_idx] == 0 && s.reserved[engine_idx] == 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};

    // BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
    #[test]
    fn init_state_satisfies_safety() {
        let s = BudgetState::init(4, 1);
        assert!(safety(&s));
        assert_eq!(s.total_committed(), 0);
        assert_eq!(s.background_committed(), 0);
        assert!(!s.block_refused);
        assert!(!s.consensus_invalid);

        let s_mdbx = BudgetState::init_mdbx(4, 1);
        assert!(safety(&s_mdbx));
    }

    // BUD-01
    #[test]
    fn reservation_before_allocation_enforced() {
        let mut s = BudgetState::init(4, 1);
        assert_eq!(
            s.allocate(AllocationOwner::CoinCache, 1),
            Err(BudgetError::UnreservedAllocation)
        );
        assert_eq!(s.charges[AllocationOwner::CoinCache.index()], 0);

        assert!(s.reserve(AllocationOwner::CoinCache, 2).is_ok());
        assert_eq!(s.reserved[AllocationOwner::CoinCache.index()], 2);
        assert_eq!(s.charges[AllocationOwner::CoinCache.index()], 0);

        assert!(s.allocate(AllocationOwner::CoinCache, 1).is_ok());
        assert_eq!(s.reserved[AllocationOwner::CoinCache.index()], 1);
        assert_eq!(s.charges[AllocationOwner::CoinCache.index()], 1);
        assert!(safety(&s));
    }

    // BUD-03
    #[test]
    fn ingress_refusal_preserves_consensus_validity() {
        let mut s = BudgetState::init(4, 1);
        assert!(s.reserve_ingress(4).is_ok());
        assert_eq!(s.total_committed(), 4);

        assert_eq!(s.reserve_ingress(1), Err(BudgetError::BudgetExhausted));
        assert!(s.block_refused);
        assert!(!s.consensus_invalid);
        assert!(safety(&s));

        let s_refused = step(&s, Action::RefuseIngress(1));
        assert!(s_refused.block_refused);
        assert!(!s_refused.consensus_invalid);
        assert!(safety(&s_refused));
    }

    // BUD-05
    #[test]
    fn foreground_capacity_preserved_under_background_load() {
        let mut s = BudgetState::init(4, 1);
        assert!(s.reserve(AllocationOwner::FactsQueue, 2).is_ok());
        assert!(s.reserve(AllocationOwner::IndexBuilder, 1).is_ok());
        assert_eq!(s.background_committed(), 3);

        assert_eq!(
            s.reserve(AllocationOwner::QueryViews, 1),
            Err(BudgetError::BudgetExhausted)
        );
        assert_eq!(s.background_committed(), 3);
        assert!(s.total_committed() <= u64::from(s.total_budget) - u64::from(s.foreground_reserve));

        assert!(s.reserve_ingress(1).is_ok());
        assert_eq!(s.total_committed(), 4);
        assert!(safety(&s));
    }

    // BUD-06, BUD-07
    #[test]
    fn total_budget_strictly_bounds_committed() {
        let mut s = BudgetState::init(4, 1);
        assert!(s.reserve(AllocationOwner::CoinCache, 2).is_ok());
        assert!(s.allocate(AllocationOwner::CoinCache, 2).is_ok());
        assert!(s.reserve(AllocationOwner::FactsQueue, 2).is_ok());
        assert_eq!(s.total_committed(), 4);

        assert_eq!(
            s.reserve(AllocationOwner::StagedImages, 1),
            Err(BudgetError::BudgetExhausted)
        );
        assert_eq!(s.total_committed(), 4);
        assert!(safety(&s));
    }

    // BUD-06
    #[test]
    fn mdbx_zero_engine_cache_reporting() {
        let mut s = BudgetState::init_mdbx(4, 1);
        assert_eq!(
            s.reserve(AllocationOwner::EngineCache, 1),
            Err(BudgetError::EngineCacheUnsupported)
        );
        let s_grown = step(&s, Action::GrowEngineCache(1));
        assert_eq!(s_grown.charges[AllocationOwner::EngineCache.index()], 0);
        assert_eq!(s_grown.reserved[AllocationOwner::EngineCache.index()], 0);
        assert!(safety(&s_grown));
    }

    // BUD-06
    #[test]
    fn negative_control_mutant_mdbx_engine_cache_fails_safety() {
        let s = BudgetState::init_mdbx(4, 1);
        let mutant = step_mutant_mdbx_engine_cache(&s, Action::GrowEngineCache(1));
        assert_eq!(mutant.charges[AllocationOwner::EngineCache.index()], 1);
        assert!(!safety(&mutant));
    }

    // BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
    #[test]
    fn exhaustive_bfs_safety_verification() {
        for is_mdbx in [false, true] {
            let initial = if is_mdbx {
                BudgetState::init_mdbx(4, 1)
            } else {
                BudgetState::init(4, 1)
            };
            assert!(safety(&initial));

            let mut visited = HashSet::new();
            let mut queue = VecDeque::new();

            visited.insert((
                initial.charges,
                initial.reserved,
                initial.block_refused,
                initial.consensus_invalid,
            ));
            queue.push_back(initial);

            while let Some(curr) = queue.pop_front() {
                let amounts = [1, 2];
                let mut actions = Vec::new();

                for &amt in &amounts {
                    actions.push(Action::ReserveIngress(amt));
                    actions.push(Action::RefuseIngress(amt));
                    actions.push(Action::AllocateIngress(amt));
                    actions.push(Action::ApplyBlock(amt));
                    actions.push(Action::ReserveCoinCache(amt));
                    actions.push(Action::AllocateCoinCache(amt));
                    actions.push(Action::ReleaseCoinCache(amt));
                    actions.push(Action::GrowEngineCache(amt));
                    actions.push(Action::ShrinkEngineCache(amt));
                    actions.push(Action::ReserveEngineCache(amt));
                    actions.push(Action::AllocateEngineCache(amt));
                    actions.push(Action::ReleaseEngineCache(amt));
                    for owner in [
                        AllocationOwner::FactsQueue,
                        AllocationOwner::IndexBuilder,
                        AllocationOwner::QueryViews,
                    ] {
                        actions.push(Action::ReserveBackground(owner, amt));
                        actions.push(Action::AllocateBackground(owner, amt));
                        actions.push(Action::ReleaseBackground(owner, amt));
                    }
                }
                actions.push(Action::Stutter);

                for a in actions {
                    let next = step(&curr, a);
                    assert!(safety(&next), "safety violated at state: {next:?}");
                    let key = (
                        next.charges,
                        next.reserved,
                        next.block_refused,
                        next.consensus_invalid,
                    );
                    if visited.insert(key) {
                        queue.push_back(next);
                    }
                }
            }
            assert!(visited.len() > 100);
        }
    }

    // BUD-03
    #[test]
    fn negative_control_mutant_fails_safety_exhaustive() {
        let mut s = BudgetState::init(4, 1);
        assert!(s.reserve_ingress(4).is_ok());

        let mutant = step_mutant_ingress_invalidation(&s, Action::ReserveIngress(1));
        assert!(mutant.block_refused);
        assert!(mutant.consensus_invalid);
        assert!(
            !safety(&mutant),
            "mutant invalidating consensus on refusal must violate safety"
        );
    }
}
