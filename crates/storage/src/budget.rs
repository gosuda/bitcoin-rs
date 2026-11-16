//! Shared byte and CPU charge interface for every retained allocation.
//!
//! One accountant owns the totals; all subsystem charges linearize through
//! its ledger. Background owners stay inside the budget minus the
//! foreground reserve (`BUD-05`), and a refusal is never a consensus
//! invalidation (`BUD-03`).

use parking_lot::Mutex;
use std::sync::Arc;

/// `BUD-06`: one owner per retained allocation.
/// `BUD-02`: peer outbound bytes share the node-wide ledger with block,
/// execution, and index owners instead of a side counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum BudgetOwner {
    CoinCache = 0,
    EngineCache = 1,
    FactsQueue = 2,
    IndexBuilder = 3,
    StagedImages = 4,
    QueryViews = 5,
    PeerOutbound = 6,
}

impl BudgetOwner {
    #[must_use]
    pub const fn index(self) -> usize {
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

    /// `BUD-05`
    #[must_use]
    pub const fn is_background(self) -> bool {
        matches!(
            self,
            Self::FactsQueue | Self::IndexBuilder | Self::QueryViews
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    #[error("allocation attempted without prior reservation")]
    UnreservedAllocation,
    #[error("budget exhausted; request refused")]
    BudgetExhausted,
    #[error("insufficient charge to release")]
    InsufficientCharge,
    #[error("engine cache accounting is unsupported for this backend")]
    EngineCacheUnsupported,
    #[error("budget reservation cancelled")]
    Cancelled,
    #[error("budget accounting is unavailable")]
    Unavailable,
}

/// `BUD-03`: a refusal is retry-later backpressure, not a consensus verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetRefusal {
    #[error("resource budget is full; retry later")]
    RetryLater,
}

impl BudgetError {
    /// `BUD-03`: an exhaustion refusal maps to retry-later backpressure.
    #[must_use]
    pub const fn refusal(&self) -> Option<BudgetRefusal> {
        match self {
            Self::BudgetExhausted | Self::EngineCacheUnsupported | Self::Unavailable => {
                Some(BudgetRefusal::RetryLater)
            }
            Self::Cancelled | Self::UnreservedAllocation | Self::InsufficientCharge => None,
        }
    }
}

/// Frees charged bytes on another thread when the budget is full (`BUD-07`).
pub trait BudgetReclaimer: Send + Sync {
    fn reclaim(&self, bytes: u64) -> u64;
}

/// The single charge interface every subsystem owner integrates against.
pub trait BudgetCharge: Send + Sync {
    fn reserve_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError>;
    fn allocate_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError>;
    fn release_bytes(&self, owner: BudgetOwner, bytes: u64);
    fn available_bytes(&self, owner: BudgetOwner) -> u64;
    fn ensure_available_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        self.reserve_bytes(owner, bytes)
    }
}

/// Off-line callers (tests and offline tools) that must never be refused.
pub struct UnboundedBudget;

impl BudgetCharge for UnboundedBudget {
    fn reserve_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        Ok(())
    }

    fn allocate_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
        Ok(())
    }

    fn release_bytes(&self, _owner: BudgetOwner, _bytes: u64) {}

    fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
        u64::MAX
    }
}

/// Owner-bound handle over one [`BudgetCharge`].
#[derive(Clone)]
pub struct ChargeHandle {
    charge: Arc<dyn BudgetCharge>,
    owner: BudgetOwner,
}

impl ChargeHandle {
    #[must_use]
    pub fn new(charge: Arc<dyn BudgetCharge>, owner: BudgetOwner) -> Self {
        Self { charge, owner }
    }

    pub fn reserve(&self, bytes: u64) -> Result<(), BudgetError> {
        self.charge.reserve_bytes(self.owner, bytes)
    }

    pub fn allocate(&self, bytes: u64) -> Result<(), BudgetError> {
        self.charge.allocate_bytes(self.owner, bytes)
    }

    /// BUD-01: reserve before materializing, then charge the allocation.
    pub fn charge(&self, bytes: u64) -> Result<(), BudgetError> {
        self.reserve(bytes)?;
        if let Err(error) = self.allocate(bytes) {
            self.release(bytes);
            return Err(error);
        }
        Ok(())
    }

    pub fn release(&self, bytes: u64) {
        self.charge.release_bytes(self.owner, bytes);
    }

    #[must_use]
    pub fn available(&self) -> u64 {
        self.charge.available_bytes(self.owner)
    }
}

struct CpuLedger {
    background_in_flight: u32,
    foreground_active: u32,
}

/// Bounded CPU share accounting over the one scheduling domain (`BUD-04`).
///
/// All counters live behind one lock, so share decisions are linearizable
/// with each other.
pub struct CpuShares {
    total_workers: u32,
    foreground_reserve: u32,
    ledger: Mutex<CpuLedger>,
}

impl CpuShares {
    #[must_use]
    pub fn new(total_workers: u32, foreground_reserve: u32) -> Self {
        Self {
            total_workers: total_workers.max(1),
            foreground_reserve: foreground_reserve.min(total_workers.max(1)),
            ledger: Mutex::new(CpuLedger {
                background_in_flight: 0,
                foreground_active: 0,
            }),
        }
    }

    #[must_use]
    pub fn try_acquire_background(self: &Arc<Self>) -> Option<BackgroundCpuPermit> {
        let mut ledger = self.ledger.lock();
        let ceiling = self.total_workers.saturating_sub(self.foreground_reserve);
        if ledger.background_in_flight >= ceiling {
            return None;
        }
        ledger.background_in_flight = ledger.background_in_flight.saturating_add(1);
        Some(BackgroundCpuPermit {
            shares: Arc::clone(self),
        })
    }

    #[must_use]
    pub fn acquire_foreground(self: &Arc<Self>) -> ForegroundCpuPermit {
        let mut ledger = self.ledger.lock();
        ledger.foreground_active = ledger.foreground_active.saturating_add(1);
        ForegroundCpuPermit {
            shares: Arc::clone(self),
        }
    }

    #[must_use]
    pub fn background_in_flight(&self) -> u32 {
        self.ledger.lock().background_in_flight
    }

    #[must_use]
    pub fn foreground_active(&self) -> u32 {
        self.ledger.lock().foreground_active
    }

    #[must_use]
    pub fn foreground_reserve(&self) -> u32 {
        self.foreground_reserve
    }
}

pub struct BackgroundCpuPermit {
    shares: Arc<CpuShares>,
}

impl Drop for BackgroundCpuPermit {
    fn drop(&mut self) {
        let mut ledger = self.shares.ledger.lock();
        ledger.background_in_flight = ledger.background_in_flight.saturating_sub(1);
    }
}

pub struct ForegroundCpuPermit {
    shares: Arc<CpuShares>,
}

impl Drop for ForegroundCpuPermit {
    fn drop(&mut self) {
        let mut ledger = self.shares.ledger.lock();
        ledger.foreground_active = ledger.foreground_active.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbounded_budget_never_refuses() {
        let budget = UnboundedBudget;
        assert_eq!(
            budget.ensure_available_bytes(BudgetOwner::IndexBuilder, u64::MAX),
            Ok(())
        );
        assert_eq!(budget.available_bytes(BudgetOwner::IndexBuilder), u64::MAX);
    }

    // BUD-04
    #[test]
    fn cpu_shares_bound_background_permits() {
        let shares = Arc::new(CpuShares::new(2, 1));
        let first = shares.try_acquire_background();
        assert!(first.is_some());
        assert!(shares.try_acquire_background().is_none());
        assert_eq!(shares.background_in_flight(), 1);
        drop(first);
        assert_eq!(shares.background_in_flight(), 0);
    }

    #[test]
    fn budget_error_maps_exhaustion_to_retry_later() {
        assert_eq!(
            BudgetError::BudgetExhausted.refusal(),
            Some(BudgetRefusal::RetryLater)
        );
        assert_eq!(BudgetError::Cancelled.refusal(), None);
    }

    const CAPACITY: u64 = 100;

    #[derive(Default)]
    struct OnceFailingAllocate {
        state: Mutex<FailingLedger>,
    }

    #[derive(Default)]
    struct FailingLedger {
        fail_next_allocate: bool,
        outstanding: u64,
        releases: Vec<(BudgetOwner, u64)>,
    }

    impl BudgetCharge for OnceFailingAllocate {
        fn reserve_bytes(&self, _owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
            let mut state = self.state.lock();
            if state.outstanding.saturating_add(bytes) > CAPACITY {
                return Err(BudgetError::BudgetExhausted);
            }
            state.outstanding += bytes;
            Ok(())
        }

        fn allocate_bytes(&self, _owner: BudgetOwner, _bytes: u64) -> Result<(), BudgetError> {
            if std::mem::take(&mut self.state.lock().fail_next_allocate) {
                return Err(BudgetError::BudgetExhausted);
            }
            Ok(())
        }

        fn release_bytes(&self, owner: BudgetOwner, bytes: u64) {
            let mut state = self.state.lock();
            state.releases.push((owner, bytes));
            state.outstanding = state.outstanding.saturating_sub(bytes);
        }

        fn available_bytes(&self, _owner: BudgetOwner) -> u64 {
            CAPACITY - self.state.lock().outstanding
        }
    }

    // BUD-01
    #[test]
    fn failed_allocation_releases_reservation_and_books_balance() {
        let fake = Arc::new(OnceFailingAllocate::default());
        fake.state.lock().fail_next_allocate = true;
        let handle = ChargeHandle::new(fake.clone(), BudgetOwner::StagedImages);

        assert_eq!(handle.charge(64), Err(BudgetError::BudgetExhausted));
        assert_eq!(
            fake.state.lock().releases,
            vec![(BudgetOwner::StagedImages, 64)]
        );
        assert_eq!(handle.available(), CAPACITY);

        assert_eq!(handle.charge(32), Ok(()));
        assert_eq!(handle.available(), CAPACITY - 32);
        handle.release(32);
        assert_eq!(handle.available(), CAPACITY);
    }
}
