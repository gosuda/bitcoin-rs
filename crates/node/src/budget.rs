//! Node-wide byte and CPU accounting for every retained allocation.
//!
//! One accountant owns the totals; all subsystem charges linearize through
//! its single ledger lock, so every reader observes a whole reservation or
//! none of it. Per-owner caps subdivide the total budget. Background owners
//! stay inside the budget minus the foreground reserve (`BUD-05`), and a
//! refusal is never a consensus invalidation (`BUD-03`).

use bitcoin_rs_execution::WindowLimits;
use parking_lot::{Condvar, Mutex, RwLock};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const STAGED_IMAGE_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
pub const FACTS_QUEUE_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const INDEX_BUILDER_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
pub const QUERY_VIEW_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const FOREGROUND_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

const INGRESS_WAIT_POLL: Duration = Duration::from_millis(100);

/// `BUD-06`: one owner per retained allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum BudgetOwner {
    CoinCache = 0,
    EngineCache = 1,
    FactsQueue = 2,
    IndexBuilder = 3,
    StagedImages = 4,
    QueryViews = 5,
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
            Self::BudgetExhausted | Self::EngineCacheUnsupported => Some(BudgetRefusal::RetryLater),
            Self::Cancelled | Self::UnreservedAllocation | Self::InsufficientCharge => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetCaps {
    pub staged_images: u64,
    pub engine_cache: u64,
    pub coin_cache: u64,
    pub facts_queue: u64,
    pub index_builder: u64,
    pub query_views: u64,
    pub foreground_reserve: u64,
}

impl BudgetCaps {
    /// `dbcache_mb` stays the operator knob for the cache-class owners
    /// (`BUD-06`): it sizes the engine caches now, and the coin cache share
    /// is carved out of it when the coin store lands in the engine.
    #[must_use]
    pub fn from_dbcache_bytes(dbcache_bytes: u64) -> Self {
        Self {
            staged_images: STAGED_IMAGE_BUDGET_BYTES,
            engine_cache: dbcache_bytes,
            coin_cache: 0,
            facts_queue: FACTS_QUEUE_BUDGET_BYTES,
            index_builder: INDEX_BUILDER_BUDGET_BYTES,
            query_views: QUERY_VIEW_BUDGET_BYTES,
            foreground_reserve: FOREGROUND_RESERVE_BYTES,
        }
    }

    #[must_use]
    pub const fn owner_cap(self, owner: BudgetOwner) -> u64 {
        match owner {
            BudgetOwner::CoinCache => self.coin_cache,
            BudgetOwner::EngineCache => self.engine_cache,
            BudgetOwner::FactsQueue => self.facts_queue,
            BudgetOwner::IndexBuilder => self.index_builder,
            BudgetOwner::StagedImages => self.staged_images,
            BudgetOwner::QueryViews => self.query_views,
        }
    }

    #[must_use]
    pub const fn total(self) -> u64 {
        self.staged_images
            .saturating_add(self.engine_cache)
            .saturating_add(self.coin_cache)
            .saturating_add(self.facts_queue)
            .saturating_add(self.index_builder)
            .saturating_add(self.query_views)
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
}

#[derive(Default)]
struct Ledger {
    charges: [u64; 6],
    reserved: [u64; 6],
    ingress_refused: bool,
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

type EngineCacheSource = Box<dyn Fn() -> u64 + Send + Sync>;

/// The one node-wide resource budget (`BUD-01` to `BUD-07`).
///
/// Every mutation runs under one ledger lock, so byte accounting is
/// linearizable: concurrent reservers either all observe a consistent total
/// or serialize behind the lock.
pub struct NodeBudget {
    caps: BudgetCaps,
    ledger: Mutex<Ledger>,
    released: Condvar,
    is_mdbx: AtomicBool,
    engine_cache_source: RwLock<Option<EngineCacheSource>>,
    reclaimers: RwLock<Vec<Arc<dyn BudgetReclaimer>>>,
    cpu: Arc<CpuShares>,
}

impl NodeBudget {
    #[must_use]
    pub fn new(caps: BudgetCaps, total_workers: u32) -> Self {
        let foreground_workers = total_workers / 4;
        Self {
            caps,
            ledger: Mutex::new(Ledger::default()),
            released: Condvar::new(),
            is_mdbx: AtomicBool::new(false),
            engine_cache_source: RwLock::new(None),
            reclaimers: RwLock::new(Vec::new()),
            cpu: Arc::new(CpuShares::new(total_workers, foreground_workers)),
        }
    }

    #[must_use]
    pub fn from_dbcache_bytes(dbcache_bytes: u64, total_workers: u32) -> Self {
        Self::new(BudgetCaps::from_dbcache_bytes(dbcache_bytes), total_workers)
    }

    #[must_use]
    pub fn caps(&self) -> BudgetCaps {
        self.caps
    }

    #[must_use]
    pub fn cpu(&self) -> Arc<CpuShares> {
        Arc::clone(&self.cpu)
    }

    pub fn set_mdbx(&self, is_mdbx: bool) {
        self.is_mdbx.store(is_mdbx, Ordering::Relaxed);
        if is_mdbx {
            let mut ledger = self.ledger.lock();
            ledger.charges[BudgetOwner::EngineCache.index()] = 0;
            ledger.reserved[BudgetOwner::EngineCache.index()] = 0;
        }
    }

    /// Polls the engine-held cache bytes through the storage seam.
    ///
    /// mdbx keeps the charge at zero because the operating system page cache
    /// owns its bytes (`BUD-06` exception).
    pub fn sample_engine_cache(&self) {
        if self.is_mdbx.load(Ordering::Relaxed) {
            return;
        }
        let sampled = {
            let source = self.engine_cache_source.read();
            source.as_ref().map(|sample| sample())
        };
        let Some(bytes) = sampled else {
            return;
        };
        self.ledger.lock().charges[BudgetOwner::EngineCache.index()] =
            bytes.min(self.caps.engine_cache);
    }

    pub fn set_engine_cache_source(&self, source: Option<EngineCacheSource>) {
        *self.engine_cache_source.write() = source;
    }

    pub fn add_reclaimer(&self, reclaimer: Arc<dyn BudgetReclaimer>) {
        self.reclaimers.write().push(reclaimer);
    }

    #[must_use]
    pub fn ingress_refused(&self) -> bool {
        self.ledger.lock().ingress_refused
    }

    #[cfg(test)]
    #[must_use]
    pub fn available_of_charges(&self, owner: BudgetOwner) -> u64 {
        self.ledger.lock().charges[owner.index()]
    }

    #[cfg(test)]
    #[must_use]
    pub fn available_of_reservations(&self, owner: BudgetOwner) -> u64 {
        self.ledger.lock().reserved[owner.index()]
    }

    #[cfg(test)]
    pub fn note_ingress_refusal_when_exhausted(&self, bytes: u64) {
        let mut ledger = self.ledger.lock();
        let committed = total_charges(&ledger).saturating_add(total_reserved(&ledger));
        if committed.saturating_add(bytes) > self.caps.total() {
            ledger.ingress_refused = true;
        }
    }

    #[cfg(test)]
    pub fn grow_engine_cache(&self, amount: u64) {
        let mut ledger = self.ledger.lock();
        let idx = BudgetOwner::EngineCache.index();
        if self.is_mdbx.load(Ordering::Relaxed) {
            ledger.charges[idx] = 0;
            ledger.reserved[idx] = 0;
            return;
        }
        let committed = total_charges(&ledger).saturating_add(total_reserved(&ledger));
        if committed.saturating_add(amount) <= self.caps.total() {
            ledger.charges[idx] = ledger.charges[idx].saturating_add(amount);
        }
    }

    #[cfg(test)]
    pub fn shrink_engine_cache(&self, amount: u64) {
        let mut ledger = self.ledger.lock();
        let idx = BudgetOwner::EngineCache.index();
        if self.is_mdbx.load(Ordering::Relaxed) {
            ledger.charges[idx] = 0;
            ledger.reserved[idx] = 0;
            return;
        }
        if ledger.charges[idx] >= amount {
            ledger.charges[idx] -= amount;
        }
    }

    #[must_use]
    pub fn total_committed(&self) -> u64 {
        let ledger = self.ledger.lock();
        total_charges(&ledger).saturating_add(total_reserved(&ledger))
    }

    #[must_use]
    pub fn background_committed(&self) -> u64 {
        let ledger = self.ledger.lock();
        background_committed_of(&ledger)
    }

    #[must_use]
    pub fn available(&self, owner: BudgetOwner) -> u64 {
        let ledger = self.ledger.lock();
        let idx = owner.index();
        self.caps
            .owner_cap(owner)
            .saturating_sub(ledger.charges[idx])
            .saturating_sub(ledger.reserved[idx])
    }

    /// `BUD-01`: reserve before materializing.
    pub fn reserve(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut ledger = self.ledger.lock();
        self.reserve_locked(&mut ledger, owner, bytes)
    }

    /// Blocking variant for ingress: waits for capacity instead of failing,
    /// bounded by the caller's cancel latch.
    pub fn reserve_blocking(
        &self,
        owner: BudgetOwner,
        bytes: u64,
        is_cancelled: impl Fn() -> bool,
    ) -> Result<(), BudgetError> {
        loop {
            {
                let mut ledger = self.ledger.lock();
                match self.reserve_locked(&mut ledger, owner, bytes) {
                    Ok(()) => return Ok(()),
                    Err(BudgetError::BudgetExhausted) => {}
                    Err(error) => return Err(error),
                }
            }
            if is_cancelled() {
                return Err(BudgetError::Cancelled);
            }
            let mut ledger = self.ledger.lock();
            self.released.wait_for(&mut ledger, INGRESS_WAIT_POLL);
        }
    }

    /// `BUD-07`: reclaim from optional owners, then reserve, then refuse.
    pub fn ensure_available(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        if self.reserve(owner, bytes).is_ok() {
            return Ok(());
        }
        for reclaimer in self.reclaimers.read().iter() {
            reclaimer.reclaim(bytes);
        }
        self.reserve(owner, bytes)
    }

    pub fn allocate(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut ledger = self.ledger.lock();
        let idx = owner.index();
        if bytes == 0 {
            return Ok(());
        }
        if ledger.reserved[idx] < bytes {
            return Err(BudgetError::UnreservedAllocation);
        }
        ledger.reserved[idx] -= bytes;
        ledger.charges[idx] = ledger.charges[idx].saturating_add(bytes);
        Ok(())
    }

    pub fn release(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        let mut ledger = self.ledger.lock();
        let idx = owner.index();
        if bytes == 0 {
            return Ok(());
        }
        if ledger.charges[idx] < bytes {
            return Err(BudgetError::InsufficientCharge);
        }
        ledger.charges[idx] -= bytes;
        drop(ledger);
        self.released.notify_all();
        Ok(())
    }

    #[must_use]
    pub fn is_safe(&self) -> bool {
        let ledger = self.ledger.lock();
        let engine_idx = BudgetOwner::EngineCache.index();
        let total = self.caps.total();
        total_charges(&ledger).saturating_add(total_reserved(&ledger)) <= total
            && background_committed_of(&ledger)
                <= total.saturating_sub(self.caps.foreground_reserve)
            && (!self.is_mdbx.load(Ordering::Relaxed)
                || (ledger.charges[engine_idx] == 0 && ledger.reserved[engine_idx] == 0))
    }

    #[must_use]
    pub fn window_limits(&self) -> WindowLimits {
        let defaults = WindowLimits::durable_head_defaults();
        WindowLimits {
            max_blocks: defaults.max_blocks,
            max_bytes: limits_bytes(
                self.available(BudgetOwner::StagedImages),
                defaults.max_bytes,
            ),
        }
    }

    #[must_use]
    pub fn script_batch_limits(&self) -> WindowLimits {
        let defaults = WindowLimits::script_batch_defaults();
        WindowLimits {
            max_blocks: defaults.max_blocks,
            max_bytes: limits_bytes(
                self.available(BudgetOwner::StagedImages),
                defaults.max_bytes,
            ),
        }
    }

    fn reserve_locked(
        &self,
        ledger: &mut Ledger,
        owner: BudgetOwner,
        bytes: u64,
    ) -> Result<(), BudgetError> {
        if bytes == 0 {
            return Ok(());
        }
        if self.is_mdbx.load(Ordering::Relaxed) && owner == BudgetOwner::EngineCache {
            return Err(BudgetError::EngineCacheUnsupported);
        }
        let total = self.caps.total();
        let committed = total_charges(ledger).saturating_add(total_reserved(ledger));
        if committed.saturating_add(bytes) > total || bytes > self.caps.owner_cap(owner) {
            if owner == BudgetOwner::StagedImages {
                ledger.ingress_refused = true;
            }
            return Err(BudgetError::BudgetExhausted);
        }
        if owner.is_background() {
            let ceiling = total.saturating_sub(self.caps.foreground_reserve);
            if background_committed_of(ledger).saturating_add(bytes) > ceiling {
                return Err(BudgetError::BudgetExhausted);
            }
        }
        let idx = owner.index();
        ledger.reserved[idx] = ledger.reserved[idx].saturating_add(bytes);
        Ok(())
    }
}

impl BudgetCharge for NodeBudget {
    fn reserve_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        self.reserve(owner, bytes)
    }

    fn allocate_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        self.allocate(owner, bytes)
    }

    fn release_bytes(&self, owner: BudgetOwner, bytes: u64) {
        let _ = self.release(owner, bytes);
    }

    fn available_bytes(&self, owner: BudgetOwner) -> u64 {
        self.available(owner)
    }
}

#[must_use]
fn total_charges(ledger: &Ledger) -> u64 {
    ledger.charges.iter().sum()
}

#[must_use]
fn total_reserved(ledger: &Ledger) -> u64 {
    ledger.reserved.iter().sum()
}

#[must_use]
fn background_committed_of(ledger: &Ledger) -> u64 {
    let mut total: u64 = 0;
    for owner in [
        BudgetOwner::FactsQueue,
        BudgetOwner::IndexBuilder,
        BudgetOwner::QueryViews,
    ] {
        let idx = owner.index();
        total = total.saturating_add(ledger.charges[idx]);
        total = total.saturating_add(ledger.reserved[idx]);
    }
    total
}

#[must_use]
fn limits_bytes(headroom: u64, ceiling: usize) -> usize {
    let ceiling_bytes = u64::try_from(ceiling).unwrap_or(u64::MAX);
    usize::try_from(headroom.min(ceiling_bytes)).unwrap_or(ceiling)
}

#[cfg(test)]
mod tests;
