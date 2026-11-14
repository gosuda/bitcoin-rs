//! Node-wide byte and CPU accounting for every retained allocation.
//!
//! One accountant owns the totals; all subsystem charges linearize through
//! its single ledger lock, so every reader observes a whole reservation or
//! none of it. Per-owner caps bound the sum of charges and reservations and
//! subdivide the total budget. Background owners stay inside the budget minus
//! the foreground reserve (`BUD-05`), and a refusal is never a consensus
//! invalidation (`BUD-03`). The owner vocabulary and charge interface live in
//! `bitcoin_rs_storage::budget` so projection,
//! storage, and offline tools charge the same ledger.

use bitcoin_rs_execution::WindowLimits;
use bitcoin_rs_storage::ChainstateCacheBudget;
use bitcoin_rs_storage::budget::{
    BudgetCharge, BudgetError, BudgetOwner, BudgetReclaimer, CpuShares,
};
use parking_lot::{Condvar, Mutex, RwLock};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const STAGED_IMAGE_BUDGET_BYTES: u64 = 512 * 1024 * 1024;
pub const FACTS_QUEUE_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const INDEX_BUILDER_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
pub const QUERY_VIEW_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const PEER_OUTBOUND_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const FOREGROUND_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetCaps {
    pub staged_images: u64,
    pub engine_cache: u64,
    pub coin_cache: u64,
    pub facts_queue: u64,
    pub index_builder: u64,
    pub query_views: u64,
    pub peer_outbound: u64,
    pub foreground_reserve: u64,
}

impl BudgetCaps {
    /// The chainstate cache allowance, already split between the engine and
    /// the coin cache (`BUD-06`). Each cache owner is capped at its own share,
    /// so the ledger never grants either one more than the cache it backs.
    #[must_use]
    pub fn from_chainstate_cache_budget(cache_allocation: ChainstateCacheBudget) -> Self {
        Self {
            staged_images: STAGED_IMAGE_BUDGET_BYTES,
            engine_cache: cache_allocation.engine_bytes,
            coin_cache: cache_allocation.coin_bytes,
            facts_queue: FACTS_QUEUE_BUDGET_BYTES,
            index_builder: INDEX_BUILDER_BUDGET_BYTES,
            query_views: QUERY_VIEW_BUDGET_BYTES,
            peer_outbound: PEER_OUTBOUND_BUDGET_BYTES,
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
            BudgetOwner::PeerOutbound => self.peer_outbound,
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
            .saturating_add(self.peer_outbound)
    }
}

#[derive(Default)]
struct Ledger {
    charges: [u64; 7],
    reserved: [u64; 7],
    ingress_refused: bool,
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
        let total_workers = total_workers.max(1);
        let foreground_workers = (total_workers / 4).max(1).min(total_workers);
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
    pub fn from_chainstate_cache_budget(
        cache_allocation: ChainstateCacheBudget,
        total_workers: u32,
    ) -> Self {
        Self::new(
            BudgetCaps::from_chainstate_cache_budget(cache_allocation),
            total_workers,
        )
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
        let mut ledger = self.ledger.lock();
        let idx = BudgetOwner::EngineCache.index();
        ledger.charges[idx] =
            bytes.min(self.caps.engine_cache.saturating_sub(ledger.reserved[idx]));
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
        if committed.saturating_add(amount) <= self.caps.total()
            && ledger.charges[idx]
                .saturating_add(ledger.reserved[idx])
                .saturating_add(amount)
                <= self.caps.engine_cache
        {
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

    fn reserve_ingress(&self, bytes: u64) -> Result<(), BudgetError> {
        let mut ledger = self.ledger.lock();
        let owner = BudgetOwner::StagedImages;
        let idx = owner.index();
        let committed = ledger.charges[idx].saturating_add(ledger.reserved[idx]);
        let ceiling = self
            .caps
            .staged_images
            .saturating_sub(self.caps.foreground_reserve);
        if bytes > ceiling.saturating_sub(committed) {
            ledger.ingress_refused = true;
            return Err(BudgetError::BudgetExhausted);
        }
        self.reserve_locked(&mut ledger, owner, bytes)
    }

    /// `BUD-07`: reclaim from optional owners, then reserve, then refuse.
    pub fn ensure_available(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        self.sample_engine_cache();
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
    pub fn wait_released(&self, timeout: Duration) {
        let mut ledger = self.ledger.lock();
        self.released.wait_for(&mut ledger, timeout);
    }

    #[must_use]
    pub fn is_safe(&self) -> bool {
        let ledger = self.ledger.lock();
        let engine_idx = BudgetOwner::EngineCache.index();
        let total = self.caps.total();
        total_charges(&ledger).saturating_add(total_reserved(&ledger)) <= total
            && background_committed_of(&ledger)
                <= total.saturating_sub(self.caps.foreground_reserve)
            && ledger.charges[engine_idx].saturating_add(ledger.reserved[engine_idx])
                <= self.caps.engine_cache
            && (!self.is_mdbx.load(Ordering::Relaxed)
                || (ledger.charges[engine_idx] == 0 && ledger.reserved[engine_idx] == 0))
    }

    #[must_use]
    pub fn window_limits(&self) -> WindowLimits {
        self.sample_engine_cache();
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
        self.sample_engine_cache();
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
        let idx = owner.index();
        let owner_committed = ledger.charges[idx].saturating_add(ledger.reserved[idx]);
        if committed.saturating_add(bytes) > total
            || bytes > self.caps.owner_cap(owner).saturating_sub(owner_committed)
        {
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

    fn ensure_available_bytes(&self, owner: BudgetOwner, bytes: u64) -> Result<(), BudgetError> {
        self.ensure_available(owner, bytes)
    }
}

pub struct BudgetedIngressLedger {
    budget: Arc<NodeBudget>,
}

impl BudgetedIngressLedger {
    #[must_use]
    pub fn new(budget: Arc<NodeBudget>) -> Self {
        Self { budget }
    }
}

impl bitcoin_rs_wire::inbound::block_memory::IngressLedger for BudgetedIngressLedger {
    fn capacity(&self) -> usize {
        usize::try_from(
            self.budget
                .caps
                .staged_images
                .saturating_sub(self.budget.caps.foreground_reserve),
        )
        .unwrap_or(usize::MAX)
    }

    fn try_take(&self, bytes: usize) -> bool {
        let bytes_u64 = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.budget.reserve_ingress(bytes_u64).is_ok()
            && self
                .budget
                .allocate(BudgetOwner::StagedImages, bytes_u64)
                .is_ok()
    }

    fn give_back(&self, bytes: usize) {
        let bytes_u64 = u64::try_from(bytes).unwrap_or(0);
        let _ = self.budget.release(BudgetOwner::StagedImages, bytes_u64);
    }

    fn wait_released(&self, timeout: Duration) {
        self.budget.wait_released(timeout);
    }
}

/// `BUD-02`: backs the wire shared outbound budget from the node ledger.
pub struct BudgetedOutboundLedger {
    budget: Arc<NodeBudget>,
}

impl BudgetedOutboundLedger {
    #[must_use]
    pub fn new(budget: Arc<NodeBudget>) -> Self {
        Self { budget }
    }
}

impl bitcoin_rs_wire::connection::OutboundLedger for BudgetedOutboundLedger {
    fn try_take(&self, bytes: usize) -> bool {
        let bytes_u64 = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.budget
            .reserve(BudgetOwner::PeerOutbound, bytes_u64)
            .is_ok()
            && self
                .budget
                .allocate(BudgetOwner::PeerOutbound, bytes_u64)
                .is_ok()
    }

    fn give_back(&self, bytes: usize) {
        let bytes_u64 = u64::try_from(bytes).unwrap_or(0);
        let _ = self.budget.release(BudgetOwner::PeerOutbound, bytes_u64);
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
