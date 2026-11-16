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
    pub fn charged_bytes(&self, owner: BudgetOwner) -> u64 {
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
mod tests {
    use super::{BudgetCaps, NodeBudget, STAGED_IMAGE_BUDGET_BYTES};
    use crate::budget_model::{self, Action, AllocationOwner};
    use bitcoin_rs_execution::WindowLimits;
    use bitcoin_rs_storage::budget::{BudgetError, BudgetOwner, BudgetRefusal, ChargeHandle};
    use bitcoin_rs_storage::{
        CoinKey, CoinStore, MemoryKvStore, WindowDelta, split_chainstate_cache_budget,
    };
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
        let charges = ALL_OWNERS.map(|owner| budget.charged_bytes(owner));
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
        let pick = rng.next() % 17;
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
            13 => Action::ReserveEngineCache(amount),
            14 => Action::AllocateEngineCache(amount),
            15 => Action::ReleaseEngineCache(amount),
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
        state.owner_caps = [AMOUNT_CAP; 7];
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
        every_action_variant_tracks_the_model();
    }

    fn every_action_variant_tracks_the_model() {
        let budget = NodeBudget::new(differential_caps(), 4);
        let mut state = budget_model::BudgetState::init(MODEL_TOTAL, MODEL_FOREGROUND);
        state.owner_caps = [AMOUNT_CAP; 7];
        let mut variants = vec![
            Action::ReserveIngress(7),
            Action::RefuseIngress(7),
            Action::AllocateIngress(7),
            Action::ApplyBlock(7),
            Action::ReserveCoinCache(7),
            Action::AllocateCoinCache(7),
            Action::ReleaseCoinCache(7),
            Action::GrowEngineCache(7),
            Action::ShrinkEngineCache(7),
            Action::ReserveEngineCache(7),
            Action::AllocateEngineCache(7),
            Action::ReleaseEngineCache(7),
            Action::ReservePeerOutbound(7),
            Action::AllocatePeerOutbound(7),
            Action::ReleasePeerOutbound(7),
            Action::Stutter,
        ];
        for owner in [
            AllocationOwner::FactsQueue,
            AllocationOwner::IndexBuilder,
            AllocationOwner::QueryViews,
        ] {
            variants.push(Action::ReserveBackground(owner, 7));
            variants.push(Action::AllocateBackground(owner, 7));
            variants.push(Action::ReleaseBackground(owner, 7));
        }
        for action in variants {
            state = budget_model::step(&state, action);
            apply_action(&budget, &action);
            assert_ledger_matches(&budget, &state, "every action variant tracks the model");
        }
    }

    // BUD-03
    #[test]
    fn exhausted_ingress_refuses_without_consent_invalidation() {
        let budget = NodeBudget::from_chainstate_cache_budget(split_chainstate_cache_budget(64), 4);
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
        assert_eq!(budget.charged_bytes(BudgetOwner::EngineCache), 1_500);
        budget.grow_engine_cache(caps.total());
        assert_eq!(
            budget.charged_bytes(BudgetOwner::EngineCache),
            1_500,
            "engine growth past the total budget must be rejected"
        );
        budget.set_engine_cache_source(Some(Box::new(|| OWNER_CAP + 1)));
        budget.sample_engine_cache();
        assert_eq!(
            budget.charged_bytes(BudgetOwner::EngineCache),
            OWNER_CAP,
            "engine sampling clamps at the owner cap"
        );
        budget.shrink_engine_cache(500);
        assert_eq!(
            budget.charged_bytes(BudgetOwner::EngineCache),
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
        assert_eq!(budget.charged_bytes(BudgetOwner::EngineCache), 0);
        assert_eq!(
            budget.reserve(BudgetOwner::EngineCache, 1),
            Err(BudgetError::EngineCacheUnsupported)
        );
        assert!(budget.is_safe());
    }

    #[test]
    fn window_limits_shrink_with_staged_headroom() {
        let budget = NodeBudget::from_chainstate_cache_budget(split_chainstate_cache_budget(16), 4);
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
        let budget = NodeBudget::from_chainstate_cache_budget(split_chainstate_cache_budget(16), 4);
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
        let allocation = split_chainstate_cache_budget(64 * 1024 * 1024);
        let budget = Arc::new(NodeBudget::from_chainstate_cache_budget(allocation, 4));
        let charge = ChargeHandle::new(budget.clone(), BudgetOwner::CoinCache);
        let coins = CoinStore::open_with_charge(
            Arc::new(MemoryKvStore::new()),
            allocation.coin_bytes,
            Some(charge),
        );
        let key = CoinKey([7; 32]);
        let value = Bytes::from(vec![0xab_u8; 1024]);
        let mut delta = WindowDelta::default();
        delta.push_final(key, Some(value));
        coins.ingest_chunk(&delta).expect("ingest succeeds");
        assert_eq!(
            budget.charged_bytes(BudgetOwner::CoinCache),
            0,
            "a durable write alone does not fill the cache"
        );
        coins.get(&key).expect("read succeeds");
        assert_eq!(
            budget.charged_bytes(BudgetOwner::CoinCache),
            1024,
            "the read fill charges the coin cache"
        );
        coins.wipe().expect("wipe succeeds");
        assert_eq!(
            budget.charged_bytes(BudgetOwner::CoinCache),
            0,
            "wipe returns the coin cache charge"
        );
    }

    #[test]
    fn repeated_owner_requests_include_charges_and_reservations() {
        for owner in ALL_OWNERS {
            let budget = NodeBudget::new(differential_caps(), 4);
            assert!(budget.reserve(owner, OWNER_CAP / 2).is_ok());
            assert!(budget.allocate(owner, OWNER_CAP / 2).is_ok());
            assert!(budget.reserve(owner, OWNER_CAP / 2).is_ok());
            assert_eq!(budget.available(owner), 0);
            for _ in 0..4 {
                assert_eq!(budget.reserve(owner, 1), Err(BudgetError::BudgetExhausted));
                assert_eq!(budget.total_committed(), OWNER_CAP);
            }
            assert!(budget.is_safe());
        }
    }

    // BUD-01, BUD-02, BUD-05, BUD-06, BUD-07
    #[test]
    fn saturated_ingress_preserves_execution_headroom_and_recovers_after_release() {
        use bitcoin_rs_wire::inbound::block_memory::IngressLedger;

        let caps = BudgetCaps {
            staged_images: 4_096,
            foreground_reserve: 1_024,
            engine_cache: 512,
            coin_cache: 512,
            facts_queue: 256,
            index_builder: 256,
            query_views: 256,
            peer_outbound: 256,
        };
        let ingress_ceiling = caps.staged_images - caps.foreground_reserve;
        let budget = Arc::new(NodeBudget::new(caps, 4));
        let ingress = super::BudgetedIngressLedger::new(Arc::clone(&budget));
        let execution = ChargeHandle::new(budget.clone(), BudgetOwner::StagedImages);
        let initial_limits = budget.window_limits();
        let held = ingress.capacity();
        assert_eq!(
            initial_limits.max_bytes,
            usize::try_from(caps.staged_images)
                .unwrap_or(usize::MAX)
                .min(WindowLimits::durable_head_defaults().max_bytes)
        );
        assert!(ingress.try_take(held));
        assert!(!ingress.try_take(1));

        assert_eq!(
            execution.charge(caps.foreground_reserve),
            Ok(()),
            "download saturation must leave the declared foreground reserve for execution"
        );
        assert_eq!(u64::try_from(held), Ok(ingress_ceiling));
        assert_eq!(budget.available(BudgetOwner::StagedImages), 0);
        assert_eq!(
            execution.reserve(1),
            Err(BudgetError::BudgetExhausted),
            "execution still obeys the shared staged-image owner cap"
        );
        for owner in ALL_OWNERS {
            assert!(
                budget.charged_bytes(owner) + budget.available_of_reservations(owner)
                    <= caps.owner_cap(owner)
            );
        }
        assert_eq!(budget.total_committed(), caps.staged_images);
        assert!(budget.total_committed() <= caps.total());
        assert!(budget.is_safe());

        execution.release(caps.foreground_reserve);
        assert!(!ingress.try_take(1));
        assert_eq!(
            budget.window_limits().max_bytes,
            usize::try_from(caps.foreground_reserve)
                .unwrap_or(usize::MAX)
                .min(initial_limits.max_bytes)
        );
        ingress.give_back(held);
        assert_eq!(budget.total_committed(), 0);
        assert_eq!(budget.window_limits(), initial_limits);
        assert!(
            ingress.try_take(held),
            "released ingress credits must be reusable"
        );
        ingress.give_back(held);
        assert_eq!(budget.total_committed(), 0);
        assert!(budget.is_safe());
    }

    #[test]
    fn repeated_ingress_then_engine_sample_stays_within_total() {
        use bitcoin_rs_wire::inbound::block_memory::IngressLedger;

        let caps = BudgetCaps::from_chainstate_cache_budget(split_chainstate_cache_budget(
            450 * 1024 * 1024,
        ));
        let budget = Arc::new(NodeBudget::new(caps, 4));
        let ingress = super::BudgetedIngressLedger::new(Arc::clone(&budget));
        let ingress_ceiling = caps.staged_images - caps.foreground_reserve;
        assert_eq!(u64::try_from(ingress.capacity()), Ok(ingress_ceiling));
        let request = ingress.capacity() / 2;
        assert!(ingress.try_take(request));
        assert!(ingress.try_take(ingress.capacity() - request));
        for _ in 0..2 {
            assert!(!ingress.try_take(1));
        }
        budget.set_engine_cache_source(Some(Box::new(move || caps.engine_cache + 1)));
        budget.sample_engine_cache();
        assert_eq!(
            budget.charged_bytes(BudgetOwner::EngineCache),
            caps.engine_cache
        );
        assert_eq!(
            budget.total_committed(),
            ingress_ceiling + caps.engine_cache
        );
        assert!(budget.is_safe());
        assert!(budget.total_committed() <= caps.total());
    }

    #[test]
    fn engine_sampling_leaves_room_for_outstanding_reservations() {
        let budget = NodeBudget::new(differential_caps(), 4);
        assert!(
            budget
                .reserve(BudgetOwner::EngineCache, OWNER_CAP / 2)
                .is_ok()
        );
        budget.set_engine_cache_source(Some(Box::new(|| OWNER_CAP + 1)));
        budget.sample_engine_cache();
        assert_eq!(
            budget.charged_bytes(BudgetOwner::EngineCache),
            OWNER_CAP / 2
        );
        assert_eq!(budget.total_committed(), OWNER_CAP);
        assert_eq!(budget.available(BudgetOwner::EngineCache), 0);
        assert!(!budget.ingress_refused());
        assert!(budget.reserve(BudgetOwner::StagedImages, 1).is_ok());
        assert!(budget.is_safe());
    }
}
