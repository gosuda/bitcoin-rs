//! The binding constraint is the *lowest* active floor.
//!
//! Each lease requires rows at heights at or above its floor to survive, so the union
//! of the constraints keeps exactly the rows the deepest lease needs; rows below every
//! floor remain prunable.

use crate::pruning::ExecutedFrontier;
use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use hashbrown::HashMap;
use parking_lot::Mutex;
use thiserror::Error;

#[derive(Default)]
pub struct RetentionRegistry {
    inner: Mutex<RegistryInner>,
    shutting_down: AtomicBool,
}

#[derive(Debug, Default)]
struct RegistryInner {
    next_ticket: u64,
    pruned_below: u32,
    reservations: Vec<u32>,
    floors: HashMap<u64, LeaseEntry>,
}

impl RegistryInner {
    /// The lowest line a lease floor must reach: everything below the
    /// executed prune line or below any outstanding prune reservation is
    /// gone or already claimed for deletion.
    fn refusal_line(&self) -> u32 {
        self.pruned_below
            .max(self.reservations.iter().copied().max().unwrap_or(0))
    }

    fn lowest_floor(&self) -> Option<u32> {
        self.floors.values().map(LeaseEntry::floor).min()
    }

    fn expire_optional_leases(&mut self, policy_line: u32) {
        self.floors
            .retain(|_, entry| !entry.expires_at(policy_line));
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum LeaseKind {
    Mandatory,
    Optional { budget: RetentionBudget },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct LeaseEntry {
    floor: u32,
    kind: LeaseKind,
}

impl LeaseEntry {
    fn mandatory(floor: u32) -> Self {
        Self {
            floor,
            kind: LeaseKind::Mandatory,
        }
    }

    fn optional(floor: u32, budget: RetentionBudget) -> Self {
        Self {
            floor,
            kind: LeaseKind::Optional { budget },
        }
    }

    const fn floor(&self) -> u32 {
        self.floor
    }

    fn expires_at(&self, policy_line: u32) -> bool {
        let LeaseKind::Optional { budget } = self.kind else {
            return false;
        };
        match budget {
            RetentionBudget::Unlimited => false,
            RetentionBudget::Depth(depth) => self.floor < policy_line.saturating_sub(depth),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RetentionBudget {
    Depth(u32),
    Unlimited,
}

impl RetentionBudget {
    #[must_use]
    pub const fn from_blocks(blocks: u32) -> Self {
        match blocks {
            0 => Self::Unlimited,
            blocks => Self::Depth(blocks),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Error)]
pub enum HistoryUnavailable {
    /// Heights below `below` are permanently gone: a committed pass deleted
    /// them. The defined recovery for an optional consumer is a rebuild from
    /// what remains, not a retry.
    #[error("history below height {below} is pruned")]
    Pruned { below: u32 },
    /// Heights below `below` are claimed by a prune pass that has not yet committed or
    /// aborted.
    ///
    /// The claim is provisional — it may release the range without deleting anything —
    /// so the defined reaction is to wait and retry, never to rebuild.
    #[error("history below height {below} is reserved by an in-flight prune pass")]
    Reserved { below: u32 },
    /// The row lies inside retained history but is not there yet: it may
    /// appear through backfill or a reconnect. Retry; do not rebuild.
    #[error("retained history is temporarily unavailable")]
    Missing,
    #[error("history is unavailable while the node shuts down")]
    Shutdown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Error)]
#[error("required history at height {requested} is already pruned (prune line {pruned_below})")]
pub struct RetentionError {
    pub requested: u32,
    pub pruned_below: u32,
}

impl fmt::Debug for RetentionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("RetentionRegistry")
            .field("inner", &self.inner)
            .field("shutting_down", &self.shutting_down)
            .field("active_leases", &inner.floors.len())
            .field("retention_floor", &inner.lowest_floor())
            .field("pruned_below", &inner.pruned_below)
            .finish()
    }
}

impl RetentionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn seeded(frontier: ExecutedFrontier) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                pruned_below: frontier.get(),
                ..RegistryInner::default()
            }),
            ..Self::default()
        }
    }

    pub fn acquire(self: &Arc<Self>, floor: u32) -> Result<RetentionLease, RetentionError> {
        let mut inner = self.inner.lock();
        let line = inner.refusal_line();
        if floor < line {
            return Err(RetentionError {
                requested: floor,
                pruned_below: line,
            });
        }
        let ticket = inner.next_ticket;
        inner.next_ticket = ticket.wrapping_add(1);
        inner.floors.insert(ticket, LeaseEntry::mandatory(floor));
        Ok(RetentionLease {
            registry: Arc::clone(self),
            lease: Some((ticket, floor)),
        })
    }

    #[must_use]
    pub fn retention_floor(&self) -> Option<u32> {
        self.inner.lock().lowest_floor()
    }

    #[must_use]
    pub fn pruned_below(&self) -> u32 {
        self.inner.lock().pruned_below
    }

    #[must_use]
    pub fn active_leases(&self) -> usize {
        self.inner.lock().floors.len()
    }

    #[must_use = "a dropped reservation releases the prune claim"]
    pub fn reserve(self: &Arc<Self>, policy_line: u32) -> PruneReservation {
        let mut inner = self.inner.lock();
        inner.expire_optional_leases(policy_line);
        let line = policy_line.min(inner.lowest_floor().unwrap_or(u32::MAX));
        inner.reservations.push(line);
        PruneReservation {
            registry: Arc::clone(self),
            line,
            committed: false,
        }
    }

    fn commit_reservation(&self, line: u32, executed: u32) {
        let mut inner = self.inner.lock();
        Self::release_reservation(&mut inner, line);
        if executed > inner.pruned_below {
            inner.pruned_below = executed;
        }
    }

    fn abort_reservation(&self, line: u32) {
        Self::release_reservation(&mut self.inner.lock(), line);
    }

    fn release_reservation(inner: &mut RegistryInner, line: u32) {
        if let Some(index) = inner
            .reservations
            .iter()
            .position(|&reserved| reserved == line)
        {
            inner.reservations.swap_remove(index);
        }
    }

    fn release(&self, ticket: u64) {
        self.inner.lock().floors.remove(&ticket);
    }

    #[must_use = "a dropped lease releases the history pin"]
    pub(crate) fn history_from(
        self: &Arc<Self>,
        floor: u32,
        budget: RetentionBudget,
    ) -> Result<HistoryLease, HistoryUnavailable> {
        let mut inner = self.inner.lock();
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(HistoryUnavailable::Shutdown);
        }
        let line = inner.refusal_line();
        if floor < line {
            return Err(if floor < inner.pruned_below {
                HistoryUnavailable::Pruned {
                    below: inner.pruned_below,
                }
            } else {
                HistoryUnavailable::Reserved { below: line }
            });
        }
        let ticket = inner.next_ticket;
        inner.next_ticket = ticket.wrapping_add(1);
        inner
            .floors
            .insert(ticket, LeaseEntry::optional(floor, budget));
        Ok(HistoryLease {
            registry: Arc::clone(self),
            ticket: Some(ticket),
        })
    }

    pub fn shutdown(&self) {
        let _inner = self.inner.lock();
        self.shutting_down.store(true, Ordering::Release);
    }

    fn floor_of(&self, ticket: u64) -> Option<u32> {
        self.inner.lock().floors.get(&ticket).map(LeaseEntry::floor)
    }

    fn advance_floor(&self, ticket: u64, floor: u32) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.floors.get_mut(&ticket) {
            entry.floor = entry.floor.max(floor);
        }
    }
}

#[derive(Clone)]
pub struct MandatoryRetention {
    registry: Arc<RetentionRegistry>,
}

impl MandatoryRetention {
    #[must_use]
    pub const fn new(registry: Arc<RetentionRegistry>) -> Self {
        Self { registry }
    }

    pub fn acquire(&self, floor: u32) -> Result<RetentionLease, RetentionError> {
        self.registry.acquire(floor)
    }
}

/// INVARIANT: the executed prune line never moves backwards, and it never
/// advances for a deletion that did not commit.
#[derive(Debug)]
pub struct PruneReservation {
    registry: Arc<RetentionRegistry>,
    line: u32,
    committed: bool,
}

impl PruneReservation {
    #[must_use]
    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn commit(mut self, executed: u32) -> u32 {
        self.committed = true;
        let line = self.line;
        self.registry.commit_reservation(line, executed);
        line
    }

    pub(crate) fn fail_closed(self) {
        core::mem::forget(self);
    }
}

impl Drop for PruneReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.registry.abort_reservation(self.line);
        }
    }
}

#[derive(Debug)]
pub struct RetentionLease {
    registry: Arc<RetentionRegistry>,
    lease: Option<(u64, u32)>,
}

impl RetentionLease {
    #[must_use]
    pub fn floor(&self) -> u32 {
        self.lease.as_ref().map_or(0, |&(_, floor)| floor)
    }

    pub fn release(mut self) {
        self.release_once();
    }

    fn release_once(&mut self) {
        if let Some((ticket, _)) = self.lease.take() {
            self.registry.release(ticket);
        }
    }
}

impl Drop for RetentionLease {
    fn drop(&mut self) {
        self.release_once();
    }
}

/// While this lease lives the authority deletes no row at or above its floor.
///
/// That guarantee is what types a byte read: a read that returns nothing under a live
/// grant is transient absence ([`HistoryUnavailable::Missing`]), never lost history.
///
/// The consumer relays those meanings instead of deciding permanence on its own.
#[derive(Debug)]
pub struct HistoryLease {
    registry: Arc<RetentionRegistry>,
    ticket: Option<u64>,
}

impl HistoryLease {
    #[must_use]
    pub fn floor(&self) -> Option<u32> {
        self.ticket
            .and_then(|ticket| self.registry.floor_of(ticket))
    }

    pub fn advance(&self, durable_progress: u32) {
        if let Some(ticket) = self.ticket {
            self.registry.advance_floor(ticket, durable_progress);
        }
    }

    pub fn release(mut self) {
        self.release_once();
    }

    fn release_once(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.registry.release(ticket);
        }
    }
}

impl Drop for HistoryLease {
    fn drop(&mut self) {
        self.release_once();
    }
}

#[derive(Clone, Debug)]
pub struct HistoryAccess {
    registry: Arc<RetentionRegistry>,
    budget: RetentionBudget,
}

impl HistoryAccess {
    #[must_use]
    pub fn new(registry: Arc<RetentionRegistry>, budget: RetentionBudget) -> Self {
        Self { registry, budget }
    }

    #[must_use = "a dropped lease releases the history pin"]
    pub fn request_history(&self, start: u32) -> Result<HistoryLease, HistoryUnavailable> {
        self.registry.history_from(start, self.budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(result: Result<RetentionLease, RetentionError>) -> RetentionLease {
        match result {
            Ok(lease) => lease,
            Err(error) => panic!("lease refused: {error}"),
        }
    }

    #[test]
    fn lowest_active_floor_binds() {
        let registry = Arc::new(RetentionRegistry::new());
        assert_eq!(registry.retention_floor(), None);

        let deep = held(registry.acquire(300));
        assert_eq!(registry.retention_floor(), Some(300));

        let shallow = held(registry.acquire(700));
        assert_eq!(registry.retention_floor(), Some(300));

        drop(shallow);
        assert_eq!(registry.retention_floor(), Some(300));
        drop(deep);
        assert_eq!(registry.retention_floor(), None);
    }

    #[test]
    fn release_is_exactly_once_and_drop_is_the_fallback() {
        let registry = Arc::new(RetentionRegistry::new());
        let lease = held(registry.acquire(10));
        assert_eq!(registry.active_leases(), 1);
        lease.release();
        assert_eq!(registry.active_leases(), 0);

        {
            let dropped = held(registry.acquire(20));
            assert_eq!(dropped.floor(), 20);
            assert_eq!(registry.active_leases(), 1);
        }
        assert_eq!(registry.active_leases(), 0);
        assert_eq!(registry.retention_floor(), None);
    }

    #[test]
    fn acquire_refuses_floors_the_prune_line_already_crossed() {
        let registry = Arc::new(RetentionRegistry::new());
        let reservation = registry.reserve(500);
        reservation.commit(500);

        assert!(matches!(
            registry.acquire(499),
            Err(RetentionError {
                requested: 499,
                pruned_below: 500
            })
        ));
        assert_eq!(held(registry.acquire(500)).floor(), 500);

        let second = registry.reserve(100);
        assert_eq!(second.commit(100), 100);
        assert_eq!(registry.pruned_below(), 500);
        assert!(registry.acquire(499).is_err());
    }

    #[test]
    fn reservation_refuses_history_until_it_commits_or_aborts() {
        let registry = Arc::new(RetentionRegistry::new());
        assert_eq!(held(registry.acquire(499)).floor(), 499);

        let reservation = registry.reserve(500);
        assert!(matches!(
            registry.acquire(499),
            Err(RetentionError {
                requested: 499,
                pruned_below: 500
            })
        ));
        assert_eq!(held(registry.acquire(500)).floor(), 500);

        assert_eq!(reservation.commit(500), 500);
        assert!(registry.acquire(499).is_err());
        assert_eq!(registry.pruned_below(), 500);

        let aborted = registry.reserve(700);
        assert!(registry.acquire(699).is_err());
        drop(aborted);
        assert_eq!(registry.pruned_below(), 500);
        assert_eq!(held(registry.acquire(699)).floor(), 699);
    }

    #[test]
    fn reservation_line_folds_live_floors_and_nests() {
        let registry = Arc::new(RetentionRegistry::new());
        let lease = held(registry.acquire(300));

        let outer = registry.reserve(500);
        assert_eq!(outer.line(), 300);

        let inner_reservation = registry.reserve(700);
        assert_eq!(inner_reservation.line(), 300);
        assert!(registry.acquire(299).is_err());
        inner_reservation.commit(300);
        assert!(registry.acquire(299).is_err());
        drop(outer);
        assert_eq!(registry.pruned_below(), 300);
        assert_eq!(held(registry.acquire(400)).floor(), 400);
        lease.release();
    }

    fn pinned(result: Result<HistoryLease, HistoryUnavailable>) -> HistoryLease {
        match result {
            Ok(lease) => lease,
            Err(error) => panic!("history refused: {error}"),
        }
    }

    #[test]
    fn history_grant_is_refused_below_the_line_and_bounded_by_budget() {
        let registry = Arc::new(RetentionRegistry::new());
        let lease = pinned(registry.history_from(100, RetentionBudget::Depth(50)));
        assert_eq!(lease.floor(), Some(100));
        assert_eq!(registry.retention_floor(), Some(100));

        let pass = registry.reserve(200);
        assert_eq!(pass.line(), 200);
        assert_eq!(registry.active_leases(), 0);
        assert_eq!(lease.floor(), None);
        drop(pass);

        let required = held(registry.acquire(100));
        let roomy = pinned(registry.history_from(150, RetentionBudget::Depth(200)));
        let pass = registry.reserve(200);
        assert_eq!(pass.line(), 100);
        assert_eq!(registry.active_leases(), 2);
        drop(pass);
        roomy.release();
        required.release();
    }

    #[test]
    fn history_advance_is_monotonic_and_release_returns_the_authority() {
        let registry = Arc::new(RetentionRegistry::new());
        let lease = pinned(registry.history_from(10, RetentionBudget::Unlimited));
        assert_eq!(registry.retention_floor(), Some(10));

        lease.advance(20);
        assert_eq!(lease.floor(), Some(20));
        assert_eq!(registry.retention_floor(), Some(20));
        lease.advance(15);
        assert_eq!(registry.retention_floor(), Some(20));

        lease.release();
        assert_eq!(registry.retention_floor(), None);
        assert_eq!(registry.active_leases(), 0);
    }

    #[test]
    fn history_request_crosses_no_reservation() {
        let registry = Arc::new(RetentionRegistry::new());
        let pass = registry.reserve(500);
        assert!(matches!(
            registry.history_from(499, RetentionBudget::Unlimited),
            Err(HistoryUnavailable::Reserved { below: 500 })
        ));
        assert_eq!(
            registry
                .history_from(500, RetentionBudget::Unlimited)
                .map(|lease| lease.floor()),
            Ok(Some(500))
        );
        drop(pass);
    }

    #[test]
    fn history_request_below_the_executed_frontier_is_permanent() {
        let registry = Arc::new(RetentionRegistry::new());
        registry.reserve(500).commit(500);
        assert!(matches!(
            registry.history_from(499, RetentionBudget::Unlimited),
            Err(HistoryUnavailable::Pruned { below: 500 })
        ));
        let pass = registry.reserve(600);
        assert!(matches!(
            registry.history_from(550, RetentionBudget::Unlimited),
            Err(HistoryUnavailable::Reserved { below: 600 })
        ));
        drop(pass);
    }

    #[test]
    fn shutdown_closes_the_history_boundary() {
        let registry = Arc::new(RetentionRegistry::new());
        assert!(registry.history_from(0, RetentionBudget::Depth(1)).is_ok());
        registry.shutdown();
        assert!(matches!(
            registry.history_from(0, RetentionBudget::Depth(1)),
            Err(HistoryUnavailable::Shutdown)
        ));
        assert_eq!(held(registry.acquire(0)).floor(), 0);
    }

    #[test]
    fn a_live_floor_zero_is_not_a_released_lease() {
        let registry = Arc::new(RetentionRegistry::new());
        let lease = pinned(registry.history_from(0, RetentionBudget::Depth(1)));
        assert_eq!(lease.floor(), Some(0));
        assert_eq!(registry.retention_floor(), Some(0));

        let pass = registry.reserve(10);
        assert_eq!(lease.floor(), None);
        drop(pass);
    }
}
