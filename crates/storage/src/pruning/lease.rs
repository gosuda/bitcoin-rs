//! Retention authority for required readers of prunable chain history.
//!
//! Pruning deletes historical block bodies and undo records once the active
//! chain no longer needs them. The active chain is not the only reader: a
//! reorg transition re-reads old-branch bodies it is about to disconnect,
//! boot replay reads the bodies the durable head names, and a derived-index
//! catch-up may read bodies older than the current prune line. Such a
//! reader holds a [`RetentionLease`]: a registered floor height that every
//! pruning pass folds into its prune line, so deletion can never cross it.
//!
//! The binding constraint is the *lowest* active floor. Each lease requires
//! rows at heights at or above its floor to survive, so the union of the
//! constraints keeps exactly the rows the deepest lease needs; rows below
//! every floor remain prunable.
//!
//! Leases are bounded by what still exists. A floor at or below the highest
//! prune line already executed is refused with
//! [`RetentionError::PrunedBelow`] — the defined required-history-is-gone
//! result (`RCV-08`: optional consumer lag cannot retain unlimited
//! segments, and missing required history is an unavailable result, never a
//! partial success). An optional consumer that falls that far behind must
//! rebuild to follow again; it can never pin rows it already lost, and
//! releasing its lease always returns pruning to exactly the policy line.
//!
//! One prune pass claims the rows it means to delete through
//! [`RetentionRegistry::reserve`]. That reservation is the protocol's
//! single linearization point: a lease request that arrives before it is
//! folded into the reserved line, and a request that arrives after it and
//! below that line is refused. The pass then commits the line it actually
//! deleted through. No consumer rechecks after the deletion, and no
//! request can cross a deletion inconsistently.

use crate::pruning::ExecutedFrontier;
use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::AtomicBool;
use hashbrown::HashMap;
use parking_lot::Mutex;
use thiserror::Error;

/// Registry of live retention leases and the highest prune line executed.
///
/// One instance per open node, shared by the pruning pass and every reader
/// that needs prunable history to stay. Leases, reservations, and
/// prune-line updates are serialized by the inner mutex, so a lease can
/// never straddle a prune that deletes its data: a floor is either
/// registered before the reserved line crosses it (the prune respects it)
/// or refused after (the reader learns the data is gone).
#[derive(Default)]
pub struct RetentionRegistry {
    inner: Mutex<RegistryInner>,
    /// Set once when the owner begins shutting down: after it, no new
    /// history is granted, so a consumer stops instead of pinning rows a
    /// process that is leaving will not serve.
    shutting_down: AtomicBool,
}

#[derive(Debug, Default)]
struct RegistryInner {
    next_ticket: u64,
    /// Heights below this line were already handed to a completed prune.
    pruned_below: u32,
    /// Deletion lines of prune passes that reserved rows but have not yet
    /// committed. A lease is refused below any of them, so no history
    /// request can cross a reservation between staging and commit.
    reservations: Vec<u32>,
    /// Live leases: ticket -> floor.
    floors: HashMap<u64, u32>,
}

impl RegistryInner {
    /// The lowest line a lease floor must reach: everything below the
    /// executed prune line or below any outstanding prune reservation is
    /// gone or already claimed for deletion.
    fn refusal_line(&self) -> u32 {
        self.pruned_below
            .max(self.reservations.iter().copied().max().unwrap_or(0))
    }
}

/// Why a retention lease could not be granted.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Error)]
pub enum RetentionError {
    /// The requested floor names data pruning has already deleted. The
    /// caller's retention budget was exceeded while it was not holding a
    /// lease; the defined recovery is to rebuild from what remains, not to
    /// retry.
    #[error("required history at height {requested} is already pruned (prune line {pruned_below})")]
    PrunedBelow {
        /// Floor the caller asked to pin.
        requested: u32,
        /// Highest prune line already executed.
        pruned_below: u32,
    },
}

impl fmt::Debug for RetentionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("RetentionRegistry")
            .field("inner", &self.inner)
            .field("shutting_down", &self.shutting_down)
            .field("active_leases", &inner.floors.len())
            .field("retention_floor", &inner.floors.values().min())
            .field("pruned_below", &inner.pruned_below)
            .finish()
    }
}

impl RetentionRegistry {
    /// Creates an empty registry with no prune line executed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a registry whose executed line is the frontier an earlier
    /// process committed.
    ///
    /// PRE: `frontier` came from [`ExecutedFrontier::reconstruct`] over the
    /// same store, so it names exactly the deletions that committed.
    ///
    /// POST: leases below the frontier are refused from the first moment, so
    /// a restart grants no lease over rows the previous process deleted.
    /// Reconstructing the boundary is therefore not a best-effort guess the
    /// node has to re-derive later: it is the registry's starting state.
    #[must_use]
    pub fn seeded(frontier: ExecutedFrontier) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                pruned_below: frontier.get(),
                ..RegistryInner::default()
            }),
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Acquires a lease pinning rows at `floor` and above against pruning.
    ///
    /// Fails when the floor is below the executed prune line or below the
    /// deletion line of an outstanding [`PruneReservation`]: those rows are
    /// gone or already claimed for deletion, and a lease cannot resurrect
    /// them.
    pub fn acquire(self: &Arc<Self>, floor: u32) -> Result<RetentionLease, RetentionError> {
        let mut inner = self.inner.lock();
        let line = inner.refusal_line();
        if floor < line {
            return Err(RetentionError::PrunedBelow {
                requested: floor,
                pruned_below: line,
            });
        }
        let ticket = inner.next_ticket;
        inner.next_ticket = ticket.wrapping_add(1);
        inner.floors.insert(ticket, floor);
        Ok(RetentionLease {
            registry: Arc::clone(self),
            lease: Some((ticket, floor)),
        })
    }

    /// The lowest active lease floor, if any lease is live.
    ///
    /// This is the line a pruning pass may not cross: rows at heights at or
    /// above it are required by their holders.
    #[must_use]
    pub fn retention_floor(&self) -> Option<u32> {
        self.inner.lock().floors.values().copied().min()
    }

    /// The highest prune line a completed pass has recorded.
    ///
    /// Monotonic: pruning only moves forward. Floors at or below it can no
    /// longer be acquired.
    #[must_use]
    pub fn pruned_below(&self) -> u32 {
        self.inner.lock().pruned_below
    }

    /// Number of live leases.
    #[must_use]
    pub fn active_leases(&self) -> usize {
        self.inner.lock().floors.len()
    }

    /// Reserves the deletion range of one prune pass.
    ///
    /// PRE: the caller holds the pruning authority, so at most one pass
    /// reserves at a time, and `policy_line` is the line the pass would
    /// delete through before any retention folding.
    ///
    /// POST: the returned reservation's line — `policy_line` folded with
    /// every live lease floor — is snapshotted, and [`Self::acquire`]
    /// refuses floors below it until the reservation commits or aborts.
    ///
    /// INVARIANT: the executed prune line advances only through
    /// [`PruneReservation::commit`], so mutation authority stays inside
    /// this protocol and no caller records a line on the side.
    #[must_use = "a dropped reservation releases the prune claim"]
    pub fn reserve(self: &Arc<Self>, policy_line: u32) -> PruneReservation {
        let mut inner = self.inner.lock();
        let line = policy_line.min(inner.floors.values().copied().min().unwrap_or(u32::MAX));
        inner.reservations.push(line);
        PruneReservation {
            registry: Arc::clone(self),
            line,
            committed: false,
        }
    }

    /// Promotes a committed reservation's executed line and releases it.
    fn commit_reservation(&self, line: u32, executed: u32) {
        let mut inner = self.inner.lock();
        Self::release_reservation(&mut inner, line);
        if executed > inner.pruned_below {
            inner.pruned_below = executed;
        }
    }

    /// Releases an aborted reservation without advancing the executed line.
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
}

/// One prune pass's claim on the rows it is about to delete.
///
/// A pass reserves its folded deletion line before it stages rows, holds
/// the claim across the commit, and then promotes the line it actually
/// deleted through. While the claim is outstanding, a lease request below
/// it is refused, so no reader can pin rows the pass has already staged.
///
/// PRE: built only by [`RetentionRegistry::reserve`].
///
/// POST: exactly one of [`Self::commit`] (the pass deleted through its
/// line) or `Drop` (the pass failed and grants flow again) settles the
/// claim.
///
/// INVARIANT: the executed prune line never moves backwards, and it never
/// advances for a deletion that did not commit.
#[derive(Debug)]
pub struct PruneReservation {
    registry: Arc<RetentionRegistry>,
    line: u32,
    committed: bool,
}

impl PruneReservation {
    /// The deletion line this reservation holds: the policy line folded
    /// with every live lease floor at reserve time.
    ///
    /// A pass stages through this line and must not re-derive it, or a
    /// lease registered after the reservation would be crossed.
    #[must_use]
    pub fn line(&self) -> u32 {
        self.line
    }

    /// Records that the pass deleted through `executed`, promotes it into
    /// the registry's executed prune line, and releases the claim.
    ///
    /// `executed` is the frontier this pass leaves behind: one past the
    /// highest row it deleted, clamped with the durable frontier it migrated
    /// from. The promotion is monotonic, so a pass never lowers the line and
    /// never claims a deletion that did not commit.
    ///
    /// Returns the line this reservation held.
    pub fn commit(mut self, executed: u32) -> u32 {
        self.committed = true;
        let line = self.line;
        self.registry.commit_reservation(line, executed);
        line
    }
}

impl Drop for PruneReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.registry.abort_reservation(self.line);
        }
    }
}

/// One reader's pin on rows at or above its floor.
///
/// Released exactly once: either by [`RetentionLease::release`] or, on any
/// exit path that skips it (cancellation, failure, panic unwinding), by
/// `Drop`. After a release, in either form, the registry no longer counts
/// the lease, so completion, cancellation, and failure each hand the
/// retention authority back exactly once.
#[derive(Debug)]
pub struct RetentionLease {
    registry: Arc<RetentionRegistry>,
    lease: Option<(u64, u32)>,
}

impl RetentionLease {
    /// The floor this lease pins.
    #[must_use]
    pub fn floor(&self) -> u32 {
        self.lease.as_ref().map_or(0, |&(_, floor)| floor)
    }

    /// Releases the pin, returning the retention authority to pruning.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwraps a lease acquisition in tests without `expect` (warn band).
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

        // A second, shallower lease must not mask the deeper one: the union
        // of the two constraints keeps rows at or above 300.
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

        // A guard that only drops (cancelled or failed holder) releases
        // through the same path exactly once.
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
            Err(RetentionError::PrunedBelow {
                requested: 499,
                pruned_below: 500
            })
        ));
        // The boundary itself still exists: rows at the line survive a
        // prune, which deletes strictly below it.
        assert_eq!(held(registry.acquire(500)).floor(), 500);

        // The line is monotonic; a smaller recording cannot roll it back.
        let second = registry.reserve(100);
        assert_eq!(second.commit(100), 100);
        assert_eq!(registry.pruned_below(), 500);
        assert!(registry.acquire(499).is_err());
    }

    #[test]
    fn reservation_refuses_history_until_it_commits_or_aborts() {
        let registry = Arc::new(RetentionRegistry::new());
        assert_eq!(held(registry.acquire(499)).floor(), 499);

        // A pass planning deletions through 500 blocks every request that
        // would cross its claim, before any deletion has committed.
        let reservation = registry.reserve(500);
        assert!(matches!(
            registry.acquire(499),
            Err(RetentionError::PrunedBelow {
                requested: 499,
                pruned_below: 500
            })
        ));
        // The reserved line itself is still grantable: the pass deletes
        // strictly below it.
        assert_eq!(held(registry.acquire(500)).floor(), 500);

        // Committing promotes the executed line, so the refusal survives
        // the reservation.
        assert_eq!(reservation.commit(500), 500);
        assert!(registry.acquire(499).is_err());
        assert_eq!(registry.pruned_below(), 500);

        // A pass that fails hands the authority back: the same floor that
        // the aborted claim refused is grantable again.
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

        // A reader that pinned 300 before the pass planned constrains the
        // reservation, so the pass cannot claim rows the lease holds.
        let outer = registry.reserve(500);
        assert_eq!(outer.line(), 300);

        // A nested claim refuses to the deepest outstanding line, and
        // releasing one claim keeps the other's refusal.
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
}
