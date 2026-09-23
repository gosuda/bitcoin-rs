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

use alloc::sync::Arc;
use core::fmt;
use hashbrown::HashMap;
use parking_lot::Mutex;
use thiserror::Error;

/// Registry of live retention leases and the highest prune line executed.
///
/// One instance per open node, shared by the pruning pass and every reader
/// that needs prunable history to stay. Leases and prune-line updates are
/// serialized by the inner mutex, so a lease can never straddle a prune
/// that deletes its data: a floor is either registered before the line
/// crosses it (the prune respects it) or refused after (the reader learns
/// the data is gone).
#[derive(Default)]
pub struct RetentionRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    next_ticket: u64,
    /// Heights below this line were already handed to a completed prune.
    pruned_below: u32,
    /// Live leases: ticket -> floor.
    floors: HashMap<u64, u32>,
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
            .field("active_leases", &inner.floors.len())
            .field("retention_floor", &inner.floors.values().min())
            .field("pruned_below", &inner.pruned_below)
            .finish()
    }
}

impl RetentionRegistry {
    /// Creates an empty registry with no prune line executed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires a lease pinning rows at `floor` and above against pruning.
    ///
    /// Fails when the floor is below the highest prune line already
    /// executed: those rows are gone, and a lease cannot resurrect them.
    pub fn acquire(self: &Arc<Self>, floor: u32) -> Result<RetentionLease, RetentionError> {
        let mut inner = self.inner.lock();
        if floor < inner.pruned_below {
            return Err(RetentionError::PrunedBelow {
                requested: floor,
                pruned_below: inner.pruned_below,
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

    /// Records the prune line a completed pass deleted through.
    ///
    /// Callers invoke this only after the deletion batch and its flat-file
    /// reclamation have both committed, so the recorded line never claims a
    /// deletion that did not happen.
    pub fn record_pruned_below(&self, line: u32) {
        let mut inner = self.inner.lock();
        if line > inner.pruned_below {
            inner.pruned_below = line;
        }
    }

    fn release(&self, ticket: u64) {
        self.inner.lock().floors.remove(&ticket);
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

    /// Raises the pinned floor, returning the effective floor.
    ///
    /// A holder that made durable progress past its oldest required row can
    /// move its pin forward so pruning reclaims what it no longer needs.
    /// The move is monotonic: a request at or below the current floor is a
    /// no-op, so a floor only ever rises under a live lease. Raising is
    /// always grantable while the lease is held — a prune pass cannot cross
    /// a live floor, so the recorded prune line never passes the floor being
    /// raised from, let alone the one being raised to.
    pub fn advance(&mut self, floor: u32) -> u32 {
        let Some((ticket, current)) = self.lease.as_mut() else {
            return 0;
        };
        if floor > *current {
            *current = floor;
            let mut inner = self.registry.inner.lock();
            if let Some(pinned) = inner.floors.get_mut(ticket) {
                *pinned = floor;
            }
        }
        *current
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
        registry.record_pruned_below(500);

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
        registry.record_pruned_below(100);
        assert_eq!(registry.pruned_below(), 500);
        assert!(registry.acquire(499).is_err());
    }

    #[test]
    fn advance_moves_the_pin_forward_and_is_monotonic() {
        let registry = Arc::new(RetentionRegistry::new());
        let mut lease = held(registry.acquire(100));
        assert_eq!(registry.retention_floor(), Some(100));

        // Raising the floor moves the registry's binding constraint so a
        // prune pass reclaims everything below the holder's durable
        // progress.
        assert_eq!(lease.advance(300), 300);
        assert_eq!(registry.retention_floor(), Some(300));
        assert_eq!(lease.floor(), 300);

        // A floor only rises: a stale caller re-advancing from an old
        // watermark cannot un-pin rows the holder already released.
        assert_eq!(lease.advance(200), 300);
        assert_eq!(registry.retention_floor(), Some(300));
    }

    #[test]
    fn advanced_floor_keeps_binding_the_prune_line() {
        let registry = Arc::new(RetentionRegistry::new());
        let mut lease = held(registry.acquire(50));
        lease.advance(500);

        // The prune line folds the live floor: while the lease lives, no
        // pass may record a line at or above it.
        assert_eq!(registry.retention_floor(), Some(500));
        drop(lease);
        assert_eq!(registry.retention_floor(), None);
    }
}
