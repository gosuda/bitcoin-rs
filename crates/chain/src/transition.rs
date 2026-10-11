//! Transition exclusion: one domain, split into the two roles that serialize against it.

use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

/// Exclusion domain split into non-convertible mutation and stable-read roles.
///
/// Composition must share one domain per opened node: a separately
/// constructed domain excludes nothing on the live chain.
#[derive(Default)]
pub struct TransitionDomain {
    inner: Arc<Mutex<()>>,
}

impl TransitionDomain {
    /// Mints a fresh domain that no other component shares yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits off the mutation role: held across an authoritative chain transition.
    #[must_use]
    pub fn authority(&self) -> TransitionAuthority {
        TransitionAuthority {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Splits off the read role: held while a read must not observe a transition.
    #[must_use]
    pub fn stable_read(&self) -> StableRead {
        StableRead {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Mutation-side role: excludes stable reads for as long as a chain transition runs.
///
/// Production composition passes it only to chainstate and destructive
/// pruning, which take it through their own admission first.
#[derive(Clone)]
pub struct TransitionAuthority {
    inner: Arc<Mutex<()>>,
}

impl TransitionAuthority {
    /// Attempts exclusion for a bounded interval, allowing observers to check
    /// cancellation while a long transition is still running.
    pub fn try_lock_for(
        &self,
        timeout: std::time::Duration,
    ) -> Option<TransitionAuthorityGuard<'_>> {
        self.inner
            .try_lock_for(timeout)
            .map(|guard| TransitionAuthorityGuard { _guard: guard })
    }

    /// Excludes every stable read on this domain until the guard is dropped.
    pub fn lock(&self) -> TransitionAuthorityGuard<'_> {
        TransitionAuthorityGuard {
            _guard: self.inner.lock(),
        }
    }
}

/// Read-side role: excludes authoritative transitions for as long as a stable read runs.
///
/// This is the capability RPC, index, and mining receive. It offers blocking and bounded read exclusion, with no access to the shared
/// cell and no path to a
/// [`TransitionAuthority`]. A caller with access to [`TransitionDomain::new`]
/// can still mint an unrelated read role.
#[derive(Clone)]
pub struct StableRead {
    inner: Arc<Mutex<()>>,
}

impl StableRead {
    /// Waits at most timeout for the read exclusion, permitting bounded callers
    /// to observe cancellation before trying again.
    pub fn try_lock_for(&self, timeout: std::time::Duration) -> Option<StableReadGuard<'_>> {
        self.inner
            .try_lock_for(timeout)
            .map(|guard| StableReadGuard { _guard: guard })
    }

    /// Excludes authoritative transitions until the returned guard is dropped.
    pub fn lock(&self) -> StableReadGuard<'_> {
        StableReadGuard {
            _guard: self.inner.lock(),
        }
    }

    /// Attempts the same exclusion without blocking, so a caller can fail fast
    /// instead of queueing behind a transition it cannot help finish.
    /// Only exercised by test fixtures. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn try_lock(&self) -> Option<StableReadGuard<'_>> {
        self.inner
            .try_lock()
            .map(|guard| StableReadGuard { _guard: guard })
    }
}

/// Opaque guard excluding stable reads until dropped.
pub struct TransitionAuthorityGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

/// Proof that authoritative transitions are excluded for as long as it lives.
pub struct StableReadGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}
