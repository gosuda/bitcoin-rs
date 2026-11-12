use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;

#[derive(Default)]
pub struct TransitionDomain {
    inner: Arc<Mutex<()>>,
}

impl TransitionDomain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn authority(&self) -> TransitionAuthority {
        TransitionAuthority {
            inner: Arc::clone(&self.inner),
        }
    }

    #[must_use]
    pub fn stable_read(&self) -> StableRead {
        StableRead {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Clone)]
pub struct TransitionAuthority {
    inner: Arc<Mutex<()>>,
}

impl TransitionAuthority {
    pub fn try_lock_for(
        &self,
        timeout: std::time::Duration,
    ) -> Option<TransitionAuthorityGuard<'_>> {
        self.inner
            .try_lock_for(timeout)
            .map(|guard| TransitionAuthorityGuard { _guard: guard })
    }

    pub fn lock(&self) -> TransitionAuthorityGuard<'_> {
        TransitionAuthorityGuard {
            _guard: self.inner.lock(),
        }
    }
}

#[derive(Clone)]
pub struct StableRead {
    inner: Arc<Mutex<()>>,
}

impl StableRead {
    pub fn try_lock_for(&self, timeout: std::time::Duration) -> Option<StableReadGuard<'_>> {
        self.inner
            .try_lock_for(timeout)
            .map(|guard| StableReadGuard { _guard: guard })
    }

    pub fn lock(&self) -> StableReadGuard<'_> {
        StableReadGuard {
            _guard: self.inner.lock(),
        }
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn try_lock(&self) -> Option<StableReadGuard<'_>> {
        self.inner
            .try_lock()
            .map(|guard| StableReadGuard { _guard: guard })
    }
}

pub struct TransitionAuthorityGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

pub struct StableReadGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}
