use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;
#[cfg(any(test, feature = "test-seam"))]
use std::sync::atomic::AtomicUsize;

pub struct TransitionDomain {
    inner: Arc<Mutex<()>>,
    #[cfg(any(test, feature = "test-seam"))]
    acquisitions: Arc<AtomicUsize>,
}

impl TransitionDomain {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::default(),
            #[cfg(any(test, feature = "test-seam"))]
            acquisitions: Arc::new(AtomicUsize::new(0)),
        }
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
            #[cfg(any(test, feature = "test-seam"))]
            acquisitions: Arc::clone(&self.acquisitions),
        }
    }
}

impl Default for TransitionDomain {
    fn default() -> Self {
        Self::new()
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
    #[cfg(any(test, feature = "test-seam"))]
    acquisitions: Arc<AtomicUsize>,
}

impl StableRead {
    pub fn try_lock_for(&self, timeout: std::time::Duration) -> Option<StableReadGuard<'_>> {
        let guard = self.inner.try_lock_for(timeout)?;
        #[cfg(any(test, feature = "test-seam"))]
        self.acquisitions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(StableReadGuard { _guard: guard })
    }

    pub fn lock(&self) -> StableReadGuard<'_> {
        let guard = self.inner.lock();
        #[cfg(any(test, feature = "test-seam"))]
        self.acquisitions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        StableReadGuard { _guard: guard }
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn lock_acquisitions(&self) -> usize {
        self.acquisitions.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn try_lock(&self) -> Option<StableReadGuard<'_>> {
        let guard = self.inner.try_lock()?;
        self.acquisitions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Some(StableReadGuard { _guard: guard })
    }
}

pub struct TransitionAuthorityGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

pub struct StableReadGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

#[cfg(test)]
mod tests {
    use super::TransitionDomain;
    use std::time::Duration;

    #[test]
    fn stable_read_counts_only_successful_acquisitions_across_all_entry_paths() {
        let domain = TransitionDomain::new();
        let reader = domain.stable_read();
        let authority = domain.authority();
        let held = authority.lock();
        assert!(reader.try_lock().is_none());
        assert!(reader.try_lock_for(Duration::ZERO).is_none());
        assert_eq!(reader.lock_acquisitions(), 0);
        drop(held);
        drop(reader.lock());
        assert_eq!(reader.lock_acquisitions(), 1);
        let immediate = reader.try_lock();
        assert!(immediate.is_some());
        assert_eq!(reader.lock_acquisitions(), 2);
        drop(immediate);
        let timed = reader.try_lock_for(Duration::ZERO);
        assert!(timed.is_some());
        assert_eq!(reader.lock_acquisitions(), 3);
        drop(timed);
    }
}
