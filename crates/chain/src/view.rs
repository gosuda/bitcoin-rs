use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwapOption;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLockWriteGuard;
use parking_lot::{RwLock, RwLockReadGuard};

use crate::{BlockTree, TipSnapshot};

#[derive(Clone)]
pub struct TipReader {
    inner: Arc<ArcSwapOption<TipSnapshot>>,
}

impl TipReader {
    #[must_use]
    pub const fn new(inner: Arc<ArcSwapOption<TipSnapshot>>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn load_full(&self) -> Option<Arc<TipSnapshot>> {
        self.inner.load_full()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn store(&self, tip: Option<Arc<TipSnapshot>>) {
        self.inner.store(tip);
    }
}

#[derive(Clone, Debug)]
pub struct LatchReader {
    inner: Arc<AtomicBool>,
}

impl From<Arc<AtomicBool>> for LatchReader {
    fn from(inner: Arc<AtomicBool>) -> Self {
        Self::new(inner)
    }
}

impl LatchReader {
    #[must_use]
    pub const fn new(inner: Arc<AtomicBool>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn load(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn is_triggered(&self) -> bool {
        self.load()
    }

    #[must_use]
    pub fn fixture_never() -> Self {
        Self::new(Arc::new(AtomicBool::new(false)))
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn store(&self, value: bool) {
        self.inner.store(value, Ordering::Release);
    }
}

#[derive(Clone)]
pub struct BlockTreeReader {
    inner: Arc<RwLock<BlockTree>>,
}

impl BlockTreeReader {
    #[must_use]
    pub const fn new(inner: Arc<RwLock<BlockTree>>) -> Self {
        Self { inner }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, BlockTree> {
        self.inner.read()
    }

    pub fn try_read_for(
        &self,
        timeout: std::time::Duration,
    ) -> Option<RwLockReadGuard<'_, BlockTree>> {
        self.inner.try_read_for(timeout)
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn write(&self) -> RwLockWriteGuard<'_, BlockTree> {
        self.inner.write()
    }
}
