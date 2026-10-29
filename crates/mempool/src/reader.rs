use std::sync::Arc;

use parking_lot::RwLock;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLockWriteGuard;

use crate::Mempool;

#[derive(Clone, Debug)]
pub struct MempoolReader {
    inner: Arc<RwLock<Mempool>>,
}

impl MempoolReader {
    #[must_use]
    pub const fn new(inner: Arc<RwLock<Mempool>>) -> Self {
        Self { inner }
    }

    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, Mempool> {
        self.inner.read()
    }

    #[cfg(any(test, feature = "test-seam"))]
    pub fn write(&self) -> RwLockWriteGuard<'_, Mempool> {
        self.inner.write()
    }

    #[cfg(any(test, feature = "test-seam"))]
    #[must_use]
    pub fn raw_handle(&self) -> &Arc<RwLock<Mempool>> {
        &self.inner
    }
}

impl From<Arc<RwLock<Mempool>>> for MempoolReader {
    fn from(inner: Arc<RwLock<Mempool>>) -> Self {
        Self::new(inner)
    }
}
