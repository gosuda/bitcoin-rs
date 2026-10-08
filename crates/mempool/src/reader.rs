use std::sync::Arc;

use parking_lot::RwLock;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLockWriteGuard;

use crate::Mempool;

/// Cloneable, read-only access to the mempool.
///
/// Only read guards are obtainable in production builds, preserving
/// [`crate::MempoolGateway`] as the sole owner of pool mutations and observer publication.
#[derive(Clone, Debug)]
pub struct MempoolReader {
    inner: Arc<RwLock<Mempool>>,
}

impl MempoolReader {
    /// Wraps a mempool without exposing its write lock in production.
    #[must_use]
    pub const fn new(inner: Arc<RwLock<Mempool>>) -> Self {
        Self { inner }
    }

    /// Acquires a shared mempool read guard.
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, Mempool> {
        self.inner.read()
    }

    /// Acquires a fixture-only write guard. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn write(&self) -> RwLockWriteGuard<'_, Mempool> {
        self.inner.write()
    }

    /// Raw pool handle for test fixtures.
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
