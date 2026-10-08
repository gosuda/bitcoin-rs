use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwapOption;
#[cfg(any(test, feature = "test-seam"))]
use parking_lot::RwLockWriteGuard;
use parking_lot::{RwLock, RwLockReadGuard};

use crate::{BlockTree, TipSnapshot};

/// Cloneable, read-only access to one published chain tip.
///
/// The publication cell stays private, so consumers can observe snapshots but
/// cannot publish a different tip.
#[derive(Clone)]
pub struct TipReader {
    inner: Arc<ArcSwapOption<TipSnapshot>>,
}

impl TipReader {
    /// Wraps a publication cell without exposing it again.
    #[must_use]
    pub const fn new(inner: Arc<ArcSwapOption<TipSnapshot>>) -> Self {
        Self { inner }
    }

    /// Loads the current tip snapshot.
    #[must_use]
    pub fn load_full(&self) -> Option<Arc<TipSnapshot>> {
        self.inner.load_full()
    }

    /// Publishes a fixture tip. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn store(&self, tip: Option<Arc<TipSnapshot>>) {
        self.inner.store(tip);
    }
}

/// Cloneable, read-only access to one chain-owned latch.
///
/// The flag cell stays private, so consumers can observe the latch but
/// cannot set it; only the owner writes.
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
    /// Wraps a latch cell without exposing it again.
    #[must_use]
    pub const fn new(inner: Arc<AtomicBool>) -> Self {
        Self { inner }
    }

    /// Loads the latch's current state.
    #[must_use]
    pub fn load(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    /// Sets a fixture latch. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn store(&self, value: bool) {
        self.inner.store(value, Ordering::Release);
    }
}

/// Cloneable, read-only access to the authoritative block tree.
///
/// Only a read guard is obtainable from this capability, and every `&self`
/// tree accessor is a pure read — the tip publication cell is only shared
/// through `&mut` access. Header admission and all other tree mutation stay
/// with the chainstate owner.
#[derive(Clone)]
pub struct BlockTreeReader {
    inner: Arc<RwLock<BlockTree>>,
}

impl BlockTreeReader {
    /// Wraps a block tree without exposing its write lock.
    #[must_use]
    pub const fn new(inner: Arc<RwLock<BlockTree>>) -> Self {
        Self { inner }
    }

    /// Acquires a shared tree guard.
    pub fn read(&self) -> RwLockReadGuard<'_, BlockTree> {
        self.inner.read()
    }

    /// Acquires a fixture-only write guard. Not present in production builds.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn write(&self) -> RwLockWriteGuard<'_, BlockTree> {
        self.inner.write()
    }
}
