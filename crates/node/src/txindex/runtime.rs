//! Revision, health, and bounded wake state shared with committed chain followers.

use bitcoin_rs_index::{
    IndexCapabilities,
    reconcile::{ReconcileLeg, ReconcilePhase},
};
use compact_str::CompactString;
use crossbeam_channel::Sender;
use parking_lot::RwLock;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

/// Shared wake/revision/health state owned by `NodeState` and referenced by
/// `Chainstate`, the worker thread, and the query engine.
#[derive(Debug)]
pub struct DerivedIndexRuntime {
    revision: AtomicU64,
    pub(super) shutdown: AtomicBool,
    pub(super) failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<CompactString>>,
    phase: arc_swap::ArcSwap<ReconcilePhase>,
}
impl DerivedIndexRuntime {
    /// Creates a runtime attached to `wake_tx`.
    #[must_use]
    pub fn new(wake_tx: Sender<()>) -> Self {
        Self {
            revision: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wake_tx,
            failure_message: RwLock::new(None),
            phase: arc_swap::ArcSwap::from_pointee(ReconcilePhase::FORWARD),
        }
    }

    /// Publishes the reconciliation phase. Only the worker thread writes it.
    pub fn publish_phase(&self, phase: ReconcilePhase) {
        if **self.phase.load() != phase {
            self.phase.store(Arc::new(phase));
        }
    }

    /// Publishes `leg` for `capabilities`, leaving the other legs as they are.
    pub fn publish_leg(&self, capabilities: IndexCapabilities, leg: ReconcileLeg) {
        self.publish_phase(self.phase().with_leg(capabilities, leg));
    }

    /// Returns the reconciliation phase the worker last published.
    #[must_use]
    pub fn phase(&self) -> ReconcilePhase {
        **self.phase.load()
    }

    /// Called immediately after a committed `applied_tip.store`.
    ///
    /// Increments the revision with `Release` ordering and `try_send`s one
    /// wake.  Coalesced or lost wakes are harmless: the worker reconciles
    /// against current authoritative state each loop.
    pub fn wake(&self) {
        self.revision.fetch_add(1, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Marks the worker as failed with an explanatory message.
    pub fn publish_failed(&self, message: impl Into<CompactString>) {
        *self.failure_message.write() = Some(message.into());
        self.failed.store(true, Ordering::Release);
    }

    /// Returns the current revision.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Returns true once a failure or shutdown has been published.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    /// Initiates graceful shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Returns the published failure message, if any.
    #[must_use]
    pub fn failure_message(&self) -> Option<CompactString> {
        self.failure_message.read().clone()
    }
}
