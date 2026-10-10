//! Read-only waits on the chain owner's durable applied-tip publication.

use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_primitives::Hash256;

use crate::{LatchReader, TipSnapshot};

/// Predicate evaluated against the current applied tip, never header history.
#[derive(Clone, Copy, Debug)]
pub enum TipWaitCondition {
    /// A different hash; `None` captures the starting tip once on entry.
    Changed(Option<Hash256>),
    /// The target must be the current tip, not merely an ancestor.
    Hash(Hash256),
    /// The current height must be at least this signed target.
    Height(i32),
}

impl TipWaitCondition {
    /// Tests one immutable published tip.
    #[must_use]
    pub fn matches(self, tip: &TipSnapshot) -> bool {
        match self {
            Self::Changed(hash) => hash.is_some_and(|hash| hash != tip.hash),
            Self::Hash(hash) => hash == tip.hash,
            Self::Height(height) => i64::from(tip.height) >= i64::from(height),
        }
    }
}

/// Chain-owned observation of applied tips, with no mutation or mining access.
///
/// The caller sets its cancellation latch before calling `wake_waiters`.
/// Implementations serialize notification with predicate checking and parking,
/// so cancellation cannot be missed even when it races waiter registration.
pub trait ActiveTipWait: Send + Sync {
    /// Waits until the predicate, absolute deadline, or either shutdown latch
    /// is satisfied. Timeout/cancellation returns the current published tip;
    /// `None` means no applied tip has been initialized.
    fn wait_for_tip(
        &self,
        condition: TipWaitCondition,
        deadline: Option<Instant>,
        cancellation: &LatchReader,
    ) -> Option<Arc<TipSnapshot>>;

    /// Wakes observers after a caller-owned cancellation latch has been set.
    /// Does not publish a tip or modify the authoritative chain.
    fn wake_waiters(&self);
}
