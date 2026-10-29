//! Parking and settled response capture for the authoritative applied tip.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{ActiveTipWait, LatchReader, TipSnapshot, TipWaitCondition};
use parking_lot::{Condvar, Mutex};

use crate::Chainstate;

#[derive(Default)]
pub(crate) struct TipNotification {
    pub(crate) gate: Mutex<()>,
    pub(crate) changed: Condvar,
}

impl ActiveTipWait for Chainstate {
    fn wait_for_tip(
        &self,
        mut condition: TipWaitCondition,
        deadline: Option<Instant>,
        cancellation: &LatchReader,
    ) -> Option<Arc<TipSnapshot>> {
        let stopped = || {
            self.shutdown.load(Ordering::Acquire)
                || cancellation.is_triggered()
                || deadline.is_some_and(|end| Instant::now() >= end)
        };
        let settled_transition = || loop {
            if stopped() {
                return None;
            }
            let remaining = deadline.map_or(Duration::from_millis(50), |end| {
                end.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50))
            });
            if let Some(guard) = self.chain_transition.try_lock_for(remaining) {
                return Some(guard);
            }
        };
        let starting_transition = if matches!(condition, TipWaitCondition::Changed(None)) {
            let Some(guard) = settled_transition() else {
                return self.applied_tip.load_full();
            };
            Some(guard)
        } else {
            None
        };
        let mut gate = self.tip_notification.gate.lock();
        if matches!(condition, TipWaitCondition::Changed(None)) {
            condition = TipWaitCondition::Changed(Some(self.applied_tip.load_full()?.hash));
        }
        drop(starting_transition);
        loop {
            let tip = self.applied_tip.load_full()?;
            if stopped() {
                return Some(tip);
            }
            if condition.matches(&tip) {
                drop(gate);
                let Some(transition) = settled_transition() else {
                    return self.applied_tip.load_full();
                };
                gate = self.tip_notification.gate.lock();
                let settled = self.applied_tip.load_full()?;
                if condition.matches(&settled) || stopped() {
                    return Some(settled);
                }
                drop(transition);
            }
            if let Some(end) = deadline {
                self.tip_notification.changed.wait_until(&mut gate, end);
            } else {
                self.tip_notification.changed.wait(&mut gate);
            }
        }
    }

    fn wake_waiters(&self) {
        let _gate = self.tip_notification.gate.lock();
        self.tip_notification.changed.notify_all();
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
