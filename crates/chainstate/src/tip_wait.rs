//! Parking and settled response capture for the authoritative applied tip.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::{ActiveTipWait, LatchReader, TipSnapshot, TipWaitCondition};
use parking_lot::{Condvar, Mutex};

use crate::Chainstate;

/// Coordination only: the published `ArcSwap` remains the sole tip value.
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
        // An omitted current_tip captures the settled starting tip, just as
        // Core's initial GetTip does. Do not start from a transient prefix.
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
                // Publication occurs inside a transition. Release the wait
                // gate BEFORE acquiring transition exclusion; a publisher
                // uses the opposite order. Only lock acquisition is timed:
                // unsatisfied tip predicates park on the Condvar, not a poll.
                drop(gate);
                let Some(transition) = settled_transition() else {
                    return self.applied_tip.load_full();
                };
                gate = self.tip_notification.gate.lock();
                let settled = self.applied_tip.load_full()?;
                if condition.matches(&settled) || stopped() {
                    return Some(settled);
                }
                // A transient reorg prefix does not satisfy a settled wait.
                // Keep the gate until parking so the next publish cannot be
                // lost after dropping the transition exclusion.
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
mod tests {
    use super::*;
    use bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at;
    use bitcoin_rs_primitives::{Hash256, Network};
    use bitcoin_rs_utxo::UtxoSet;
    use std::sync::{atomic::AtomicBool, mpsc};

    fn owner() -> Chainstate {
        let owner = crate::test_fixtures::handles(Network::Regtest, Arc::new(UtxoSet::new()));
        owner
            .apply_block(&Network::Regtest.genesis_block(), None)
            .expect("genesis");
        owner
    }

    fn spawn_wait(
        owner: &Chainstate,
        condition: TipWaitCondition,
        stop: Arc<AtomicBool>,
    ) -> (
        mpsc::Receiver<Option<Arc<TipSnapshot>>>,
        std::thread::JoinHandle<()>,
    ) {
        let owner = owner.clone();
        let (tx, rx) = mpsc::channel();
        let task = std::thread::spawn(move || {
            tx.send(owner.wait_for_tip(
                condition,
                Some(Instant::now() + Duration::from_secs(2)),
                &stop.into(),
            ))
            .expect("result receiver");
        });
        (rx, task)
    }

    #[test]
    fn registration_races_never_lose_durable_publication() {
        for _ in 0..20 {
            let owner = owner();
            let genesis = owner.applied_tip.load_full().expect("genesis");
            let (rx, task) = spawn_wait(
                &owner,
                TipWaitCondition::Changed(Some(genesis.hash)),
                Arc::new(AtomicBool::new(false)),
            );
            let child = mined_regtest_child_at(Network::Regtest.genesis_block().block_hash(), 1)
                .expect("child");
            owner.apply_block(&child, None).expect("durable connect");
            let observed = rx
                .recv_timeout(Duration::from_secs(1))
                .expect("publication wake")
                .expect("tip");
            assert_eq!(observed.hash, Hash256::from(child.block_hash()));
            task.join().expect("waiter");
        }
    }

    #[test]
    fn all_owner_shutdown_paths_and_external_cancellation_wake_observers() {
        for mode in 0..4 {
            let owner = owner();
            let stop = Arc::new(AtomicBool::new(false));
            let genesis = owner.applied_tip.load_full().expect("genesis");
            let (rx, task) = spawn_wait(&owner, TipWaitCondition::Height(1), Arc::clone(&stop));
            match mode {
                0 => owner.request_shutdown(),
                1 => owner.fail_closed_for_recovery(),
                2 => {
                    drop(owner.close());
                }
                _ => {
                    stop.store(true, Ordering::Release);
                    owner.wake_waiters();
                }
            }
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(1))
                    .expect("shutdown wake")
                    .expect("tip")
                    .hash,
                genesis.hash
            );
            task.join().expect("waiter");
        }
    }

    #[test]
    fn external_cancellation_does_not_wait_for_a_busy_transition() {
        let owner = owner();
        let transition = owner.chain_transition.lock();
        let stop = Arc::new(AtomicBool::new(false));
        let (rx, task) = spawn_wait(&owner, TipWaitCondition::Height(0), Arc::clone(&stop));
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        stop.store(true, Ordering::Release);
        owner.wake_waiters();
        assert!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("cancel during transition")
                .is_some()
        );
        drop(transition);
        task.join().expect("waiter");
    }

    #[test]
    fn grouped_publication_returns_settled_tip_and_transient_round_trip_keeps_waiting() {
        let owner = owner();
        let genesis = owner.applied_tip.load_full().expect("genesis");
        let first = mined_regtest_child_at(Network::Regtest.genesis_block().block_hash(), 1)
            .expect("first");
        let second = mined_regtest_child_at(first.block_hash(), 2).expect("second");
        let (rx, task) = spawn_wait(
            &owner,
            TipWaitCondition::Height(1),
            Arc::new(AtomicBool::new(false)),
        );
        {
            let transition = owner.begin_transition().expect("transition");
            transition.connect(&first, None).expect("first commit");
            assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
            transition.connect(&second, None).expect("second commit");
        }
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("settled wake")
                .expect("tip")
                .height,
            2
        );
        task.join().expect("waiter");

        let (rx, task) = spawn_wait(
            &owner,
            TipWaitCondition::Hash(genesis.hash),
            Arc::new(AtomicBool::new(false)),
        );
        {
            let transition = owner.begin_transition().expect("transition");
            transition.disconnect(&second).expect("disconnect second");
            transition.disconnect(&first).expect("disconnect first");
            transition.connect(&first, None).expect("reconnect first");
        }
        assert!(
            rx.recv_timeout(Duration::from_millis(30)).is_err(),
            "transient ancestor must not satisfy current-tip wait"
        );
        owner.request_shutdown();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("shutdown")
                .expect("tip")
                .height,
            1
        );
        task.join().expect("waiter");
    }

    #[test]
    fn headers_spurious_wakes_and_other_chainstates_do_not_change_active_tip() {
        let owner = owner();
        let historical = self::owner();
        let genesis = owner.applied_tip.load_full().expect("genesis");
        let (rx, task) = spawn_wait(
            &owner,
            TipWaitCondition::Changed(Some(genesis.hash)),
            Arc::new(AtomicBool::new(false)),
        );
        let child = mined_regtest_child_at(Network::Regtest.genesis_block().block_hash(), 1)
            .expect("child");
        owner
            .admit_headers(&[child.header])
            .expect("header admission");
        historical
            .apply_block(&child, None)
            .expect("separate chainstate");
        historical.request_shutdown();
        owner.wake_waiters();
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        owner.request_shutdown();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("shutdown")
                .expect("tip")
                .hash,
            genesis.hash
        );
        task.join().expect("waiter");
    }

    #[test]
    fn rejection_and_spurious_wakes_do_not_extend_absolute_deadline() {
        let owner = owner();
        let genesis = owner.applied_tip.load_full().expect("genesis");
        let mut invalid = mined_regtest_child_at(Network::Regtest.genesis_block().block_hash(), 1)
            .expect("child");
        invalid.txs.clear();
        assert!(owner.apply_block(&invalid, None).is_err());
        let notifier = owner.clone();
        let noise = std::thread::spawn(move || {
            for _ in 0..100 {
                notifier.wake_waiters();
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let start = Instant::now();
        let answer = owner
            .wait_for_tip(
                TipWaitCondition::Height(1),
                Some(start + Duration::from_millis(30)),
                &LatchReader::fixture_never(),
            )
            .expect("tip");
        assert_eq!(answer.hash, genesis.hash);
        assert!(start.elapsed() < Duration::from_millis(500));
        noise.join().expect("notifier");
    }
    #[test]
    fn timeout_and_cancellation_return_a_durable_reorg_prefix_without_waiting_for_completion() {
        let owner = owner();
        let first = mined_regtest_child_at(Network::Regtest.genesis_block().block_hash(), 1)
            .expect("first");
        owner.apply_block(&first, None).expect("first commit");
        let transition = owner.begin_transition().expect("transition");
        transition
            .disconnect(&first)
            .expect("durable rollback prefix");
        let start = Instant::now();
        let tip = owner
            .wait_for_tip(
                TipWaitCondition::Height(2),
                Some(start + Duration::from_millis(20)),
                &LatchReader::fixture_never(),
            )
            .expect("published prefix");
        assert_eq!(tip.height, 0);
        assert!(start.elapsed() < Duration::from_secs(1));
        let stopped = LatchReader::new(Arc::new(AtomicBool::new(true)));
        assert_eq!(
            owner
                .wait_for_tip(TipWaitCondition::Height(2), None, &stopped)
                .expect("cancelled prefix")
                .height,
            0
        );
        drop(transition);
    }
    #[test]
    fn omitted_current_tip_captures_after_an_in_flight_transition() {
        let owner = owner();
        let first = mined_regtest_child_at(Network::Regtest.genesis_block().block_hash(), 1)
            .expect("first");
        let second = mined_regtest_child_at(first.block_hash(), 2).expect("second");
        let third = mined_regtest_child_at(second.block_hash(), 3).expect("third");
        let transition = owner.begin_transition().expect("transition");
        transition.connect(&first, None).expect("first");
        let (rx, task) = spawn_wait(
            &owner,
            TipWaitCondition::Changed(None),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        transition.connect(&second, None).expect("second");
        drop(transition);
        // Notify is only a test observation of parking, not publication.
        let deadline = Instant::now() + Duration::from_secs(1);
        while owner.tip_notification.changed.notify_all() == 0 {
            assert!(Instant::now() < deadline, "waiter must capture then park");
            std::thread::yield_now();
        }
        assert!(rx.recv_timeout(Duration::from_millis(20)).is_err());
        owner.apply_block(&third, None).expect("third");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("next publication")
                .expect("tip")
                .height,
            3
        );
        task.join().expect("waiter");
    }
}
