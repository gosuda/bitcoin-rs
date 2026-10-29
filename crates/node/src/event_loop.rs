use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, select, tick};

const STATS_INTERVAL: u64 = 1024;

const SYNC_TICK: Duration = Duration::from_secs(1);
const SYNC_PROGRESS_INTERVAL: Duration = Duration::from_mins(1);

pub(crate) struct EventLoop {
    shutdown_signal: Receiver<()>,
    sync_tick: Receiver<Instant>,
    sync_wake: Receiver<()>,
    sync: Arc<crate::BlockSync>,
}

impl EventLoop {
    #[must_use]
    pub(crate) fn with_sync_wake(
        shutdown_signal: Receiver<()>,
        sync: Arc<crate::BlockSync>,
        sync_wake: Receiver<()>,
    ) -> Self {
        Self {
            shutdown_signal,
            sync_tick: tick(SYNC_TICK),
            sync_wake,
            sync,
        }
    }

    pub(crate) fn spin(
        self,
        shutdown: &bitcoin_rs_chain::LatchReader,
        request_shutdown: impl Fn(),
    ) {
        let mut iterations: u64 = 0;
        let mut sync_ticks: u64 = 0;
        let mut last_progress = Instant::now();
        while !shutdown.is_triggered() {
            iterations += 1;
            if iterations.is_multiple_of(STATS_INTERVAL) {
                tracing::debug!(iterations, sync_ticks, "event loop heartbeat");
            }
            select! {
                recv(self.shutdown_signal) -> _ => {
                    request_shutdown();
                    metrics::gauge!("node.shutdown.requested").set(1.0);
                    break;
                }
                recv(self.sync_tick) -> ticked => {
                    if ticked.is_ok() {
                        sync_ticks += 1;
                        self.on_sync_tick();
                    }
                }
                recv(self.sync_wake) -> woke => {
                    if woke.is_ok() {
                        sync_ticks += 1;
                        metrics::counter!("node.event_loop.sync_wakes").increment(1);
                        self.on_sync_tick();
                    }
                }
            }
            let now = Instant::now();
            if progress_due(last_progress, now) {
                self.sync.emit_sync_progress();
                last_progress = now;
            }
        }
    }

    fn on_sync_tick(&self) {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.sync_ticks").increment(1);
        self.sync.tick();
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
    }
}

fn progress_due(last: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last) >= SYNC_PROGRESS_INTERVAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_uses_elapsed_time_not_wake_count() {
        let start = Instant::now();
        for _ in 0..120 {
            assert!(!progress_due(start, start + Duration::from_secs(59)));
        }
        assert!(progress_due(start, start + Duration::from_mins(1)));
        assert!(progress_due(start, start + Duration::from_secs(61)));
        assert!(!progress_due(
            start + Duration::from_mins(1),
            start + Duration::from_secs(61)
        ));
    }
}
