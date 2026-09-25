use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, never, select, tick};

const STATS_INTERVAL: u64 = 1024;

const MEMPOOL_TICK: Duration = Duration::from_secs(1);
const METRICS_TICK: Duration = Duration::from_secs(10);
const SYNC_TICK: Duration = Duration::from_secs(1);
/// Elapsed time owns telemetry cadence, independently of inbound wake volume.
const SYNC_PROGRESS_INTERVAL: Duration = Duration::from_mins(1);

/// Central v1 event loop for process-level tick coordination.
///
/// The p2p, JSON-RPC, and `ScriptIndex` subsystems still own their connection
/// channels and worker threads. This loop coordinates the shared tick-style
/// work that must stop cleanly with the process.
pub struct EventLoop {
    shutdown_signal: Receiver<()>,
    mempool_tick: Receiver<Instant>,
    metrics_scrape: Receiver<Instant>,
    sync_tick: Receiver<Instant>,
    sync_wake: Receiver<()>,
    sync: Arc<crate::BlockSync>,
}

impl EventLoop {
    /// Builds an event loop from an already-bridged shutdown signal receiver.
    #[must_use]
    pub fn new(shutdown_signal: Receiver<()>, sync: Arc<crate::BlockSync>) -> Self {
        Self::with_sync_wake(shutdown_signal, sync, never())
    }

    /// Builds an event loop that can also wake sync work from inbound P2P data.
    #[must_use]
    pub fn with_sync_wake(
        shutdown_signal: Receiver<()>,
        sync: Arc<crate::BlockSync>,
        sync_wake: Receiver<()>,
    ) -> Self {
        Self {
            shutdown_signal,
            mempool_tick: tick(MEMPOOL_TICK),
            metrics_scrape: tick(METRICS_TICK),
            sync_tick: tick(SYNC_TICK),
            sync_wake,
            sync,
        }
    }

    /// Runs the event loop until a shutdown notification arrives.
    pub fn spin(self, shutdown: &AtomicBool) -> Result<()> {
        let mut iterations: u64 = 0;
        let mut mempool_ticks: u64 = 0;
        let mut metrics_scrapes: u64 = 0;
        let mut sync_ticks: u64 = 0;
        let mut last_progress = Instant::now();
        while !shutdown.load(Ordering::Acquire) {
            iterations += 1;
            if iterations.is_multiple_of(STATS_INTERVAL) {
                tracing::debug!(
                    iterations,
                    mempool_ticks,
                    metrics_scrapes,
                    sync_ticks,
                    "event loop heartbeat"
                );
            }
            select! {
                recv(self.shutdown_signal) -> _ => {
                    shutdown.store(true, Ordering::Release);
                    metrics::gauge!("node.shutdown.requested").set(1.0);
                    break;
                }
                recv(self.mempool_tick) -> ticked => {
                    if ticked.is_ok() {
                        mempool_ticks += 1;
                        Self::on_mempool_tick();
                    }
                }
                recv(self.metrics_scrape) -> ticked => {
                    if ticked.is_ok() {
                        metrics_scrapes += 1;
                        Self::on_metrics_scrape();
                    }
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
        Ok(())
    }

    fn on_mempool_tick() {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.mempool_ticks").increment(1);
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("mempool maintenance tick");
    }

    fn on_metrics_scrape() {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.metrics_scrapes").increment(1);
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("metrics scrape tick");
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
