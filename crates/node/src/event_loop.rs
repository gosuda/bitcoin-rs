use core::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossbeam_channel::{Receiver, select, tick};

use crate::shutdown;

const MEMPOOL_TICK: Duration = Duration::from_secs(1);
const DEFRAG_TICK: Duration = Duration::from_secs(1);
const METRICS_TICK: Duration = Duration::from_secs(10);

/// Central v1 event loop for process-level tick coordination.
///
/// The p2p, JSON-RPC, and Electrum subsystems still own their connection
/// channels and worker threads. This loop coordinates the shared tick-style
/// work that must stop cleanly with the process.
pub struct EventLoop {
    shutdown_signal: Receiver<()>,
    mempool_tick: Receiver<Instant>,
    defrag_tick: Receiver<Instant>,
    metrics_scrape: Receiver<Instant>,
}

impl EventLoop {
    /// Builds an event loop from an already-bridged shutdown signal receiver.
    #[must_use]
    pub fn new(shutdown_signal: Receiver<()>) -> Self {
        Self {
            shutdown_signal,
            mempool_tick: tick(MEMPOOL_TICK),
            defrag_tick: tick(DEFRAG_TICK),
            metrics_scrape: tick(METRICS_TICK),
        }
    }

    /// Runs the event loop until a shutdown notification arrives.
    pub fn spin(self, shutdown: &AtomicBool) -> Result<()> {
        shutdown::mark_draining();
        while !shutdown.load(Ordering::Acquire) {
            select! {
                recv(self.shutdown_signal) -> _message => {
                    shutdown.store(true, Ordering::Release);
                    metrics::gauge!("node.shutdown.requested").set(1.0);
                    break;
                }
                recv(self.mempool_tick) -> ticked => {
                    if ticked.is_ok() {
                        Self::on_mempool_tick();
                    }
                }
                recv(self.defrag_tick) -> ticked => {
                    if ticked.is_ok() {
                        Self::on_defrag_tick();
                    }
                }
                recv(self.metrics_scrape) -> ticked => {
                    if ticked.is_ok() {
                        Self::on_metrics_scrape();
                    }
                }
            }
        }
        shutdown::notify_drained();
        Ok(())
    }

    fn on_mempool_tick() {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.mempool_ticks").increment(1);
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("mempool maintenance tick");
    }

    fn on_defrag_tick() {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.defrag_ticks").increment(1);
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("utxo defrag tick");
    }

    fn on_metrics_scrape() {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.metrics_scrapes").increment(1);
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("metrics scrape tick");
    }
}
