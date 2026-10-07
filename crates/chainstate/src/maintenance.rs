//! Chainstate-owned idle maintenance: journal durability and retention.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::checkpoint::publisher::CheckpointPublisher;
use crate::checkpoint::{CheckpointError, CheckpointWrite};
/// Poll interval for the maintenance loop. Short enough to flush soon after
/// a journal boundary passes and to drain retention pressure soon after it
/// appears; long enough to avoid busy-waiting.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Spawns the chainstate maintenance worker thread.
fn spawn_chainstate_maintenance_worker(
    publisher: Arc<CheckpointPublisher>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-chainstate-maintenance".into())
        .spawn(move || maintenance_loop(&publisher, &shutdown))
}

fn maintenance_loop(publisher: &CheckpointPublisher, shutdown: &AtomicBool) {
    let mut prev_pressure = false;
    while !shutdown.load(Ordering::Relaxed) {
        if wait_for_shutdown(shutdown, POLL_INTERVAL) {
            break;
        }
        let retention_pressure = idle_journal_maintenance(publisher);
        if !retention_pressure {
            prev_pressure = false;
            continue;
        }
        if !prev_pressure {
            tracing::info!(
                "journal retention pressure; draining it through a checkpoint publication"
            );
            prev_pressure = true;
        }
        match publisher.publish() {
            Ok(CheckpointWrite::Published { generation }) => tracing::info!(
                ?generation,
                "retention compaction published a chainstate checkpoint"
            ),
            Ok(CheckpointWrite::SkippedNoAppliedTip) => {
                tracing::debug!("retention compaction skipped: no applied tip");
            }
            Err(CheckpointError::DisconnectInFlight { hash, height }) => {
                tracing::debug!(%hash, height, "retention compaction deferred: disconnect in flight");
            }
            Err(error) => {
                tracing::warn!(?error, "retention compaction failed; will retry next tick");
            }
        }
    }
}

/// Idle journal durability and retention inspection: flushes records whose
/// batch boundary has passed and reports whether segment retention
/// requires compaction.
fn idle_journal_maintenance(publisher: &CheckpointPublisher) -> bool {
    let Some(journal) = publisher.journal.read().clone() else {
        return false;
    };
    let mut journal = journal.lock();
    if let Err(error) = journal.flush_due() {
        metrics::counter!("node.chainstate_journal.flush_failures").increment(1);
        tracing::warn!(%error, "idle chainstate journal flush failed; apply backpressure remains armed");
    }
    match journal.requires_compaction() {
        Ok(required) => required,
        Err(error) => {
            metrics::counter!("node.chainstate_journal.maintenance_failures").increment(1);
            tracing::warn!(%error, "failed to inspect chainstate journal retention");
            false
        }
    }
}

/// Sleeps for `duration` unless `shutdown` is set, returning `true` if the
/// worker should exit.
fn wait_for_shutdown(shutdown: &AtomicBool, duration: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < duration {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let remaining = duration
            .checked_sub(start.elapsed())
            .unwrap_or(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(200).min(remaining));
    }
    shutdown.load(Ordering::Relaxed)
}

impl crate::Chainstate {
    /// Spawns chainstate journal and retention maintenance.
    pub fn start_maintenance(&self) -> anyhow::Result<JoinHandle<()>> {
        let publisher = self
            .checkpoint_publisher
            .clone()
            .ok_or_else(|| anyhow::anyhow!("maintenance requires checkpoint configuration"))?;
        spawn_chainstate_maintenance_worker(publisher, self.shutdown_handle())
            .map_err(anyhow::Error::new)
    }
}
