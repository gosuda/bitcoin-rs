use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::checkpoint::publisher::CheckpointPublisher;
use crate::checkpoint::{CheckpointError, CheckpointWrite};

#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    #[error("maintenance requires checkpoint configuration")]
    MissingCheckpointConfiguration,
    #[error(transparent)]
    Spawn(#[from] std::io::Error),
}

const CHECKPOINT_PUBLICATION_CADENCE: Duration = Duration::from_secs(600);

fn should_publish_checkpoint(
    elapsed_since_attempt: Duration,
    applied_height: u32,
    published_height: u32,
) -> bool {
    elapsed_since_attempt >= CHECKPOINT_PUBLICATION_CADENCE && applied_height > published_height
}

fn spawn_chainstate_maintenance_worker(
    publisher: Arc<CheckpointPublisher>,
    shutdown: crate::chain::LatchReader,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-execution-maintenance".into())
        .spawn(move || maintenance_loop(&publisher, &shutdown))
}

fn maintenance_loop(publisher: &CheckpointPublisher, shutdown: &crate::chain::LatchReader) {
    let ticker = crossbeam_channel::tick(Duration::from_secs(1));
    let mut last_attempt: Option<Instant> = None;
    loop {
        crossbeam_channel::select! {
            recv(shutdown.closed()) -> _ => break,
            recv(ticker) -> _ => {
                if shutdown.is_triggered() {
                    break;
                }
                let elapsed = last_attempt.map_or(Duration::MAX, |attempt| attempt.elapsed());
                if maintenance_step(publisher, elapsed) {
                    last_attempt = Some(Instant::now());
                }
            }
        }
    }
}

fn maintenance_step(publisher: &CheckpointPublisher, elapsed: Duration) -> bool {
    let applied_height = publisher
        .applied_tip
        .load_full()
        .as_ref()
        .map_or(0, |tip| tip.height);
    let published_height = publisher.durable_tip_height.load(Ordering::Acquire);
    if !should_publish_checkpoint(elapsed, applied_height, published_height) {
        return false;
    }
    match publisher.publish() {
        Ok(CheckpointWrite::Published { reference }) => tracing::info!(
            generation = reference.generation,
            applied_height,
            "maintenance published a chainstate checkpoint"
        ),
        Ok(CheckpointWrite::SkippedNoAppliedTip) => {
            tracing::debug!("maintenance publication skipped: no applied tip");
        }
        Err(CheckpointError::DisconnectInFlight { hash, height }) => {
            tracing::debug!(%hash, height, "maintenance publication deferred: disconnect in flight");
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "maintenance publication failed; will retry on a later cadence tick"
            );
        }
    }
    true
}

impl crate::Chainstate {
    pub fn start_maintenance(&self) -> Result<JoinHandle<()>, MaintenanceError> {
        let publisher = self
            .checkpoint_publisher
            .clone()
            .ok_or(MaintenanceError::MissingCheckpointConfiguration)?;
        Ok(spawn_chainstate_maintenance_worker(
            publisher,
            self.shutdown_reader(),
        )?)
    }
}

#[cfg(test)]
mod tests;
