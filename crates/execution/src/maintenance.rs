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
    shutdown: bitcoin_rs_consensus::latch::LatchReader,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-execution-maintenance".into())
        .spawn(move || maintenance_loop(&publisher, &shutdown))
}

fn maintenance_loop(
    publisher: &CheckpointPublisher,
    shutdown: &bitcoin_rs_consensus::latch::LatchReader,
) {
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
    if elapsed < CHECKPOINT_PUBLICATION_CADENCE {
        return false;
    }
    match publisher.settle_disconnect_debt() {
        Ok(true) => {
            log::info!("maintenance settled completed disconnect debt with a checkpoint");
            return true;
        }
        Ok(false) => {}
        Err(CheckpointError::DisconnectInFlight { hash, height }) => {
            log::debug!(
                "maintenance publication deferred: disconnect in flight at {hash} height {height}"
            );
            return true;
        }
        Err(error) => {
            log::warn!(
                "maintenance disconnect settlement failed; will retry on a later cadence tick: {error}"
            );
            return true;
        }
    }
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
        Ok(CheckpointWrite::Published { reference }) => log::info!(
            "maintenance published a chainstate checkpoint generation {} at applied height {applied_height}",
            reference.generation
        ),
        Ok(CheckpointWrite::SkippedNoAppliedTip) => {
            log::debug!("maintenance publication skipped: no applied tip");
        }
        Err(CheckpointError::DisconnectInFlight { hash, height }) => {
            log::debug!(
                "maintenance publication deferred: disconnect in flight at {hash} height {height}"
            );
        }
        Err(error) => {
            log::warn!(
                "maintenance publication failed; will retry on a later cadence tick: {error}"
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
