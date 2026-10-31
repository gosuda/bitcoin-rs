//! Chainstate-owned idle maintenance: journal durability and retention.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::checkpoint::publisher::CheckpointPublisher;
use crate::checkpoint::{CheckpointError, CheckpointWrite};
/// Failures while starting the chainstate maintenance worker.
#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    #[error("maintenance requires checkpoint configuration")]
    MissingCheckpointConfiguration,
    #[error(transparent)]
    Spawn(#[from] std::io::Error),
}

fn spawn_chainstate_maintenance_worker(
    publisher: Arc<CheckpointPublisher>,
    shutdown: bitcoin_rs_chain::LatchReader,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-chainstate-maintenance".into())
        .spawn(move || maintenance_loop(&publisher, &shutdown))
}

fn maintenance_loop(publisher: &CheckpointPublisher, shutdown: &bitcoin_rs_chain::LatchReader) {
    let ticker = crossbeam_channel::tick(Duration::from_secs(1));
    let mut prev_pressure = false;
    loop {
        crossbeam_channel::select! {
            recv(shutdown.closed()) -> _ => break,
            recv(ticker) -> _ => perform_retention_compaction(publisher, &mut prev_pressure),
        }
    }
}

fn perform_retention_compaction(publisher: &CheckpointPublisher, prev_pressure: &mut bool) {
    let retention_pressure = idle_journal_maintenance(publisher);
    if !retention_pressure {
        *prev_pressure = false;
        return;
    }
    if !*prev_pressure {
        tracing::info!("journal retention pressure; draining it through a checkpoint publication");
        *prev_pressure = true;
    }
    match publisher.publish() {
        Ok(CheckpointWrite::Published { reference }) => tracing::info!(
            generation = reference.generation,
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
mod tests {
    use super::*;
    use bitcoin_rs_chain::LatchWriter;
    use std::sync::Arc;
    use std::time::Instant;

    struct UnsupportedBody;
    impl bitcoin_rs_storage::block_body::BlockBodyStore for UnsupportedBody {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
            _body: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Ok(())
        }
        fn load_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            Ok(None)
        }
        fn sync(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            Ok(())
        }
    }

    fn test_publisher(dir: &std::path::Path) -> Result<CheckpointPublisher, std::io::Error> {
        let checkpoint_data_dir =
            cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority())?;
        let network = bitcoin_rs_primitives::Network::Regtest;
        Ok(CheckpointPublisher {
            admission: Arc::new(crate::ApplyAdmission::new()),
            undo_store: Arc::new(bitcoin_rs_storage::InMemoryUndoStore::default()),
            durable_head: Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new()),
            block_body_store: Arc::new(UnsupportedBody),
            applied_tip: Arc::new(arc_swap::ArcSwapOption::empty()),
            checkpoint_data_dir,
            network,
            genesis_hash: network.genesis_block_hash(),
            block_tree: Arc::new(parking_lot::RwLock::new(bitcoin_rs_chain::BlockTree::new())),
            utxo: Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
            coin_stats: Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                bitcoin_rs_utxo::stats::CoinStats::default(),
            )),
            journal: Arc::new(parking_lot::RwLock::new(None)),
            seed_offer: None,
            data_dir: dir.to_path_buf(),
            chain_events: Arc::new(crate::events::ChainEventPublisher::detached(0)),
            durable_tip_height: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }

    #[test]
    fn maintenance_loop_cancels_promptly_on_latch_trigger() -> crate::test_fixtures::TestResult {
        let dir = tempfile::tempdir()?;
        let publisher = test_publisher(dir.path())?;
        let writer = LatchWriter::new();
        let reader = writer.reader();
        let (join_tx, join_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            maintenance_loop(&publisher, &reader);
            let _ = join_tx.send(());
        });
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        writer.trigger();
        let joined = join_rx.recv_timeout(Duration::from_secs(5));
        assert!(
            joined.is_ok(),
            "maintenance loop did not exit within 5s deadline"
        );
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "maintenance loop did not cancel promptly within 100ms deadline, elapsed: {:?}",
            started.elapsed()
        );
        let _ = worker.join();
        Ok(())
    }
}
