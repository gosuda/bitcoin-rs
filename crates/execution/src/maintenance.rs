use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::checkpoint::publisher::CheckpointPublisher;

#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    #[error("maintenance requires checkpoint configuration")]
    MissingCheckpointConfiguration,
    #[error(transparent)]
    Spawn(#[from] std::io::Error),
}

fn spawn_chainstate_maintenance_worker(
    publisher: Arc<CheckpointPublisher>,
    shutdown: crate::chain::LatchReader,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-execution-maintenance".into())
        .spawn(move || maintenance_loop(&publisher, &shutdown))
}

fn maintenance_loop(_publisher: &CheckpointPublisher, shutdown: &crate::chain::LatchReader) {
    let ticker = crossbeam_channel::tick(Duration::from_secs(1));
    loop {
        crossbeam_channel::select! {
            recv(shutdown.closed()) -> _ => break,
            recv(ticker) -> _ => {}
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
    use crate::chain::LatchWriter;
    use std::sync::Arc;
    use std::time::Instant;

    struct UnsupportedBody;
    impl bitcoin_rs_storage::block_body::BlockBodyStore for UnsupportedBody {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_consensus::primitives::Hash256,
            _body: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Ok(())
        }
        fn load_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_consensus::primitives::Hash256,
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
        let network = bitcoin_rs_consensus::primitives::Network::Regtest;
        Ok(CheckpointPublisher {
            admission: Arc::new(crate::ApplyAdmission::new()),
            undo_store: Arc::new(bitcoin_rs_storage::InMemoryUndoStore::default()),
            durable_head: Arc::new(bitcoin_rs_storage::InMemoryDurableHeadStore::new()),
            block_body_store: Arc::new(UnsupportedBody),
            applied_tip: Arc::new(arc_swap::ArcSwapOption::empty()),
            checkpoint_data_dir,
            network,
            genesis_hash: network.genesis_block_hash(),
            block_tree: Arc::new(parking_lot::RwLock::new(crate::chain::BlockTree::new())),
            coin_stats: Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
                bitcoin_rs_storage::utxo::stats::CoinStats::default(),
            )),
            data_dir: dir.to_path_buf(),
            chain_events: Arc::new(crate::events::ChainEventPublisher::detached(0)),
            durable_tip_height: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            store: Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::default()),
        })
    }

    #[test]
    fn maintenance_loop_cancels_within_500ms_on_latch_trigger() -> crate::test_fixtures::TestResult
    {
        let dir = tempfile::tempdir()?;
        let publisher = test_publisher(dir.path())?;
        let writer = LatchWriter::new();
        let reader = writer.reader();
        let (join_tx, join_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            maintenance_loop(&publisher, &reader);
            let _ = join_tx.send(());
        });
        let started = Instant::now();
        writer.trigger();
        let joined = join_rx.recv_timeout(Duration::from_secs(5));
        assert!(
            joined.is_ok(),
            "maintenance loop did not exit within 5s deadline"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "maintenance loop did not cancel promptly within deadline, elapsed: {:?}",
            started.elapsed()
        );
        let _ = worker.join();
        Ok(())
    }
}
