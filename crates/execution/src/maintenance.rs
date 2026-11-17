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
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
    use bitcoin_rs_storage::KvStore;
    use bitcoin_rs_storage::block_body::BlockBodyStore;
    use bitcoin_rs_storage::checkpoint::CHECKPOINT_ROOT;
    use bitcoin_rs_storage::utxo::UtxoSet;

    use crate::chain::regtest_fixture::mined_regtest_child_at;
    use crate::checkpoint::publisher::CheckpointPublisher;
    use crate::test_fixtures::{TestError, TestResult};
    use bitcoin_rs_consensus::latch::LatchWriter;

    use super::{CHECKPOINT_PUBLICATION_CADENCE, maintenance_loop, should_publish_checkpoint};

    struct UnsupportedBody;
    impl BlockBodyStore for UnsupportedBody {
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

    #[test]
    fn publication_decision_refuses_before_the_cadence() -> TestResult {
        assert!(
            !should_publish_checkpoint(
                CHECKPOINT_PUBLICATION_CADENCE.saturating_sub(Duration::from_secs(1)),
                289,
                0
            ),
            "a tip above the frontier is not due before the cadence"
        );
        Ok(())
    }

    #[test]
    fn publication_decision_publishes_when_due_and_the_tip_is_above_the_frontier() -> TestResult {
        assert!(should_publish_checkpoint(
            CHECKPOINT_PUBLICATION_CADENCE,
            289,
            0
        ));
        assert!(should_publish_checkpoint(
            CHECKPOINT_PUBLICATION_CADENCE + Duration::from_secs(1),
            289,
            288
        ));
        Ok(())
    }

    #[test]
    fn publication_decision_publishes_nothing_when_the_tip_meets_the_frontier() -> TestResult {
        assert!(!should_publish_checkpoint(
            CHECKPOINT_PUBLICATION_CADENCE,
            289,
            289
        ));
        assert!(!should_publish_checkpoint(
            CHECKPOINT_PUBLICATION_CADENCE + Duration::from_secs(600),
            289,
            289
        ));
        Ok(())
    }

    const APPLIED_HEIGHT: u32 = 289;
    const PRUNE_HEIGHT: u32 = 1;

    fn checkpoint_generation_dirs(root: &std::path::Path) -> TestResult<Vec<String>> {
        let mut dirs = Vec::new();
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        dirs.sort();
        Ok(dirs)
    }

    fn seed_prunable_body_row(
        store: &bitcoin_rs_storage::memory_kv::MemoryKvStore,
        hash: Hash256,
    ) -> TestResult {
        let mut batch = store.new_batch();
        batch.put(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            &bitcoin_rs_storage::pruning::block_body_key(0, hash),
            &bitcoin_rs_storage::BlockFilePosition {
                file_no: 0,
                offset: 0,
                len: 1,
            }
            .encode(),
        );
        batch.put(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            &bitcoin_rs_storage::block_file_max_height_key(0),
            &bitcoin_rs_storage::encode_block_file_max_height(0),
        );
        store.write(batch)?;
        Ok(())
    }

    fn prune_to(
        store: &bitcoin_rs_storage::memory_kv::MemoryKvStore,
        block_files: &bitcoin_rs_storage::FlatFileBlockStore,
        retention: &Arc<bitcoin_rs_storage::RetentionRegistry>,
        applied_height: u32,
        durable_tip_height: u32,
    ) -> TestResult<bitcoin_rs_storage::pruning::StagedPrune> {
        bitcoin_rs_storage::pruning::prune_to_height(
            store,
            block_files,
            retention,
            applied_height,
            durable_tip_height,
            PRUNE_HEIGHT,
            |_| Ok(()),
        )
        .map_err(|error| {
            TestError::Storage(bitcoin_rs_storage::StorageError::backend(error.to_string()))
        })
    }

    // RCV-10, SYNC-07
    #[test]
    fn maintenance_worker_publishes_the_frontier_and_advances_the_prune_line() -> TestResult {
        let dir = tempfile::tempdir()?;
        let network = Network::Regtest;
        let store = Arc::new(bitcoin_rs_storage::memory_kv::MemoryKvStore::default());
        let mut chain = crate::test_fixtures::handles_with_store(
            network,
            Arc::new(UtxoSet::new()),
            Arc::clone(&store),
        );
        chain.block_body_store = Some(Arc::new(crate::test_support::MemoryBodies::default()));
        let genesis = network.genesis_block();
        chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
        let mut previous = genesis.block_hash();
        for height in 1..=APPLIED_HEIGHT {
            let block = mined_regtest_child_at(previous, height)?;
            previous = block.block_hash();
            chain.apply_block(&BlockImage::from_local(block))?;
        }
        let applied = chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip"))?;
        assert_eq!(applied.height, APPLIED_HEIGHT);

        let durable_tip_height = Arc::new(AtomicU32::new(0));
        chain.configure_checkpointing(dir.path(), Arc::clone(&durable_tip_height))?;

        let block_files = Arc::new(bitcoin_rs_storage::FlatFileBlockStore::open(dir.path())?);
        let retention = Arc::new(bitcoin_rs_storage::RetentionRegistry::new());
        seed_prunable_body_row(&store, Hash256::from(genesis.block_hash()))?;

        let withheld = prune_to(
            &store,
            &block_files,
            &retention,
            applied.height,
            durable_tip_height.load(Ordering::Acquire),
        )?;
        assert_eq!(
            withheld.pruned_below, 0,
            "a stale checkpoint frontier reclaims nothing"
        );

        let worker = chain.start_maintenance().map_err(|error| {
            TestError::Storage(bitcoin_rs_storage::StorageError::backend(error.to_string()))
        })?;
        let deadline = Instant::now() + Duration::from_secs(60);
        while durable_tip_height.load(Ordering::Acquire) != applied.height
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            durable_tip_height.load(Ordering::Acquire),
            applied.height,
            "the maintenance worker must publish the applied tip on its first due tick"
        );

        let generations = checkpoint_generation_dirs(&dir.path().join(CHECKPOINT_ROOT))?;
        assert_eq!(generations.len(), 1, "one checkpoint generation published");
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(
            checkpoint_generation_dirs(&dir.path().join(CHECKPOINT_ROOT))?,
            generations,
            "an unmoved tip must not publish again"
        );
        assert_eq!(durable_tip_height.load(Ordering::Acquire), applied.height);

        let advanced = prune_to(
            &store,
            &block_files,
            &retention,
            applied.height,
            durable_tip_height.load(Ordering::Acquire),
        )?;
        assert_eq!(
            advanced.pruned_below, 1,
            "the published frontier makes the requested line eligible"
        );

        chain.request_shutdown();
        worker
            .join()
            .map_err(|_| TestError::WorkerPanicked("maintenance worker panicked"))?;
        Ok(())
    }

    // RCV-15
    #[test]
    fn maintenance_retires_completed_disconnect_debt_at_same_or_lower_height() -> TestResult {
        for publish_child in [false, true] {
            let dir = tempfile::tempdir()?;
            let network = Network::Regtest;
            let mut chain = crate::test_fixtures::handles(network, Arc::new(UtxoSet::new()));
            chain.block_body_store = Some(Arc::new(crate::test_support::MemoryBodies::default()));
            let genesis = network.genesis_block();
            chain.apply_block(&BlockImage::from_local(genesis.clone()))?;
            chain.configure_checkpointing(dir.path(), Arc::new(AtomicU32::new(0)))?;
            chain.publish_checkpoint()?;
            let child = mined_regtest_child_at(genesis.block_hash(), 1)?;
            chain.apply_block(&BlockImage::from_local(child.clone()))?;
            if publish_child {
                chain.publish_checkpoint()?;
            }
            chain.disconnect_block(&child)?;
            let hash = Hash256::from(child.block_hash());
            chain.undo_store.arm_disconnect(1, hash)?;
            chain.undo_store.complete_disconnect(1, hash)?;
            let publisher = chain
                .checkpoint_publisher
                .as_ref()
                .ok_or(TestError::Missing("checkpoint publisher"))?;
            let root = dir.path().join(CHECKPOINT_ROOT);
            let current = std::fs::read(root.join("CURRENT"))?;
            assert!(!super::maintenance_step(publisher, Duration::ZERO));
            assert!(chain.undo_store.load_disconnect_marker()?.is_some());
            assert_eq!(std::fs::read(root.join("CURRENT"))?, current);
            assert!(super::maintenance_step(
                publisher,
                CHECKPOINT_PUBLICATION_CADENCE
            ));
            assert!(chain.undo_store.load_disconnect_marker()?.is_none());
            assert_ne!(std::fs::read(root.join("CURRENT"))?, current);
            assert_eq!(publisher.durable_tip_height.load(Ordering::Acquire), 0);
            assert!(!super::maintenance_step(publisher, Duration::ZERO));
            assert!(!super::maintenance_step(
                publisher,
                CHECKPOINT_PUBLICATION_CADENCE
            ));
        }
        Ok(())
    }
}
