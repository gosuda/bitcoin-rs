//! Node-owned checkpoint publication and periodic worker startup.

use super::NodeState;
use anyhow::Result;
use anyhow::bail;
use std::sync::Arc;
use std::time::Duration;

impl NodeState {
    /// Publishes a durable clean checkpoint and returns the published
    /// generation, or an error if there is no applied tip.
    ///
    /// This is the public boundary for the private checkpoint machinery; it
    /// keeps `CheckpointWrite`, `CheckpointError`, and the checkpoint module
    /// internal to the crate.
    pub fn publish_checkpoint(&self) -> Result<u64> {
        match self.write_clean_checkpoint()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                bail!("checkpoint refused: no applied tip to publish")
            }
            crate::checkpoint::CheckpointWrite::Published { generation } => Ok(generation),
        }
    }

    /// Creates a [`crate::checkpoint_worker::CheckpointPublisher`] from this
    /// state's shared handles, for use by the periodic checkpoint worker.
    ///
    /// The publisher owns its own `Dir` handle (reopened from the data-dir
    /// path) and cloned `Arc`s, so it can be moved into a background thread
    /// without borrowing from `self`.
    pub(crate) fn checkpoint_publisher(
        &self,
    ) -> core::result::Result<
        crate::checkpoint_worker::CheckpointPublisher,
        crate::checkpoint::CheckpointError,
    > {
        Ok(crate::checkpoint_worker::CheckpointPublisher {
            admission: Arc::clone(&self.apply_handles.admission),
            undo_store: Arc::clone(&self.apply_handles.undo_store),
            block_body_store: Arc::clone(&self.block_body_store),
            applied_tip: Arc::clone(&self.applied_tip),
            checkpoint_data_dir: crate::checkpoint_fs::open_data_dir(&self.data_dir)
                .map_err(crate::checkpoint::CheckpointError::Io)?,
            network: self.config.network,
            genesis_hash: self.config.network.genesis_block_hash(),
            block_tree: Arc::clone(&self.block_tree),
            utxo: Arc::clone(&self.utxo),
            coin_stats: Arc::clone(&self.coin_stats),
            chain_tx_count: Arc::clone(&self.chain_tx_count),
            journal: self.apply_handles.journal.clone(),
            data_dir: self.data_dir.clone(),
            chain_events: Arc::clone(&self.chain_events),
            durable_tip_height: Arc::clone(&self.durable_tip_height),
        })
    }

    /// Spawns the periodic checkpoint worker with a custom cadence.
    ///
    /// Production wiring goes through `start_node`, which uses
    /// [`crate::checkpoint_worker::CHECKPOINT_INTERVAL_BLOCKS`] and
    /// [`crate::checkpoint_worker::CHECKPOINT_INTERVAL_SECS`]. This method
    /// is `pub` so integration tests can use a small cadence.
    ///
    /// Returns the worker's join handle. The worker exits when the node's
    /// shutdown flag is set.
    pub fn start_periodic_checkpoint(
        &self,
        interval_blocks: u32,
        interval_secs: Duration,
    ) -> Result<std::thread::JoinHandle<()>> {
        let publisher = self.checkpoint_publisher().map_err(anyhow::Error::new)?;
        Ok(crate::checkpoint_worker::spawn_periodic_checkpoint_worker(
            publisher,
            Arc::clone(&self.shutdown()),
            interval_blocks,
            interval_secs,
        )?)
    }

    pub(crate) fn write_clean_checkpoint(
        &self,
    ) -> core::result::Result<crate::checkpoint::CheckpointWrite, crate::checkpoint::CheckpointError>
    {
        self.checkpoint_publisher()?.publish()
    }
}
