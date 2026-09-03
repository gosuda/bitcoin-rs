//! Periodic chainstate checkpoint publication during sync.
//!
//! Without a periodic publisher, a node killed mid-sync restarts from whatever
//! the last *clean shutdown* left behind — which may be far behind the crash
//! point. This worker publishes a checkpoint when the applied tip has advanced
//! [`CHECKPOINT_INTERVAL_BLOCKS`] blocks or [`CHECKPOINT_INTERVAL_SECS`]
//! seconds since the last publication, whichever fires first.
//!
//! ## Cadence
//!
//! [`CHECKPOINT_INTERVAL_BLOCKS`] = 10 000. At 30–75 blocks/s during IBD this
//! fires every ~2–5 min. [`CHECKPOINT_INTERVAL_SECS`] = 1800 (30 min) is the
//! fallback for a slow-syncing node that has not reached the block count but
//! still wants progress anchored.
//!
//! ## Recovery story
//!
//! The published checkpoint is the sole recovery anchor: a node killed
//! mid-sync restarts from the last published checkpoint (periodic or
//! clean-shutdown) and re-validates blocks mined after it.  The former V1
//! recovery sidecar / body-replay path was retired (issue #230, task 0); a
//! stale sidecar file on disk is simply ignored.
//!
//! ## Cost when it fires
//!
//! `publish` closes apply admission for the duration (pausing block
//! application), syncs the block-body store, then writes the full checkpoint
//! snapshot (staging dir → per-artifact fsync → generation rename → `CURRENT`
//! atomic swap). Snapshot size scales with tip (22.8 MB at height 130k;
//! plausibly several GB near modern tips). At a 10k-block cadence the pause is
//! seconds-to-tens-of-seconds — well under 1 % of wall time during IBD.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::RwLock;

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_utxo::stats::CoinStatsListener;

use crate::apply::{ApplyAdmission, PruneBodyStore, UndoStore};
use crate::checkpoint::{self, CheckpointError, CheckpointWrite};
use crate::recovery_evidence;
use crate::state::ChainEventPublisher;

/// Block count between periodic checkpoint publications during sync.
///
/// At 30–75 blocks/s during IBD this fires every ~2–5 min. The worst-case
/// replay window when the node is killed between publications is this many
/// blocks.
pub(crate) const CHECKPOINT_INTERVAL_BLOCKS: u32 = 10_000;

/// Maximum elapsed time between periodic checkpoint publications (30 min).
///
/// Ensures a slow-syncing node that has not reached the block count still
/// anchors progress durably.
pub(crate) const CHECKPOINT_INTERVAL_SECS: u64 = 1800;

/// Poll interval for the worker loop. Short enough to publish soon after a
/// trigger fires; long enough to avoid busy-waiting.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// All the shared handles needed to publish a checkpoint from a background
/// thread, without holding a reference to [`crate::state::NodeState`].
///
/// Created once from `NodeState`'s Arc fields and moved into the worker
/// thread. The `checkpoint_data_dir` is reopened from the data-dir path
/// (a cheap `openat`) so the worker does not borrow from `NodeState`.
pub(crate) struct CheckpointPublisher {
    pub(crate) admission: Arc<ApplyAdmission>,
    pub(crate) undo_store: Arc<dyn UndoStore>,
    pub(crate) block_body_store: Arc<dyn PruneBodyStore>,
    pub(crate) applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    pub(crate) checkpoint_data_dir: cap_std::fs::Dir,
    pub(crate) network: bitcoin_rs_primitives::Network,
    pub(crate) genesis_hash: Hash256,
    pub(crate) block_tree: Arc<RwLock<BlockTree>>,
    pub(crate) utxo: Arc<UtxoSet>,
    pub(crate) coin_stats: Arc<CoinStatsListener>,
    pub(crate) chain_tx_count: Arc<std::sync::atomic::AtomicU64>,

    pub(crate) data_dir: PathBuf,
    pub(crate) chain_events: Arc<ChainEventPublisher>,
    pub(crate) durable_tip_height: Arc<std::sync::atomic::AtomicU32>,
}

impl CheckpointPublisher {
    /// Publishes a durable checkpoint, mirroring
    /// [`crate::state::NodeState::write_clean_checkpoint`].
    ///
    /// After a successful publication, rewrites the recovery sidecar to match
    /// the published tip so the checkpoint and sidecar never disagree about
    /// what is durable.
    pub(crate) fn publish(&self) -> core::result::Result<CheckpointWrite, CheckpointError> {
        let _exclusive_apply = self.admission.close();
        if let Some(marker) = self.undo_store.load_disconnect_marker()?
            && marker.phase == crate::apply::DisconnectPhase::InFlight
        {
            return Err(CheckpointError::DisconnectInFlight {
                hash: marker.hash,
                height: marker.height,
            });
        }
        // A checkpoint may name this tip only after body files then index rows sync.
        self.block_body_store.sync()?;
        let applied_tip = self.applied_tip.load_full();
        let written = checkpoint::write_checkpoint_from_dir(
            &self.checkpoint_data_dir,
            checkpoint::HeaderCheckpointConfig {
                network: self.network,
                genesis: self.genesis_hash,
            },
            &self.block_tree,
            &self.utxo,
            &self.coin_stats,
            applied_tip.as_deref(),
            self.chain_tx_count
                .load(std::sync::atomic::Ordering::Relaxed),
        )?;
        // A2: Only after `CheckpointWrite::Published` and root fsync, write
        // the applied-tip witness for the same captured tip.
        if let CheckpointWrite::Published { .. } = written
            && let Some(tip) = applied_tip.as_ref()
        {
            let genesis_hex = self.genesis_hash.to_string_be();
            let witness = recovery_evidence::AppliedTipWitness::new(
                genesis_hex,
                self.chain_events.epoch(),
                tip.height,
                tip.hash.to_string_be(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            );
            recovery_evidence::write_witness(&self.data_dir, &witness)
                .map_err(|e| CheckpointError::Invalid(e.to_string()))?;
        }
        // Remove the disconnect marker only after this checkpoint publishes the
        // matching UTXO set and applied tip.
        self.undo_store
            .disarm_disconnect()
            .map_err(CheckpointError::from)?;
        // Everything up to this tip is now recoverable, so undo records below
        // it may be pruned.
        self.durable_tip_height.store(
            applied_tip.as_ref().map_or(0, |tip| tip.height),
            Ordering::Release,
        );
        Ok(written)
    }
}

/// Spawns the periodic checkpoint worker thread.
///
/// The worker polls the applied tip every [`POLL_INTERVAL`] and publishes a
/// checkpoint when the tip has advanced `interval_blocks` since the last
/// publication or `interval_secs` has elapsed since the last publication,
/// whichever fires first. A `DisconnectInFlight` refusal or an in-flight
/// publication error is logged and retried on the next tick. The worker exits
/// when `shutdown` is set.
pub(crate) fn spawn_periodic_checkpoint_worker(
    publisher: CheckpointPublisher,
    shutdown: Arc<AtomicBool>,
    interval_blocks: u32,
    interval_secs: Duration,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("bitcoin-rs-checkpoint-worker".to_owned())
        .spawn(move || {
            let mut last_published_height: u32 = publisher
                .applied_tip
                .load()
                .as_ref()
                .map_or(0, |tip| tip.height);
            let mut last_published_at = Instant::now();

            while !shutdown.load(Ordering::Relaxed) {
                if wait_for_shutdown(&shutdown, POLL_INTERVAL) {
                    break;
                }

                let current_tip = publisher.applied_tip.load();
                let Some(tip) = current_tip.as_ref() else {
                    // No applied tip yet; nothing to checkpoint.
                    continue;
                };

                let blocks_advanced = tip.height.saturating_sub(last_published_height);
                let elapsed = last_published_at.elapsed();

                if blocks_advanced < interval_blocks && elapsed < interval_secs {
                    continue;
                }

                match publisher.publish() {
                    Ok(CheckpointWrite::Published { generation }) => {
                        last_published_height = tip.height;
                        last_published_at = Instant::now();
                        tracing::info!(
                            generation,
                            height = tip.height,
                            blocks_advanced,
                            elapsed_secs = elapsed.as_secs(),
                            "published periodic chainstate checkpoint during sync",
                        );
                    }
                    Ok(CheckpointWrite::SkippedNoAppliedTip) => {
                        tracing::debug!("periodic checkpoint skipped: no applied tip");
                    }
                    Err(CheckpointError::DisconnectInFlight { hash, height }) => {
                        tracing::debug!(
                            %hash,
                            height,
                            "periodic checkpoint deferred: disconnect in flight",
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "periodic checkpoint publication failed; will retry next tick",
                        );
                    }
                }
            }
        })
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
