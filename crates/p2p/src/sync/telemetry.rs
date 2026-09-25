//! Read-only synchronization progress and bounded-window metrics.

use super::BlockSync;

impl BlockSync {
    /// Emits a one-line sync-progress summary at INFO level.
    ///
    /// Reports applied height, header (chain) height, the gap, live peer
    /// count, and whether the node is still in initial block download. This
    /// is the operator-facing progress signal that #223 identified as
    /// missing during IBD — without it, `docker logs` shows no indication
    /// that the node is alive and applying blocks.
    ///
    /// When the canonical frontier cannot make progress at all, the line
    /// names the explicit reason instead of staying silent (#1128).
    pub fn emit_sync_progress(&self) {
        let now = std::time::Instant::now();
        let chain = self.observe_chain_frontier();
        let frontier = self.observe_frontier(chain, now);
        let plan = frontier.plan();
        let applied_height = frontier
            .chain
            .applied_tip
            .as_ref()
            .map_or(0, |tip| tip.height);
        let header_height = frontier
            .chain
            .chain_tip
            .as_ref()
            .map_or(applied_height, |tip| tip.height);
        let live_peers = frontier.usable_peers.len();
        let in_ibd = self.in_initial_block_download();
        let gap = header_height.saturating_sub(applied_height);

        if let Some(reason) = plan.no_progress
            && reason != crate::sync::NoProgressReason::AtTip
        {
            tracing::warn!(
                applied_height,
                header_height,
                gap,
                peers = live_peers,
                ibd = in_ibd,
                %reason,
                "sync progress: frontier cannot advance"
            );
            return;
        }
        if in_ibd {
            tracing::info!(
                applied_height,
                header_height,
                gap,
                peers = live_peers,
                ibd = true,
                "sync progress"
            );
        } else {
            tracing::info!(
                applied_height,
                header_height,
                peers = live_peers,
                ibd = false,
                "sync progress"
            );
        }
    }

    /// The initial-block-download fact reported by sync progress.
    ///
    /// PRE: none.
    /// POST: answers with the node's shared chain-owned
    ///   [`bitcoin_rs_chain::InitialBlockDownload`] latch at the current
    ///   second — the same answer RPC and the listener see.
    /// INVARIANT: telemetry never decides initial block download from
    ///   heights. The applied and header heights, and `gap`, stay progress
    ///   facts only.
    pub(super) fn in_initial_block_download(&self) -> bool {
        self.ibd
            .is_active(crate::counters::now_seconds(), self.chain.network())
    }

    pub(super) fn record_sync_metrics(&self) {
        let scheduler = self.scheduler.lock();
        let window = &scheduler.window;
        let stager = &scheduler.stager;
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
        metrics::gauge!("node.sync.received_blocks").set(metric_count(stager.received_len()));
        metrics::gauge!("node.sync.received_bytes").set(metric_count(stager.received_bytes()));
        let (pending_blocks_high_water, pending_bytes_high_water) = window.pending_high_water();
        metrics::gauge!("node.sync.pending_blocks_high_water")
            .set(metric_count(pending_blocks_high_water));
        metrics::gauge!("node.sync.pending_bytes_high_water")
            .set(metric_count(pending_bytes_high_water));
        metrics::gauge!("node.sync.staged_blocks_high_water")
            .set(metric_count(stager.received_high_water()));
        metrics::gauge!("node.sync.staged_bytes_high_water")
            .set(metric_count(stager.received_bytes_high_water()));
    }

    pub(super) fn record_pending_sync_metrics(&self) {
        let scheduler = self.scheduler.lock();
        let window = &scheduler.window;
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
    }
}

pub(super) fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}
