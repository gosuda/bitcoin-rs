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
    pub fn emit_sync_progress(&self) {
        let applied_tip = self.handles.applied_tip.load_full();
        let chain_tip = self.handles.chain_tip.load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
        let live_peers = self.peer_table.len();
        let in_ibd = header_height > 0 && applied_height < header_height;
        let gap = header_height.saturating_sub(applied_height);

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

    pub(super) fn record_sync_metrics(&self) {
        let window = self.download_window.lock();
        let stager = self.block_stager.lock();
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
        let window = self.download_window.lock();
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
    }
}

pub(super) fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}
