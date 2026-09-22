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
        let frontier = self.observe_frontier();
        let plan = frontier.reconcile(std::time::Instant::now());
        let applied_height = frontier.applied_tip.as_ref().map_or(0, |tip| tip.height);
        let header_height = frontier
            .header_tip
            .as_ref()
            .map_or(applied_height, |tip| tip.height);
        let usable_peers = frontier.usable_peers.len();
        let next_required_height = frontier.next_required.map(|body| body.height);
        let next_required_hash = frontier.next_required.map(|body| body.hash);
        let body_state = frontier.body_state;
        let header_request_peer = frontier.header_request.map(|request| request.source.addr);
        let header_request_locator = frontier
            .header_request
            .map(|request| request.locator_tip_hash);
        let header_request_target = frontier.header_request.map(|request| request.target_height);
        let no_progress_reason = plan.no_progress_reason;
        let in_ibd = header_height > 0 && applied_height < header_height;
        let gap = header_height.saturating_sub(applied_height);

        if in_ibd {
            tracing::info!(
                applied_height,
                header_height,
                gap,
                peers = usable_peers,
                ?next_required_height,
                ?next_required_hash,
                ?body_state,
                ?header_request_peer,
                ?header_request_locator,
                ?header_request_target,
                ?no_progress_reason,
                ibd = true,
                "sync progress"
            );
        } else {
            tracing::info!(
                applied_height,
                header_height,
                peers = usable_peers,
                ?next_required_height,
                ?next_required_hash,
                ?body_state,
                ?header_request_peer,
                ?header_request_locator,
                ?header_request_target,
                ?no_progress_reason,
                ibd = false,
                "sync progress"
            );
        }
    }

    pub(super) fn record_sync_metrics(&self) {
        let frontier_state = self.frontier_state.lock();
        let window = &frontier_state.window;
        let stager = &frontier_state.stager;
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
        let frontier_state = self.frontier_state.lock();
        let window = &frontier_state.window;
        metrics::gauge!("node.sync.pending_blocks").set(metric_count(window.pending_len()));
        metrics::gauge!("node.sync.pending_bytes").set(metric_count(window.pending_bytes()));
    }
}

pub(super) fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}
