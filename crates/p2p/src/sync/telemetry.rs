//! Read-only synchronization progress and bounded-window metrics.

use super::BlockSync;

impl BlockSync {
    /// Emits a one-line sync-progress summary at INFO level.
    pub fn emit_sync_progress(&self) {
        let now = std::time::Instant::now();
        let chain = self.observe_chain_frontier();
        let frontier = self.observe_frontier(chain, now);
        let plan = frontier.plan();
        let (applied_height, header_height) = frontier.heights();
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
        self.ibd.is_active(
            bitcoin_rs_primitives::unix_time_secs(),
            self.chain.network(),
        )
    }

    /// Publishes the staged-body, pending-window, and inbound-queue gauges
    /// from one scheduler-lock hold.
    ///
    /// `staged_decoded_bytes` and `staged_retained_bytes` attribute staged
    /// decoded-heap capacity and preserved serialized buffers; they exclude
    /// allocator rounding, are not a process-RSS measure, and never feed an
    /// admission decision. `received_bytes` and `staged_bytes_high_water`
    /// remain the serialized fact the byte budget reads.
    /// `inbound_block_queue_depth` is the bounded inbound channel's length at
    /// emission. The only caller runs after the drain pass has emptied the
    /// receiver, so it reports the residual queue that arrived during or
    /// after the pass; bodies the pass already pulled are in the staged
    /// gauges, or in the apply batch the stager no longer owns, and are not
    /// attributed in bytes.
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
        metrics::gauge!("node.sync.staged_decoded_bytes").set(metric_bytes(stager.decoded_bytes()));
        metrics::gauge!("node.sync.staged_retained_bytes")
            .set(metric_bytes(stager.retained_attributed_bytes()));
        metrics::gauge!("node.sync.staged_retained_bytes_high_water")
            .set(metric_bytes(stager.retained_attributed_bytes_high_water()));
        metrics::gauge!("node.sync.inbound_block_queue_depth")
            .set(metric_count(self.inbound_blocks_rx.len()));
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

/// A byte attribution as a gauge value without the `u32` clamp of
/// [`metric_count`]: the retained gauges exist to show residency growing past
/// the serialized budget, so a total above 4 GiB must not saturate. The high
/// and low 32-bit halves each convert to `f64` exactly.
fn metric_bytes(value: usize) -> f64 {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

#[cfg(test)]
mod tests {
    use super::metric_bytes;

    #[test]
    fn metric_bytes_is_exact_across_the_u32_boundary() {
        assert_eq!(metric_bytes(0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(metric_bytes(4_096).to_bits(), 4_096.0_f64.to_bits());
        if let Ok(above_u32) = usize::try_from(5_000_000_000_u64) {
            assert_eq!(
                metric_bytes(above_u32).to_bits(),
                5_000_000_000.0_f64.to_bits()
            );
        }
    }
}
