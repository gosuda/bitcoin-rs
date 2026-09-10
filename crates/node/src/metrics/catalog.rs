//! Metric names and descriptions registered by the node scrape service.

pub(super) fn describe_node_metrics() {
    metrics::describe_counter!("node.event_loop.mempool_ticks", "mempool maintenance ticks");
    metrics::describe_counter!("node.event_loop.metrics_scrapes", "metrics scrape ticks");
    metrics::describe_counter!("node.event_loop.sync_ticks", "block sync ticks");
    metrics::describe_counter!(
        "node.event_loop.sync_wakes",
        "block sync wakeups from inbound p2p data"
    );
    metrics::describe_gauge!(
        "node.shutdown.requested",
        "whether shutdown has been requested"
    );
    metrics::describe_histogram!(
        "node.event_loop.tick_seconds",
        "event loop tick latency seconds"
    );
    metrics::describe_counter!(
        "node.sync.duplicate_deliveries",
        "blocks received that were already staged"
    );
    metrics::describe_histogram!(
        "node.sync.apply_idle_seconds",
        "durations the apply frontier stayed starved while the window owed downloads"
    );
    metrics::describe_histogram!(
        "node.sync.download_blocked_by_apply_seconds",
        "durations the window front stayed in flight while apply held the frontier"
    );
    metrics::describe_gauge!(
        "node.sync.pending_blocks_high_water",
        "highest in-flight block count observed"
    );
    metrics::describe_gauge!(
        "node.sync.pending_bytes_high_water",
        "highest in-flight byte estimate observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_blocks_high_water",
        "highest staged block count observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_bytes_high_water",
        "highest staged byte total observed"
    );
    metrics::describe_counter!(
        "storage.writes_total",
        "storage write batches applied, by backend and durability"
    );
    metrics::describe_counter!(
        "storage.flushes_total",
        "storage durability flushes by backend"
    );
    metrics::describe_histogram!("storage.write_bytes", "storage write batch payload bytes");
    metrics::describe_gauge!(
        "storage.cache_capacity_bytes",
        "configured per-engine cache capacity in bytes"
    );
}
