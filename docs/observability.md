# Observability boundary

The normative rule for where instrumentation lands in bitcoin-rs. The
observability surface has three layers — `metrics::` counters/histograms/
gauges, `tracing::` logs, and USDT probes (`bitcoin-rs-trace`) — and this page
is what keeps new instrumentation in the right one. Raised by issue #1195 as a
follow-up to the USDT work of #1187/#1194.

Owners:

- Boundary rule and audit: this page (`OBS-01`..`OBS-06`)
- USDT probe ABI and compatibility table: [`tracing.md`](tracing.md)
  (`crates/trace/`, `crates/trace/probes.d`)
- Hot-path attribution of measured product stages:
  [`contracts/hot-path-attribution.md`](contracts/hot-path-attribution.md)
  (HPA-01..HPA-13), inventory in [`benchmarks/hot-path-ledger.toml`](benchmarks/hot-path-ledger.toml)
- Metrics module docs and signal registry: `crates/node/src/metrics.rs`

## Clauses

### `OBS-01`: `metrics::` is a small, stable set of operator signals

The metrics API carries only signals an operator would dashboard or alert on:
rates, totals, backpressure/fallback counts, backlog gauges, and latency
distributions with stable names. Names and semantics are an API: renaming or
removing a shipped signal is a breaking change and needs a documented
migration.

Metrics MUST NOT carry per-event payloads, block/tx/peer identity, or any
other high-cardinality label value. The only label values allowed are
enumerations: backend names, durability modes, closed reason taxonomies
(see `node.sync.stall_episodes_cleared{reason}` in `crates/p2p/src/download_window.rs`
for the pattern), and the enum capability states of `node.capability.txindex_readiness`.
No speculative instrumentation: a signal earns its place by an operator
decision (alert, dashboard, SLO) or a named contract hook (below).
Benchmark evidence identity (binary/configuration/corpus digests and hardware)
is recorded with benchmark samples under HPA-12; it is not attached to every
Prometheus series as global labels.

### `OBS-02`: `tracing::` is diagnostics, not an API

Free-form development and debugging detail belongs in `tracing::` events and
spans: per-event stage decompositions, timings a developer attaches to one
investigation, and anything whose fields or verbosity will change with the
code. `tracing::` content is explicitly not a stable surface: field names,
event names, and levels may change without notice. Operator runbooks
(`docs/operations/runtime-stall.md`) do not depend on log field shapes.

### `OBS-03`: USDT probes carry the detailed payloads

Core-compatible per-event payloads — block hashes, txids, raw message bytes,
per-event durations — belong in the USDT probes of `crates/trace`
(see [`tracing.md`](tracing.md), issues #1121/#1194). Probe payloads are the
layer that must not pollute metrics cardinality. If a detailed per-event datum
is worth keeping in production but is not operator-facing, it is a probe
argument, not a metric label. This slice adds no new probes.

### `OBS-04`: Hot-path attribution hooks are exempt, and only via the ledger

The measured product-stage histograms that
[`contracts/hot-path-attribution.md`](contracts/hot-path-attribution.md)
consumes (HPA-04: "Existing `metrics::histogram!` names in the ledger are
diagnostic hooks") are grandfathered into the metrics API even though they are
per-event decompositions. Their inventory is exactly the `histogram = ` keys of
[`benchmarks/hot-path-ledger.toml`](benchmarks/hot-path-ledger.toml); a hook
outside that file must be renamed into `tracing::`, and a new hook must first
become a ledger path row. The named hooks are:

| Ledger hook | Ledger path |
| --- | --- |
| `node.window.verify_seconds` | `apply.prove_window` |
| `node.apply_block.total_seconds` | `apply.commit` |
| `node.window.context_seconds` | `apply.header_accept` |
| `node.window.parse_seconds` | `apply.block_decode` |
| `node.window.prepare_seconds` | `apply.window_overlay` |
| `node.apply_block.block_rules_seconds` | `apply.merkle_witness` |
| `node.apply_block.script_verify_seconds` | `apply.script_verify` |
| `node.apply_block.bip30_bip34_seconds` | `apply.contextual_checks` |
| `node.apply_block.utxo_commit_seconds` | `apply.utxo_commit` |
| `node.apply_block.undo_persist_seconds` | `apply.undo_persist` |
| `node.apply_block.block_body_persist_seconds` | `apply.body_persist` |
| `node.apply_block.coin_stats_finish_seconds` | `apply.coinstats` |
| `node.apply_block.block_tree_insert_seconds` | `apply.tip_publish` |
| `node.sync.getdata_batch_size` | `p2p.request_schedule` |
| `node.sync.apply_idle_seconds` | `p2p.apply_idle` |
| `node.sync.download_blocked_by_apply_seconds` | `p2p.download_blocked_by_apply` |
| `node.event_loop.tick_seconds` | `p2p.event_loop` |

### `OBS-05`: Decision table for new instrumentation

| Question | Layer |
| --- | --- |
| Would an operator alert or dashboard on it? Is it a rate/total, backlog, or stable latency? | `metrics::` (OBS-01) |
| Is it a per-event decomposition a developer attaches to one investigation? | `tracing::` (OBS-02) |
| Is it detailed per-event data (hashes, payloads, peer identity, raw durations) worth keeping in production? | USDT probe argument (OBS-03) |
| Is it a measured product stage the hot-path attribution consumes? | ledger path first, then `metrics::` hook (OBS-04) |
| Does it need a block hash, txid, or peer address as a metric label? | none of the above — it is a `tracing::` field or probe argument |

### `OBS-06`: Audit trail and migration

The issue #1195 audit classifies every `metrics::` call site of current
upstream `73f9ee62` in the table below. Clearly diagnostic sites were edited:
per-event stage decompositions and internal P2P strategy decisions moved into
the `tracing::` events named in the table (the events already existed or are
the natural diagnostic events of their path), and one redundant histogram was
removed because its value was already a traced field. The mempool observer
failure counter remains operational, but its embedder-chosen `leg` label was
removed and its name narrowed to an aggregate. Every other operator signal and
ledger hook keeps its name.

Removed or narrowed (scrape consumers of an old name must use the replacement
below):

| Former metric | New home |
| --- | --- |
| `node.apply_block.contextual_header_seconds` | `tracing::debug!("apply_block: profile")` field `contextual_header_us` |
| `node.apply_block.pow_self_consistency_seconds` | `"apply_block: profile"` field `pow_self_us` |
| `node.apply_block.coinbase_maturity_seconds` | `"apply_block: profile"` field `coinbase_maturity_us` |
| `node.apply_block.bip68_seconds` | `"apply_block: profile"` field `bip68_us` |
| `node.apply_block.utxo_changes_seconds` | `"apply_block: profile"` field `utxo_changes_us` |
| `node.apply_block.durable_sync_seconds` | `tracing::debug!("apply_block: publish profile")` field `durable_sync_us` |
| `node.apply_block.durable_commit_seconds` | `"apply_block: publish profile"` field `durable_commit_us` |
| `node.apply_block.script_verify_coinbase_only_seconds` | `"apply_block: profile"` field `script_dispatch="coinbase_only"` |
| `node.apply_block.script_verify_serial_overlay_seconds` | `"apply_block: profile"` field `script_dispatch="serial_overlay"` |
| `node.apply_block.script_verify_parallel_seconds` | `"apply_block: profile"` field `script_dispatch="parallel"` |
| `node.apply_block.script_resolution_seconds` | `tracing::debug!("script_verify: profile")` field `script_resolution_us` |
| `node.apply_block.script_prepare_seconds` | `"script_verify: profile"` field `script_prepare_us` |
| `node.apply_block.script_parallel_seconds` | `"script_verify: profile"` field `script_parallel_us` |
| `node.chainstate_journal.replay_seconds` | removed as redundant: already a `replay_seconds` field on `tracing::info!("chainstate restore selected")` |
| `node.durable_head.group_sync_seconds` | `tracing::debug!("durable_head: group commit")` field `sync_us` |
| `node.durable_head.group_commit_seconds` | `"durable_head: group commit"` field `commit_us` |
| `node.durable_head.group_blocks` | `"durable_head: group commit"` field `blocks` |
| `node.window.checks_seconds` | `tracing::debug!("prove_window: profile")` field `checks_us` |
| `node.utxo.listener.event_batches_seconds` | `tracing::debug!("utxo listener: event batches")` field `listener_us` |
| `mempool_observer_leg_failed_total{leg}` | aggregate `node.mempool.observer_failures_total`; leg identity remains on `tracing::warn!(leg = *name, "mempool observer leg panicked; later legs continue")` |
| `node.sync.frontier_rewinds` | `tracing::debug!("block sync: rewound unowned request frontier")` |
| `node.sync.prefix_probe_wins` | `tracing::info!("block sync: prefix probe elected winner")` |
| `node.sync.cold_front_wins` | `tracing::info!("block sync: cold-front hedge elected alternate")` |
| `node.sync.extra_peer_disconnects` | `tracing::info!("p2p retiring the extra full-relay connection: the tip is moving again")` |
| `node.sync.idle_frontier_probes` | `tracing::debug!("block sync: sent idle-frontier capability probe")` |
| `node.sync.chain_sync_probes` | `tracing::debug!("block sync: sent chain-sync eviction probe")` |
| `node.sync.prefix_probe_peers` | `tracing::info!("block sync: started common-prefix peer probe")` field `alternates` |
| `node.sync.cold_front_hedges` | `tracing::info!("block sync: hedged cold-start stalled front")` |
| Prometheus global labels `binary_sha256`, `version`, `config_sha256`, `backend`, `durability`, `hardware`, `corpus_id`, `corpus_manifest_sha256` | removed from operator scrapes; `EvidenceIdentity` remains attached to benchmark ledger samples under HPA-12 |

Retired validation-stage timers emit `apply_block: profile` events as each
stage completes, before its error is propagated. They include `height` and
`block_hash`, cover proposals as well as commits, and contain only the fields
for the completed stage; unvisited stages have no event. The later commit
summary retains the operational/ledger stage durations. The migrated validation
and prevout-resolution clocks start only when DEBUG tracing is enabled; no
retired metric is restored. `script_verify: profile` emits `script_resolution_us`
before propagating a resolution error, then emits preparation/parallel timings
if verification runs. Consumers must not require every field on a single event.

### Call-site audit

Audited base: `73f9ee62` (upstream/main). Total `metrics::counter!`/`histogram!`/`gauge!` call sites: 121. The table covers macro call sites; the separate scrape-surface audit also removed the high-cardinality global evidence labels listed above.

The retained classifications answer a stable operator question; the macro
kind alone never makes a signal operational:

| Class | Operator use |
| --- | --- |
| ledger hook | Exact histogram named by `hot-path-ledger.toml`, retained under OBS-04/HPA-04. |
| progress/liveness | Alert or dashboard whether apply, the event loop, or durable publication is advancing (`txs_applied`, verify success, ticks/wakes, commits, flushes, stall episodes). |
| fault/safety | Alert on durability/recovery gaps, fallbacks, checksum or append failures, invalid or dropped bodies, peer timeouts/convictions, retries, and observer callback failure. |
| backlog/capacity | Alert on pending/staged bytes and blocks, stall age, journal lag/size/gap, readiness, shutdown state, or stable queue latency. |
| storage workload | Capacity and saturation dashboard for cache size, write/flush rates, batch bytes, and durable flush latency. |
| test fixture | Exercises the exporter only; not a shipped signal. |

Per-event stage decomposition and internal scheduling choices (probe, hedge,
winner, cursor rewind) are diagnostic even when expressed as a count. Their
fields stay in tracing, where they can change with the implementation.

| # | file:line | macro | signal | classification | action |
| --- | --- | --- | --- | --- | --- |
| 1 | `crates/chainstate/src/connect.rs:115` | `histogram!` | `node.apply_block.contextual_header_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("apply_block: profile")` field `contextual_header_us` |
| 2 | `crates/chainstate/src/connect.rs:127` | `counter!` | `node.chainstate_journal.backpressure_total` | operational signal (rate/total) | kept (name unchanged) |
| 3 | `crates/chainstate/src/connect.rs:143` | `histogram!` | `node.apply_block.pow_self_consistency_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"apply_block: profile"` field `pow_self_us` |
| 4 | `crates/chainstate/src/connect.rs:235` | `histogram!` | `node.apply_block.block_rules_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 5 | `crates/chainstate/src/connect.rs:244` | `histogram!` | `node.apply_block.bip30_bip34_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 6 | `crates/chainstate/src/connect.rs:267` | `histogram!` | `node.apply_block.script_verify_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 7 | `crates/chainstate/src/connect.rs:278` | `histogram!` | `node.apply_block.script_verify_{coinbase_only,serial_overlay,parallel}_seconds` (one call site, three dispatch names) | diagnostic (per-event dispatch split) | moved to `tracing::debug!("apply_block: profile")` field `script_dispatch={coinbase_only,serial_overlay,parallel}` |
| 8 | `crates/chainstate/src/connect.rs:285` | `histogram!` | `node.apply_block.coinbase_maturity_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"apply_block: profile"` field `coinbase_maturity_us` |
| 9 | `crates/chainstate/src/connect.rs:304` | `histogram!` | `node.apply_block.bip68_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"apply_block: profile"` field `bip68_us` |
| 10 | `crates/chainstate/src/connect.rs:334` | `histogram!` | `node.apply_block.utxo_changes_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"apply_block: profile"` field `utxo_changes_us` |
| 11 | `crates/chainstate/src/connect.rs:374` | `histogram!` | `node.apply_block.undo_persist_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 12 | `crates/chainstate/src/connect.rs:416` | `histogram!` | `node.apply_block.block_body_persist_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 13 | `crates/chainstate/src/connect.rs:429` | `histogram!` | `node.apply_block.block_tree_insert_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 14 | `crates/chainstate/src/connect.rs:436` | `histogram!` | `node.apply_block.utxo_commit_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 15 | `crates/chainstate/src/connect.rs:463` | `histogram!` | `node.apply_block.coin_stats_finish_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 16 | `crates/chainstate/src/connect.rs:466` | `histogram!` | `node.apply_block.total_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 17 | `crates/chainstate/src/connect.rs:467` | `counter!` | `node.apply_block.txs_applied` | operational signal (rate/total) | kept (name unchanged) |
| 18 | `crates/chainstate/src/connect.rs:523` | `histogram!` | `node.apply_block.durable_sync_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("apply_block: publish profile")` field `durable_sync_us` |
| 19 | `crates/chainstate/src/connect.rs:546` | `histogram!` | `node.apply_block.durable_commit_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"apply_block: publish profile"` field `durable_commit_us` |
| 20 | `crates/chainstate/src/connect.rs:1041` | `counter!` | `node.chainstate_journal.append_failures` | operational signal (rate/total) | kept (name unchanged) |
| 21 | `crates/chainstate/src/connect.rs:1051` | `counter!` | `node.chainstate_journal.append_failures` | operational signal (rate/total) | kept (name unchanged) |
| 22 | `crates/chainstate/src/disconnect.rs:178` | `counter!` | `node.chainstate_journal.reorg_failures` | operational signal (rate/total) | kept (name unchanged) |
| 23 | `crates/chainstate/src/durable.rs:149` | `counter!` | `node.durable_head.commits` | operational signal (rate/total) | kept (name unchanged) |
| 24 | `crates/chainstate/src/durable.rs:214` | `counter!` | `node.durable_head.commits` | operational signal (rate/total) | kept (name unchanged) |
| 25 | `crates/chainstate/src/durable.rs:884` | `counter!` | `node.durable_head.recovery_gaps_replayed` | operational signal (rate/total) | kept (name unchanged) |
| 26 | `crates/chainstate/src/durable.rs:885` | `counter!` | `node.durable_head.recovery_gaps` | operational signal (rate/total) | kept (name unchanged) |
| 27 | `crates/chainstate/src/maintenance.rs:87` | `counter!` | `node.chainstate_journal.flush_failures` | operational signal (rate/total) | kept (name unchanged) |
| 28 | `crates/chainstate/src/maintenance.rs:93` | `counter!` | `node.chainstate_journal.maintenance_failures` | operational signal (rate/total) | kept (name unchanged) |
| 29 | `crates/chainstate/src/prepare.rs:352` | `histogram!` | `node.apply_block.script_resolution_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("script_verify: profile")` field `script_resolution_us` |
| 30 | `crates/chainstate/src/prepare.rs:368` | `histogram!` | `node.apply_block.script_prepare_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"script_verify: profile"` field `script_prepare_us` |
| 31 | `crates/chainstate/src/prepare.rs:370` | `histogram!` | `node.apply_block.script_parallel_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"script_verify: profile"` field `script_parallel_us` |
| 32 | `crates/chainstate/src/recovery.rs:162` | `counter!` | `node.chainstate_journal.fallback_total` | operational signal (count) | kept (name unchanged) |
| 33 | `crates/chainstate/src/recovery.rs:178` | `counter!` | `node.chainstate_journal.fallback_total` | operational signal (count) | kept (name unchanged) |
| 34 | `crates/chainstate/src/recovery.rs:218` | `histogram!` | `node.chainstate_journal.replay_seconds` | diagnostic (per-event/dev-only decomposition) | redundant: removed; already traced as `replay_seconds` on `chainstate restore selected` |
| 35 | `crates/chainstate/src/recovery.rs:259` | `counter!` | `node.chainstate_journal.fallback_total` | operational signal (count) | kept (name unchanged) |
| 36 | `crates/chainstate/src/recovery.rs:265` | `counter!` | `node.chainstate_journal.checksum_failures_total` | operational signal (rate/total) | kept (name unchanged) |
| 37 | `crates/chainstate/src/window.rs:153` | `histogram!` | `node.durable_head.group_sync_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("durable_head: group commit")` field `sync_us` |
| 38 | `crates/chainstate/src/window.rs:188` | `histogram!` | `node.durable_head.group_commit_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `"durable_head: group commit"` field `commit_us` |
| 39 | `crates/chainstate/src/window.rs:191` | `histogram!` | `node.durable_head.group_blocks` | diagnostic (per-event/dev-only decomposition) | moved to `"durable_head: group commit"` field `blocks` |
| 40 | `crates/chainstate/src/window.rs:222` | `counter!` | `node.durable_head.group_flushes` | operational signal (rate/total) | kept (name unchanged) |
| 41 | `crates/chainstate/src/window.rs:540` | `histogram!` | `node.window.context_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 42 | `crates/chainstate/src/window.rs:554` | `histogram!` | `node.window.parse_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 43 | `crates/chainstate/src/window.rs:589` | `histogram!` | `node.window.prepare_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 44 | `crates/chainstate/src/window.rs:690` | `histogram!` | `node.window.checks_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("prove_window: profile")` field `checks_us` |
| 45 | `crates/chainstate/src/window.rs:694` | `histogram!` | `node.window.verify_seconds` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 46 | `crates/chainstate/src/window.rs:700` | `counter!` | `node.window.verify_success_total` | operational signal (rate/total) | kept (name unchanged) |
| 47 | `crates/mempool/src/gateway.rs:485` | `counter!` | `mempool_observer_leg_failed_total{leg}` | operational fault count, but `leg` is embedder-chosen and not a closed taxonomy | renamed to aggregate `node.mempool.observer_failures_total`; leg stays in the warning event |
| 48 | `crates/node/src/event_loop.rs:62` | `gauge!` | `node.shutdown.requested` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 49 | `crates/node/src/event_loop.rs:74` | `counter!` | `node.event_loop.sync_wakes` | operational signal (rate/total) | kept (name unchanged) |
| 50 | `crates/node/src/event_loop.rs:90` | `counter!` | `node.event_loop.sync_ticks` | operational signal (rate/total) | kept (name unchanged) |
| 51 | `crates/node/src/event_loop.rs:92` | `histogram!` | `node.event_loop.tick_seconds` | stable operator latency and HPA-04 ledger hook | kept (name unchanged) |
| 52 | `crates/node/src/metrics.rs:380` | `gauge!` | `TXINDEX_READINESS_GAUGE` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 53 | `crates/node/tests/unit/metrics/tests.rs:96` | `counter!` | `node_metrics_retry_probe` | test-only fixture (not a shipped signal) | kept (test-only) |
| 54 | `crates/node/tests/unit/metrics/tests.rs:112` | `counter!` | `node_metrics_scrape_probe` | test-only fixture (not a shipped signal) | kept (test-only) |
| 55 | `crates/node/tests/unit/metrics/tests.rs:132` | `counter!` | `node_metrics_sequential_probe` | test-only fixture (not a shipped signal) | kept (test-only) |
| 56 | `crates/node/tests/unit/metrics/tests.rs:140` | `counter!` | `node_metrics_sequential_probe` | test-only fixture (not a shipped signal) | kept (test-only) |
| 57 | `crates/p2p/src/download_window.rs:757` | `counter!` | `node.sync.stall_episodes_cleared` | operational signal (count) | kept (name unchanged) |
| 58 | `crates/p2p/src/download_window.rs:1454` | `counter!` | `node.sync.stall_episodes_started` | operational signal (count) | kept (name unchanged) |
| 59 | `crates/p2p/src/download_window.rs:1513` | `histogram!` | `node.sync.apply_idle_seconds` | stable operator starvation latency and HPA-04 ledger hook | kept (name unchanged) |
| 60 | `crates/p2p/src/download_window.rs:1522` | `histogram!` | `node.sync.download_blocked_by_apply_seconds` | stable operator backpressure latency and HPA-04 ledger hook | kept (name unchanged) |
| 61 | `crates/p2p/src/download_window.rs:2133` | `counter!` | `node.sync.frontier_rewinds` | diagnostic (internal request-cursor correction) | moved to `tracing::debug!("block sync: rewound unowned request frontier")` |
| 62 | `crates/p2p/src/download_window.rs:2394` | `counter!` | `node.sync.prefix_probe_wins` | diagnostic (internal peer-selection outcome) | existing `tracing::info!("block sync: prefix probe elected winner")` |
| 63 | `crates/p2p/src/download_window.rs:2425` | `counter!` | `node.sync.cold_front_wins` | diagnostic (internal hedge outcome) | moved to `tracing::info!("block sync: cold-front hedge elected alternate")` |
| 64 | `crates/p2p/src/listener.rs:332` | `counter!` | `node.sync.dropped_unsolicited_blocks` | operational ingress-pressure/safety count (P2P-05) | kept (name unchanged) |
| 65 | `crates/p2p/src/service.rs:1104` | `counter!` | `node.sync.extra_peer_disconnects` | diagnostic (internal extra-slot retirement decision) | existing `tracing::info!("p2p retiring the extra full-relay connection: the tip is moving again")` |
| 66 | `crates/p2p/src/sync.rs:725` | `counter!` | `node.sync.no_progress_ticks` | operational signal (count) | kept (name unchanged) |
| 67 | `crates/p2p/src/sync/commit.rs:73` | `counter!` | `node.sync.invalid_block_disconnects` | operational signal (count) | kept (name unchanged) |
| 68 | `crates/p2p/src/sync/commit.rs:110` | `counter!` | `node.sync.apply_halted_ticks` | operational signal (count) | kept (name unchanged) |
| 69 | `crates/p2p/src/sync/commit.rs:231` | `counter!` | `node.sync.invalidated_blocks` | operational consensus-failure count | kept (name unchanged) |
| 70 | `crates/p2p/src/sync/commit.rs:271` | `histogram!` | `node.sync.apply_buffered_blocks_seconds` | operational signal (latency/backlog distribution) | kept (name unchanged) |
| 71 | `crates/p2p/src/sync/headers.rs:758` | `counter!` | `node.sync.idle_frontier_probes` | diagnostic (internal capability-probe dispatch) | moved to `tracing::debug!("block sync: sent idle-frontier capability probe")` |
| 72 | `crates/p2p/src/sync/headers.rs:800` | `counter!` | `node.sync.chain_sync_probes` | diagnostic (internal eviction-probe dispatch) | moved to `tracing::debug!("block sync: sent chain-sync eviction probe")` |
| 73 | `crates/p2p/src/sync/peers.rs:398` | `gauge!` | `node.sync.stall_seconds` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 74 | `crates/p2p/src/sync/peers.rs:451` | `counter!` | `node.sync.staller_disconnects` | operational signal (count) | kept (name unchanged) |
| 75 | `crates/p2p/src/sync/peers.rs:461` | `counter!` | `node.sync.pending_timeout_disconnects` | operational signal (count) | kept (name unchanged) |
| 76 | `crates/p2p/src/sync/peers.rs:526` | `counter!` | `node.sync.apply_side_stall_escalations` | operational signal (count) | kept (name unchanged) |
| 77 | `crates/p2p/src/sync/peers.rs:751` | `counter!` | `node.sync.chain_sync_disconnects` | operational signal (count) | kept (name unchanged) |
| 78 | `crates/p2p/src/sync/receive.rs:533` | `counter!` | `node.sync.body_binding_drops` | operational signal (count) | kept (name unchanged) |
| 79 | `crates/p2p/src/sync/receive.rs:655` | `counter!` | `node.sync.duplicate_deliveries` | operational signal (count) | kept (name unchanged) |
| 80 | `crates/p2p/src/sync/receive.rs:746` | `counter!` | `node.sync.retry_count` | operational signal (count) | kept (name unchanged) |
| 81 | `crates/p2p/src/sync/requests.rs:76` | `counter!` | `node.sync.prefix_probe_peers` | diagnostic (internal probe fan-out) | existing `tracing::info!("block sync: started common-prefix peer probe")` field `alternates` |
| 82 | `crates/p2p/src/sync/requests.rs:229` | `histogram!` | `node.sync.getdata_batch_size` | diagnostic ledger hook required by HPA-04 | kept under OBS-04 (name unchanged) |
| 83 | `crates/p2p/src/sync/requests.rs:315` | `counter!` | `node.sync.cold_front_hedges` | diagnostic (internal hedge dispatch) | existing `tracing::info!("block sync: hedged cold-start stalled front")` |
| 84 | `crates/p2p/src/sync/telemetry.rs:87` | `gauge!` | `node.sync.pending_blocks` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 85 | `crates/p2p/src/sync/telemetry.rs:88` | `gauge!` | `node.sync.pending_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 86 | `crates/p2p/src/sync/telemetry.rs:89` | `gauge!` | `node.sync.received_blocks` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 87 | `crates/p2p/src/sync/telemetry.rs:90` | `gauge!` | `node.sync.received_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 88 | `crates/p2p/src/sync/telemetry.rs:92` | `gauge!` | `node.sync.pending_blocks_high_water` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 89 | `crates/p2p/src/sync/telemetry.rs:94` | `gauge!` | `node.sync.pending_bytes_high_water` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 90 | `crates/p2p/src/sync/telemetry.rs:96` | `gauge!` | `node.sync.staged_blocks_high_water` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 91 | `crates/p2p/src/sync/telemetry.rs:98` | `gauge!` | `node.sync.staged_bytes_high_water` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 92 | `crates/p2p/src/sync/telemetry.rs:105` | `gauge!` | `node.sync.pending_blocks` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 93 | `crates/p2p/src/sync/telemetry.rs:106` | `gauge!` | `node.sync.pending_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 94 | `crates/storage/src/chainstate_journal/writer.rs:432` | `gauge!` | `node.chainstate_journal.append_gap` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 95 | `crates/storage/src/chainstate_journal/writer/durability.rs:102` | `histogram!` | `node.chainstate_journal.storage_flush_seconds` | operational signal (latency/backlog distribution) | kept (name unchanged) |
| 96 | `crates/storage/src/chainstate_journal/writer/open.rs:111` | `gauge!` | `node.chainstate_journal.append_gap` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 97 | `crates/storage/src/chainstate_journal/writer/retention.rs:95` | `gauge!` | `node.chainstate_journal.lag_blocks` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 98 | `crates/storage/src/chainstate_journal/writer/retention.rs:96` | `gauge!` | `node.chainstate_journal.head_height` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 99 | `crates/storage/src/chainstate_journal/writer/retention.rs:104` | `gauge!` | `node.chainstate_journal.size_mib` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 100 | `crates/storage/src/fjall_impl.rs:39` | `gauge!` | `storage.cache_capacity_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 101 | `crates/storage/src/fjall_impl.rs:99` | `counter!` | `storage.writes_total` | operational signal (rate/total) | kept (name unchanged) |
| 102 | `crates/storage/src/fjall_impl.rs:101` | `histogram!` | `storage.write_bytes` | operational storage batch-size distribution | kept (name unchanged) |
| 103 | `crates/storage/src/fjall_impl.rs:263` | `counter!` | `storage.flushes_total` | operational signal (rate/total) | kept (name unchanged) |
| 104 | `crates/storage/src/redb_impl.rs:58` | `gauge!` | `storage.cache_capacity_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 105 | `crates/storage/src/redb_impl.rs:90` | `counter!` | `storage.writes_total` | operational signal (rate/total) | kept (name unchanged) |
| 106 | `crates/storage/src/redb_impl.rs:92` | `histogram!` | `storage.write_bytes` | operational storage batch-size distribution | kept (name unchanged) |
| 107 | `crates/storage/src/redb_impl.rs:244` | `counter!` | `storage.writes_total` | operational signal (rate/total) | kept (name unchanged) |
| 108 | `crates/storage/src/redb_impl.rs:246` | `histogram!` | `storage.write_bytes` | operational storage batch-size distribution | kept (name unchanged) |
| 109 | `crates/storage/src/redb_impl.rs:255` | `counter!` | `storage.flushes_total` | operational signal (rate/total) | kept (name unchanged) |
| 110 | `crates/storage/src/redb_impl.rs:369` | `counter!` | `storage.writes_total` | operational signal (rate/total) | kept (name unchanged) |
| 111 | `crates/storage/src/redb_impl.rs:371` | `histogram!` | `storage.write_bytes` | operational storage batch-size distribution | kept (name unchanged) |
| 112 | `crates/storage/src/redb_impl.rs:513` | `counter!` | `storage.writes_total` | operational signal (rate/total) | kept (name unchanged) |
| 113 | `crates/storage/src/redb_impl.rs:515` | `histogram!` | `storage.write_bytes` | operational storage batch-size distribution | kept (name unchanged) |
| 114 | `crates/storage/src/redb_impl.rs:524` | `counter!` | `storage.flushes_total` | operational signal (rate/total) | kept (name unchanged) |
| 115 | `crates/storage/src/redb_impl.rs:572` | `gauge!` | `storage.cache_capacity_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 116 | `crates/storage/src/rocksdb_impl.rs:46` | `gauge!` | `storage.cache_capacity_bytes` | operational signal (state/backlog gauge) | kept (name unchanged) |
| 117 | `crates/storage/src/rocksdb_impl.rs:224` | `counter!` | `storage.flushes_total` | operational signal (rate/total) | kept (name unchanged) |
| 118 | `crates/storage/src/rocksdb_impl.rs:245` | `counter!` | `storage.writes_total` | operational signal (rate/total) | kept (name unchanged) |
| 119 | `crates/storage/src/rocksdb_impl.rs:247` | `histogram!` | `storage.write_bytes` | operational storage batch-size distribution | kept (name unchanged) |
| 120 | `crates/utxo/src/set.rs:517` | `histogram!` | `node.utxo.listener.event_batches_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("utxo listener: event batches")` field `listener_us` |
| 121 | `crates/utxo/src/set.rs:551` | `histogram!` | `node.utxo.listener.event_batches_seconds` | diagnostic (per-event/dev-only decomposition) | moved to `tracing::debug!("utxo listener: event batches")` field `listener_us` |

## Evidence and checks

- The metrics module docs (`crates/node/src/metrics.rs`) restate this boundary
  where a new call site is written.
- `scrape_returns_operator_metrics_without_evidence_identity_labels` exercises
  the rendered Prometheus boundary using a corpus-bearing process identity and
  scans every sample, including the real txindex readiness gauge; evidence
  identity remains in benchmark ledger records, not operator time-series labels.
- The chainstate observability fixtures check retired metric names only on the
  caller thread with coinbase-only apply/window fixtures. The window verify
  histogram is emitted after the parallel verifier joins; the local recorder
  does not cover arbitrary Rayon-worker emissions or script sub-stage metrics.
- Real tracing-subscriber regressions cover proposal completion, contextual
  header rejection, and a missing-prevout script rejection. The last exercises
  successful prevout resolution followed by verification failure, not resolution
  failure: the resolver's fallible overlay insertion currently rejects only a
  vout index exceeding `u32`, which is not a practical valid-block fixture.
- `composite_isolates_a_panicking_leg` exercises the real observer failure
  path and requires the operator counter to have no leg label.
- Review enforcement: a new `metrics::` call site must cite an OBS clause in
  the PR. A series not in the ledger and not an operator signal is a
  review-failing diagnostic leak into the metrics API.
