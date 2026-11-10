# Observability boundary

The normative rule for where instrumentation lands in bitcoin-rs. The
observability surface has three layers: `metrics::` counters/histograms/
gauges, `tracing::` logs, and USDT probes (`bitcoin_rs_consensus::trace`). This
page keeps new instrumentation in the right one. Issue #1195 raised it as a
follow-up to the USDT work of #1187/#1194.

Owners:

- Boundary rule and audit: this page (`OBS-01`..`OBS-06`)
- USDT probe ABI and compatibility table: [`tracing.md`](tracing.md)
  (`crates/consensus/probes.d`, `crates/consensus/src/trace.rs`)
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
enumerations: backend names, durability modes, and closed reason taxonomies
(see `node.sync.stall_episodes_cleared{reason}` in `crates/node/src/p2p/download_window.rs`
for the pattern). They also include the enum capability states of `node.capability.txindex_readiness`, and
the closed family labels of `index.family_planned_write_bytes{family}` where
`family` in `{tx_lookup, script_history, script_live, headers, filters, tail_log}`.
No speculative instrumentation: a signal earns its place by an operator
decision (alert, dashboard, SLO) or a named contract hook (below).
Evidence identity (binary/configuration/corpus digests and hardware)
is not attached to Prometheus series as global labels.

RPC connection isolation (API-34/WF-02) exposes `rpc.connections.active`
(gauge, admitted live workers), `rpc.connections.rejected_total` (counter,
connection-budget refusals), and `rpc.http.request_seconds` (histogram).
The histogram covers the complete request head through body read,
authentication and response write, including subsequent failures; it excludes idle/head acquisition. The closed `surface`
label is `shared`, `management`, or `public`; the histogram's closed `route`
label is `json_rpc`, `rest`, `esplora_public`, `esplora_backend`, or `not_found`.
`route` records classification before the listener's route policy is checked;
it includes refused routes. For example, `surface=management, route=rest`
records a REST request rejected by the management listener with 404.
Values aggregate bindings of the same surface. Operators can distinguish
public saturation from management pressure and compare classified request
latency. Occupancy updates follow the existing connection permit lifetime,
including spawn failure and shutdown; no second admission counter is added.
No paths, method names, credentials, addresses, hashes or txids are labels.

For staged block bodies, `node.sync.received_bytes` and
`node.sync.staged_bytes_high_water` stay the serialized wire fact that the
staging byte budget and request headroom read. Four further signals attribute
retained residency without changing any admission rule:

| Signal | Meaning |
| --- | --- |
| `node.sync.staged_decoded_bytes` | Sum over staged blocks of `Block::retained_heap_bytes()`: the capacity of each block's transaction, input, output, script, and witness allocations. |
| `node.sync.staged_retained_bytes` | `staged_decoded_bytes` plus the preserved serialized buffers (`received_bytes`). |
| `node.sync.staged_retained_bytes_high_water` | Highest `staged_retained_bytes` observed this run. |
| `node.sync.inbound_block_queue_depth` | Length of the bounded inbound channel (`inbound_block_queue_limit`) when the drain pass emitted. A count of unstaged bodies, not bytes. |

The three byte signals are attribution, not measurement of the process. They
exclude allocator rounding, the inline `Block` value, and the stager's map and
queue bookkeeping, so they are not an RSS or `VmHWM` figure and need not equal
one. They cover only bodies the stager owns. A body drained for apply, or
pulled from the channel into a stage batch, is unattributed until it is
staged or restored. `staged_retained_bytes = 0` in the middle of an apply
does not mean no block memory is held. A block is measured once, when the
stager takes ownership of its allocation. This occurs on arrival, or restore
after a partial apply (which re-measures the restored allocation because the
restored copy need not have the drained original's capacities). It is released
at the transition that releases its serialized bytes: drain, branch retirement,
count-budget eviction, discard, expiry, or replacement. The retained high-water
mark advances on arrival and on restore; an arrival's mark is taken before the
count-budget eviction it causes. `node.sync.staged_blocks_high_water` and
`node.sync.staged_bytes_high_water` keep their earlier arrival-only behavior.
Nothing admits, evicts, or retries on these signals. They are backlog/capacity
gauges (OBS-01) published with the other staged gauges from one scheduler-lock
hold by the sync drain pass that saw arrivals, expiry, applies, or failures.
That pass runs after it has emptied the receiver.
`inbound_block_queue_depth` is a post-drain residual, normally near zero, not
a peak. It is not refreshed on passes that emit nothing.

Staging policy decision (retained): production keeps the fixed 256-block /
512 MiB wire budget. Observed once, not evidence. The run used 48 synthetic
regtest trials (4 cells x 4 policies x 3 rounds, 320 blocks applied each).
Candidate `f24b7ded0` was committed after the matrix so source bytes match
the gated binary (raw samples in
`.outline/evidence/native-gate-20261026T183745Z-1096270/gate.log`). The gate
evaluated it under the fixed Step 25 criteria (>=10% peak-RSS reduction,
throughput >=98%, strictly lower retained high-water, no
retry/starvation/stall regression) and rejected it. No horizon met the RSS
gate (observed binding medians ~1.00-1.01x fixed vs required <=0.90). The
modern-large 8-peer 15 s and 30 s horizons each added a stall-episode start
(observed median 1 vs fixed 0; disconnects stayed 0, which does not cancel
the episode regression). Five early-multi rows were not valid binding
comparisons (all 60 s first refusals arrived after the corpus was fully
requested; 30 s rounds 1-2 had no refusal). Synthetic regtest only
(early/small and modern/large-OP_RETURN corpora, 3 runs per arm); no mainnet,
p99, or whole-node claim.

The call-site audit table below is a snapshot of its audited base. It has no
row for `index.family_planned_write_bytes`. This clause describes it.

`index.family_planned_write_bytes{family}` is a histogram in bytes with one
label, `family`, in `{tx_lookup, script_history, script_live, headers,
filters, tail_log}`. The families are the transaction-id lookup rows, the
script history rows, the live-view mutations, the block header identity rows,
the basic compact-filter rows, and the segment-tail log rows. A forward batch
commit records one observation
for each family whose planned bytes are non-zero, after the store commit
succeeds (`commit_forward_with_cursor` in `crates/projection/src/index/write.rs`;
`commit_forward` and `commit_block` use it). A failed commit records nothing,
and no other commit path records this metric. The value is the sum, over the
blocks of the batch, of the bytes each block planned for that family under the
rule in the next table (`PendingRows::encoded_bytes_by_family` in
`crates/projection/src/index/rows.rs` for `script_live` and `headers`, and
`planned_tail_bytes` in `crates/projection/src/index/tail_writes.rs` for the
other families). The sum is fixed as blocks join the batch,
before the commit merges, sorts, and de-duplicates the batch rows. The value is
row-size arithmetic over the prepared rows. It does not read the store, so it
does not include write-ahead-log, storage-engine, or device write volume, and
it is not a count of bytes written.

| `family` | Planned bytes per block |
| --- | --- |
| `tx_lookup` | The key and value bytes of each `TxDir` put that the block's segment-tail append writes. |
| `script_history` | The key and value bytes of each `ScriptDict`, `ScriptPost`, `SpendDir`, and `ScriptStats` put that the tail append writes. |
| `script_live` | For each live insert, `SCRIPT_LIVE_ROW_SIZE` (43) plus the encoded value length. For each live delete, 43, the key only. |
| `headers` | `HEADER_ROW_SIZE` (80) times the number of header rows. |
| `filters` | The key and value bytes of each `Filters` put that the tail append writes. |
| `tail_log` | The key and value bytes of each `IdxMeta` put that the tail append writes, plus 36 bytes (`4 + SCRIPT_STATS_VALUE_LEN`) for each `ScriptStats` put, the prior value its undo entry may carry. |

### `OBS-02`: `tracing::` is diagnostics, not an API

Free-form development and debugging detail belongs in `tracing::` events and
spans. This includes per-event stage decompositions, timings a developer
attaches to one investigation, and anything whose fields or verbosity will
change with the code. `tracing::` content is explicitly not a stable surface: field names,
event names, and levels may change without notice. Operator runbooks
(`docs/operations/runtime-stall.md`) do not depend on log field shapes.

### `OBS-03`: USDT probes carry the detailed payloads

Core-compatible per-event payloads (block hashes, txids, raw message bytes,
per-event durations) belong in the USDT probes of `bitcoin_rs_consensus::trace`
(see [`tracing.md`](tracing.md), issues #1121/#1194). Probe payloads are the
layer that must not pollute metrics cardinality. If a detailed per-event datum
is worth keeping in production but is not operator-facing, it is a probe
argument, not a metric label. This slice adds no new probes.

### `OBS-04`: Per-event decomposition histograms are a fixed exempt set

The per-event decomposition histograms named below are grandfathered into the
metrics API. They are the only `metrics::histogram!` names allowed to carry
per-event decompositions; a new decomposition is a `tracing::` event, not a new
metric. The named hooks are:
| Histogram |
| --- |
| `node.window.verify_seconds` |
| `node.apply_block.total_seconds` |
| `node.window.context_seconds` |
| `node.window.parse_seconds` |
| `node.window.prepare_seconds` |
| `node.apply_block.block_rules_seconds` |
| `node.apply_block.script_verify_seconds` |
| `node.apply_block.bip30_bip34_seconds` |
| `node.apply_block.utxo_commit_seconds` |
| `node.apply_block.undo_persist_seconds` |
| `node.apply_block.block_body_persist_seconds` |
| `node.apply_block.coin_stats_finish_seconds` |
| `node.apply_block.block_tree_insert_seconds` |
| `node.sync.getdata_batch_size` |
| `node.sync.apply_idle_seconds` |
| `node.sync.download_blocked_by_apply_seconds` |
| `node.sync.apply_buffered_blocks_seconds` |
| `node.event_loop.tick_seconds` |

### `OBS-05`: Decision table for new instrumentation

| Question | Layer |
| --- | --- |
| Would an operator alert or dashboard on it? Is it a rate/total, backlog, or stable latency? | `metrics::` (OBS-01) |
| Is it a per-event decomposition a developer attaches to one investigation? | `tracing::` (OBS-02) |
| Is it detailed per-event data (hashes, payloads, peer identity, raw durations) worth keeping in production? | USDT probe argument (OBS-03) |
| Is it a new per-event decomposition of a measured product stage? | `tracing::` (OBS-02); the OBS-04 histogram exempt set is closed |
| Does it need a block hash, txid, or peer address as a metric label? | none of the above, so it is a `tracing::` field or probe argument |

### `OBS-06`: Metric migration

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
| Prometheus global labels `binary_sha256`, `version`, `config_sha256`, `backend`, `durability`, `hardware`, `corpus_id`, `corpus_manifest_sha256` | removed from operator scrapes; `EvidenceIdentity` (`crates/node/src/metrics.rs`) stays in code, not in operator series |

Retired validation-stage timers emit `apply_block: profile` events as each
stage completes, before its error is propagated. They include `height` and
`block_hash`, cover proposals as well as commits, and contain only the fields
for the completed stage; unvisited stages have no event. The later commit
summary retains the per-stage durations. The migrated validation
and prevout-resolution clocks start only when DEBUG tracing is enabled; no
retired metric is restored. `script_verify: profile` emits `script_resolution_us`
before propagating a resolution error, then emits preparation/parallel timings
if verification runs. Consumers must not require every field on a single event.

## Evidence and checks

- `scrape_returns_operator_metrics_without_evidence_identity_labels` exercises
  the rendered Prometheus boundary with a corpus-bearing process identity. It
  scans every sample, including the real txindex readiness gauge. Evidence
  identity remains in code, not in operator time-series
  labels.
- The chainstate observability fixtures check retired metric names only on the
  caller thread. The fixtures connect coinbase-only apply/window cases on
  top of a directly published genesis seed. Seeding alone (`seed_genesis` in
  `crates/execution/src/test_fixtures.rs`) publishes the genesis tip with
  count 1 without connect and without hooks, so it emits no apply/window
  observation. Nonzero stage observations require at least one connected mined
  coinbase-only child: `apply_block` for the apply timers, a `connect_window`
  pair for the window histogram, or `validate_block` for proposal timings. The
  window verify histogram is emitted after the parallel verifier joins. The
  local recorder does not cover arbitrary Rayon-worker emissions, spending
  transactions, or script-resolution sub-stages.
- Real tracing-subscriber regressions cover proposal completion, contextual
  header rejection, and a missing-prevout script rejection. The last exercises
  successful prevout resolution followed by verification failure, not
  resolution failure. The resolver's fallible overlay insertion currently
  rejects only a vout index exceeding `u32`, which is not a practical
  valid-block fixture.
- `composite_isolates_a_panicking_leg` exercises the real observer failure
  path and requires the operator counter to have no leg label.
- `family_byte_histograms_recording` (`crates/projection/src/index/rows/tests.rs`)
  drives `record_family_byte_histograms` against a local recorder. It checks the
  six `family` label values with their byte values, and that a family with zero
  planned bytes records nothing. It does not drive a commit.
- Review enforcement: a new `metrics::` call site must cite an OBS clause in
  the PR. A series outside the OBS-04 exempt set and not an operator signal is
  a review-failing diagnostic leak into the metrics API.
- The historical stage-timer tables are in Git history at commit `bda50acd4`.
  They use old metric names on
  retired artifacts. They are evidence, not a promise that those series still
  exist.
