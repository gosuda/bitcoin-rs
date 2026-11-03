# UTXO set memory and coin-record cells

This document owns the UTXO set memory and coin-record measurement cells.
The production `UtxoSet` is a fully resident, 256-shard table of grouped v5
records with full transaction/output identity. It has no eviction tier.
Incremental coin persistence and a bounded cache are conditional on the
full-node measurement decision in [#631](https://github.com/gosuda/bitcoin-rs/issues/631),
not prerequisites for the existing
[durable-head/checkpoint/replay recovery contract](../contracts/recovery.md).
The `CoinRecords` column-family definition and historical persistent-coin work
do not establish an integrated production backing store.

The prior attribution below (the former checkpoint RSS hook, the Apple Silicon
fragmentation harness, the height-412,732 chainstate load) is historical
evidence for the arena rejection, not a current full-tip RSS result. The v5
codec measurements moved to Git history; see History.

## Cells it owns

| Cell | Metric | Status |
|---|---|---|
| `utxo.record.bytes_per_output` | payload bytes per live output and RSS bytes per output on a real pinned chainstate, v5 layout, production allocator | `planned_not_executed` |
| `utxo.commit.p95` | production grouped-record mutation p50/p95/p99/max; any conditional backing-store path must include its durability cost | `planned_not_executed` |
| `utxo.cache.eviction_reload` | conditional on #631's decision: eviction reloads identical records and bounds total retained memory | `planned_not_executed` |
| `utxo.fragmentation` | RSS growth after churn equal to twice the live set on the production allocator (mimalloc, x86-64 Linux) and on each additional measured configuration | `planned_not_executed` |
| `node.tip_rss` | full-node RSS at the pinned stop identity including backend and runtime; #631 baseline and conditional candidate | `planned_not_executed` |

Accelerators (truncated prefixes) remain hints, never identity. No heap object per coin. No second database. An arena or pool proposal reopens only with attribution on its own production allocator and domain workload.

## Required identities per sample

The six identities of [`README.md`](README.md).

## Acceptance rule

The promotion, regression, reporting, retention and `BLOCKED` rules of [`README.md`](README.md).


## Status

The end-state cells remain `planned_not_executed`, as defined in
[`README.md`](README.md). The #631 decision is **unmeasured**: neither a need
for a cache nor adequate full-tip memory headroom has been demonstrated.
The 13.83 GiB observation stopped at height 645,804; v5 tip projections and
synthetic commit measurements cannot complete this decision.

## Full-tip decision evidence (#631)

Use the shared [sample identities and acceptance rules](README.md) and the
resource reporting boundary in
[HPA-12/HPA-13](../contracts/hot-path-attribution.md#hpa-12-evidence-identity-per-sample).
Full-tip evidence is separate from the frozen C150/Cmodern product cells; it
does not extend their denominator or turn a bounded replay into full-tip proof.

Pin the network, stop height/hash, source corpus digest, binary digest/commit,
resolved configuration, features, allocator, toolchain, backend and durability
posture, hardware, and resource limits. Include the default full-node resource
profile (450 MiB `dbcache`, optional indexes and pruning off, Fjall and the
production allocator). Explicitly disable assume-valid for the required
full-validation run. Label optional index and pruning profiles separately.

The [historical G14 target](end-to-end-sync.md) is
16 GiB tip RSS with Fjall and txindex; it is not evidence that the current
default profile meets a budget. Record the applicable supported profile,
approved RSS limit, and required operating headroom before judging a run.
`dbcache` budgets backend caches, not the resident UTXO set or total process RSS.

| Evidence | Existing owner / remaining gap |
|---|---|
| Peak and steady process RSS, wall and CPU | External process monitoring; the offline comparator samples wall/CPU/peak RSS but does not capture steady-state samples or a full-tip default-node campaign. Retain the raw timeline and define the steady observation interval. |
| UTXO attribution at the pinned state | `UtxoSetView::memory_report()` owns record/output counts, exact requested payload bytes, and **estimated** table bytes. The retained `utxo_commit --measure-memory` mode exercises small diagnostic fixtures, not a live full-tip node. A same-state full-node report is still needed. |
| Other memory owners | Report backend, runtime, indexes, and allocator measurements where available. The difference between RSS and UTXO accounting is an **unattributed residual**, not an allocator-fragmentation measurement. Cache configuration is a limit, not observed allocation. |
| Apply throughput/latency | Reuse the existing hot-path instrumentation with counts and percentile samples. Do not sum nested/parallel stage intervals or infer latency tails from total wall time. |
| Disk, writes and compaction | Reuse the [offline storage-footprint utility](../contracts/storage-footprint.md) for a quiescent snapshot. It does not measure peak allocation, write amplification or compaction; those need separate observed counters or an explicit unsupported gap. |

The existing [offline comparator](offline-full-validation.md) preserves corpus
custody and correctness checks, but its fixture tests and C150/Cmodern scope
do not supply this evidence. Reuse the existing tooling boundaries for a real
campaign rather than adding a parallel benchmark framework. Until the pinned
full-tip corpus, suitable host, attribution capture, and applicable resource
target are available, record the missing prerequisites as `BLOCKED` in the
run discussion; do not publish a budget verdict or treat harness tests as a
measurement.

Record the decision here with links to raw execution artifacts in the issue
or PR. Within-budget evidence with sufficient headroom and no demonstrated
low-memory requirement supports closing #631 without a cache. An over-budget
result or supported low-memory requirement must quantify the RSS target and
acceptable validation/I/O cost before implementing a cache, then compare
matched baseline/candidate runs. Any backing store must preserve the existing
chainstate recovery authority and grouped v5 identity.

## Historical measurements the hot-path ledger cites

`hot-path-ledger.toml` cites these measurements by value. Both come from
retired tooling: the churn test from the Apple Silicon fragmentation harness
(the retired `utxo_memory_attribution` example), and the height-412,732
chainstate load from the former checkpoint RSS-attribution hook. Current
full-node RSS evidence must use an external process monitor.

### Churn test

The memory campaign's leading hypothesis was allocator fragmentation from tens
of millions of small allocations. We tested it directly. We spent the oldest
tenth of the set and refilled it, repeatedly, holding the live count constant:

| Churn | RSS bytes/output | RSS / accounted |
|---|---:|---:|
| None (monotonic insert) | 105.7 | 1.207x |
| 50% of the set replaced | 108.3 | 1.237x |
| 200% of the set replaced | 110.5 | 1.263x |

Churning twice the whole set costs **5% more RSS**, and the curve is flattening,
not climbing. Uniform small allocations are the case a size-class allocator
handles well. **The hypothesis is refuted at this scale on this allocator.**
Two caveats are worth keeping. Production links mimalloc rather than the system
allocator, and 645,804 blocks is far more churn than twenty rounds.

### Height-412,732 chainstate load

A pruned mainnet sync to **height 412,732** (38,145,360 outputs across
10,519,335 records) settled the UTXO share of process RSS. The figures below
are historical evidence. They come from the former checkpoint RSS-attribution
hook, and that hook is no longer part of the node runtime. The former
`snapshot_memory` helper was also retired with the completed memory campaign.

| Layer | Bytes/output | Total |
|---|---:|---:|
| Record payload | 55.1 | 1.96 GiB |
| ...plus allocation header and slack | 57.3 | |
| ...plus hash-table backing store | 61.2 | 2.18 GiB |
| **Process RSS** | **79.2** | **2.81 GiB** |

**The UTXO set is 77.4% of process RSS**, not the ~44% an in-flight sample
suggested. The remaining 0.64 GiB is fjall, CoinStats, the block-record log and
the runtime.

An earlier revision attributed 450 MB of that residual to the configured
`dbcache`. That was wrong at the time: `Config::dbcache_mb` was parsed but never
reached a backend constructor. **Update:** the budget is now real. `dbcache_mb`
divides across namespaces, and every backend takes its share through
`open_with_cache` (issue #51). The attribution numbers in this document predate
that change. A fresh RSS decomposition is needed before any residual claim is
re-earned.

## When to revert v5

These terms are stated now, while the numbers are in front of us. Whoever
reads this later then does not have to reconstruct the trade.

v5 costs about **3 ns per lookup** at the measured mainnet average and **3-21%
on block commit p95**. Both sit against budgets with roughly twenty times the
headroom. The G14 commit p95 budget is 50 ms, and the worst case measured is
2.57 ms. It buys **12 points of the 16 GiB tip-RSS budget**. That is a good
trade only while tip RSS is actually near the budget, and the budget has never
been measured. The 13.83 GiB figure everything here is projected from comes from
*excluded* evidence at height 645,804, on a run that never made the tip.

**If G14 tip RSS measures well under budget, say below 10 GiB, this
complexity is not earning its keep and reverting is the right call.** The
historical v4 implementation and its comparison harness have since been
retired. The measurements that chose this trade moved to Git history (see
History); they remain evidence for that decision, not a current compatibility
or benchmark contract.

The second thing that would change the answer is outputs per record. The
projection holds it at 3.626, and it has not converged (2.296 at height 183k,
4.056 at 390k). It is the number the result is most sensitive to, because the
32-byte txid amortizes over it directly.

## History

The rest of the prior-evidence essay (the synthetic per-output attribution, the
payload decomposition, the tip projection, the v5 codec A/B measurements, the
lookup crossover tables, the rejected flat-varint draft, the decoder-panic
record, and the superseded pre-measurement sizing) was removed and lives in Git
history at commit `bda50acd4`. Retrieve it with `git show bda50acd4:docs/benchmarks/utxo-memory.md`.
