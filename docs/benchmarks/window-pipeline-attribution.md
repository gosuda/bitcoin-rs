# Window pipeline and group commit attribution (ENG-91, #1607)

Anchors: John Carmack, Richard Feynman

This page owns the measurement protocol, the evidence schema and the promotion
gates for the windowed block apply and its durable group commit (ENG-91, issue
#1607). It records no measured value: every number lives in the files a run
generates, never here (`HPA-08`, `HPA-12`).

Status: `planned_not_executed`. No arm has run under this protocol, so no
cell, ratio or percentile is on this page. Rules shared by all cells are in
[README.md](README.md); the attribution method is
[`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md).

## 1. What exists and what does not

| Item | State |
|---|---|
| Baseline pipeline | `apply_window_admitted` in `crates/chainstate/src/window.rs`: `prove_window` proves the whole window, then the sequential per-block loop stages blocks into a `WindowGroup` and flushes at 64 blocks or 8 MiB, all under one chain transition. |
| Candidate S-A | Not implemented. The tree has no `prove_chunk` and no scoped worker thread. Nothing here adopts it. |
| Diagnostic spans | `transition_held_us` and `flush_wait_us` exist (section 2). |
| Existing series | `node.sync.apply_idle_seconds` and `node.sync.download_blocked_by_apply_seconds` exist in `crates/p2p/src/download_window.rs`. |
| Replay harness | `crates/node/benches/sync_pipeline.rs`, `--window-attribution` (section 3). |
| Candidate arm | Defined so it can run once S-A exists. Until then only the control arm is measurable, and no control-against-candidate comparison may be written. |

Out-of-transition pipelines (S-B) and verify-only lock release (S-C) stay
rejected: tip identity alone cannot fence `replace_from`, header-gate changes,
reorg and script-cache takes.

## 2. Diagnostic spans

Both spans use `quanta::Instant` and `tracing::debug!`. They create no metric
family, change no lock scope and never feed a decision.

| Span | Acquire or start | Release or end | Emitted |
|---|---|---|---|
| `transition_held_us` | `begin_chain_transition` in `crates/chainstate/src/lib.rs`, the instant `chain_transition.lock()` returns | `TransitionGuard::drop`, or the admission refusal that returns before a guard exists | Every path: success, fatal unwind, refusal |
| `flush_wait_us` | `flush_group` in `crates/chainstate/src/window.rs`, entering `group.flush` with a non-empty staged prefix | `group.flush` returns: staged-tip hook, body sync, head commit, journal, tip publication | Success event `window: group flush` with `blocks`; failure event `window: group flush failed` with `flush_error` |

`flush_wait_us` is nested inside `transition_held_us`, and `window: group
flush` is a development diagnostic beside `durable_head: group commit`, whose
`sync_us` and `commit_us` are sub-intervals of the same wait. The spans are
reported side by side and never added (`HPA-12`).

## 3. Replay harness

### 3.1 Invocation

Run from the repository root so `rust-toolchain.toml` selects the toolchain
that built the binary. `TMPDIR` must name a directory on a disk-backed
filesystem, because the harness refuses `tmpfs` and `ramfs`: a group flush
there is not a durable write.

```bash
cargo bench -p bitcoin-rs-node --bench sync_pipeline -- \
  --window-attribution <control|candidate> <single_group|multi_group>
```

The flag takes exactly one arm and one scenario. Cargo appends `--bench`, which
the parser ignores. Pin the cores with `taskset -c <set>` before `cargo bench`.
One invocation is one run: it executes every unit of one arm and one scenario in
one process.

### 3.2 Scenarios and units

| Scenario | Body blocks | Group flushes | Shape |
|---|---|---|---|
| `single_group` | 64 | 1 | The largest window that flushes once. |
| `multi_group` | 128 | 2 | A mid-window flush separates two full groups. |

The blocks are the coinbase-only regtest blocks of the existing
`deterministic_initial_sync_proxy_production_state_128_blocks` arm: production
`NodeState`, the compiled storage backend, one synthetic peer and a
4,096-header chain. Only the body count differs between scenarios. The 8 MiB
byte bound of a group is not reached by these blocks; only the 64-block bound is
exercised.

Every unit builds fresh durable state outside all timers, then replays four
production ticks. One run is 5 warmup units, kept raw and excluded from every
summary and from the ledger, followed by 100 measured units.

| Tick | Work |
|---|---|
| 1 | Request: the sync issues the first getdata. |
| 2 | Stage: every block except the head arrives out of order. |
| 3 | Apply: the head arrives and the window applies. This tick is `apply_wall_ns`. |
| 4 | Settle: closes the window's measurement-only intervals, which record only when they close. |

### 3.3 Captured per unit

| Field | Source |
|---|---|
| `wall_ns` | Ticks 1 to 4. This is the target wall of the replay. |
| `apply_wall_ns`, `settle_wall_ns` | Tick 3 and tick 4 alone. |
| `cpu_ns`, `cpu_ticks` | `/proc/self/stat` user plus system, every thread including exited ones. Resolution is one tick of 10 ms, so read `cpu_total_ns` beside the per-unit values. |
| `rss_start_bytes`, `rss_peak_bytes` | `VmRSS` before the unit, and `VmHWM` after resetting the peak through `/proc/self/clear_refs`. The harness checks the reset took effect. |
| `transition_held_us` | Every `transition_held_us` event in the unit. The summary uses the longest, which is the window commit; other holds stay in the raw record. |
| `flush_wait_us`, `flush_blocks` | One event per group flush, with the blocks it covered. |
| `apply_idle_ns`, `download_blocked_by_apply_ns` | Observations of the two existing histograms, through a recorder scoped to the replay. An empty list means unobserved, never zero. |

The harness stops with a panic, and records nothing, when a unit applies fewer
blocks than the scenario names, issues a flush count other than one per started
group, covers fewer blocks than the window, hits a failed flush, lacks a
`transition_held_us` event, runs a build with debug assertions, or finds a
non-disk `TMPDIR`.

### 3.4 Evidence artifacts

| Artifact | Path under `target/benchmarks/` of the tree that built the binary | Content |
|---|---|---|
| Ledger | `window_attribution.toml` | Append-only `bitcoin-rs-hot-path-ledger-v2` cells `window_attribution.<scenario>.<arm>`. Every measured unit adds identity-bearing samples at paths `apply.window.replay_wall` (with CPU and peak RSS), `apply.window.apply_tick`, `apply.window.transition_held`, `apply.window.flush_wait`, `p2p.window.apply_idle` and `p2p.window.download_blocked_by_apply`. Spans carry run-clock intervals, so the ledger refuses to add nested ones. |
| Record | `window_attribution/<arm>.<scenario>.<unix_ns>.json` | Schema `bitcoin-rs-window-attribution-v1`: the identities, every raw unit including warmups, and a summary of p50, p95, p99 and max with the sample count and whether p99 is supported (at least 100 samples, `HPA-13`). |

Repeated runs append and are never collapsed. A run that panics writes neither
file.

### 3.5 Six identities

Each sample carries the six identities of [README.md](README.md).

| Identity | Where recorded |
|---|---|
| Artifact | `identity.binary_sha256` and `identity.version` |
| Configuration | `identity.config_sha256`, `identity.backend`, and `toolchain.features`, `toolchain.allocator`, `toolchain.validation_engine` |
| Corpus | `identity.corpus`: id `sync_pipeline.window_replay.<scenario>` and the SHA-256 of the replayed block bytes. The corpus is synthetic regtest, not `C150` or `Cmodern`. |
| Durability | `identity.durability` and `host.storage` (filesystem type and device holding the state) |
| Toolchain | `toolchain.rustc` (`rustc -vV`), `toolchain.profile` and `toolchain.debug_assertions` |
| Hardware | `identity.hardware` plus `host.kernel`, `host.cpus_allowed_list`, `host.mem_total_kib` |

The two arms must differ in `binary_sha256` and agree in every other identity.
A pair that shares a binary digest is not a comparison.

## 4. Experiment design

The control arm is the tree with the timing spans and the sequential pipeline.
The candidate arm is that tree plus S-A, and its binary must carry the spans too,
because the harness refuses a build without `transition_held_us`. The arm label
names custody only; the artifact digest proves the programs differ.

Run each scenario alternately, control then candidate, three times
(`A-B-A-B-A-B`). With no candidate in the tree, run the control arm three times
per scenario: the runs set the stability and the host noise floor, and no
comparison is produced.

## 5. Gates for the replay (`HPA-13`)

All statistics come from the measured units of the retained records.

| Gate | Rule |
|---|---|
| Run statistic | The median of `wall_ns` over one run's 100 units. |
| Arm statistic | The median of the arm's three run statistics. |
| Stability | Each run statistic lies within 5% of its arm statistic. |
| Target | In `multi_group`, control arm statistic divided by candidate arm statistic is at least 1.05. |
| Noise | The improvement exceeds the control arm's observed range, `max - min` of its run statistics. A 5% magnitude alone is not enough. |
| Non-target | For `single_group` wall, and for CPU and peak RSS in both scenarios, the candidate's median is at most 3% above control and its pooled p99 at most 5% above. |
| Reporting | p50, p95, p99 and max of wall, CPU and RSS, plus both spans and both series, with sample counts. A p99 over fewer than 100 samples is flagged and not read. |

The stated target needs a workload that carries script checks. The replayed
blocks are coinbase-only, so they hold no scripts for S-A to overlap with a
neighbour's commit: this replay can attribute the transition hold and the flush
wait and can refuse S-A, but a pass here does not adopt it. Adoption also needs
the product cells:

- Replay results are diagnostic and fill no ledger cell (`HPA-09`, `HPA-12`).
- A product-cell claim needs seven valid hashed interleaved Core 31.1 and
  bitcoin-rs pairs (`HPA-02`), the observed noise floor (`HPA-03`) and the
  overlap-aware account (`HPA-04`), run by `tools/benchmark-campaign/` on the
  campaign corpora of
  [`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md).
- If the gates fail, the sequential `prove_window` and grouped commit stay and
  the rejection is recorded; no queue or epoch is added.

## 6. Ledger

No measured cell exists. The first runs create the files of section 3.4; this
page then keeps only the protocol and links to the retained records.
