# Window pipeline and group commit attribution (ENG-91, #1607)

Owns the measurement protocol, the evidence schema, and the promotion gates for the windowed block apply and its durable group commit (ENG-91, #1607). Records no measured value: every number lives in the files a run generates, never here (`HPA-08`, `HPA-12`). Status: `planned_not_executed`. No arm has run, so no cell, ratio, or percentile is on this page. Shared cell rules are in [README.md](README.md); the attribution method is in [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md).

| Item | State |
|---|---|
| Baseline pipeline | `apply_window_admitted` (`crates/chainstate/src/window.rs`): `prove_window` proves the whole window, then the sequential per-block loop stages blocks into a `WindowGroup` and flushes at 64 blocks or 8 MiB, all under one chain transition |
| Candidate S-A | NOT implemented: the tree has no `prove_chunk` and no scoped worker thread; nothing here adopts it |
| Diagnostic spans | `transition_held_us` and `flush_wait_us` (table below) |
| Existing series | `node.sync.apply_idle_seconds` and `node.sync.download_blocked_by_apply_seconds` in `crates/p2p/src/download_window.rs` |
| Replay harness | `crates/node/benches/sync_pipeline.rs --window-attribution` (command below) |
| Candidate arm | defined so it can run once S-A exists; until then control-only, and no control-against-candidate comparison may be written. S-B (out-of-transition pipelines) and S-C (verify-only lock release) stay REJECTED: tip identity alone cannot fence `replace_from`, header-gate changes, reorg, and script-cache takes. |

| Span | Acquire or start | Release or end | Emitted |
|---|---|---|---|
| `transition_held_us` | `begin_chain_transition` lock return (`crates/chainstate/src/lib.rs`) | `TransitionGuard::drop`, or the admission refusal before a guard exists | every path: success, fatal unwind, refusal |
| `flush_wait_us` | `flush_group` entry with a non-empty staged prefix (`crates/chainstate/src/window.rs`) | `group.flush` return | `window: group flush` with blocks; `window: group flush failed` with `flush_error` |

Spans use `quanta::Instant` plus `tracing::debug!`; they create no metric family, change no lock scope, and never feed a decision. `flush_wait_us` is nested inside `transition_held_us`; the two are reported side by side and never added (`HPA-12`). `window: group flush` is a development diagnostic beside `durable_head: group commit`.
```bash
cargo bench -p bitcoin-rs-node --bench sync_pipeline -- --window-attribution <control|candidate> <single_group|multi_group>
```
Run from the repository root so `rust-toolchain.toml` selects the toolchain; `TMPDIR` MUST name a disk-backed filesystem (`tmpfs` and `ramfs` are refused, since a group flush there is not a durable write). One invocation takes exactly one arm and one scenario; pin cores with `taskset -c <set>`; one run executes every unit of one arm and one scenario in one process, 5 warmup units excluded from every summary and the ledger, then 100 measured units. Blocks are coinbase-only regtest blocks from `deterministic_initial_sync_proxy_production_state_128_blocks` (production `NodeState`, compiled backend, one synthetic peer, 4,096-header chain); only the 64-block bound is exercised, the 8 MiB bound is not reached. Every unit rebuilds fresh durable state outside all timers, then replays four ticks (request, stage, apply as `apply_wall_ns`, settle). The harness panics and records nothing on short apply, wrong flush count or coverage, failed flush, missing `transition_held_us`, or non-disk `TMPDIR`.

| Scenario | Body blocks | Group flushes | Shape |
|---|---|---:|---|
| `single_group` | 64 | 1 | largest window that flushes once |
| `multi_group` | 128 | 2 | a mid-window flush separates two full groups |

| Gate (`HPA-13`, over retained measured units) | Rule |
|---|---|
| Run and arm statistic | run statistic is the median of `wall_ns` over its 100 units; arm statistic is the median of the three run statistics; each run lies within 5% of its arm |
| Target | in `multi_group`, control divided by candidate is at least 1.05, AND the improvement exceeds the control range (`max` minus `min`); replay blocks are coinbase-only with no scripts for S-A to overlap, so a pass attributes hold and flush wait and can refuse S-A but does NOT adopt it |
| Non-target | for `single_group` wall, CPU, and peak RSS in both scenarios: candidate median at most 3% above control, pooled p99 at most 5% above; report p50, p95, p99, max plus spans and series; a p99 over fewer than 100 samples is flagged, not read |
Conclusion: no measured cell exists. Replay results are diagnostic and fill no ledger cell (`HPA-09`, `HPA-12`); a product-cell claim needs seven valid hashed interleaved Core 31.1 and bitcoin-rs pairs (`HPA-02`), the observed noise floor (`HPA-03`), and the overlap-aware account (`HPA-04`), run by `tools/benchmark-campaign/` on the campaign corpora of [`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md). First runs create `target/benchmarks/window_attribution.toml` (`bitcoin-rs-hot-path-ledger-v2`) and `window_attribution/<arm>.<scenario>.<unix_ns>.json` (`bitcoin-rs-window-attribution-v1`, corpus `sync_pipeline.window_replay.<scenario>`, six README identities; arms MUST differ in `binary_sha256` and agree in every other identity).
