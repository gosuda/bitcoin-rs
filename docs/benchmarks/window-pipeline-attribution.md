# Window pipeline and group commit attribution

Owns the measurement protocol, the evidence schema, and the promotion gates for the windowed block apply and its durable group commit (ENG-91, #1607). Product-domain measured seconds never live here (`HPA-08`, `HPA-12`). This page records the diagnostic run summaries and the keep-or-revert decision for one window-apply mechanism (`HPA-09`). Status: `measured_rejected`. The candidate arm ran, failed the gate, and was reverted. Its regression tests stayed. Shared cell rules are in [README.md](README.md). The attribution method is in [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md).

| Item | State |
|---|---|
| Baseline pipeline | `apply_window_admitted` (`crates/chainstate/src/window.rs`): `prove_window` proves the whole window, then the per-block loop stages blocks into a `WindowGroup` and flushes at 64 blocks or 8 MiB (`RCV-02`), all under one chain transition |
| Candidate | Per-block prepare/verify overlap inside the same transition: block N+1 prepares while block N verifies. One scoped verifier thread, one-slot handoff channel. Commits stay in order and unchanged. Measured, rejected, reverted. |
| Diagnostic spans | `transition_held_us` and `flush_wait_us` (table below) |
| Existing series | `node.sync.apply_idle_seconds` and `node.sync.download_blocked_by_apply_seconds` in `crates/p2p/src/download_window.rs` |
| Replay harness | `crates/node/benches/sync_pipeline.rs --window-attribution` (command below) |
| Decision | REJECT the candidate. S-B (out-of-transition pipelines) and S-C (verify-only lock release) stay REJECTED: tip identity alone cannot fence `replace_from`, header-gate changes, reorg, and script-cache takes. |

| Span | Acquire or start | Release or end | Emitted |
|---|---|---|---|
| `transition_held_us` | `begin_chain_transition` lock return (`crates/chainstate/src/lib.rs`) | `TransitionGuard::drop`, or the admission refusal before a guard exists | every path: success, fatal unwind, refusal |
| `flush_wait_us` | `flush_group` entry with a non-empty staged prefix (`crates/chainstate/src/window.rs`) | `group.flush` return | `window: group flush` with blocks; `window: group flush failed` with `flush_error` |

Spans use `quanta::Instant` plus `tracing::debug!`; they create no metric family, change no lock scope, and never feed a decision. `flush_wait_us` is nested inside `transition_held_us`; the two are reported side by side and never added (`HPA-12`). `window: group flush` is a development diagnostic beside `durable_head: group commit`.
```bash
cargo bench -p bitcoin-rs-node --bench sync_pipeline -- --window-attribution <control|candidate> <single_group|multi_group>
```
Run from the repository root so `rust-toolchain.toml` selects the toolchain; `TMPDIR` MUST name a disk-backed filesystem (`tmpfs` and `ramfs` are refused, since a group flush there is not a durable write). `BRS_BENCH_EVIDENCE_DIR` MAY override the record directory (`target/benchmarks` by default). One invocation takes exactly one arm and one scenario; pin cores with `taskset -c <set>`; one run executes every unit of one arm and one scenario in one process, 5 warmup units excluded from every summary and the ledger, then 100 measured units. The harness registers one synthetic peer per lease and publishes its `PeerInfo` with `NETWORK | WITNESS` services and a best height of 4,096, so the sync frontier sees a usable peer. Blocks are coinbase-only regtest blocks from `deterministic_initial_sync_proxy_production_state_128_blocks` (production `NodeState`, compiled backend, one synthetic peer, 4,096-header chain); only the 64-block bound is exercised, the 8 MiB bound is not reached. Every unit rebuilds fresh durable state outside all timers, then replays four ticks (request, stage, apply as `apply_wall_ns`, settle). The harness panics and records nothing on short apply, wrong flush count or coverage, failed flush, missing `transition_held_us`, or non-disk `TMPDIR`. Peak RSS comes from `/proc/self/status` `VmHWM`. Resetting that counter needs `CAP_SYS_RESOURCE`; without it the harness warns once per unit and `rss_peak_bytes` covers the whole process, not one unit. Every record states which quantity it measured in `rss_reset`.

| Scenario | Body blocks | Group flushes | Shape |
|---|---|---:|---|
| `single_group` | 64 | 1 | largest window that flushes once |
| `multi_group` | 128 | 2 | a mid-window flush separates two full groups |

| Gate (`HPA-13`, over retained measured units) | Rule |
|---|---|
| Run and arm statistic | run statistic is the median of `wall_ns` over its 100 units; arm statistic is the median of the three run statistics; each run lies within 5% of its arm |
| Target | in `multi_group`, control divided by candidate is at least 1.05, AND the improvement exceeds the control range (`max` minus `min`); replay blocks are coinbase-only with no scripts for the candidate to overlap, so a pass attributes hold and flush wait and can refuse the candidate but does NOT adopt it |
| Non-target | for `single_group` wall, CPU, and peak RSS in both scenarios: candidate median at most 3% above control, pooled p99 at most 5% above; report p50, p95, p99, max plus spans and series; a p99 over fewer than 100 samples is flagged, not read |

Conclusion: no measured cell exists. Replay results are diagnostic and fill no ledger cell (`HPA-09`, `HPA-12`); a product-cell claim needs seven valid hashed interleaved Core 31.1 and bitcoin-rs pairs (`HPA-02`), the observed noise floor (`HPA-03`), and the overlap-aware account (`HPA-04`), run by `tools/benchmark-campaign/` on the campaign corpora of [`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md). First runs create `target/benchmarks/window_attribution.toml` (`bitcoin-rs-hot-path-ledger-v2`) and `window_attribution/<arm>.<scenario>.<unix_ns>.json` (`bitcoin-rs-window-attribution-v1`, corpus `sync_pipeline.window_replay.<scenario>`, six README identities; arms MUST differ in `binary_sha256` and agree in every other identity).

## Measured decision: per-block prepare/verify overlap

The candidate moves the per-block script-check preparation and verification into one pipeline. A scoped verifier thread owns one prepared unit at a time and returns each unit verdict on a channel. The producer stays on the calling thread, because the window overlay and the script-cache takes are ordered. At most two prepared units are alive. Commits, flushes, publication, and every failure path are unchanged.

### Protocol of this run

Six control runs preceded the paired rounds, three per scenario. The paired comparison then ran three alternating rounds per scenario: control, then candidate. Both arms used one bench binary each, differing only in `window.rs`. `SHA-256` of the control binary was `551912636377aca9d55cbd9f28e3cb5d28ad52e61fd1d64d2817e71e65bf8ff9`; of the candidate binary, `1cba0a4f5f4f5bb8d61ec6ae38dddd4982c10c513c15b531ddb42d77fbd916fb`. All runs used `taskset -c 8-23` on one 80-vCPU host with other builds in flight, so wall time drifted between rounds. Each round is therefore read as a pair, never across rounds. CPU time is process CPU in 10 ms ticks. Peak RSS is process-wide, because the reset needs `CAP_SYS_RESOURCE`; `rss_reset` is `false` in every record of this run.

### Result

Wall time, median of the 100 unit medians, in milliseconds. Ratio is candidate divided by control.

| Scenario | Round | Control | Candidate | Ratio | Control p95 | Candidate p95 |
|---|---:|---:|---:|---:|---:|---:|
| `single_group` | 1 | 14.842 | 34.778 | 2.343 | 30.321 | 49.917 |
| `single_group` | 2 | 32.557 | 35.574 | 1.093 | 47.878 | 48.251 |
| `single_group` | 3 | 35.044 | 36.627 | 1.045 | 56.863 | 48.898 |
| `multi_group` | 1 | 49.699 | 69.028 | 1.389 | 65.882 | 111.050 |
| `multi_group` | 2 | 60.087 | 67.403 | 1.122 | 83.617 | 106.025 |
| `multi_group` | 3 | 61.225 | 67.480 | 1.102 | 97.481 | 114.012 |

Arm medians: `single_group` control 32.557 ms, candidate 35.574 ms; `multi_group` control 60.087 ms, candidate 67.480 ms. The candidate is slower in all six paired rounds. Its p95 is higher in every `multi_group` round.

| Scenario | Arm | Apply p50 | Transition held p50 | Transition held p95 | Flush wait p50 | Flush wait p95 | CPU total per run | Peak RSS |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `single_group` | control | 11.733 / 25.073 / 28.470 ms | 11.469 / 24.781 / 27.232 ms | 23.102 / 35.225 / 45.617 ms | 3.864 / 9.528 / 9.771 ms | 9.206 / 14.166 / 17.626 ms | 1.38 / 1.46 / 1.40 s | 10.62 / 10.10 / 10.39 MiB |
| `single_group` | candidate | 28.092 / 28.523 / 29.434 ms | 27.825 / 28.181 / 29.160 ms | 44.307 / 40.487 / 40.618 ms | 8.912 / 9.223 / 9.443 ms | 12.738 / 12.427 / 12.834 ms | 1.47 / 1.42 / 1.40 s | 10.30 / 10.56 / 10.57 MiB |
| `multi_group` | control | 39.641 / 47.654 / 51.235 ms | 39.330 / 46.564 / 50.458 ms | 55.748 / 72.116 / 80.166 ms | 8.642 / 9.476 / 9.777 ms | 12.605 / 14.344 / 15.804 ms | 2.51 / 2.66 / 2.58 s | 10.13 / 10.19 / 10.33 MiB |
| `multi_group` | candidate | 58.571 / 57.144 / 57.947 ms | 58.207 / 55.511 / 56.204 ms | 91.518 / 83.149 / 94.662 ms | 9.540 / 9.460 / 9.435 ms | 15.276 / 15.018 / 14.830 ms | 2.97 / 2.89 / 2.82 s | 10.62 / 10.34 / 10.49 MiB |

Each cell lists rounds 1 / 2 / 3. The candidate holds the transition longer, because it adds one thread handoff per block and one verifier wakeup per verdict. Candidate peak RSS stays within 0.5 MiB of control in both scenarios, inside the 10% guard. CPU total rises by up to 0.39 s per run in `multi_group`; the 10 ms tick resolution cannot resolve `single_group`.

### Decision

REJECT. The target gate needs control divided by candidate to reach 1.05, with the improvement larger than the control range. Control divided by candidate is between 0.43 and 0.96 over the six paired rounds, because candidate divided by control is between 1.045 and 2.343. The non-target gate fails too: the candidate raises the median wall time by 9.3% in `single_group` and 12.3% in `multi_group`, beyond the 3% limit, and raises p95 by more than 5% in `multi_group`. `window.rs` went back to its baseline, and the six regression tests stayed.

### Why it lost on this corpus

- The replay corpus holds coinbase-only blocks. A coinbase has no input script checks, so the verifier has nothing to run while the producer prepares the next block. The overlap has no work to hide.
- The pipeline costs two thread wakeups per block: the producer hands off a unit, and the verifier returns a verdict. The baseline verifies the whole window in one call with no handoff.
- Per-block verification also splits the batch. The baseline verifies all window checks in one parallel pass, so a window with fewer than 32 checks per block still saturates the verify pool; the candidate verifies each block separately and falls below the pool threshold.
- The corpus cannot measure the script-heavy case this mechanism targets. A future candidate needs a script-heavy replay corpus, a verification batch of several blocks, and a handoff that does not wake the producer per block. Until then, the mechanism stays unadopted.
