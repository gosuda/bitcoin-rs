# Index rollback-versus-rebuild cutover

This document owns the rollback-versus-rebuild cutover for optional index capabilities. In the target node the runtime that applies it moves from `crates/node/src/txindex_worker.rs` to `crates/index/src/runtime.rs` (T29); the node keeps only wiring. The current default `100_000` is a remeasurement baseline on the target storage and data distribution, not a settled end-state value.

## Cell it owns

Per-block forward ingest cost (`t_fw`) versus per-block rollback commit cost (`t_rb`) for each capability (`TxLookup`, `ScriptLive`, `ScriptHistory`) on the target index schema (T30) and default fjall backend, and the derived cutover `clamp(100_000 * t_fw / t_rb, 1_000, 100_000)`.

## Target rule

Reorg handling finds the common ancestor by hash. Within the cutover depth it reverses per-block contributions with exact inverses, including restored prior values. Beyond it, or when a contribution record is missing, it resets and rebuilds only the affected capability. Optional index commit failure never blocks ordinary chain progress. A capability in `RollingBack` or `Rebuilding` reports unavailable, never empty history.

## End-state cells

| Cell | Owner | Fixture | Status |
|---|---|---|---|
| `t_fw` and `t_rb` per-block medians per capability on target schema, fjall | `crates/index/src/runtime.rs` | bounded fjall fixture with per-commit coherent fence recapture, at least three runs | `planned_not_executed` |
| Derived cutover and spread | same | medians of medians, spread recorded | `planned_not_executed` |
| Routing regression: depth at or below cutover rewinds, above rebuilds; `cutover = 0` rebuilds everything; `u32::MAX` rewinds at any depth | `crates/node/tests/overhaul_index_owner.rs` and retained recovery tests | small fork fixtures | `planned_not_executed` |

The behavioral requirement is unchanged: the #208 incident shape (834k-block stale branch) routes to rebuild while organic reorgs of roughly 100 blocks or fewer rewind. Any value in `[1_000, 100_000]` satisfies it; the measured ratio picks the value.

```bash
cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --test overhaul_index_owner -- --nocapture
```

## Required identities per sample

Every sample in this cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

| Identity | Content |
|---|---|
| Artifact | SHA-256 of the exact binary, library or image measured; source commit |
| Configuration | Resolved `NodeConfig`, feature set, allocator, validation mode |
| Corpus | Corpus digest, height range, stop height and stop hash |
| Durability | Backend, batch mode (`write`, `write_deferred`, `write_durable`), flush and sync posture |
| Toolchain | `rustc 1.95.0`, edition 2024, profile, enabled features |
| Hardware | CPU model, pinned core set, memory, storage device, OS kernel |

## Acceptance rule

- Promotion of a candidate over its control requires a median gain of at least 1.05x over at least three alternating candidate/control runs. Each arm stays within 5% of its own median. The improvement must exceed the observed host noise.
- Non-target cells guard at no more than 3% median regression and no more than 5% p99 regression, measured with repeated runs and reported uncertainty. Average-only reporting never passes.
- Report p50, p95, p99 and max with the sample count. Never sum nested intervals. Never sum concurrent intervals. Parallel worker walls and inclusive stage histograms are reported beside the process wall, not added to it.
- Retain raw samples beside every summary. A Criterion adaptive elapsed total is not a median source.
- A missing binary, corpus, hardware target or digest marks the cell `BLOCKED` with the missing identity named. `BLOCKED` is never a pass and never a skip.

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement. The section `Prior candidate evidence` below is historical and unchanged; it does not prove any end-state cell.

## Prior candidate evidence (512-block fjall fixture, harness removed in a5e9858b)

Retained verbatim from the pre-rewrite document. Headings are demoted one level. Nothing below is end-state proof.

### Knob

`txindex_worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (`crates/node/src/txindex_worker.rs`), default
`100_000`.

Decision rule implemented by the txindex worker (`reconcile_once`): for each
stale-watermark selection, `depth = reconcile::rollback_depth(...)` (watermark
height minus common-ancestor height with the active tip). `depth > cutover`
routes to `writer.reset_capabilities(capabilities)`; otherwise the per-block
`rollback_one` rewind runs. Strict `>`: `depth == cutover` rewinds.

### Derivation model

- Rebuild cost ≈ `tip_height × t_fw` (per-block forward ingest).
- Rewind cost ≈ `depth × t_rb` (per-block rollback commit).
- `cutover = clamp(100_000 × t_fw / t_rb, 1_000, 100_000)`, rounded to one
  significant figure.
- The knob must route the #208 incident shape (834k-block stale branch) to a
  rebuild while organic reorgs (≤ ~100 blocks) keep rewinding, so any value in
  `[1_000, 100_000]` satisfies the behavioral requirement.

### Measured runs (512-block fjall fixture, per-block medians)

The numbers below were produced by an `#[ignore]`d measurement test,
`measure_rollback_vs_rebuild_per_block_medians`, that built a 512-block fjall
fixture and printed the per-block forward and rollback medians plus the
derived clamp value. That test was removed in commit `a5e9858b` (durable
process-epoch fencing); this tree has no in-tree harness that reproduces
the table. The record is kept as the historical grounding for the default.
The benchmark as run captured a fresh coherent fence before every commit, as
required by the ordinary-state revision protocol.

| Run  | t_fw (ns)  | t_rb (ns)  | derived    |
|------|------------|------------|------------|
| 1    | 1,802,566  | 1,886,277  | 95,562     |
| 2    | 562,004    | 590,221    | 95,219     |
| 3    | 552,931    | 608,231    | 90,908     |

- Median of derived values: **95,219**.
- Median t_fw: **562,004 ns**; median t_rb: **608,231 ns**.
- Derived spread (max − min): **4,654** — 4.89 % of the median, stable.

The three-run record above predates the ordinary-state revision. After that
protocol landed, one verification run with per-rollback fence recapture
measured t_fw = 461,187 ns and t_rb = 477,798 ns. It derived 96,523, which
preserves the 100,000-block choice after rounding to one significant figure.

### Derivation of the default

```
cutover = clamp(100_000 × t_fw / t_rb, 1_000, 100_000)
        = clamp(100_000 × 562_004 / 608_231, 1_000, 100_000)
        = 95_219
        → one significant figure = 100_000
```

The default is `100_000`. The recorded measurement showed the derived value
rounds to 100,000. With that default, the #208 834k-gap incident shape
routes to rebuild and ≤ ~100-block organic reorgs continue to rewind. The
routing rule itself (rewind at or below the cutover, rebuild above it) is
exercised on small fork fixtures with explicit cutover values in
`crates/node/src/txindex_worker_recovery_tests.rs`. The per-block ratio does
not prove rebuild always scales better because total costs depend on tip
height versus rollback depth.

Status: measurement COMPLETED (three runs, medians of medians, spread
recorded, 2026); harness since removed.

### Notes

- `cutover = 0` means every resolvable stale watermark rebuilds (used in
  tests); `u32::MAX` restores the pre-cutover rewind-at-any-depth behavior.
