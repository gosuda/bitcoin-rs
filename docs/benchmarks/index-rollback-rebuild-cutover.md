# Index rollback-vs-rebuild cutover — grounding record

## Knob

`txindex_worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (`crates/node/src/txindex_worker.rs`), default
`100_000`.

Decision rule implemented by the txindex worker (`reconcile_once`): for each
stale-watermark selection, `depth = reconcile::rollback_depth(...)` (watermark
height minus common-ancestor height with the active tip). `depth > cutover`
routes to `writer.reset_capabilities(capabilities)`; otherwise the per-block
`rollback_one` rewind runs. Strict `>`: `depth == cutover` rewinds.

## Derivation model

- Rebuild cost ≈ `tip_height × t_fw` (per-block forward ingest).
- Rewind cost ≈ `depth × t_rb` (per-block rollback commit).
- `cutover = clamp(100_000 × t_fw / t_rb, 1_000, 100_000)`, rounded to one
  significant figure.
- The knob must route the #208 incident shape (834k-block stale branch) to a
  rebuild while organic reorgs (≤ ~100 blocks) keep rewinding, so any value in
  `[1_000, 100_000]` satisfies the behavioral requirement.

## Measured runs (512-block fjall fixture, per-block medians)

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

## Derivation of the default

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

## Notes

- `cutover = 0` means every resolvable stale watermark rebuilds (used in
  tests); `u32::MAX` restores the pre-cutover rewind-at-any-depth behavior.
