# Index rollback-versus-rebuild cutover

Owns the rollback-versus-rebuild cutover for optional index capabilities. The runtime now lives in `crates/index/src/runtime.rs`, with rollback in `crates/index/src/runtime/rollback.rs` (T29); the node keeps only wiring. The current default `100_000` is a remeasurement baseline on the target storage and data distribution, not a settled end-state value.

Cell: per-block forward ingest cost (`t_fw`) versus per-block rollback commit cost (`t_rb`) for each capability (`TxLookup`, `ScriptLive`, `ScriptHistory`) on the target index schema (T30) and default fjall backend, with the derived cutover `clamp(100_000 * t_fw / t_rb, 1_000, 100_000)`. Target rule: reorg handling finds the common ancestor by hash; at or below the cutover it reverses per-block contributions with exact inverses, restoring prior values; beyond it, or when a contribution record is missing, it resets and rebuilds only the affected capability. An optional index commit failure NEVER blocks ordinary chain progress. A capability in `RollingBack` or `Rebuilding` reports unavailable, never empty history.

```bash
cargo test --locked -p bitcoin-rs-index --no-default-features --features fjall --lib runtime::recovery_tests -- --nocapture
```

Routing regression (`crates/index/src/runtime/recovery_tests.rs`, small fork fixtures; strict `>`, so `depth == cutover` rewinds; `cutover = 0` rebuilds everything, `u32::MAX` restores rewind-at-any-depth): depth at or below the cutover rewinds, above it rebuilds. Any value in `[1_000, 100_000]` routes the #208 834k-block stale branch to a rebuild while organic reorgs around 100 blocks or fewer rewind; the measured ratio picks the value. Sample identities: the six of [`README.md`](README.md) via the T02 collector. Acceptance: the promotion, regression, reporting, retention, and `BLOCKED` rules of [`README.md`](README.md). Status: end-state cells `planned_not_executed`; the measurement below is prior candidate evidence (512-block fjall fixture, harness removed in a5e9858b), not end-state proof.

| Run | t_fw (ns) | t_rb (ns) | derived |
|---|---|---:|---:|
| 1 | 1,802,566 | 1,886,277 | 95,562 |
| 2 | 562,004 | 590,221 | 95,219 |
| 3 | 552,931 | 608,231 | 90,908 |

Medians: t_fw 562,004 ns, t_rb 608,231 ns, derived 95,219; spread (max minus min) 4,654, which is 4.89% of the median, stable. One post-revision verification run with per-rollback fence recapture measured t_fw 461,187 ns and t_rb 477,798 ns, deriving 96,523. The derivation is `cutover = clamp(100_000 x 562_004 / 608_231, 1_000, 100_000) = 95_219`, which rounds to `100_000` at one significant figure.

Conclusion: the default is `100_000` (grounds `txindex::DEFAULT_ROLLBACK_REBUILD_CUTOVER` in `crates/index/src/runtime.rs`); the #208 834k-gap shape rebuilds and reorgs around 100 blocks or fewer rewind; the per-block ratio does not prove rebuild always scales better, since total cost depends on tip height versus rollback depth.
