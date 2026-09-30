# Index rollback-versus-rebuild cutover

This document owns the rollback-versus-rebuild cutover for optional index capabilities. In the target node the runtime that applies it moves from `crates/node/src/txindex/rollback.rs` to `crates/index/src/runtime.rs` (T29); the node keeps only wiring. The current default `100_000` is a remeasurement baseline on the target storage and data distribution, not a settled end-state value.

## Cell it owns

Per-block forward ingest cost (`t_fw`) versus per-block rollback commit cost (`t_rb`) for each capability (`TxLookup`, `ScriptLive`, `ScriptHistory`) on the target index schema (T30) and default fjall backend, and the derived cutover `clamp(100_000 * t_fw / t_rb, 1_000, 100_000)`.

## Target rule

Reorg handling finds the common ancestor by hash. Within the cutover depth it reverses per-block contributions with exact inverses, including restored prior values. Beyond it, or when a contribution record is missing, it resets and rebuilds only the affected capability. Optional index commit failure never blocks ordinary chain progress. A capability in `RollingBack` or `Rebuilding` reports unavailable, never empty history.

## End-state cells

| Cell | Owner | Fixture | Status |
|---|---|---|---|
| `t_fw` and `t_rb` per-block medians per capability on target schema, fjall | `crates/index/src/runtime.rs` | bounded fjall fixture with per-commit coherent fence recapture, at least three runs | `planned_not_executed` |
| Derived cutover and spread | same | medians of medians, spread recorded | `planned_not_executed` |
| Routing regression: depth at or below cutover rewinds, above rebuilds; `cutover = 0` rebuilds everything; `u32::MAX` rewinds at any depth | `crates/index/src/runtime/recovery_tests.rs` and retained recovery tests | small fork fixtures | `planned_not_executed` |

The behavioral requirement is unchanged: the #208 incident shape (834k-block stale branch) routes to rebuild while organic reorgs of roughly 100 blocks or fewer rewind. Any value in `[1_000, 100_000]` satisfies it; the measured ratio picks the value.

```bash
cargo test --locked -p bitcoin-rs-index --no-default-features --features fjall --lib runtime::recovery_tests -- --nocapture
```

## Required identities per sample

See [`measurement-rules.md`](measurement-rules.md). A sample missing any of the six identities is not evidence.

## Acceptance rule

See [`measurement-rules.md`](measurement-rules.md).

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement.
