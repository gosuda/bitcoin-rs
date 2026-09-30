# UTXO set memory and coin-record cells

This document owns the UTXO set memory and coin-record cells of the target node. Coin records stay transaction-grouped (v5 directory layout) with full 256-bit txid identity and `u16` script-length bound (`UtxoError::ScriptTooLarge`); T10 persists only grouped changed records incrementally with exact before-images through the storage batch ladder, and T38 measures cache, allocation and I/O treatments one at a time.

## Cells it owns

| Cell | Metric | Status |
|---|---|---|
| `utxo.record.bytes_per_output` | payload bytes per live output and RSS bytes per output on a real pinned chainstate, v5 layout, production allocator | `planned_not_executed` |
| `utxo.commit.p95` | grouped-record commit p50/p95/p99/max on existing, uniform and concentrated fixtures through `write_durable_if` | `planned_not_executed` |
| `utxo.cache.eviction_reload` | bounded-cache eviction reloads identical records; retained bytes stay at or below the resolved cache budget | `planned_not_executed` |
| `utxo.fragmentation` | RSS growth after churn equal to twice the live set on the production allocator (mimalloc, x86-64 Linux) and on each additional measured configuration | `planned_not_executed` |
| `node.tip_rss` | full-node RSS at the pinned stop identity including fjall, block record log and runtime; T02 baseline versus final | `planned_not_executed` |

Accelerators (truncated prefixes) remain hints, never identity. No heap object per coin. No second database. An arena or pool proposal reopens only with attribution on its own production allocator and domain workload.

## Required identities per sample

See [`measurement-rules.md`](measurement-rules.md). A sample missing any of the six identities is not evidence.

## Acceptance rule

See [`measurement-rules.md`](measurement-rules.md).

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement.
