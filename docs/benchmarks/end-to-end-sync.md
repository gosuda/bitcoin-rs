# End-to-end synchronization lanes

This document owns the two synchronization lanes of the target node. Offline replay keeps blocks local, where wall is validation plus durable commit. Live IBD runs over loopback peers, where wall includes download scheduling under `P2pService`. Both lanes are product cells under [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md): `replay.offline_full_validation` and `replay.live_ibd_loopback`.

## Lanes

| Lane | Boundary | Owner path | Comparator |
|---|---|---|---|
| Offline replay | spawn to durable clean exit over a hash-pinned Core-framed archive (harness also proves dual packed/indexed parity, still `planned_not_executed` live) | `bounded ingress -> parse once -> contextual preparation -> parallel proof -> ordered durable commit -> coherent publication` | [`offline-full-validation.md`](offline-full-validation.md) |
| Live IBD, loopback | start to pinned stop over deterministic loopback peers, no public nodes | `P2pService` download window plus the same commit spine | [`p2p-loopback.md`](p2p-loopback.md) |

Both lanes run under full validation (`--assume-valid-height 0`), strict-Rust cryptography, default unpruned fjall, optional indexes off, on the final artifact. Every run records the six sample identities and the pinned stop identity. Restart and reorg recovery to each intermediate committed ancestor is exercised in the same lanes (T12, T13).

## End-state cells

| Cell | Metric | Status |
|---|---|---|
| Offline replay, C150, bitcoin-rs versus Core `v31.1` | p50/p95/p99/max wall, CPU, peak RSS, per-owner storage bytes; ratio only after gates | `planned_not_executed` |
| Offline replay, Cmodern, bitcoin-rs versus Core `v31.1` | same | `BLOCKED`: Cmodern corpus missing; the archive and manifest were retired from `.outline/reference-corpus` and `acquire-modern` is empty (recorded identity: manifest file sha256 `b694c91880ac15edbb3e8dbb8a62bf8c0a0c1c64ef7dbec2e3f79eadf918db7d`, logical `manifest_sha256` `b87bac6720d1b68acadaa9863b56073ee213f4613e8dfa4a93c4459dc5f017cd`) |
| Offline replay, full mainnet to pinned stop | same, plus certified end state and physical high-water | `planned_not_executed` |
| Live IBD loopback, bounded range, one peer and multi-peer | wall, blocks/s, peak RSS, requeue exactness on disconnect | `planned_not_executed` |
| Restart at intermediate committed ancestor | recovered tip and coins equal; fence reopened only after reconciliation | `planned_not_executed` |
| Stage histograms (`node.apply_block.*`) | inclusive per-stage histograms reported beside the wall, never summed | `planned_not_executed` |

The targets are contracts, not measurements. No applicable cell may regress against the recorded baseline: cost, latency, RSS and bytes must not increase, and throughput must not decrease. Any optimization is promoted only by the acceptance rule below.

## Required identities per sample

The six identities of [`README.md`](README.md), enforced by the evidence collector.

## Acceptance rule

The promotion, regression, reporting, retention and `BLOCKED` rules of [`README.md`](README.md).


## Status

`planned_not_executed`, as defined in [`README.md`](README.md).

## Historical C150 comparator ratio

A disk-bounded campaign at commit
`de8001e83bd4e09077d4cebbbdd23d0cebade194` used the exact mainnet range
0–150,000. Both implementations used full validation, the same stop hash, and
CPU set 0–31. The row is observed once, not evidence, and is kept for context
only.

| Workload | bitcoin-rs observed | Bitcoin Core 31.1 observed | Core / bitcoin-rs | Result |
|---|---:|---:|---:|---|
| Full-validation local replay / chainstate reindex | 39.251s | 64.922s | 1.654× | Observed once, not evidence |

## History

The historical evidence that filled this page (machine-readable run tables,
same-range observations, the live-network index, excluded runs, the G14 budget
table, the bounded daemon IBD comparison, retired artifact digests, the stage
timers, and the harness note) was removed and lives in Git history at commit
`bda50acd4`. Retrieve it with `git show bda50acd4:docs/benchmarks/end-to-end-sync.md`.
The raw JSON behind those runs was retired by #224, and the stage-timer metric
names predate #1195.
