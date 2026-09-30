# End-to-end synchronization lanes

This document owns the two synchronization lanes of the target node: offline replay (blocks local, wall is validation plus durable commit) and live IBD over loopback peers (wall includes download scheduling under `P2pService`). Both lanes are product cells under [`docs/contracts/hot-path-attribution.md`](../contracts/hot-path-attribution.md): `replay.offline_full_validation` and `replay.live_ibd_loopback`.

## Lanes

| Lane | Boundary | Owner path | Comparator |
|---|---|---|---|
| Offline replay | spawn to durable clean exit over a hash-pinned Core-framed archive | `bounded ingress -> parse once -> contextual preparation -> parallel proof -> ordered durable commit -> coherent publication` | [`offline-full-validation.md`](offline-full-validation.md) |
| Live IBD, loopback | start to pinned stop over deterministic loopback peers, no public nodes | `P2pService` download window plus the same commit spine | [`p2p-loopback.md`](p2p-loopback.md) |

Both lanes run under full validation (`--assume-valid-height 0`), strict-Rust cryptography, default unpruned fjall, optional indexes off, on the final artifact. Every run records the six sample identities and the pinned stop identity. Restart and reorg recovery to each intermediate committed ancestor is exercised in the same lanes (T12, T13).

## End-state cells

| Cell | Metric | Status |
|---|---|---|
| Offline replay, C150 and Cmodern, bitcoin-rs versus Core `v31.1` | p50/p95/p99/max wall, CPU, peak RSS, per-owner storage bytes; ratio only after gates | `planned_not_executed` |
| Offline replay, full mainnet to pinned stop | same, plus certified end state and physical high-water | `planned_not_executed` |
| Live IBD loopback, bounded range, one peer and multi-peer | wall, blocks/s, peak RSS, requeue exactness on disconnect | `planned_not_executed` |
| Restart at intermediate committed ancestor | recovered tip and coins equal; fence reopened only after reconciliation | `planned_not_executed` |
| Stage histograms (`node.apply_block.*`) | inclusive per-stage histograms reported beside the wall, never summed | `planned_not_executed` |

Targets are contracts, not measurements: no regression against the T02 baseline on any applicable cell (cost, latency, RSS, bytes not greater; throughput not less), and promotion of any optimization only by the acceptance rule below.

## Required identities per sample

See [`measurement-rules.md`](measurement-rules.md). A sample missing any of the six identities is not evidence.

## Acceptance rule

See [`measurement-rules.md`](measurement-rules.md).

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement.
