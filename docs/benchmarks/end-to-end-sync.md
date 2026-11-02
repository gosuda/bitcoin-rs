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
| Offline replay, C150, bitcoin-rs versus Core `v31.1` | p50/p95/p99/max wall, CPU, peak RSS, per-owner storage bytes; ratio only after gates | `measured 2026-11-02, no acceptance verdict`; see [the first gated campaign](#first-gated-c150-offline-campaign-2026-11-02) |
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

`planned_not_executed` for every end-state cell except the C150 offline
replay row, which measured on 2026-11-02 with no acceptance verdict. The
vocabulary is defined in [`README.md`](README.md).

## First gated C150 offline campaign (2026-11-02)

The offline comparator ran its first live campaign against the staged C150
custody on this head, `0c0975652`. Seven alternating pairs, Core 31.1 first on
even pairs. Every comparator gate passed: arm count, alternation, archive and
binary identity, exit 0 on all 14 arms, full validation, indexes off, and
equal certified state across arms. The result document is
`offline-full-validation-result-v1` with `result_sha256`
`ea355abdab58a7333c252846120e73fefa6dc3cd19987ad28179174c00abf067`. A copy
sits beside `.outline/evidence/evidence-refresh-20261102/records/published/`
with the operator identity bundle `operator-identity-offline-import.json`
(`bundle_sha256` `45c589b34e03b21b4f18e55e86e63d670180f738960e0de07b688014ea37d98e`).

| Arm | wall p50 | wall p95, p99, max | CPU per arm | peak RSS per arm |
|---|---:|---:|---:|---:|
| Core `v31.1` (wrapper arm) | 109.504 s | 117.346 s | not attributed (wrapper process) | not attributed (wrapper process) |
| bitcoin-rs, fjall | 824.676 s | 881.600 s | 4754 to 4915 s | 0.60 to 0.72 GiB |

`candidate_over_core_p50_ratio` is 7.531. Core validates the 150,001-block
archive about 7.5 times faster than bitcoin-rs on this host, full validation
on both sides, no acceptance verdict attached. The candidate and Core arm
walls spread 11.7 and 12.6 percent from minimum to maximum, above the 5
percent stability band of [`README.md`](README.md#acceptance-rule), so this
run is a baseline observation, not a promotion gate. The ledger cell
`offline.c150.x86_64.fjall` carries the seven bitcoin-rs walls as its first
seven samples.

Two reading rules for these numbers. The Core arm runs through a wrapper
script that spawns `bitcoind` and then dumps the certified state, so the
per-arm CPU and peak-RSS fields measure the wrapper process on that arm and
attribute no Core resource cost; the wall still spans spawn to clean exit
with nothing subtracted. The campaign started at 1-minute load 3.48 and the
only sustained load in its two-hour window was the campaign itself, but the
shared host cannot prove an empty window, so read single-arm values with the
spread above. The certified states of both arms agree with the `CORP-05`
oracle on height, best block, txouts, total amount, and MuHash.



## Historical C150 comparator ratio

Removed on 2026-11-02. A disk-bounded campaign at commit
`de8001e83bd4e09077d4cebbbdd23d0cebade194` once recorded a 1.654x
Core-over-bitcoin-rs ratio for the same mainnet range, observed once, not
evidence. The gated campaign above now owns this comparison from this head
and measures the opposite direction. The retired row lives in Git history.

## History

The historical evidence that filled this page (machine-readable run tables,
same-range observations, the live-network index, excluded runs, the G14 budget
table, the bounded daemon IBD comparison, retired artifact digests, the stage
timers, and the harness note) was removed and lives in Git history at commit
`bda50acd4`. Retrieve it with `git show bda50acd4:docs/benchmarks/end-to-end-sync.md`.
The raw JSON behind those runs was retired by #224, and the stage-timer metric
names predate #1195.
