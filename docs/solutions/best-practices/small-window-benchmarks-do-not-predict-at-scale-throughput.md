---
title: Small-window benchmarks do not predict at-scale throughput — at-scale matched-validation replay disproved the "beats Core" premise
date: 2026-06-10
category: docs/solutions/best-practices
module: performance measurement / benchmark harnesses (IBD replay, criterion benches, workspace-wide)
problem_type: best_practice
component: tooling
severity: high
applies_when:
  - "Claiming or relying on a bitcoin-rs vs Bitcoin Core performance comparison"
  - "Extrapolating throughput from a small or degenerate block window (e.g. blocks 0-1000)"
  - "Building a replay/benchmark harness that drives Core via per-block subprocess calls"
related_components:
  - development_workflow
  - testing_framework
tags:
  - benchmark
  - at-scale-measurement
  - ibd-replay
  - harness-overhead
  - profile-before-optimize
---

# Small-window benchmarks do not predict at-scale throughput

> The `mainnet_prefix_replay` executable used for the measurements below was
> retired after the campaign. The workload-matching lesson remains current;
> the commands are historical provenance, not supported tooling.

## Context

The project's optimization roadmap rested on a measured-looking premise: bitcoin-rs beats
Bitcoin Core in the processing-bound regime (~56 s vs ~157 s over blocks 0–1000, the old G14
head-to-head). On 2026-06-09/10 the first at-scale, matched-validation comparison was run:
mainnet genesis → height 150,000, full script verification on both sides (Core
`-reindex-chainstate -assumevalid=0`; bitcoin-rs `mainnet_prefix_replay` with
`assume_valid_height = 0`), same 128-core machine, local blocks only, serial runs.

Result: **Core 67 s vs bitcoin-rs 389.7 s — Core ~5.8× faster** (≥4.3× under maximal
harness-cost concession). The live-IBD comparison over the same window was worse: Core 628 s,
gocoin ~277 s, bitcoin-rs 5,332 s (single-peer download path saturates once block sizes grow).
Verdict artifacts: `~/bench-g14/results/{cross-node-ibd-150k-verdict.md,processing-bound-150k-verdict.md}`.

**This supersedes the 56 s/157 s figure entirely.** The
[multi-peer doc's](../architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md)
guidance point 8 already rejected it as live-IBD evidence (wrong regime); the at-scale run
shows it is not valid *processing-bound* evidence either — a 1000-block prefix of near-empty
blocks measures startup costs, not apply architecture. That doc's point 2(b) ("make
bitcoin-rs's faster processing the deciding factor") relied on the disproven premise; it has
since been refreshed in place to cite this measurement.

## Guidance

1. **A throughput claim is only as strong as its largest measured window.** Blocks 0–1000
   carry ~2k transactions; blocks 0–150,000 carry 1.72M. Workload composition changes the
   ranking, not just the magnitude — measure at the scale where the architecture differences
   (parallel script-check queues, coin-cache batching) actually engage.
2. **Measure the harness before trusting it.** The replay example's per-block `bitcoin-cli`
   spawns cost a measured 11.3 ms/block — 28 minutes of fake time over a 150k window whose
   true Core-side cost is 67 s. Probe harness overhead with a no-op loop first; if it is not
   ≪ the effect being measured, fix the harness (here: keep-alive REST block source,
   commit `4700c25`) before recording any number.
3. **Match validation posture across nodes or the comparison is fiction.** Core defaults
   (`-assumevalid`) and gocoin defaults (`LastTrustedBlock`) skip historical script checks.
   `bitcoin-rs` mainnet nodes default to assume-valid enabled using the hash-pinned anchor
   at height 938343 (block `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`),
   skipping historical script checks once the active header chain validates the anchor.
   Full script verification requires explicit opt-in (`--assume-valid-height 0` or
   `mainnet_prefix_replay`, which defaults to 0). The rest of the node's shipped tuning is the
   [*Optimized default posture*](../../../CONCEPTS.md#optimized-default-posture); a benchmark
   that does not match it is not measuring the shipped node. For head-to-head benchmarks,
   pin both sides explicitly (`-assumevalid=0` ↔ `--assume-valid-height 0`) and record
   the posture in the artifact.
Single-machine criterion trust (rebuild codegen drift, CLI baseline flags, allocator parity)
is its own note: [criterion-bench-trust-rebuild-drift-baselines-allocator](criterion-bench-trust-rebuild-drift-baselines-allocator.md).

## Why This Matters

A wrong performance premise silently misranks every optimization decision downstream: round-2
shipped real micro-wins (MuHash −33%, apply-cache repopulation) in paths that the at-scale
measurement now shows are not the bottleneck. The measured lever ranking for the
faster-than-Core goal is: (1) apply-path parallelism granularity (Core's input-level
CCheckQueue vs per-block rayon fan-out), (2) coin-cache batching ahead of the KvStore commit,
(3) multi-peer download (live regime). Optimization effort spent below that ranking is
entropy.

## When to Apply

- Before citing any cross-node performance number: check its window size, validation posture,
  and harness overhead disclosure.
- When a roadmap decision hangs on a benchmark older than the architecture it measures.

## Examples

- At-scale replay (repo-native, measurement-grade):
  `target/release/examples/mainnet_prefix_replay --stop-height 150000 --rest-url 127.0.0.1:8332`
  against a `bitcoind -rest` serving a synced datadir (the campaign executable is now retired).
- Matched-validation Core side:
  `bitcoind -reindex-chainstate -assumevalid=0 -connect=0` (elapsed from `debug.log`
  start → `UpdateTip height=N`).

## Related

- [multi-peer-block-download-requires-core-stalling-disconnect](../architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md)
  — the download-regime analysis this learning's live-IBD numbers confirm; its point 2(b) now
  carries this measurement's correction, and its point 8 already rejected the 0-1000 figure.
