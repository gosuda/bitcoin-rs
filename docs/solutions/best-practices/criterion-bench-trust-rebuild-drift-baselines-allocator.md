---
title: Criterion bench trust — rebuild codegen drift, baseline CLI exclusivity, allocator parity
date: 2026-06-10
category: docs/solutions/best-practices
module: criterion benchmarking across the workspace (node, utxo, coinstats benches)
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - "Interpreting a criterion p<0.05 regression or improvement that spans a rebuild"
  - "Chaining criterion runs with --baseline / --save-baseline flags"
  - "Reading criterion numbers for code whose production binary ships mimalloc"
related_components:
  - testing_framework
tags:
  - criterion
  - benchmark
  - codegen-drift
  - baseline
  - mimalloc
  - measured-regression
---

# Criterion bench trust: three failure modes that fabricate or hide deltas

## Context

During the round-2 hot-path campaign (2026-06-10) three independent criterion pitfalls each
nearly corrupted a commit decision: a phantom regression almost vetoed a verified
optimization, a CLI flag conflict silently killed half an A/B chain, and allocator mismatch
turned out to skew alloc-heavy benches by up to 83% relative to the shipped binary.

## Guidance

1. **A p=0.00 delta across a fat-LTO rebuild can be codegen drift, not your change.**
   `partial_apply_tick` read +3.9% (p=0.00) against a rebuilt binary while benches on
   untouched code "improved" 2–5% in the same run — the tell that inter-build noise spans
   ±2–5%. A same-binary re-probe (re-run the suspect bench against the same saved baseline
   with no intervening rebuild) read +0.0% (p=0.99). Only a delta that reproduces on the
   same binary is binary-level; only one that survives a rebuild pair is attributable to
   the source change.
2. **`--baseline` and `--save-baseline` are mutually exclusive criterion CLI args.**
   Combining them fails the entire bench invocation immediately ("an argument cannot be
   used with one or more of the other specified arguments"), and inside a piped chain the
   failure reads as an empty phase with a misleading exit code. Save first, compare in a
   separate run.
3. **Allocator parity gates bench trust.** `bin/bitcoin-rs` ships mimalloc; crate benches
   measure the system allocator. Measured A/B (`bench-mimalloc` bench-only feature,
   commit `777f12b`): alloc-heavy `utxo_commit` paths improve up to −83% under mimalloc,
   the parallel two-shard commit path regresses +23%, and compute-bound coinstats paths
   are insensitive. System-allocator numbers understate the production binary on
   alloc-heavy paths and overstate it on the two-shard path — run the A/B
   (`cargo bench -p <crate> --features bench-mimalloc -- --baseline <sysalloc>`) before
   trusting a delta on an allocation-dominated bench.

## Why This Matters

The round-2 commit policy used benches as a regression veto; an unexamined phantom
regression would have killed a correct, adversarially-verified optimization, and the flag
conflict cost a full serial measurement slot. Bench-driven decisions inherit every bias of
the bench run.

## When to Apply

- Before accepting or vetoing a change on a criterion delta that spans a rebuild.
- When scripting multi-phase criterion chains with saved baselines.
- When a bench's workload allocates heavily and the binary ships a custom allocator.

## Examples

- Same-binary re-probe:
  `cargo bench -p bitcoin-rs-node --bench sync_pipeline -- --baseline fixed partial_apply_tick`
  (no rebuild in between).
- A/B chain shape: run 1 `-- --save-baseline sysalloc`; run 2
  `--features bench-mimalloc -- --baseline sysalloc`.

## Related

- [small-window-benchmarks-do-not-predict-at-scale-throughput](small-window-benchmarks-do-not-predict-at-scale-throughput.md)
  — the cross-node measurement methodology this note's single-machine hygiene supports.
- [utxo-commit-borrowed-removal-win-is-off-the-coalescing-event-path](../architecture-patterns/utxo-commit-borrowed-removal-win-is-off-the-coalescing-event-path.md)
  — bench path ≠ production path, the listener-routing instance.
