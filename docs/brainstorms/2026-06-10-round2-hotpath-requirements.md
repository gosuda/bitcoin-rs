# Round-2 hot-path optimization campaign — requirements

**Date:** 2026-06-10
**Status:** approved (plan-mode approval of `Round 2` section in the session plan file)

## Summary

Land all three round-2 candidate tracks — the MuHash3072 ILP multiply rewrite, the sync_pipeline
bench-validity fix plus apply-side cache repopulation, and the mimalloc bench A/B wiring — gated on
correctness proof rather than measured wins. Criterion benches still run serially afterward as a
regression veto, and an adversarial-verification pass audits each diff before its atomic commit.

## Problem Frame

Round 1 of the same-node `/optimize` campaign closed all five non-script criterion benches with
honest dispositions (three exit-12, two deferred). Round 2 generated three worktree-isolated
candidates for the deferred targets, all compiling and test/clippy-clean. The blocking question was
disposition policy: the T1 cache-repopulation win is production-only and unmeasurable by existing
sub-benches, and the T2 MuHash rewrite is consensus-critical.

## Key Decision — commit policy (user, verbatim)

Asked how to disposition T1 Part B given no measurement path, the user answered:

> "We don't measure first, we optimize all the efforts when possible."

Combined with the twice-repeated directive "Run all the possible hot-path optimizations", this sets
the round-2 policy: **correctness-gated optimization-first.** Correctness proof (byte-identity
differentials, unit tests, clippy/fmt) decides commits; benches run only as a regression veto — a
null result no longer blocks, a p<0.05 regression on a track's gate benches does.

## Requirements

- **R1 (T2 MuHash):** lands if the differential suite (frozen reference multiply, ≥100k seeded
  inputs, adversarial carry patterns), `cargo test -p bitcoin-rs-coinstats`, clippy, and fmt all
  pass re-run in the main tree. Commit `perf(coinstats)`, flagged consensus-critical for user review.
- **R2 (T1 sync):** Part A (bench-validity fix: timed regions cover only production-path work)
  commits first as `fix(node)`. Part B (apply-side `expected_apply_cache` repopulation) commits on
  its cache-coherence structural argument plus unit tests (miss→populate→hit, invalidation on failed
  apply / tip move, horizon cap) as `perf(node)`.
- **R3 (T3 mimalloc):** commits as bench infrastructure (`bench-mimalloc` feature, plain
  dev-dependency, default OFF, zero `src/` changes) if both configurations build/test/clippy clean.
  The A/B delta is recorded as a bench-fidelity finding. Only track adding a dependency —
  flagged and accepted.
- **R4 (regression veto):** serial measurement barrier on idle pinned cores, one bench at a time:
  T2 vs saved baseline → T3 A/B → T1-A fixed-bench baseline → T1-B vs that baseline. Any p<0.05
  regression on a track's gate benches blocks that track's commit.
- **R5 (adversarial verification):** a parallel verification pass audits every track before commit:
  differential-gate re-execution, T1-B cache-coherence attack review, per-track diff-vs-claim audit.
- **R6 (commits):** atomic, conventional, one concern each, `Op:` body trailers, no agent identity
  trailers; then worktree cleanup and disposition-table update.

## Scope Boundaries

- The cross-node faster-than-Core/gocoin verdict stays corpus-blocked (owner: user).
- The three settled exit-12 targets (`utxo_commit`, `sync_apply_metrics`, `kvstore_backends`) stay closed.
- No new sync_pipeline sub-bench — not needed as a commit gate under the round-2 policy.
