---
title: Re-probe "blocked on external artifacts" before re-asserting it
date: 2026-06-10
category: docs/solutions/best-practices
module: development workflow (cross-session task dispositions)
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - "A task is carried as blocked on external binaries, data, or access for more than one session"
  - "A goal verdict is declared unreachable because of missing infrastructure"
related_components:
  - development_workflow
tags:
  - workflow
  - blocked-tasks
  - stale-state
  - verification
---

# Re-probe stale external blockers before re-asserting them

## Context

The cross-node faster-than-Core/gocoin verdict was carried across multiple sessions as
"blocked on user-provided Core/gocoin binaries plus a multi-GB block corpus (owner: user)" —
and restated verbatim each time the goal check fired. A two-minute probe on 2026-06-10 found
`bitcoind` v31 already installed in `/tmp`, the Bitcoin P2P network reachable (one TCP
connect to a DNS seed), and a Go toolchain present. gocoin built from source in minutes, the
"corpus" self-provisioned via a live sync, and the supposedly user-blocked verdict was
measured the same day — twice (live-IBD and processing-bound regimes).

## Guidance

1. **A blocker disposition is a cached fact with no invalidation.** Environments change
   between sessions (binaries appear, network access changes, toolchains get installed);
   the disposition text does not. Treat any blocker older than the current session as
   unverified.
2. **Probe before re-asserting.** The probe is almost always cheap relative to the blocked
   work's value: `which`/`fd` for binaries, one TCP connect for network reachability, one
   `--version` for toolchains. Budget two minutes before writing "still blocked."
3. **Ask what the blocker actually decomposes into.** "Missing multi-GB corpus" decomposed
   into "missing a synced node datadir" — which a present binary plus reachable network
   could create. Blockers stated as artifacts are often blockers on capabilities that have
   multiple acquisition paths.

## Why This Matters

Every session that re-asserts a stale blocker converts available work into idle waiting and
trains the goal loop to accept "unreachable" as terminal. Here the entire headline goal
measurement — the project's reason to exist — sat executable behind a blocker that had
silently expired.

## When to Apply

- Any time a status report is about to repeat a blocked-on-external claim from a prior
  session.
- Before assigning a blocker's "owner" to someone else: verify the dependency still exists.

## Related

- [small-window-benchmarks-do-not-predict-at-scale-throughput](small-window-benchmarks-do-not-predict-at-scale-throughput.md)
  — the measurement campaign this probe unblocked.
