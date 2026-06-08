---
title: Multi-peer block download is the only IBD wall-time lever and requires Core-style stalling-disconnect
date: 2026-06-08
category: docs/solutions/architecture-patterns
module: node IBD block-download scheduler (crates/node/src/sync.rs, sync/window.rs)
problem_type: architecture_pattern
component: background_job
severity: high
applies_when:
  - "Optimizing bitcoin-rs Initial Block Download (IBD) end-to-end wall time"
  - "Considering or building a multi-peer parallel block-download scheduler"
  - "Judging whether a deterministic simulation is enough to validate a network-scheduler change"
  - "Trying to measure faster-than-Core sync inside a dev session"
related_components:
  - p2p
  - consensus-apply
  - storage-utxo
tags:
  - ibd
  - block-download
  - multi-peer
  - p2p
  - stalling-detection
  - sync-scheduler
  - performance
  - validation-limits
---

# Multi-peer block download is the only IBD wall-time lever and requires Core-style stalling-disconnect

## Context

Goal: make bitcoin-rs end-to-end mainnet IBD at least as fast as Bitcoin Core C++. An extended
investigation (build → live-test → revert cycle plus first-principles + oracle review) converged on a
firm conclusion about *what* can move IBD wall time and *why* the obvious attempts fail. This documents
that conclusion so a future agent does not re-tread the same ~100-turn exploration, and so the next
multi-peer attempt starts from the correct design and validation plan instead of a known-collapsing one.

## Guidance

1. **IBD wall time is DOWNLOAD-bandwidth-bound, not apply/CPU-bound.** Apply runs ~1228 blk/s
   (early-height); single-peer high-height download is ~5-25 blk/s — apply is 50-250x faster than
   download. The UTXO set is an in-memory, sharded, arena-backed cache (`crates/utxo/src/set.rs`
   `commit_block` -> `crates/utxo/src/shard.rs` `commit_batch`) with periodic flush, so per-block apply
   hits in-memory hashtables and is **off the single-peer critical path**. Corollary: apply/UTXO/storage
   micro-optimizations (and the wire-byte reuse in commit `42aa2c7`) do **not** move end-to-end IBD,
   because download is the bottleneck. (auto memory [claude])

2. **The only lever for the binding regime is multi-peer bandwidth aggregation.** At high height
   (1-2 MB blocks) a single peer is *serving-rate-limited* by its per-connection upload cap, so on a fast
   local link single-peer download leaves bandwidth on the table. Multi-peer is *doubly* necessary: it is
   the only way to (a) not lose to Core on download, and (b) make bitcoin-rs's faster processing the
   deciding factor instead of single-peer input starvation.

3. **Naive multi-peer collapses — this was built, live-tested, and reverted.** Commit `5608279`
   (opt-in parallel download, per-peer inflight cap = 3) collapsed in 2/3 block-downloading live runs
   (apply/recv ratio ~= 0.01) and was reverted. Root cause: a stalled *frontier* peer freezes the
   contiguous apply frontier for the full `PENDING_TIMEOUT` (1 min) while other peers race ahead and
   overflow `RECEIVED_BLOCK_BUDGET` (128) into evict/re-download churn. A follow-up experiment
   (cap = 3 + 8s timeout) still collapsed 1/4 of the time AND ran ~18x slower than single-peer, because
   the shallow per-peer cap cripples early-height request cadence (3 x ~7 peers ~= 21 in-flight vs
   single-peer 128). (auto memory [claude])

4. **The correct design is a faithful Core port, not a shallow stripe.** Core uses a deep in-order
   window + per-peer cap ~16 (`MAX_BLOCKS_IN_TRANSIT_PER_PEER`) + **window-blocked staller detection**:
   in `net_processing.cpp` it sets `m_stalling_since` when the download window is blocked by an
   in-flight block owned by a slow peer, then *disconnects* that peer after an adaptive
   `BLOCK_STALLING_TIMEOUT` (2s doubling to 64s). bitcoin-rs already has the recovery plumbing
   (`DownloadWindow::release_disconnected_peers` re-queues a dropped peer's pending blocks). A correct
   port must use window-blocked detection (NOT raw `applied_tip+1` stagnation), plus peer-eligibility
   checks and a no-blame rule when OUR apply/stager backpressure (not the peer) is the bottleneck.

5. **`cap = 16` is NOT automatically safe at early height.** `DownloadWindow::request_peer_scan_limit`
   divides request capacity by `min(getdata_batch_limit, max_peer_inflight)`, so cap=16 with the
   128-block window fans out to ~8 peers *immediately*. With fewer than ~8 eligible peers it
   *under-fills* the window versus single-peer-128 -> early-height regression. A correct design must
   preserve single-peer-128 depth and fan out only when enough eligible peers AND staging capacity exist.

6. **Staging budgets must be resized for high-height fan-out.** `RECEIVED_BLOCK_BYTE_BUDGET = 128*256KiB`
   (~32 MB) is far below 128 high-height blocks at 1-2 MB (128-256 MB). Multi-peer fan-out re-creates the
   eviction/retry churn from failure mode (3) unless staging budgets (or disk-backed staging) are
   redesigned first.

7. **Deterministic simulations give dangerously false confidence for net-scheduler changes.** A prior
   discrete-event simulator (`.outline/sim/agg_sim.rs`) reported 82-88% aggregation efficiency; live
   testing against real peers collapsed. The failure-path *logic* (stalling-peer -> disconnect/requeue
   -> frontier advances, no churn) IS deterministically testable with synthetic peers and an injectable
   `now: Instant` (the window scheduler already takes `now` and operates on injectable peer sets). What
   is NOT certifiable without real high-height peers is the emergent *throughput* and the full set of
   emergent failure modes — the live collapse exhibited several (HOL stall, eviction churn, stop-start
   idle) that the sim did not model. (auto memory [claude])

8. **The faster-than-Core measurement is itself gated.** The high-height download-bound regime is
   unreachable in a dev session: block download always starts at genesis (`next_request_height: 1`),
   there is no assumeutxo / replay-to-near-tip path, the local block corpus
   (`crates/primitives/tests/testdata/*.bin`) is non-contiguous singletons, and reaching height ~700k via
   live P2P is infeasible in bounded time. The existing G14 head-to-head
   (`.outline/live-smoke/criterion-1000/`: rs 56s vs Core 157s over blocks 0-1000) is **not** valid
   evidence — it is a 1000-block early prefix and it runs *processing-bound* (`connect=0`, blocks fed
   locally with download removed as a variable), which erases exactly the download bottleneck that
   decides real faster-than-Core.

9. **gocoin's sync speedups are mostly trust shortcuts bitcoin-rs rejects.** A prior planning
   campaign that mined the local `gocoin/` tree for portable initial-sync ideas found that gocoin's
   biggest wins depend on consensus-trust shortcuts — `TrustAll`, `LastTrustedBlock`, trust propagation
   during header sync, `TrustedTxChecker`, and script-verification override hooks — which must NOT be
   ported (bitcoin-rs keeps deterministic accept/reject; kernel is consensus authority). The safe,
   portable leverage is internal: the `DownloadWindow` / `BlockStager` / `ApplyScratch` rework,
   shard-aware UTXO batching (the UTXO set already has 256 shards, so reduce churn + reuse per-commit
   scratch rather than adding shards), and batched storage writes. Net: gocoin does not hand over a
   free faster-than-Core lunch; the multi-peer download lever above remains the real one. (session history)
   Caveat on stale constants: a prior session recorded `GETDATA_BATCH_SIZE = 16`; current code has it
   `= PENDING_BUDGET = 128` — re-read `crates/node/src/sync.rs` before trusting any cited constant.

## Why This Matters

- Prevents re-deriving this conclusion from scratch (the prior exploration spanned ~100+ holding turns).
- Stops a well-intentioned but known-collapsing multi-peer attempt (shallow per-peer cap, or raw
  tip+1 stall timing) from being shipped again.
- Frames what "faster than Core" actually requires (multi-peer + Core-faithful stalling-disconnect) and,
  crucially, what is needed to *validate* it — so the scheduler is built together with its validation
  environment rather than blind.

## When to Apply

- Before starting any IBD throughput optimization: confirm the bottleneck is still download, not apply.
- Before building/shipping a multi-peer scheduler: adopt the Core-faithful design (deep window, cap ~16,
  window-blocked staller-disconnect, single-peer fallback, resized staging) — not a shallow stripe.
- Before trusting a simulation to sign off a network-scheduler change: treat sim throughput numbers as
  unverified; require deterministic failure-path tests + real high-height live validation.

## Examples

Reverted attempt and its failure signature:

```
5608279  feat(node): opt-in parallel multi-peer block download   (per-peer cap = 3)
  -> live: 2/3 download runs collapsed, apply/recv ~= 0.01  -> REVERTED
  cap=3 + PARALLEL_PENDING_TIMEOUT=8s
  -> 1/4 still collapsed AND ~18x slower than single-peer    -> DISCARDED
```

Key constants and anchors (`crates/node/src/sync.rs`):

```
PENDING_BUDGET = 128            // in-flight getdata window
PEER_INFLIGHT_BUDGET = 128      // default per-peer cap == global (single fast peer fills window)
RECEIVED_BLOCK_BUDGET = 128     // staged-out-of-order cap
PENDING_TIMEOUT = 1 min         // re-request timeout (too slow for a stalled frontier peer)
RECEIVED_BLOCK_BYTE_BUDGET = 128 * 256 KiB   // << 128 * 1-2 MB high-height blocks
```

Scheduler entry points: `BlockSync` (sync.rs), `DownloadWindow::next_peer_request`,
`mark_received`, `expire_pending`, `release_disconnected_peers`, `request_peer_scan_limit`
(`crates/node/src/sync/window.rs`).

## Related

- Delivered/gate-verified hardening from the same investigation: `b46e5e4` (gate in-flight getheaders),
  `42aa2c7` (reuse P2P block wire bytes), `19ce127` (bound inbound block channel),
  `e95eb58` (bound submitblock inbound-channel send).
- Reverted experiment: `5608279` (opt-in parallel download) — recoverable via git history; do not
  restack speculatively.
- Investigation residue (gitignored scratch): `.outline/sim/agg_sim.rs`,
  `.outline/live-smoke/criterion-1000/`.
- Prior-session planning evidence (Codex memory): `~/.codex/memories/MEMORY.md` task group
  `bitcoin-rs-gocoin-sync-campaign-planning` and rollout summary
  `2026-06-02T15-17-30-...bitcoin_rs_pr_merge_gocoin_aggressive_sync_campaign.md` (gocoin harvest:
  portable internal sync/UTXO ideas vs. unsafe trust shortcuts).
