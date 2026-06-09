---
title: UTXO-commit borrowed-removal alloc win lands off the production coalescing event path — exit-12
date: 2026-06-09
category: docs/solutions/architecture-patterns
module: crates/utxo
problem_type: architecture_pattern
component: utxo
severity: medium
applies_when:
  - "Proposing to eliminate the per-spent-coin ScriptBuf allocation in the UTXO commit listener path"
  - "Optimizing the UtxoChangeListener removal dispatch (on_remove / on_remove_coins)"
  - "Treating a criterion utxo_commit *_noop_listener win as evidence of a production CoinStats speedup"
  - "Deciding whether a measured hotspot is on the path the production listener actually takes"
related_components:
  - utxo
  - coinstats
  - muhash
tags:
  - utxo
  - coinstats
  - allocation
  - listener-dispatch
  - benchmark
  - profile-before-optimize
  - off-critical-path
  - exit-12
---

# UTXO-commit borrowed-removal alloc win lands off the production coalescing event path — exit-12

## Context

The same-node apply-optimization campaign (`/optimize`, criterion-gated) promoted `utxo_commit` as the
one target with real headroom: the listener removal path allocates one `ScriptBuf` per spent coin at
`crates/utxo/src/shard.rs:1336` —

```rust
fn txout_from_parts(value: u64, script: &[u8]) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(script.to_vec()), // shard.rs:1336 — per-spent-coin alloc
    }
}
```

reached via `output_details_from_parts` (`shard.rs:1325`) when a `UtxoChangeListener` is installed. Three
worktree-isolated candidates each eliminated it by handing the listener a **borrowed** `UtxoRemovedRef`
(`op`, `&[u8] script`, `value`, `height`, `coinbase`) built straight from the shard's append-only
`table.script_bytes` slab, with the production `CoinStatsListener` folding the borrowed parts into MuHash
via the same encoders the owned path uses. All three compiled, passed tests + clippy `-D warnings`, and
carried a deterministic counting-allocator proof that per-spent-coin script allocations drop to zero
(512 -> 0). On allocation count, the win is genuine and byte-identical in MuHash output.

It was still **rejected (exit-12)**. The hotspot is real but **off the path the production listener
actually takes** for any realistic block.

## Guidance

**Before crediting a UTXO-commit listener optimization, trace which dispatch path the *production*
listener (`CoinStatsListener`) takes — not which path the benchmark's `NoopListener` takes.** They differ,
and the difference is the whole story.

The commit router in `crates/utxo/src/set.rs` (`commit_adds_and_removes`, `commit_multi_shard_with_listener`)
branches on the number of distinct active shards and on `listener.coalesces_committed_events()`:

- `active_shard_count == 1` -> `commit_single_shard` -> `commit_single_shard_batch_with_listener`
  -> `commit_single_shard_with_listener` (`shard.rs:511`), which calls
  `apply_outpoint_remove_run_with_listener` **directly** and never consults `coalesces_committed_events()`.
  **This is the optimized direct-dispatch path.**
- `active_shard_count >= 2` -> `commit_multi_shard_with_listener` (`set.rs:928`). When the listener
  coalesces (`coalesces_committed_events() == true`), it routes to `commit_serial_coalesced_event_batches`
  (for `< PARALLEL_LISTENER_SHARD_THRESHOLD == 8`, `set.rs:23`/`936`) or to the parallel
  `commit_batch_collect_events` -> `on_committed_event_batches` (for `>= 8`). **This is the event-collect
  path, which the optimization does NOT touch.**

`CoinStatsListener::coalesces_committed_events()` returns `true` (`crates/coinstats/src/stats.rs:551`).
Therefore the production listener reaches the optimized direct path **only when `active_shard_count == 1`**
— i.e. when every coin touched by the commit hashes into a single one of the 256 shards. That is a
degenerate, tiny-block case. A realistic IBD block touches many distinct txids, scatters across `>= 8`
shards by birthday math, and routes through the parallel event-collect path every time. There the owned
`UtxoRemoved` is still built, and the borrowed-removal change has **zero effect**.

**The event path cannot be borrow-optimized without `unsafe`, and must not be.** `table.script_bytes` is a
`bumpalo::collections::Vec` that **relocates on growth**. Buffered events are read by
`on_committed_event_batches` *after* subsequent inserts have appended to (and possibly moved) that slab, so
a borrow into it would be a use-after-free -> silent UTXO/MuHash corruption -> consensus break. All three
candidates correctly refused to cross that line; safe Rust cannot express the required `'arena`-stable
borrow there.

## Why This Matters

This is the **third instance** of one recurring pattern in this codebase, and the most subtle:

> The optimization is real, measurable, and correct — and it lives off the production-critical path.

The two siblings:
- `script-verification-delegated-to-core-c-no-rust-headroom.md` — non-taproot script verification *is*
  Core's own C engine; no Rust headroom there.
- `multi-peer-block-download-requires-core-stalling-disconnect.md` — IBD is download-bandwidth-bound;
  shaving CPU off an apply path already 50–250x faster than download buys nothing.

This one adds the intra-subsystem version: **a real hotspot inside the right crate can still be off the
hot path, because dispatch routing — not the line of code — decides what the production caller executes.**

Two specific traps it documents:

1. **The benchmark listener is not the production listener.** `utxo_commit`'s `*_noop_listener` benches
   install a *non-coalescing* `NoopListener`, so `two_shard` / `four_shard` (`< 8` shards) take the direct
   path and *do* show the win. The production `CoinStatsListener` coalesces those same commits onto the
   event path. A green criterion delta on those sub-benches is **not** evidence of a production speedup.
   The only sub-bench representing the production direct path is `concentrated` (single-shard) — itself a
   degenerate case, so measuring it would only quantify the degenerate win and re-tempt a commit.

2. **The concurrency steelman points the wrong way.** "Fewer allocations help under concurrent allocator
   contention" is backwards here: the contended path is `active_shard_count >= 8` -> rayon `par_iter` ->
   event-collect — the path left untouched. The optimized `commit_single_shard` path runs *serially*. The
   strongest argument for the win cuts against it.

Because the added surface (a new trait method / capability + a parallel borrowed dispatch + a new event
type + encoder refactors across two crates) buys a win only on a degenerate case and nothing on the hot
path, landing it would be Excess/Sprawl: structure grown without functional cause on the critical path.
The 3-copies-to-1 dedup of the offset/len helper is swamped by the added surface; net entropy is up, so it
does not even qualify as `compress`. **Correct outcome: exit-12, commit nothing, record the finding.**

## When to Apply

- Before optimizing any `UtxoChangeListener` removal dispatch: trace `commit_adds_and_removes` ->
  `commit_multi_shard_with_listener` and check `coalesces_committed_events()` for the *production* listener.
  If it coalesces, the direct `on_remove*` path is reached only at `active_shard_count == 1`.
- When a criterion `utxo_commit` win appears only on `*_noop_listener` sub-benches with `< 8` active
  shards: that is the non-coalescing `NoopListener` taking a path the coalescing `CoinStatsListener` does
  not — discount it.
- Whenever a removal/event optimization is tempted to borrow from `table.script_bytes` across an
  `entry.remove()` *and* an insert: stop. The bumpalo slab relocates on growth; buffered events read it
  after later inserts. Borrowing there is a consensus-grade use-after-free.
- When a deterministic alloc-count proof passes but the wall-clock criterion gate does not move on a
  production-representative scenario: alloc-count is not the success metric; production-path reachability
  is. Prefer the structural exit-12 (path is untouched) over a measured one (small bench delta).

## Related

- `script-verification-delegated-to-core-c-no-rust-headroom.md` — sibling: non-script paths are where any
  Core-beating headroom lives; this doc narrows *within* one of those paths (UTXO commit) and shows even
  there the production listener routes around the optimized branch.
- `multi-peer-block-download-requires-core-stalling-disconnect.md` — sibling: optimize the rate-limiting
  stage, not the convenient one. Same principle, subsystem scale.
