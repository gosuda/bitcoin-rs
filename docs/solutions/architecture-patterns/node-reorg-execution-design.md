---
title: "Node-level reorg execution: authoritative chainstate and derived indexes"
date: 2026-08-08
category: docs/solutions/architecture-patterns
module: crates/node (apply path), crates/index, crates/utxo, crates/chain
problem_type: architecture_pattern
component: consensus
severity: high
applies_when:
  - "Implementing block disconnect / chain reorganization in the node"
  - "Deciding where the commit point of a multi-store mutation sits"
  - "Adding derived state that follows committed applied-tip changes"
related_components:
  - apply_path
  - utxo
  - index
tags:
  - reorg
  - undo-data
  - crash-recovery
  - commit-point
---

# Node-level reorg execution: authoritative chainstate and derived indexes

## Status

**Live branch switching is implemented and called from sync. Crash replay remains
open.**

Done:

* `ColumnFamily::UndoData` across all four backends, and a versioned undo codec
  bound to the block hash (`crates/utxo/src/undo_codec.rs`).
* Undo generation in the same pass as the forward UTXO changes. The undo write
  is queued before the block body and UTXO commit. A clean checkpoint makes the
  queued record durable.
* `disconnect_block`, which restores the UTXO set, rewinds block-level
  coinstats, publishes the parent `applied_tip`, and wakes the derived TxIndex
  worker. Its authoritative ordering claims are mutation-verified.
* Node-owned `invalidateblock` control, which invalidates the named header
  subtree and uses the normal branch-switch/disconnect path rather than
  mutating chainstate in the RPC crate. It previews the replacement tip and
  preloads the complete disconnect/connect plan before changing header status;
  one chain-transition witness then spans header invalidation and all
  chainstate mutation.
* `switch_to_branch` (`crates/node/src/reorg.rs`), called by sync when the
  best-work header branch outweighs the applied branch. It loads all
  disconnect bodies and the contiguous target prefix that fits in bounded
  staging. The disconnect preload remains $O(\text{disconnect depth})$. If the
  first connect body is absent, chainstate does not change. The transition
  witness recomputes the complete authoritative plan and permits mutation only
  when that plan is unchanged. Each available prefix then forms a coherent
  applied-tip checkpoint; `MissingBody` names the next suffix block. A permanent
  connect failure invalidates its header subtree, selects the best valid tip,
  and purges that subtree from staging and download ownership. Operational
  failures preserve both branch eligibility and ownership.
* Fork-aware download requests start at the common ancestor's child. A target
  change discards pending ownership from the losing branch.
* A node-owned supervised TxIndex worker reconciles independent versioned
  `TxLookup` and `ScriptHistory` `(height, hash)` watermarks to exact
  applied-tip ancestry. Equal cursors share one body scan and one atomic commit;
  divergent cursors move only the lagging capability. It can retain one bounded
  forward batch across strict descendant tip revisions. A rival, lower, or
  absent tip can commit the complete prepared prefix; the next pass repairs it.
* A fatal disconnect closes apply admission and sets the process shutdown token.
  The durable marker prevents a restart on torn authoritative state.
* Whole-UTXO RPC scans share the node's chain-transition mutex. In particular,
  `scantxoutset` captures its UTXO view and applied-tip metadata while connects
  and disconnects are excluded, so response height, hash, confirmations, and
  unspents describe one authoritative state.

Still open: transaction reconsideration, filter-index backfill, real crash
replay, and the ignored live `g10_reorg_deep` gate. ZMQ now publishes block
disconnect notifications through `pubsequence`, but mempool `A`/`R` events remain
intentionally open.
Transaction reconsideration requires one production admission pipeline shared
by Esplora broadcast, P2P relay, and reorg handling. Raw mempool insertion cannot supply
the required fee, policy, conflict, and ancestry metadata.

## Why it matters

A Bitcoin full node that cannot disconnect a block cannot follow the most-work
chain. Everything else — sync throughput, index correctness, mempool policy —
is downstream of being on the right chain.

## The authoritative store and derived index have different crash models

This distinction is load-bearing. Do not force both states into one transaction.

| | Authoritative UTXO set and applied tip | Derived TxIndex |
|---|---|---|
| Lives in | UTXO set in RAM; tip published in process | On disk |
| Durability | clean checkpoints | each atomic rows-plus-capability-watermark batch |
| A crash during mutation | can leave a torn UTXO set; marker blocks restart | leaves each selected capability at its previous or next complete watermark; an uncommitted pending batch disappears |
| Recovery | refuse torn state; otherwise load the checkpoint | reconcile each enabled durable watermark to the applied tip; queries remain unavailable until every capability they consume matches |

Consequences:

1. **Undo records serve live reorgs, not per-block crash recovery.** Connection
   queues each record before later apply mutations. The backend write is
   deferred. A clean checkpoint flushes storage, publishes the matching UTXO
   state, and then advances the durable horizon. The record is not a per-block
   fsync boundary.
2. **The durable disconnect marker covers authoritative state only.** `InFlight`
   is flushed before the UTXO mutation. A completed rollback changes the marker
   to `RolledBack`; only a clean checkpoint can clear it after publication. A
   checkpoint refuses `InFlight`, and startup refuses either phase. The marker
   prevents service on inconsistent authoritative state. It does not repair it.
3. **TxIndex recovery starts from atomic capability watermarks.** `TxLookup`
   owns `TxConfirmed`; `ScriptHistory` owns `Funding` and `Spending`; the
   identity-bearing `BlockHeaders` rows are shared rollback metadata. The worker
   can retain one bounded forward batch while the applied tip moves through
   strict descendants. Equal cursors prepare both families in one block scan
   and write their rows and final watermarks together. Divergent cursors commit
   and roll back independently. A crash drops an uncommitted batch or leaves
   each selected capability at one complete watermark, so exact query gating
   cannot publish partial coverage as complete. Version-one stores promote the
   old all-family watermark to both capability watermarks without reindexing.

   A disabled capability keeps its cursor and the shared ancestor identities it
   may still need. Competing-branch rows can coexist in `BlockHeaders`, so its
   iteration order and row count are not an active chain or tip; authoritative
   header queries use `BlockTree`. On re-enable the worker reconciles from that
   cursor. If a disconnected body or rollback identity is gone, a durable reset
   marker first makes the affected capability unavailable, then bounded deletion
   and rebuild replace its derived rows. Startup resumes an interrupted reset.

## Disconnect order

1. `utxo.undo_block(&undo)`
2. refresh block-level coinstats and best-effort caches
3. roll `applied_tip` back to the parent
4. increment the TxIndex revision and send a nonblocking, coalesced wake

Step 3 is the authoritative commit point. Preflight failures before the marker
refuse without mutation. Failures after the UTXO mutation are fatal because the
sharded undo can stop part-way. After step 3, TxIndex may lag safely; complete
queries remain unavailable until their required capability watermarks reach the
applied tip.

## Do not assume undo is idempotent

`UtxoSet::undo_block` restores the outpoints a block spent and removes those it
created. Applying it twice is **not** safe: if a competing block re-created one
of those outpoints in between — exactly what a reorg does — the second undo
deletes a live output. That is silent chainstate corruption.

Any idempotency claim in this area must be backed by a test that double-applies
the operation and asserts the state matches a single application. An untested
idempotency claim in consensus code is a defect.

## Undo record retention

Key records by **block hash**, not height alone: a stale record from an
abandoned branch must never be replayable against a different block at the same
height. Verify the hash on load and hard-error on mismatch.

**Do not delete the record when a block is disconnected.** Reorg flip-flop
between two competing branches is normal, and discarding the record means
regenerating it on every reconnect. Retention is bounded by the durable
chainstate horizon (the checkpoint height), not by disconnection.

Write the record before or in the same batch as the UTXO commit. A UTXO commit
with no recoverable undo record is an unrecoverable chainstate.

## Work remaining

Done:

| Piece | Notes |
|---|---|
| `ColumnFamily::UndoData` | enum, its `ALL` list, and all four backends |
| Versioned undo codec | first byte a format version; keyed by height **and** block hash, with 10 rejection tests |
| Undo generation in apply | built in the same pass as `BorrowedBlockChanges`, sharing one set of filters so the two halves cannot drift |
| Persistence | queued before the block body and UTXO commit; flushed with a clean checkpoint, not per block |
| `disconnect_block` | restores the UTXO set, coinstats, and applied tip; then publishes a TxIndex wake |
| TxIndex reconciliation | one node-owned worker rolls enabled capability watermarks back to the common ancestor, then assembles count-and-byte-bounded forward batches across strict descendant tip revisions. Equal cursors share one body parse and atomic commit; divergent cursors move independently. `--scriptindex` enables generic script UTXO, history, and outpoint-spender queries, while only explicit `--txindex` advertises Core txindex semantics. Each queued wake triggers reconciliation without moving the pending batch's fixed deadline. Exact capability snapshot-plus-tip gating keeps individual queries unavailable until every consumed watermark matches. Esplora additionally captures the applied-tip identity around each GET response so independently safe index reads cannot be combined across a reorg. |
| `coin_stats` rewind | block-level fields only; the per-coin ones ride the `UtxoSet` change listener, which the undo already drives in reverse |
| Filter header cache | repointed at the parent; the index itself needs no rollback because its rows are hash-addressed like block bodies |
| `blocks` RPC cache | popped when the tail is ours; absence is legitimate after a restart or a prune |
| `DisconnectError` | splits `Refused` (nothing touched) from `Fatal` (partly rolled back, carries hash and height), plus `MarkerStuck` (rolled back, but the interlock would not clear) |
| Durable interlock | a phased in-flight marker in `UndoData`, armed and flushed before the UTXO mutation; startup refuses while it is set. TxIndex is outside this marker. See *Disconnect marker phase* in `CONCEPTS.md` |
| Chain-transition serialization | `ChainTransition` proves that admission and the exclusive transition lock were acquired in that order. One witness covers authoritative replanning, all disconnects, and the available contiguous connect prefix. `PruneGuard` wraps the same witness, reads the applied tip only after acquisition, validates the monotonic prune height against the reorg-safety margin, and remains held through storage, file, and cache deletion. |
| Branch switching | `switch_to_branch` recomputes the complete ordered `plan_reorg` result under the transition guard and mutates only when it equals the optimistic plan. A shorter branch is eligible when its accumulated work is greater. A permanent connect failure invalidates its subtree and selects the best valid tip. |
| Body acquisition | Each attempt loads all disconnect bodies and the contiguous connect prefix from bounded staging first, then the fallible `PruneBodyStore`; there is no applied-record body cache. The first missing connect body prevents mutation. A later missing body follows a coherent committed prefix. Each committed connect retires its exact staging and download-window entry; invalid subtree ownership is purged. |
| Fatal lifecycle | `Fatal` and `MarkerStuck` close apply admission while the transition lock is held; sync sets the shared process shutdown token |
| RPC invalidation | `invalidateblock` delegates through `ChainControl`; unknown blocks map to Core not-found, genesis is refused, required bodies are preflighted before header mutation, one transition witness spans invalidation and branch switching, and a successful active-tip rollback emits `pubsequence D` |
| Whole-chainstate RPC reads | `scantxoutset` shares the chain-transition mutex and reads its UTXO scan plus applied-tip identity under that guard; it cannot publish metadata from the opposite side of a connect or disconnect. |

Open:

| Piece | Notes |
|---|---|
| Mempool reconsideration | Block transactions need the same production admission pipeline as Esplora broadcast and future P2P relay. Direct insertion is invalid because it fabricates admission metadata |
| Mempool sequence events | Mempool `A`/`R` notifications remain intentionally absent until event sequencing and removal reasons are redesigned |
| Filter-index backfill | a gap leaves the index unavailable from that point, by design; nothing repairs it |
| Real crash replay | the node detects and refuses torn disconnect state, but cannot replay or repair it in place |
| Un-ignore `g10_reorg_deep` | prove the full path against `bitcoind` regtest |

A body-load error occurs before its attempt mutates. A missing suffix body can
be reported after a coherent target prefix commits. A refused disconnect can
leave a shorter coherent applied chain when earlier disconnects completed. A
connect failure leaves a coherent prefix of the target branch. The node does
not run a
compensating rollback because that second rollback can turn a recoverable stop
into a fatal one. `Fatal` and `MarkerStuck` stop further mutation and trigger the
normal shutdown path.

## Guidance

1. **Name the commit point before writing any of it.** Which single mutation
   decides that the disconnect happened? Everything after it is cleanup.
   Everything before it must be atomic, compensatable, or recoverable, and you
   must say which for each store. "Safe to re-enter" was the earlier wording and
   it was wishful: it assumed each step either happens or does not, which the
   shard-walking UTXO commit does not honour.
2. **Do not add a mechanism whose failure mode cannot occur, and do not assume a
   failure mode cannot occur because one store is in RAM.** The phase marker is
   the durable boundary for disconnect. Keep `InFlight` until rollback completes,
   keep `RolledBack` until a clean checkpoint is durable, and refuse to clear an
   incomplete operation.
3. **Keep derived durable state outside the authoritative rollback.** Give each
   derived row family an exact atomic capability watermark and make every query
   prove complete coverage of the applied tip for all families it consumes. A
   wake is only a scheduling hint; the watermarks are the recovery and
   correctness boundary.
