# Recovery contract

## Implementation status

This page specifies the **target durable-root protocol**, not the current
startup implementation. The proposed `crates/chainstate` owner and `DurableHead`
below do not exist in the runtime. Current startup/shutdown still restores and
publishes node checkpoints; see [embedding](embedding.md). `PersistentUtxoSet`
is an isolated persisted-cache API, not an integrated node recovery protocol.

Existing `crates/storage/tests/overhaul_atomic_durability.rs` checks injected
backend faults and clean reopen: each recovered batch is wholly old or new,
and a successful durable receipt requires the proposed bytes. It does not
simulate power loss or prove whole-node recovery. The owner paths and crash,
reorg, and checkpoint-independence tests below are planned unless they actually
exist; naming a test here is not evidence that it ran.

Target owners:
- Authoritative durable root and ordered commit protocol:
  `crates/chainstate/src/transition.rs`
- Recovery and schema admission: `crates/chainstate/src/recovery.rs`
- Crash and lost-write fault tests: `crates/node/tests/overhaul_crash_matrix.rs`
- Reorg and disconnect: `crates/node/tests/overhaul_streaming_reorg.rs`
- Checkpoint independence: `crates/node/tests/overhaul_checkpoint_independence.rs`
- Index worker recovery: `crates/node/src/txindex_worker_recovery_tests.rs`
- Policy: `docs/policies/db-migration.md`

## Durable root

The proposed authoritative durable root is:

```text
R = (tip, height, CommitId, coins_version, coins, body_extent, undo_extent, refs)
```

- `tip` is the 32-byte block hash of the applied tip.
- `height` is the block height, a compact big-endian integer.
- `CommitId` is a strictly monotonic durable serial. It advances on every
  committed connect and every committed disconnect.
- `coins_version` equals the current `CommitId` at the time the coin set
  was committed; it is not computed from coin contents.
- `coins` is the authoritative UTXO set. It is keyed and valued as
  defined in `crates/utxo`.
- `body_extent` and `undo_extent` are the committed durable high-water
  bounds for body and undo segment files.
- `refs` is the authoritative map from `(height, block_hash, Body|Undo)` to
  the durable byte range in the corresponding segment file. Undo and body
  references include the block hash, not only the height.

The proposed persisted form (not an implemented Rust type) is:

```rust
struct DurableHead {
    tip: BlockHash,
    height: u32,
    commit_id: u64,
    coins_version: u64,
    body_extent: u64,
    undo_extent: u64,
    refs: Vec<FrameRef>,
}
```

The durable head, coins, and `refs` are committed in one atomic named-family
batch. `commit_id` is monotonic on disconnect as well as on connect.

## Clauses

### `RCV-01`: Authority and identity

- `crates/chainstate` is the only authoritative position. Block bodies,
  `txindex`, `scriptindex`, and undo or lookup metadata are derived.
- Every derived position is a `(height, block_hash)` pair, not height alone.
- Off the active chain: stale `(height, block_hash)` pairs are rewound to the
  common ancestor, not to a height.
- Absent tip: headers-only start; every row is rewound.
- The chain does not own a position the chainstate has not durably
  committed.
- Checkpoints are a durable copy of the chainstate; block bodies, `txindex`,
  `scriptindex`, and undo or lookup metadata are derived.

### `RCV-02`: Ordered commit protocol

For one block, or a bounded fully verified prefix during IBD:

1. Hold the chain transition reservation; close admission and mixed
   reads with the generation fence.
2. Build exact forward and undo facts without mutating the public stable
   view.
3. Append required body and undo frames. Sync files and required directory
   entries.
4. Apply one atomic storage batch containing coins, metadata, and the new
   durable head. Wait for durable completion.
5. Publish the committed chain and coin view.
6. Feed the committed chain update into the mempool canonical lifecycle,
   update the fee estimator, and reconcile projections.
7. Publish the stable coherent generation only after mempool and projection
   alignment.
8. Dispatch notifications, relay, and index wake hints in the declared
   observable order outside all domain locks.

A failure before stable publication leaves the fence closed until explicit
recovery. A guard destructor must never quietly reopen the fence after an
error. A live `submitblock` success waits for durable body, undo, coins, and
head completion. IBD may group a bounded verified prefix; only committed
prefixes are published. This is the ordered commit protocol. It is also called
the durable root recovery contract.

### `RCV-03`: Prior-or-whole-proposed and orphan tails

- The storage engine resolves an outstanding atomic batch to the prior root
  or to the wholly proposed root. It never mixes a new head with old coins,
  or a new coins set with an old head.
- A durable head never references a body or undo range that has not itself
  become durable.
- Files may have orphan append tails. Those tails are not authoritative.
  The root is installed only after the required file and directory syncs and
  the atomic batch finish.
- A partial append after the head is not a valid connect or disconnect.
- On disconnect, `DurableHead.commit_id` advances to a new value that is
  greater than the previous value. Monotonicity holds for both connect and
  disconnect.
- Undo records are keyed by `(height, block_hash)`. Replaying a side branch
  at the same height must not alias the undo record of the active branch.

### `RCV-04`: Crash matrix

The target crash and error points in `docs/chainstate-recovery.md` and
`docs/policies/db-migration.md` produce exactly these results:

| Crash or error point | Recovery result |
|---|---|
| Body append mid-frame | The in-progress frame is discarded on next start; no durable head references it. |
| Undo append mid-frame | Same as body append; partial undo is not the authoritative head. |
| Append/sync fails before the atomic batch is attempted | Keep the prior root. Even synced orphan frames do not authorize a new head. |
| Durable batch complete, no publish | Restart sees the new head, coins, and `refs`; mempool and index reconcile. |
| Durable batch ambiguous | Keep the fence closed. Recover the prior or whole proposed root by `CommitId` and full identity, then reconcile before publication or retry. Do not assume rollback. |
| Publication callback lost | The durable root is still authoritative; mempool and index reconcile after restart. |
| Reorg stage 1: disconnect | Apply the exact per-block inverse; hold the fence until all disconnects commit. |
| Reorg stage 2: reconnect | Apply the new branch using ordinary connect; each connect advances `CommitId`. |
| Index watermark commit failure | The failure does not block ordinary chain progress; the affected capability reconciles. |
| Incompatible `CURRENT_SCHEMA` | `incompatible_schema` error at open; existing datadirs stay untouched. |

Tests must exercise actual process death and storage fault semantics in an
isolated local environment. A process kill is not a substitute for simulated
power loss. Fault-injection storage tests must exercise lost writes, partial
writes, and failures around sync completion in addition to child-process kill
tests.

### `RCV-05`: Deep rollback and selective rebuild

- A rollback deeper than the configured cutover resets the affected
  capabilities and rebuilds them from the durable root, not from a
  checkpoint. The rebuild phase stays published until the reset
  capabilities reach the applied tip again.
- Independent capabilities carry their own watermarks, so one capability
  may rebuild while a sibling rewinds. The rebuild leg outlives the
  rollback loop and is published until the reset rows reach the applied
  tip.
- The index runtime reconciles against the durable applied tip from
  `chainstate` and canonical retained bodies. It does not derive
  authority from a checkpoint.

### `RCV-06`: Tip change during rebuild

- The applied tip moving while a rebuild is in flight does not restart or
  abort the rebuild. The worker converges on the new applied tip.
- The new target is identified by its full block hash and the durable
  `CommitId` from `chainstate`, not by height alone.
- A rebuild that has already consumed canonical bodies re-uses valid
  prepared work; stale work is discarded.

### `RCV-07`: Missing disconnected body routes to canonical rebuild

- A rewind whose disconnected body is missing cannot produce exact-identity
  deletions. The affected capabilities reset and rebuild from canonical
  bodies instead of failing the worker.
- The worker does not fabricate missing body bytes or substitute a
  different block at the same height.
- Rebuild uses retained canonical bodies from the durable `refs` or an
  explicit archive input. A pruned node reports unavailable history.

### `RCV-08`: Exact disconnect and reorg

- Disconnect restores the pre-connect live coins, consensus bookkeeping,
  and metadata. Reconnection applies the new branch using ordinary connect.
- Missing retained undo fails closed. Optional consumer lag cannot retain
  unlimited segments.
- Reorg memory stays bounded while depth grows. Restart at each
  intermediate committed ancestor is valid.
- Streaming reorg uses bounded descriptors, before-images, and committed
  ancestors with exact inverse transitions; no whole-branch preload.

### `RCV-09`: Fresh replay and schema refusal

- The changed durable format requires an increment of `CURRENT_SCHEMA` for
  the authoritative chainstate bytes. Keep no translator, no legacy reader,
  and no in-place converter.
- An incompatible datadir returns `incompatible_schema` at open. Existing
  operator datadirs stay untouched. A fresh replay uses a separately named
  directory with explicit resync instructions.
- `CURRENT_SCHEMA` covers only authoritative chainstate bytes.
  Estimator-only, discovery-only, and index-only format evolution keep
  `CURRENT_SCHEMA` unchanged. Each carries its own owner-local version.
- A corrupt, missing, or unknown owner-local version never fails
  authoritative startup. Estimator degrades to insufficient data,
  discovery degrades to seeded or empty with reseed or rebuild status, and
  an affected index capability reports unavailable or rebuilding through
  the existing `CapabilityState` vocabulary and rebuilds from retained
  canonical data.
- A rejected owner-local file is left in place until explicit authorized
  rebuild. It is never silently deleted.

### `RCV-10`: Checkpoint-worker removal

- Normal full-checkpoint publication is removed as a recovery authority
  after the candidate `crates/chainstate` gates pass.
- The durable root and the ordered commit protocol are the only recovery
  authority. Checkpoints may remain as a maintenance and export command,
  but no code path treats a checkpoint as an authority for chainstate.
- Manual export and checkpoint commands still exist; they write a durable
  copy for operator convenience, not a new authority.

### `RCV-11`: Owner-local schema versions

- `CURRENT_SCHEMA` is the authoritative chainstate schema version. It
  increments only when the durable root format changes.
- The fee estimator carries its own estimator-owned version. The P2P
  discovery store carries its own discovery-owned version. The index
  carries its own `INDEX_FORMAT_VERSION`. None of these increment
  `CURRENT_SCHEMA`.
- A missing or unknown owner-local version does not fail node startup.
  The affected owner degrades to a typed, logged state and rebuilds from
  canonical or seeded data.

## Proven by

- `crates/chainstate/src/transition.rs` (planned): owns the durable root, the
  ordered commit protocol, and the publication fence.
- `crates/chainstate/src/recovery.rs` (planned): owns schema admission,
  `incompatible_schema` refusal, and `CURRENT_SCHEMA` increment logic.
- `crates/node/tests/overhaul_crash_matrix.rs` (planned): exercises the
  `RCV-04` crash and lost-write points, including process kill, lost and
  partial writes, and ambiguous durable completion.
- `crates/node/tests/overhaul_streaming_reorg.rs` (planned): covers
  `RCV-05`, `RCV-08`, and bounded disconnect and reorg memory.
- `crates/node/tests/overhaul_checkpoint_independence.rs` (planned):
  validates fresh replay, schema refusal, and checkpoint authority removal.
- `crates/storage/tests/overhaul_atomic_durability.rs` (planned): tests the
  storage-level prior-or-whole-proposed rule and durable batch completion.
- `crates/node/src/txindex_worker_recovery_tests.rs` (existing):
  - `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
    (`RCV-05`);
  - `tip_change_during_rebuild_converges_on_new_tip` (`RCV-06`);
  - `missing_disconnected_body_routes_rewind_to_rebuild` (`RCV-07`);
  - `selective_rebuild_leg_survives_sibling_rollback` (`RCV-05`).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
ordered commit protocol, durable root, `DurableHead`, `CommitId`,
`CapabilityState`.
