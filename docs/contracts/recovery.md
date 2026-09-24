# Recovery contract

How the node recovers an authoritative chainstate after a crash, a lost
write, a reorganization, or an incompatible datadir. The chainstate is
the single durable authority. `crates/chainstate` owns the ordered commit
protocol over the storage durable head. That head certifies ordering and
high-water bounds, not coin contents. If startup restores no chainstate while
a durable head still exists, `reconcile_at_boot` replays the head chain
from genesis out of the durable bodies it certifies — coins are durable
only through the checkpoint export, so the head is the only surviving
authority — and a missing or mismatched body fails closed. Every
other persisted component is derived and reconciles to it.

Owners:
- Authoritative durable root and ordered commit protocol:
  `crates/chainstate/src/connect.rs`, `disconnect.rs`, and `durable.rs`
- Recovery and schema admission: `crates/chainstate/src/recovery.rs`;
  process-composition tests remain in `crates/node/tests/unit/state/tests/`
- Persistent coin transition boundary: `crates/utxo/src/set.rs`
  (transition types); durable form in
  `crates/storage/src/durable_head.rs`
- Crash and lost-write fault tests:
  `crates/node/tests/crash_recovery.rs`
- Reorg and disconnect: `crates/chainstate/src/reorg.rs` and
  `crates/chainstate/src/disconnect.rs`
- Checkpoint publication and recovery:
  `crates/chainstate/src/checkpoint.rs`, its checkpoint companions,
  and `crates/storage/src/checkpoint/`
- Index worker recovery: `crates/index/src/runtime/recovery_tests.rs`
- Policy: `docs/policies/db-migration.md`

## Durable root

The authoritative durable root is:

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

`DurableHead` is the persisted form, landed in
`crates/storage/src/durable_head.rs` as one versioned, CRC32C-framed row in
the `UtxoMeta` family of the chainstate key-value store:

```rust
struct DurableHead {
    commit_id: u64,
    height: u32,
    tip: Hash256,
    chain_tx_count: u64,
    body_extent: Option<BodyExtent { file_no: u32, offset: u64 }>,
    undo_extent: Option<(u32, Hash256)>,
}
```

The row carries a format version byte and a checksum over its payload; any
malformed row fails closed at load instead of decoding to absence. The head
record lives in the chainstate key-value store and the ordered protocol is
owned by `crates/chainstate`.

One connect or disconnect commits one atomic named-family batch whose
`write_durable_if` receipt covers the head row, the block's undo row, and its
body locator row; the appended body bytes and the blocks directory are synced
before the batch may name them. The coins themselves commit in memory and
become durable through the checkpoint export; the undo and body records in
the batch are what make a committed tip recoverable. The chainstate journal
is derived from this batch and may lag it, never lead it. `commit_id` is
strictly monotonic on disconnect as well as on connect: a reorg lowers
`height`, never `commit_id`.

## Clauses

### `RCV-01`: Authority and identity

- The chainstate is the only authoritative position. `crates/chainstate`
  owns that position and its commit/recovery protocol. Block bodies,
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
8. Dispatch notifications and relay in the declared observable order outside
   all domain locks.

A failure before stable publication leaves the fence closed until explicit
recovery. A guard destructor must never quietly reopen the fence after an
error. A live `submitblock` success waits for durable body, undo, and head
completion: `apply_block` returns only after the batch receipt, and the
returned `ConnectOutcome.commit_id` is the receipt's id. IBD may group a
bounded verified prefix; only committed prefixes are published. The group
caps are stated constants, not emergent cadence:
`DURABLE_HEAD_GROUP_BLOCKS` = 64 blocks or `DURABLE_HEAD_GROUP_MAX_BYTES` =
8 MiB of block data, whichever first — one durable batch every one to two
seconds at IBD rates, and a crash-redo bound of at most 64 body re-applies.
This is the ordered commit protocol. It is also called the durable root
recovery contract.

### `RCV-03`: Prior-or-whole-proposed and orphan tails

- The storage engine resolves an outstanding atomic batch to the prior root
  or to the wholly proposed root. It never mixes a new head with old coins,
  or a new coins set with old head.
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

The crash and error points in this contract and
`docs/policies/db-migration.md` produce exactly these results:

| Crash or error point | Recovery result |
|---|---|
| Body append mid-frame | The in-progress frame is discarded on next start; no durable head references it. |
| Undo append mid-frame | Same as body append; partial undo is not the authoritative head. |
| Sync before durable batch | The atomic batch contains only data that reached the OS; any missing body or undo prevents commit. |
| Durable batch complete, no publish | Restart sees the new head, coins, and `refs`; mempool and index reconcile. |
| Durable batch ambiguous | Recovery resolves the ambiguity by `CommitId` and full identity; no mixed head/coins. |
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
- Chainstate owns planning, body retention/loading, mutation, invalidation, and
  disconnect-debt settlement. Node-owned observers receive each committed
  connect/disconnect to reconcile mempool, mining, RPC/ZMQ, and index wakes.
  Those observers are not recovery authority and cannot widen chainstate's
  dependency graph.

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

- Full-checkpoint publication is not recovery authority.
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

### `RCV-12`: Recovery evidence warning and marker ordering

- The storage-owned `RecoveryEvidencePublisher`
  (`crates/storage/src/recovery_evidence.rs`) owns warning rendering, the
  warning snapshot, the marker/witness codec, and the atomic write
  protocol; it is evidence publication, not chainstate authority. It
  publishes a recovery fact only after the restored authoritative position is
  known; neither the warning store nor the marker may move chainstate. The
  node crate keeps `RecoveryReporter` (`crates/node/src/recovery_reporter.rs`)
  as the composition adapter implementing `IndexAheadSink` and
  `RollbackWarningSource`.
- For checkpoint fallback and index-watermark-ahead evidence, the publisher
  first renders/logs the warning and updates the process-visible warning
  snapshot, then attempts the atomic durable marker write.
- Marker persistence failure is returned to the caller and keeps the warning
  visible for the lifetime of that process. Callers that require durable
  evidence fail closed rather than pretending the marker succeeded.
- Marker and applied-tip-witness payloads are checked against `MAX_FILE_BYTES`
  after being read; marker publication uses the owner-local atomic
  write/rename/directory-sync protocol. Corrupt or mismatched evidence is
  rejected instead of silently becoming authority.
- Tests for recovery evidence must cite this clause (and `RCV-04` where they
  exercise crash/failure behavior) so extracted test modules do not become an
  independent specification.

### `RCV-13`: Chain transaction count recovery

The in-memory chain transaction count uses zero as the durable-compatible
sentinel for unknown. Legacy datadirs that predate the counter, rewinds that
would underflow, and additions that would overflow must preserve or restore
zero; they must never clamp or wrap into a plausible known total. A known
count advances and rewinds by the exact transaction delta.

### `RCV-14`: Checkpoint reconcile against the durable head

The checkpoint publisher freezes the published state, which always trails or
meets the durable head: publication follows the batch. Before writing, the
publisher loads the head and refuses a checkpoint whose tip is at or above
the head without being certified by it. A tip below the head is the
committed-but-unpublished gap a crash can leave; checkpointing the older
state is harmless and keeps the node operating until replay closes the gap.

### `RCV-15`: Disconnect marker recovery

A surviving disconnect marker is recovery evidence, not a permanent
operator refusal. The durable head is the commit point, and `RCV-14` keeps
every published checkpoint at or below it, so the restored state is
self-consistent and at worst stale: startup replays the authenticated head
chain onto it (`reconcile_at_boot`), warns with the marker identity,
publishes a clean checkpoint, and retires the marker only after that
publication is durable. Whether the head still certifies the disconnected
tip or its parent decides only what the warning reports.

- An unreadable marker or head, no head at all, or a restored state that
  does not sit below an authenticated head is divergence, not lag: recovery
  fails closed, retains the marker, and startup stops. No partial success
  serves.
- `InFlight` stays barred from ordinary checkpoint publication; only the
  recovery transaction may publish over it, and only after the replay
  succeeded. Retirement is an unconditional clearing owned by that recovery
  path alone.
- Core v31.1 reconstructs interrupted branch state the same way:
  `Chainstate::ReplayBlocks` reads the two persisted heads, rolls the
  restored coins back to the fork point, replays the active chain forward,
  and flushes the result
  (`bitcoin-core/src/validation.cpp:4792-4880`). An interrupted disconnect
  is replayed, not deleted.

## Proven by

- `crates/chainstate/src/durable.rs`: owns the durable-head
  advance for connect, group, and disconnect commits, the lineage fence, and
  the boot reconciliation of the stored head. `reconcile_at_boot` replays a
  committed-but-unpublished gap from the durable bodies the stored head
  chain names — any authenticated width above a restored tip, applied
  through the ordinary commit path with the head suppressed
  (`PublishMode::Replay`), publishing only the state the head already
  certifies — replays the whole head chain from genesis when no chainstate
  was restored, and fails startup closed on a gap that is not an ancestor
  prefix of stored bodies (`RCV-02`, `RCV-04`).
- `crates/chainstate/tests/unit/durable_replay_tests.rs`:
  - `committed_gap_replays_to_head_without_recommitting_it` proves replay
    lands exactly on the stored head and consumes its existing `commit_id`
    instead of issuing a second durable receipt;
  - `committed_gap_with_missing_body_fails_closed` proves a stored head whose
    named body is gone is rejected without advancing the restored applied tip;
  - `cold_chainstate_replays_head_chain_from_genesis` proves a durable head
    with no restored chainstate replays its certified bodies from genesis
    and consumes the existing `commit_id`;
  - `cold_chainstate_with_missing_genesis_body_fails_closed` proves a cold
    chainstate whose head chain names a missing body still fails closed
    with no applied tip published;
  - `committed_gap_replay_failure_fails_closed` proves an apply failure inside
    the replay transition closes admission and leaves `begin_transition`
    refusing with `ApplyError::Shutdown`.
- `crates/chainstate/src/connect.rs` and
  `crates/chainstate/src/disconnect.rs`: run the `RCV-02` tail —
  sync, one atomic batch, derived journal emission, then publication — and
  keep the durable root with the mutation authority (`ARCH-07`).
- `crates/storage/src/durable_head.rs` (existing): owns the head record
  codec, the encoded-head fence, and the atomic batch contents.
- `crates/node/tests/overhaul_durable_head.rs` (existing): the `RCV-04`
  fault matrix for the durable head — every `PersistFault` at the
  connect-shaped and disconnect-shaped batch boundaries, fail-closed
  startup on a corrupted head row, durability before publication,
  commit-id monotonicity across restarts, and body reachability through
  the real block files.
- `crates/storage/tests/durable_head_store.rs` (existing): backend-level
  reopen, fence, and fault laws for the head store.
- `crates/chainstate/src/recovery.rs` orchestrates restart recovery and invokes
  schema admission; `crates/storage/src/checkpoint/fs.rs` owns the
  `incompatible_schema` refusal and the `CURRENT_SCHEMA` gate.
- `crates/node/tests/crash_recovery.rs`: the `RCV-04` crash
  points — SIGKILL restart across journal, reorg, and publication scenarios,
  partial-write handling, and upgrade-matrix fallback;
  `torn_disconnect_replays_parent_tip` and `torn_disconnect_cold_replays_head`
  prove automatic marker recovery to the certified head (`RCV-15`), and
  `checkpoint_fallback_replays_wide_gap_to_durable_head` proves an
  authenticated gap of any width replays from stored bodies (`RCV-10`).
- `crates/node/tests/unit/state/tests/recovery.rs`:
  `restart_without_periodic_publication_restores_tip_and_commit_id` proves
  the durable head replays past the last checkpoint with `commit_id`
  preserved across restarts (`RCV-10`).
- `crates/chainstate/src/reorg.rs` and `crates/chainstate/src/disconnect.rs`
  cover `RCV-05` and bounded disconnect/reorg memory; `RCV-08`'s bounded
  stream windows and retention leases are exercised by the node sync/recovery
  scenarios together with the #655 boot-replay tests above.
- Checkpoint publication and recovery:
  `crates/chainstate/tests/unit/checkpoint/tests/` covers consensus-valid active-chain
  replay, applied-ancestry selection, competing-fork rejection, and
  immutable-generation resume, including
  `failed_publication_preserves_current`;
  `crates/chainstate/tests/unit/checkpoint_debt_tests.rs`
  `checkpoint_refuses_inflight_disconnect_and_preserves_state` proves an
  `InFlight` marker refuses publication with marker, `CURRENT`, and
  generations untouched; `crates/node/tests/unit/lifecycle/tests.rs`
  `shutdown_checkpoint_io_failure_is_returned_and_preserves_current` proves
  clean-shutdown publication errors propagate through `run` without skipping
  worker teardown; `crates/storage/src/checkpoint/tests.rs`
  covers generation publication, failpoint preservation, and
  manifest/artifact validation. This replaces the retired `overhaul_*`
  checkpoint-independence row.
- `crates/storage/tests/overhaul_atomic_durability.rs` (existing): tests the
  storage-level prior-or-whole-proposed rule and durable batch completion.
- `crates/index/src/runtime/recovery_tests.rs` (existing):
  - `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up`
    (`RCV-05`);
  - `tip_change_during_rebuild_converges_on_new_tip` (`RCV-06`);
  - `missing_disconnected_body_routes_rewind_to_rebuild` (`RCV-07`);
  - `selective_rebuild_leg_survives_sibling_rollback` (`RCV-05`).

- `crates/node/tests/overhaul_fee_history.rs` (existing):
  - `restart_adopts_persisted_estimator_history`,
    `corrupt_history_file_degrades_to_insufficient_data` (`RCV-11`);

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
ordered commit protocol, durable root, `DurableHead`, `CommitId`,
`CapabilityState`.
