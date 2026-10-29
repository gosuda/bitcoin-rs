# Recovery contract

How the node recovers an authoritative chainstate after a crash, a lost write, a reorganization, or an incompatible datadir. The chainstate is the single durable authority. `crates/chainstate` owns the ordered commit protocol over the storage durable head. That head certifies ordering and high-water bounds, not coin contents. If startup restores no chainstate while a durable head still exists, `reconcile_at_boot` replays the head chain from the newest accepted checkpoint out of the durable bodies it certifies (or from genesis when no checkpoint is accepted). Coins are recovery artifacts and the durable head remains the only surviving authority; a missing or mismatched body fails closed. Every other persisted component is derived and reconciles to it.
For an AssumeUTXO historical role, the durable head may name a complete historical checkpoint in the isolated `assumeutxo-historical-checkpoints` namespace. Startup restores that checkpoint before replaying any remaining certified historical suffix; an unreferenced generation is ignored.

Owners: authoritative durable root and ordered commit protocol (`crates/chainstate/src/connect.rs`, `disconnect.rs`, `durable.rs`); recovery and schema admission (`crates/chainstate/src/recovery.rs`, with process-composition tests in `crates/node/tests/unit/state/tests/`); persistent coin transition boundary (`crates/utxo/src/set.rs`, durable form in `crates/storage/src/durable_head.rs`); crash and lost-write fault tests (`crates/node/tests/crash_recovery.rs`); reorg and disconnect (`crates/chainstate/src/reorg.rs`, `disconnect.rs`); checkpoint publication and recovery (`crates/chainstate/src/checkpoint.rs` and companions, `crates/storage/src/checkpoint/`); index worker recovery (`crates/index/src/runtime/recovery_tests.rs`); policy (`docs/policies/db-migration.md`).

## Durable root

The authoritative durable root is:

```text
R = (tip, height, CommitId, coins_version, coins, body_extent, undo_extent, refs,
     historical_checkpoint)
```

`tip` is the 32-byte block hash of the applied tip; `height` is the block height as a compact big-endian integer. `CommitId` is a strictly monotonic durable serial advancing on every committed connect and every committed disconnect. `coins_version` equals the current `CommitId` at commit time, never derived from coin contents. `coins` is the authoritative UTXO set, keyed and valued as defined in `crates/utxo`. `body_extent` and `undo_extent` are the committed durable high-water bounds for body and undo segment files. `refs` maps `(height, block_hash, Body|Undo)` to the durable byte range in the matching segment file; undo and body references include the block hash, never height alone. `historical_checkpoint` optionally names a complete historical checkpoint generation with its generation, height, and hash.
`DurableHead` is the persisted form, landed in `crates/storage/src/durable_head.rs` as one versioned, CRC32C-framed row in the `UtxoMeta` family of the chainstate key-value store:

```rust
struct DurableHead {
    commit_id: u64,
    height: u32,
    tip: Hash256,
    chain_tx_count: u64,
    body_extent: Option<BodyExtent { file_no: u32, offset: u64 }>,
    undo_extent: Option<(u32, Hash256)>,
    assumeutxo: AssumeUtxoDiskStatus,
}
```

The row carries a format version byte and a checksum over its payload; any malformed row fails closed at load instead of decoding to absence. The head record lives in the chainstate key-value store and the ordered protocol is owned by `crates/chainstate`.
One connect or disconnect commits one atomic named-family batch whose `write_durable_if` receipt covers the head row, the block's undo row, its body locator row, and block-file maximum-height rows; the appended body bytes and the blocks directory are synced before the batch may name them. The coins themselves commit in memory and become durable through the checkpoint export; the undo and body records in the batch are what make a committed tip recoverable. The chainstate journal derives from this batch and may lag it, never lead it. `commit_id` is strictly monotonic on disconnect as well as on connect: a reorg lowers `height`, never `commit_id`.
AssumeUTXO activation and historical archive updates use the same transition reservation but separate recovery namespaces. The manager holds a required persistent data directory, and activation archive writes, full-revalidation marker checks, reservation cleanup, and historical checkpoint maintenance always use it. The required path guarantees a directory was supplied, not filesystem health; missing or corrupt files fail at use. Activation first syncs immutable `coins.dat` and `headers.dat` under `assumeutxo/<base_hash>/`, then commits the pinned base, count, and lifecycle in the head. An unreferenced import is an orphan, never a checkpoint or activation authority. Historical updates advance `commit_id` without changing the active tip. Each new candidate body is synced and referenced as pending before validation; its locator becomes visible to derived readers only with the validated undo/progress batch. An unresolved pending check is reconstructed and completed during startup, before service admission, even if the preceding process could not persist its terminal failure; discarding an intermediate intent could forget a consensus failure whose `Failed` receipt was lost, below the base as well. When the durable head names a historical checkpoint, startup restores its UTXO, CoinStats, and applied tip, then replays only the validated archive suffix. Checkpoint publication and its durable-head reference are ordered so an unreferenced generation is ignored after a crash. Publication retains older historical generations until the durable-head batch accepts the replacement. Startup opens the generation named by that head directly, even when `CURRENT` leads it; cleanup runs only after head commit. A missing or corrupt named checkpoint fails closed rather than attaching an unverified height to empty coins. Without an accepted checkpoint, reconstruction can still delay startup by the full historical prefix. Already archived blocks replay without another pending/archive write.
Snapshot activation refuses while the full-revalidation marker is present, including a recheck under transition exclusion before committing its anchor. The marker and pre-activation head remain intact on refusal. Snapshot recovery validates the root's network pin, restores a compatible checkpoint or verifies the immutable snapshot archive, and replays the root-certified foreground suffix. A full-revalidation marker still overrides incremental recovery. The pre-activation journal cannot extend a snapshot jump and is detached. Historical coins are restored from the head-accepted checkpoint and retained bodies supply only the remaining suffix; durable archive progress never pretends to be a recovered coin set. Finalized history supplies ordinary undo/reorg behavior. A disconnect below the base clears the snapshot anchor in its head batch. These bytes use datadir schema epoch 2; older datadirs are refused without conversion. A checkpoint exactly at the pinned snapshot base must match its commitment and transaction count and must contain no coin created above that base height. Recovery uses the same height-bounded commitment traversal as snapshot activation and immutable archive restoration; valid file checksums do not waive this rule.
Ordinary and historical checkpoints share the same generation and manifest-digest reference and manifest/artifact verification. The ordinary owner selects that reference through `CURRENT`; historical recovery uses the durable head's reference directly, even when `CURRENT` is ahead. Historical publication explicitly retains generations until the new reference commits. Retirement runs after that commit and again at startup after the accepted generation has been validated, using the same cleanup routine without a second durable cleanup record. After `Finalized` commits, the historical namespace's recognized generations, staging files and `CURRENT` are removed. Startup retries this cleanup for a committed `Finalized` head. Cleanup failures are warnings, not recovery failures; ordinary checkpoints and unknown files are preserved.
Proof: `crates/chainstate/tests/unit/assumeutxo_tests.rs` (commitment verification, isolated replay, terminal-write failures, role guards); `assumeutxo_recovery_tests.rs` (real-storage restart, process-kill boundaries, lost failure receipts, root-preserving archive replay, checkpoint pin binding, pruning and below-base reorg restart).

## Clauses

### `RCV-01`: Authority and identity

- The chainstate is the only authoritative position. `crates/chainstate` owns that position and its commit/recovery protocol. Block bodies, `txindex`, `scriptindex`, and undo or lookup metadata are derived.
- Every derived position is a `(height, block_hash)` pair, never height alone. Off the active chain, stale pairs rewind to the common ancestor, not to a height. With an headers-only absent tip, every row rewinds.
- The chain owns no position the chainstate has not durably committed. Checkpoints are a durable copy of the chainstate, never a second authority (see `RCV-10`).

### `RCV-02`: Ordered commit protocol

For one block, or a bounded fully verified prefix during IBD:

1. Hold the chain transition reservation; close admission and mixed reads with the generation fence.
2. Build exact forward and undo facts without mutating the public stable view.
3. Append required block-body frames. Sync the block files and required directory entries.
4. Apply one atomic storage batch containing the durable head row, undo rows, body locator records, and block-file maximum-height rows. Wait for durable completion. A successful commit on this nonempty batch makes prior deferred body-index writes on the same store durable with the head.
5. Publish the committed chain and coin view.
6. Feed the committed chain update into the mempool canonical lifecycle, update the fee estimator, and reconcile projections.
7. Publish the stable coherent generation only after mempool and projection alignment.
8. Dispatch notifications and relay in the declared observable order outside all domain locks.

Coins commit in memory rather than as rows in the durable-head batch; their durability comes from checkpoint export. Before the block-file sync in step 3, chainstate fires an optional staged-tip hook to enqueue prospective work: in `PublishMode::Now` only for a direct child of the published tip (reorg connects never match); in `PublishMode::Grouped` only for the newest block of the staged prefix immediately before the group sync (a failing window hands off only the last successful block); gated on the IBD latch in `crates/node/src/state/open.rs`; never in `PublishMode::Replay`. The hook enqueues without waiting; commit order is unchanged (sync in step 3, batch in step 4, publication in step 5, follower dispatch in step 8). Speculative projections never advance `tip` or `DurableHead`, publish no applied tip, advance no durable serials, and expose no candidate before durable commit.
Cache installation needs an authoritative committed receipt for the exact tip (matching txids and removal reasons, live full generation key); any mismatch, prioritisation, or failure discards the preparation for lazy assembly. In follower dispatch (step 8) a gatewayless connect publishes a truthful empty receipt at the same point. Receipt publication releases foreground waiters, including gatewayless connects.
A failure before stable publication leaves the fence closed until explicit recovery; a guard destructor must never quietly reopen the fence after an error. A live `submitblock` success waits for durable body, undo, and head completion: `apply_block` returns only after the batch receipt, and the returned `ConnectOutcome.commit_id` is the receipt's id. IBD may group a bounded verified prefix; only committed prefixes are published. Group caps are stated constants: `DURABLE_HEAD_GROUP_BLOCKS` = 64 blocks or `DURABLE_HEAD_GROUP_MAX_BYTES` = 8 MiB of block data, whichever first (one durable batch every one to two seconds at IBD rates; crash-redo bound of at most 64 body re-applies). Callers of `BlockBodyStore::sync` without a following durable batch on the body-index store must call `flush_index` after syncing the block files.
Boot-time durable-head replay runs before the journal maintenance worker starts. If retention pressure refuses a replay block, recovery releases its transition, publishes a marker-preserving progress checkpoint to compact the journal, reacquires the transition, verifies the applied tip is unchanged, and retries that same block once. The progress checkpoint does not retire the disconnect or full-revalidation marker. Intermediate replay tips retain the cumulative transaction count from their parent; only the landing tip adopts the head's certified count, so every progress checkpoint agrees with CoinStats. Failure to publish the checkpoint, reacquire the transition, preserve the captured tip, or apply the retry fails closed. Before genesis no progress checkpoint is possible. An empty cold writer hitting retention pressure with the full-revalidation marker present removes only invalidated, non-active journal segment generations and syncs the journal directory, preserving marker, head, and active cursor; append-gap admission and filesystem errors still fail closed. Other journal refusals (append gaps, unreadable state, corruption, storage/filesystem failures) never enter this checkpoint-and-retry path.
Proof: `crates/node/tests/mining/coordination.rs` (staged preparation, commit-time install, stale-race discard); `crates/chainstate/tests/unit/apply/` (grouped-window staging); `durable_replay_tests.rs` (gap replay never fires the staged-tip hook); `crates/mining/src/coordinator/tests.rs` (receipt install, mismatch fallback, waiter release); `crates/node/src/chain_effects.rs` (gatewayless empty receipt).

### `RCV-03`: Prior-or-whole-proposed and orphan tails

- The storage engine resolves an outstanding atomic batch to the prior root or to the wholly proposed root, never a new head with old coins or a new coins set with old head.
- A durable head never references a body or undo range that has not itself become durable.
- Files may hold orphan append tails, which are not authoritative. The root installs only after the required file and directory syncs and the atomic batch finish; a partial append past the head is no valid connect or disconnect.
- Startup loads the durable head before opening block files for tail recovery. The head's extent file must hold complete frames through its committed offset; a missing file, short prefix, or malformed frame refuses open with `StorageError::IncompatibleData` while preserving every block file. Only a torn append beyond that extent may be discarded, even when the restored checkpoint already matches the head. This framing scan covers the extent file and current append tail, not the historical archive; earlier pruned file gaps stay valid, and locator/body integrity checks keep their existing owners.
- On disconnect, `DurableHead.commit_id` advances past its previous value; monotonicity holds for connect and disconnect alike. Undo records key by `(height, block_hash)`, so replaying a side branch at one height never aliases the active branch's undo record.

### `RCV-04`: Crash matrix

The crash and error points in this contract and `docs/policies/db-migration.md` produce exactly these results:

| Crash or error point | Recovery result |
|---|---|
| Body append mid-frame | The in-progress frame is discarded on next start; no durable head references it. |
| Undo row written, head batch not committed | An undo row without a committed head reference is not authoritative. The head batch atomically commits the head and the undo rows it names. |
| Sync before durable batch | The atomic batch contains only data that reached the OS; any missing body or undo prevents commit. |
| Durable batch complete, no publish | Restart sees the new head, coins, and `refs`; mempool and index reconcile. |
| Durable batch ambiguous | Recovery resolves the ambiguity by `CommitId` and full identity; no mixed head/coins. |
| Publication callback lost | The durable root is still authoritative; mempool and index reconcile after restart. |
| Reorg stage 1: disconnect | Apply the exact per-block inverse; hold the fence until all disconnects commit. |
| Reorg stage 2: reconnect | Apply the new branch using ordinary connect; each connect advances `CommitId`. |
| Index watermark commit failure | The failure does not block ordinary chain progress; the affected capability reconciles. |
| Incompatible `CURRENT_SCHEMA` | `incompatible_schema` error at open; existing datadirs stay untouched. |

Tests must exercise actual process death and storage fault semantics in an isolated local environment. A process kill is not a substitute for simulated power loss. Fault-injection storage tests must exercise lost writes, partial writes, and failures around sync completion in addition to child-process kill tests.

### `RCV-05`: Deep rollback and selective rebuild

- A rollback deeper than the configured cutover resets the affected capabilities and rebuilds them from the durable root, never from a checkpoint. The rebuild phase stays published until the reset capabilities reach the applied tip again.
- Independent capabilities carry their own watermarks, so one may rebuild while a sibling rewinds; the rebuild leg outlives the rollback loop and stays published until reset rows reach the applied tip. The index runtime reconciles against the durable applied tip from `chainstate` and canonical retained bodies, never checkpoint authority.

### `RCV-06`: Tip change during rebuild

- The applied tip moving while a rebuild is in flight neither restarts nor aborts the rebuild; the worker converges on the new applied tip.
- The new target is identified by its full block hash and the durable `CommitId` from `chainstate`, never by height alone. A rebuild that already consumed canonical bodies re-uses valid prepared work; stale work is discarded.

### `RCV-07`: Missing disconnected body routes to canonical rebuild

- A rewind whose disconnected body is missing cannot produce exact-identity deletions. The affected capabilities reset and rebuild from canonical bodies instead of failing the worker.
- The worker fabricates no missing body bytes and substitutes no different block at the same height. Rebuild uses retained canonical bodies from the durable `refs` or an explicit archive input; a pruned node reports unavailable history.

### `RCV-08`: Exact disconnect and reorg

- Disconnect restores the pre-connect live coins, consensus bookkeeping, and metadata; reconnection applies the new branch with ordinary connect. Missing retained undo fails closed. Optional consumer lag cannot retain unlimited segments. Reorg memory stays bounded while depth grows; restart at each intermediate committed ancestor is valid.
- Streaming reorg uses bounded descriptors, before-images, and committed ancestors with exact inverse transitions, never a whole-branch preload. Chainstate owns planning, body loading, mutation, invalidation, and disconnect-debt settlement, taking the mandatory retention pin each transition needs; storage/pruning owns the retained-history authority those pins draw on (`ARCH-07`). Node-owned observers receive each committed connect/disconnect to reconcile mempool, mining, RPC/ZMQ, and index wakes; those observers are never recovery authority and cannot widen chainstate's dependency graph.

### `RCV-09`: Fresh replay and schema refusal

- The changed durable format requires a `CURRENT_SCHEMA` increment for the authoritative chainstate bytes. Keep no translator, legacy reader, or in-place converter. The one approved exception is the version-1 checkpoint header artifact (see "Checkpoint header artifact and side branches").
- An incompatible datadir returns `incompatible_schema` at open; existing operator datadirs stay untouched. A fresh replay uses a separately named directory with explicit resync instructions.
- `CURRENT_SCHEMA` covers only authoritative chainstate bytes. Estimator-only, discovery-only, and index-only format evolution keep it unchanged, each carrying its own owner-local version. A corrupt, missing, or unknown owner-local version never fails authoritative startup: estimator degrades to insufficient data, discovery to seeded or empty with reseed/rebuild status, an affected index capability reports unavailable or rebuilding through the existing `CapabilityState` vocabulary and rebuilds from retained canonical data. A rejected owner-local file is left in place until explicit authorized rebuild, never silently deleted.

### `RCV-10`: Checkpoint-worker removal

- Full-checkpoint publication is not recovery authority. The durable root and the ordered commit protocol are the only recovery authority. Checkpoints may remain as a maintenance and export command, but no code path treats a checkpoint as chainstate authority. Manual export and checkpoint commands still write a durable copy for operator convenience, not a new authority.

### `RCV-11`: Owner-local schema versions

- `CURRENT_SCHEMA` is the authoritative chainstate schema version, incrementing only when the durable root format changes. The fee estimator carries its own estimator-owned version; the P2P discovery store its own discovery-owned version; the index carries its own durability marker (`[0x00, b'V']`, currently row-format 5) with full-reset rebuild on mismatch. None of these increment `CURRENT_SCHEMA`.
- A missing or unknown owner-local version never fails node startup; the affected owner degrades to a typed, logged state and rebuilds from canonical or seeded data.

### `RCV-12`: Recovery evidence warning and marker ordering

- The storage-owned `RecoveryEvidencePublisher` (`crates/storage/src/recovery_evidence.rs`) owns warning rendering, the warning snapshot, the marker/witness codec, and the atomic write protocol; it is evidence publication, not chainstate authority. It publishes a recovery fact only after the restored authoritative position is known; neither the warning store nor the marker may move chainstate. The node crate keeps `RecoveryReporter` (`crates/node/src/state/storage.rs`) as the composition adapter implementing `IndexAheadSink` and `RollbackWarningSource` alongside the storage capabilities it adapts.
- For checkpoint fallback and index-watermark-ahead evidence, the publisher first renders/logs the warning and updates the process-visible warning snapshot, then attempts the atomic durable marker write. Marker persistence failure returns to the caller and keeps the warning visible for the life of that process. Callers needing durable evidence fail closed rather than pretending the marker succeeded. Marker and applied-tip-witness payloads are checked against `MAX_FILE_BYTES` after reading; marker publication uses the owner-local atomic write/rename/directory-sync protocol; corrupt or mismatched evidence is rejected instead of silently becoming authority.
- Tests for recovery evidence must cite this clause (and `RCV-04` where they exercise crash/failure behavior) so extracted test modules do not become an independent specification.

### `RCV-13`: Chain transaction count recovery

- The in-memory chain transaction count uses zero as the durable-compatible sentinel for unknown. Legacy datadirs predating the counter, rewinds that would underflow, and additions that would overflow must preserve or restore zero; they must never clamp or wrap into a plausible known total. A known count advances and rewinds by the exact transaction delta.

### `RCV-14`: Checkpoint reconcile against the durable head

- The checkpoint publisher freezes the published state, which always trails or meets the durable head, because publication follows the batch. Before writing, the publisher loads the head and refuses a checkpoint whose tip is at or above the head without being certified by it. A tip below the head is the committed-but-unpublished gap a crash can leave; checkpointing the older state is harmless and keeps the node operating until replay closes the gap.

### `RCV-15`: Disconnect marker recovery

- A surviving disconnect marker is recovery evidence, never a permanent operator refusal. The durable head is the commit point. `RCV-14` freezes each checkpoint against the head at its own moment, so a checkpoint can sit above a head that a later disconnect rewound below it: the restored state may lead the head, not only trail it. Recovery picks the one mode the restored state allows, and the warning names it:
- `cold-replay`: nothing was restored. The certified head chain is the whole state, and `reconcile_at_boot` replays it from genesis.
- `gap-replay`: the restored tip lies on the certified head's ancestor chain (the head itself included). The ordinary gap walk closes the committed-but-unpublished lag onto it.
- `checkpoint-rewind`: the restored tip is not on the head's ancestor chain: it leads the head, meets its height with another hash, or sits below it on a branch a reorg already left. Recovery rolls the restored coins back block by block against the undo rows the head batch certified (to the head, or to the fork it descends from, where reconciliation takes over) and never re-commits the head.
- Every mode warns with the marker identity and the mode chosen, publishes a clean checkpoint, and retires the marker only after that publication is durable.
- A restored tip that leads the head is recovery input, not divergence, and the rewind discards it. An unreadable marker or head, no head at all, a body or undo row the durable evidence does not hold, or a chain that is not an authenticated ancestor prefix of stored bodies is divergence: recovery fails closed, retains the marker, and startup stops. No partial success serves.
- `InFlight` stays barred from ordinary checkpoint publication; only the recovery transaction may publish over it, and only after the replay succeeded. Retirement is an unconditional clearing owned by that recovery path alone.
- Core v31.1 reconstructs interrupted branch state the same way: `Chainstate::ReplayBlocks` reads the two persisted heads, rolls the restored coins back to the fork point, replays the active chain forward, and flushes the result (`bitcoin-core/src/validation.cpp:4792-4880`). An interrupted disconnect is replayed, never deleted.

### Checkpoint header artifact and side branches

- The checkpoint header artifact restores the block tree, not only the active chain. `crates/chainstate/src/checkpoint/headers.rs` owns its layout; the manifest-bound artifact SHA-256 authenticates every byte, and no other file persists branch state.
- Version 2 is written: the active ancestry of the selected best tip, then every tree node off that ancestry that is not `Invalid`, whose chainwork does not exceed the selected best tip, and whose parent is retained (`BlockTree::replayable_side_nodes`), in insertion order. Invalid subtrees and branches heavier than the selected tip are excluded whole, so the restored tree selects the same best and applied tips as an active-only restore. Manifest `header_count` and both chain commitments still cover only the active ancestry.
- Restore replays the side section after the authenticated active section through the same historical contextual header validation. Each side header must add one new node under a restored valid parent and must not displace the best tip; a wrong length, duplicate or orphan header, failed validation, displaced tip, or manifest/artifact version mismatch is a corrupt checkpoint. Side nodes restore as header-valid with unknown chain transaction counts. Replay keeps their relative insertion order, which the stale-tip retainer uses as learn order.
- Version 1 (active ancestry only) remains readable and restores no side branches; the next publication writes version 2. No datadir epoch changes and no existing checkpoint is rewritten or deleted on load. A binary that predates version 2 refuses a version-2 checkpoint as corrupt, so downgrade needs a fresh resync into a separate datadir.
- Journal replay reuses a restored node with the record's hash and parent instead of inserting a duplicate, as block connection does.
- Proof: `crates/chainstate/src/checkpoint/tests/side_branches.rs` (valid side branches survive restart in learn order; version-1 loads branch-free; malformed side sections rejected); `chainstate_journal_replay.rs` (replay over a restored node reuses the held header).

## Proven by

- Durable-head advance, lineage fence, and boot reconciliation (`crates/chainstate/src/durable.rs`; `reconcile_at_boot` replays committed-but-unpublished gaps in `PublishMode::Replay`, whole head chain from genesis when cold, and fails closed on non-ancestor gaps): `RCV-02`, `RCV-04`. Gap/missing-body/apply-failure/append-gap rows: `crates/chainstate/tests/unit/durable_replay_tests.rs`. Grouped-window staging rows: `crates/chainstate/tests/unit/apply/`. `connect.rs`/`disconnect.rs` run the `RCV-02` tail (sync, one atomic batch, derived journal emission, publication) under mutation authority (`ARCH-07`). Head-record codec, encoded-head fence, atomic batch contents: `crates/storage/src/durable_head.rs`.
- Storage laws: `crates/storage/tests/overhaul_atomic_durability.rs` (prior-or-whole-proposed, batch completion; `RCV-02`, `RCV-03`); `crates/storage/tests/durable_head_store.rs` (reopen, fence, fault laws). Head fault matrix (every `PersistFault` at connect/disconnect batch boundaries, corrupt-head fail-closed, durability-before-publication, commit-id monotonicity, body reachability): `crates/node/tests/overhaul_durable_head.rs` (`RCV-04`). Schema gate: `crates/chainstate/src/recovery.rs` with `crates/storage/src/checkpoint/fs.rs` (`incompatible_schema`, `CURRENT_SCHEMA`).
- Crash points (SIGKILL restart across journal, reorg, publication; partial writes; upgrade-matrix fallback; torn-disconnect marker recovery to the certified head including checkpoint-above-rewound-head; wide-gap authenticated replay): `crates/node/tests/crash_recovery.rs` (`RCV-04`, `RCV-10`, `RCV-15`). Restart without periodic publication (tip plus `commit_id` preserved): `crates/node/tests/unit/state/tests/recovery.rs` (`RCV-10`); cold revalidation under journal pressure (progress compaction, marker preservation, pre-genesis restart): same suite (`RCV-02`). Journal segment lifecycle (progress preserves the full-revalidation marker; compaction cannot clear append gaps; cold retention preserves recovery): `crates/storage/src/chainstate_journal/writer/tests/segment_lifecycle.rs` (`RCV-02`, `JW-MARK-2`, `JW-ORDER-1`). Reorg/disconnect bounded memory and stream windows: `crates/chainstate/src/reorg.rs`, `disconnect.rs` (`RCV-05`, `RCV-08`).
- Pruning and retained-history authority (#1151): `node:prune_executed` holds the executed frontier (one past the highest deleted row), written atomically with its deletions; pre-first-pass all three prune records are absent and ordinary unpruned stores use an empty frontier; every pass (including empty) atomically writes frontier, requested `node:pruneheight`, and receipt; failed first commit leaves all absent; committed or ambiguous-applied passes leave all present; a missing frontier beside either other prune record (or a malformed frontier) refuses recovery without inferring a boundary; simultaneous loss of all three records is outside the atomic-write guarantee. `RetentionRegistry::reserve` is the single prune/retention linearization point and `PruneReservation::commit` the only path moving the executed line. Rows: `crates/storage/tests/prune_then_reorg.rs` (planning-vs-commit race, restart law, monotonicity, missing/corrupt refusal, empty-pass lifecycle, ambiguous-durability commits).
- Checkpoint publication and recovery: `crates/chainstate/src/checkpoint/tests/` (consensus-valid replay, ancestry selection, heavier-fork exclusion, immutable-generation resume, failed-publication preservation); `side_branches.rs` (restart retention, invalid exclusion, version-1 loading, side-section corruption); `chainstate_journal_replay.rs` (replay over restored node); `checkpoint_debt_tests.rs` (`InFlight` refusal); `crates/node/tests/unit/lifecycle/tests.rs` (shutdown checkpoint I/O errors propagate); `crates/storage/src/checkpoint/tests.rs` (generation publication, failpoint preservation, manifest/artifact validation). Retired `overhaul_*` checkpoint-independence row replaced.
- Estimator history: `crates/node/tests/overhaul_fee_history.rs` (`RCV-11` adopt/degrade rows). Speculative preparation (`RCV-02`): `crates/node/tests/mining/coordination.rs` (no-publish-before-commit, commit-time install, stale-race discard, staged shutdown); `crates/mining/src/coordinator/tests.rs` (receipt install/mismatch, waiter parking/release, panic release); `crates/node/src/chain_effects.rs` (gatewayless empty receipt).
- Index worker recovery: `crates/index/src/runtime/recovery_tests.rs` (ahead-of-tip report/rewind `RCV-04`; deep-rollback rebuild `RCV-05`; pruned-history frontier rebuild `RCV-07`).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md): ordered commit protocol, durable root, `DurableHead`, `CommitId`, `CapabilityState`.
