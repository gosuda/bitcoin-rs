# Atomic durability

The node commits a block when one atomic key-value batch writes the head, undo records, body locators, attestation, and coin replacements into the storage engine. Bodies reach disk before that batch; the published tip comes after it. A crash before the batch leaves the previous head, a crash after it leaves the new one, and the next start reads the committed head and coins directly from the engine.

[`RCV-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-02-ordered-commit-protocol) owns the ordered protocol, [`RCV-03`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-03-prior-or-whole-proposed-and-orphan-tails) owns prior-or-whole-proposed resolution, and [`SYNC-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md#sync-05-validateddurable-progress-and-coherent-cross-consumer-views) owns commit-before-publish.

## The commit point is one atomic batch

`DurableHead` carries `commit_id`, `height`, `tip`, `chain_tx_count`, an optional body extent, an optional undo extent, and the assumeutxo disk status (`crates/storage/src/durable_head.rs`). The stored form is a fixed frame: magic `BRSD`, format version 4, CRC32C over the payload, then big-endian fields with the tip hash in little-endian byte order. `KvDurableHeadStore::load` refuses a row it cannot decode with `StorageError::IncompatibleData`.

`CommitAuthority::commit_prefix` builds one atomic batch containing:

- undo rows keyed by `block_undo_key(height, block_hash)` in `UndoData`;
- body locator rows keyed by `(height, block_hash)` in `BLOCK_DATA_CF`, each a 16-byte `BlockFilePosition`;
- a `blkfile<file_no>` maximum-height row for every block file named by those locators;
- the 9-byte `node:script-attestation` row, a commit id plus one level;
- coin replacements for every touched txid in `Coins` (deletes for fully spent txids, serialized `UtxoRecord` for surviving outputs);
- the new `node:durable-head` row.

The batch goes through `write_durable_if` with `WriteCondition::Equals` on the previous encoded head, or `Absent` for the first commit. If the condition fails, the commit returns `CommitError::PreconditionFailed` and writes nothing. Ambiguous storage failures permanently close admission (`CommitAuthority::close_admission`).

The successful return of that atomic batch is the commit point: cache installation (`CoinStore::install_committed`) runs strictly after durable success. Every earlier write is preparation, and every later step is derived or publication.

## Write order for one connect

```text
validate -> append body frames (deferred locator rows)
         -> sync block files and their directory
         -> atomic batch: undo rows + locators + max heights + attestation + coins + head
         -> install committed delta into coin cache
         -> receipt certifies the tip
         -> publish the applied tip to readers
```

1. During validation, `IndexedBlockBodyStore::persist_block_body` appends a framed record to `blocks/blkNNNNN.dat` and writes the locator row with `write_deferred`. The frame is a 44-byte header (`BRSB`, length, height, hash) followed by the block bytes.
2. `sync_appended_blocks` flushes the writer, calls `sync_data` on the active file, and syncs the `blocks` directory when it created a new file.
3. `CommitAuthority::commit_prefix` executes the atomic batch with head, attestation, undo rows, body index, and coin replacements.
4. On success, `CoinStore::install_committed` updates the byte-bounded `CoinCache`.
5. The returned `DurableReceipt` certifies the cumulative transaction count on the outgoing tip, so publication cannot carry a count the head did not commit.
6. `publish_applied` swaps the applied tip and wakes waiters. Until this line, a concurrent reader sees the previous tip.

IBD groups a verified prefix into one atomic commit. `DURABLE_HEAD_GROUP_BLOCKS` is 64 blocks and `DURABLE_HEAD_GROUP_MAX_BYTES` is 8 MiB of block data, whichever comes first. The group syncs the bodies once, then commits the whole prefix in one atomic batch.

## What each crash window leaves

| Crash point | On disk after restart | What recovery does |
|---|---|---|
| Mid-frame body append | A tail shorter than one frame in the active block file; no head names it | Scans from the committed extent, truncates the tail, logs `discarding incomplete block-file tail` |
| Body synced, head batch not applied | Body frames and possibly deferred locator rows; old head | Opens at the old head; the unreferenced frame is dead bytes, and the block is appended again when it is next applied |
| Head batch applied, publication lost | New head row, undo rows, locators, attestation, coins | Compares the head with the restored tip and replays the gap; no new head is written for gap blocks |
| Batch outcome ambiguous | Engine resolves to the prior or the wholly proposed root | Admission closes permanently; restart reads whatever the engine made durable |

## Fatal versus operational

`ChainTransition::settle_apply` closes the node for recovery when `classify_apply_error` returns `Fatal`. `fail_closed_for_recovery` does two things: `admission.close_permanently()` and `request_shutdown()`. It does not rewrite the head or roll anything back. `getblockchaininfo` then reports `is_apply_halted: true` until the process exits, and the next start replays durable state with a clean engine.

| Class | Examples | Effect |
|---|---|---|
| Fatal | `DurableHeadCommit`, `DurableHeadLineage`, `DurableHeadGapUnrecoverable`, `BlockBodyPersistence`, `UndoPersistence`, `UtxoCommit`, `RecoveryPublication` | Admission closes permanently, shutdown is requested, no retry is scheduled |
| Operational | `Shutdown`, `ConcurrentChainChange`, `PrevHashMismatch`, `UndoLoad`, `DisconnectNotTip`, `PruneDuringHistoricalValidation` | The caller sees an error; the node keeps running or retries under its owning mechanism |
| Permanent | `ProofOfWork`, invalid chain or consensus outcomes | The block and its descendants are invalid; storage is untouched |

The full mapping is `classify_apply_error` (`crates/execution/src/window.rs`). A failed disconnect after mutation began is separate: `DisconnectError::Fatal` and `MarkerStuck` also call `fail_closed_for_recovery`.
## Failure modes

- Head row undecodable: open refuses with `durable head row is unreadable; refusing to treat it as absent`. Nothing is repaired in place; the [datadir policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md) applies.
- Failed compare-and-set: `durable head moved since it was read`. The batch wrote nothing, so the loser of a race retries against the new head.
- Wrong lineage: `durable head names tip {head}, not this block's parent {prev}`. The block is not applied and the head is unchanged.
- Unrecoverable gap: `durable head {head_tip} at height {head_height} cannot be reconciled with restored tip ...: {reason}`. Reasons include a missing committed body, a body that does not hash to its committed hash, and a head chain that does not descend from the restored tip. The node fails closed rather than guessing.

## Where the invariant is proven

- `RCV-01`, `RCV-02`, `RCV-03`, `RCV-04`, `RCV-09`, `SYNC-05`, `ARCH-07`, and the datadir policy own the rules above.
- `crates/execution/src/durable/tests.rs::committed_gap_replays_to_head_without_recommitting_it` proves replay reuses the receipt instead of recommitting.
- `committed_gap_with_missing_body_fails_closed`, `committed_gap_body_must_hash_to_the_head_identity`, `committed_gap_must_descend_from_restored_tip`, `committed_gap_replay_failure_fails_closed`, and `cold_replay_attestation_failure_fails_closed` in the same module prove the refusal paths.
- `crates/execution/src/tests/window_commit_tests.rs::failure_at_block_j_commits_prefix_before_j` proves a failed prefix commits exactly the blocks before the failure, and `crash_between_commit_and_cache_install_reloads_from_engine` proves the restarted node rebuilds the coin cache from the engine rather than from memory.
- `crates/storage/tests/overhaul_atomic_durability.rs::rocksdb_injected_faults_never_mix_families` proves an injected fault at apply, sync, or flush boundaries never leaves a mixed batch.
- `crates/node/tests/crash_recovery.rs::pruned_frontier_survives_sigkill_and_preserves_boundary` proves the process-level kill path; `run_sigkill_scenario` is the driver.

## Boundaries

`SIGKILL` is not power loss. The fault matrix injects lost, failed, and partial writes around apply, sync, and flush, but it runs in one process on one filesystem; device-cache behaviour is unmeasured here. No group-commit latency measurement backs the 64-block redo bound; that bound is a constant in `crates/execution/src/window.rs`, not a measured figure.

Pruning deletes the bodies and undo records this chapter leans on, so the next chapter is [Pruning](pruning.md).
