# Durability and the journal

The node commits a block when one atomic key-value batch replaces the `node:durable-head` row in the `UtxoMeta` column family. Bodies and undo records reach disk before that batch; the published tip and the journal record come after it. A crash before the batch leaves the previous head, a crash after it leaves the new one, and the next start either replays the committed gap or rewinds to it. The roles stay as [Chain state and storage](state-and-storage.md) describes them.

[`RCV-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-02-ordered-commit-protocol) owns the ordered protocol, [`RCV-03`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-03-prior-or-whole-proposed-and-orphan-tails) owns prior-or-whole-proposed resolution, and [`SYNC-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md#sync-05-validateddurable-progress-and-coherent-cross-consumer-views) owns commit-before-publish.

## The commit point is one row

`DurableHead` carries `commit_id`, `height`, `tip`, `chain_tx_count`, an optional body extent, an optional undo extent, and the assumeutxo disk status (`crates/storage/src/durable_head.rs:76`). The stored form is a fixed frame: magic `BRSD`, format version 4, CRC32C over the payload, then big-endian fields with the tip hash in little-endian byte order (`crates/storage/src/durable_head.rs:61-160`). `KvDurableHeadStore::load` refuses a row it cannot decode with `StorageError::IncompatibleData("durable head row is unreadable; refusing to treat it as absent")` (`crates/storage/src/durable_head.rs:243`). The node never reads a corrupt head as a fresh datadir.

`KvDurableHeadStore::commit` builds one batch containing:

- undo rows keyed by `block_undo_key(height, block_hash)` in `UndoData`;
- body locator rows keyed by `(height, block_hash)` in `BLOCK_DATA_CF`, each a 16-byte `BlockFilePosition`;
- a `blkfile<file_no>` maximum-height row for every block file named by those locators;
- the 9-byte `node:script-attestation` row, a commit id plus one level;
- the new `node:durable-head` row (`crates/storage/src/durable_head.rs:262-333`).

The batch goes through `write_durable_if` with `WriteCondition::Equals` on the previous encoded head, or `Absent` for the first commit. If the condition fails, the commit returns `StorageError::InvalidOperation("durable head moved since it was read")` and writes nothing. `write_durable` is a deferred write followed by `flush` on the engine. Two writers cannot both advance the tip, and the row, its undo rows, its locators, and its attestation land together or not at all. The successful return of that call is the commit point: every earlier write is preparation, and every later step is derived or publication.

The batch does not carry the coin set. The UTXO mutation happens in memory before the batch, and coin durability comes from checkpoint export; the batch names the undo and body records that make the mutation recoverable ([`RCV-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-02-ordered-commit-protocol)).

The attestation level in a commit is the weaker of the previous level and the level of this batch, so a batch that skipped scripts under an assume-valid anchor can never raise the recorded level (`crates/storage/src/durable_head.rs:262-280`). The row is bound to a `commit_id`; a row naming another commit id reads as `Unattested` (`crates/storage/src/durable_head.rs:44-58`).

`commit_connect_head` enforces lineage before it builds the batch: the stored head's tip must equal the new block's parent, otherwise it returns `ApplyError::DurableHeadLineage { head, prev }` (`crates/chainstate/src/durable.rs:55-107`). `commit_id` is the previous value plus one, or `1` for the first commit. A disconnect commits through the same row with the same monotonic rule (`crates/chainstate/src/durable.rs:110-156`).

## Write order for one connect

```text
validate -> append body frames (deferred locator rows)
         -> sync block files and their directory
         -> atomic batch: undo rows + locators + max heights + attestation + head
         -> receipt certifies the tip
         -> append journal record (failure only warns)
         -> publish the applied tip to readers
```

1. `prepare_journal_for_apply` runs before any write and is the only admission gate that exists to bound journal growth (`crates/chainstate/src/connect.rs:125`). It can refuse a block before the expensive validation runs, when the journal cannot accept another record.
2. During validation, `IndexedBlockBodyStore::persist_block_body` appends a framed record to `blocks/blkNNNNN.dat` and writes the locator row with `write_deferred`, so the locator becomes durable with the next durable batch on the same store (`crates/storage/src/block_body.rs:406-441`). The frame is a 44-byte header (`BRSB`, length, height, hash) followed by the block bytes (`crates/storage/src/block_file.rs:167-265`).
3. `commit_now` calls the optional staged-tip hook, then `sync_appended_blocks` (`crates/chainstate/src/connect.rs:923-941`). `FlatFileBlockStore::sync` flushes the writer, calls `sync_data` on the active file, and syncs the `blocks` directory when it created a new file (`crates/storage/src/block_file.rs:273-282`).
4. `commit_connect_head` runs the head batch with the undo bytes, body locators resolved by `stored_body_row`, and the attestation (`crates/chainstate/src/connect.rs:947-967`).
5. The returned `DurableReceipt` certifies the cumulative transaction count on the outgoing tip, so publication cannot carry a count the head did not commit (`crates/chainstate/src/durable.rs:14-33`).
6. `emit_journal_record` appends the journal record after the head batch and before publication (`crates/chainstate/src/connect.rs:742-754`, `1498-1527`). An append failure logs `chainstate journal append failed; recovery may fall back to full re-validation`, increments `node.chainstate_journal.append_failures`, and marks an append gap. The commit that already returned is not undone.
7. `publish_applied` swaps the applied tip and wakes waiters (`crates/chainstate/src/connect.rs:755`, `crates/chainstate/src/lib.rs:522-533`). Until this line, a concurrent reader sees the previous tip.

IBD groups a verified prefix into one head commit. `DURABLE_HEAD_GROUP_BLOCKS` is 64 blocks and `DURABLE_HEAD_GROUP_MAX_BYTES` is 8 MiB of block data, whichever comes first (`crates/chainstate/src/window.rs`). The group syncs the bodies once, then commits one head for the whole prefix, so a crash redoes at most 64 bodies.

## What each crash window leaves

| Crash point | On disk after restart | What recovery does |
|---|---|---|
| Mid-frame body append | A tail shorter than one frame in the active block file; no head names it | Scans from the committed extent, truncates the tail, logs `discarding incomplete block-file tail` (`crates/storage/src/block_file.rs:419-435`) |
| Body synced, head batch not applied | Body frames and possibly deferred locator rows; old head | Opens at the old head; the unreferenced frame is dead bytes, and the block is appended again when it is next applied |
| Head batch applied, publication lost | New head row, undo rows, locators, attestation | Compares the head with the restored tip and replays the gap; no new head is written for gap blocks |
| Batch outcome ambiguous | Engine resolves to the prior or the wholly proposed root | The fault matrix asserts no mixed families survive (`crates/storage/tests/overhaul_atomic_durability.rs`) |
| Torn journal `head.json` | Unreadable marker frame | Journal replay is rejected and the node restores the checkpoint; with no complete checkpoint the start fails closed (`crates/chainstate/src/recovery.rs:402-428`) |
| Journal segment longer than its durable offset | Torn record tail | `recover_active_segment` truncates to the offset; a shorter file refuses open (`crates/storage/src/chainstate_journal/writer/open.rs:107-138`) |

The body tail is not authoritative, and the code says so twice. At open, `open_with_committed_extent` first validates the prefix named by the head's `body_extent`; a missing file, a short extent, or a malformed frame refuses open with `committed block-file extent {file_no}:{offset} is missing or malformed; preserving block files` (`crates/storage/src/block_file.rs:715-734`). The store scans only bytes beyond that prefix and truncates an incomplete tail. A shorter active file after admission returns `committed block file shortened after extent admission; preserving block files` (`crates/storage/src/block_file.rs:419-423`).

Boot reconciliation is `recover_disconnect_marker` then `reconcile_at_boot` (`crates/chainstate/src/durable.rs:174-265`). Without a disconnect marker, a stored head equal to the restored tip returns immediately. Otherwise `replay_committed_gap` walks the head chain back to the restored tip by body hash and requires that the chain descends from the restored tip (`crates/chainstate/src/durable.rs:487-585`). `replay_gap_chain` re-applies each block with `PublishMode::Replay { receipt, certify_head }` (`crates/chainstate/src/durable.rs:627-707`). Gap blocks reuse the receipt from the durable head, so replay publishes the committed count and never commits a second head for the same blocks. With a disconnect marker, recovery picks one of `cold-replay`, `gap-replay`, or `checkpoint-rewind` and logs `automatic disconnect recovery replayed the certified head chain` with the mode (`crates/chainstate/src/durable.rs:189-245`).

Two sidecar files record suspicion, not state. `applied-tip-witness.json` carries a writer epoch, height, block hash, and time; `chain-rollback-event.json` records either a checkpoint fallback or an index watermark ahead of the restored tip (`crates/storage/src/recovery_evidence.rs:31-119`). `write_sidecar` writes a temporary file, syncs it, moves a valid current file to `.prev`, renames the temporary file into place, and syncs the directory; `read_sidecar` falls back to `.prev` (`crates/storage/src/recovery_evidence.rs:122-166`). A witness from an older writer epoch whose height exceeds the restored tip is a checkpoint fallback, not corruption (`crates/storage/src/recovery_evidence.rs:199-203`). [`RCV-12`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-12-recovery-evidence-warning-and-marker-ordering) owns the warning and marker ordering.

The [sync and recovery chapter](../run/sync-and-recovery.md) shows the `SIGKILL` transcript and the replay log line. The disk artifacts behind that line are the ones in the table: an old or new head row, body frames, undo rows, and a journal that never leads the head.

## The journal is derived and may lag

The chainstate journal records committed UTXO mutations so a restart can replay from a checkpoint without re-validating bodies. It is not a second authority. A journal head marker names a base checkpoint generation, a base height, and a cursor; records above the cursor are not committed (`crates/storage/src/chainstate_journal/writer.rs:155-170`). The marker frame is `JRNH`, version 1, CRC32C over a JSON payload, and it is rewritten by temporary file, `sync_all`, rename, then directory sync (`crates/storage/src/chainstate_journal/writer/durability.rs:22-45`). A damaged marker is reported as `chainstate journal head marker is unreadable: marker checksum mismatch: expected ..., found ...`.

The writer batches appends by block count and time and advances durability at a boundary. `try_advance_durability_upto` flushes the key-value store first, syncs the segment, then publishes the marker (`crates/storage/src/chainstate_journal/writer/durability.rs:74-141`). That order makes the journal head a receipt for rows already in the store. Defaults are 500 blocks, 5 seconds, 256 MiB per segment, 2048 MiB total, 500 blocks and 30 seconds of maximum lag (`crates/storage/src/chainstate_journal/writer.rs:19-42`).

At boot the journal has three outcomes. If the journal base generation does not match the restored checkpoint, replay returns `BaseMismatch` and the checkpoint is used alone (`crates/storage/src/chainstate_journal/replay.rs:8-33`). If a record in the committed range is torn or non-contiguous, replay fails closed with `committed journal range is invalid` and never truncates the committed prefix. If replay succeeds, the node reports `restore_source=journal` with `replayed_records` (`crates/chainstate/src/recovery.rs:374-465`). When the journal head is below the durable head, boot reconciliation replays the remaining gap from bodies and the journal stays behind; the next checkpoint publication compacts it.

A journal fork below the checkpoint base invalidates the generation, writes the `full-revalidation` marker, and refuses the append with `journal fork height {fork_height} is below checkpoint base {base_height}` (`crates/storage/src/chainstate_journal/writer/rewind.rs:21-36`, `186-211`). The next start takes the cold path; [`RCV-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md#rcv-02-ordered-commit-protocol) owns the script-attestation consequence.

## Retention and the one backpressure

`prepare_for_apply` measures the retained segment bytes. At or above `max_journal_mib` it returns `JournalWriterError::RetentionLimit { bytes, limit }` (`crates/storage/src/chainstate_journal/writer/retention.rs:52-78`). That error, and only that error, is classified as backpressure: `JournalWriterError::is_backpressure` matches `RetentionLimit` alone (`crates/storage/src/chainstate_journal/writer.rs:146-149`), and `classify_apply_error` maps a `JournalBackpressure` that is backpressure to `Operational` while every other journal error is `Fatal` (`crates/chainstate/src/window.rs:343-402`).

Backpressure has two release paths.

- Online: the chainstate maintenance worker ticks once per second, calls `requires_compaction`, and publishes a checkpoint through `CheckpointPublisher` (`crates/chainstate/src/maintenance.rs:25-80`). It logs `journal retention pressure; draining it through a checkpoint publication` once when pressure starts. Publication freezes the writer, compacts it to the checkpoint base, removes the retained segments, and resumes (`crates/storage/src/chainstate_journal/writer/retention.rs:163-318`, `crates/chainstate/src/checkpoint/publisher.rs:96-160`).
- During boot replay: a `RetentionLimit` refusal releases the transition, publishes a progress checkpoint that keeps the recovery markers, reacquires the transition, verifies the applied tip did not move, and retries the same block once (`crates/chainstate/src/durable.rs:589-625`). The log line is `compacted the chainstate journal during boot replay; retrying the refused block`, and the counter is `node.durable_head.recovery_backpressure_reliefs`. Every other journal refusal on that path fails closed.

An append failure is a third case, and it is not backpressure. The failed append marks `append_gap_height`; every later `ensure_appendable` returns `AppendGap { height }` (`crates/storage/src/chainstate_journal/writer.rs:325-336`). The next commit reaches `prepare_for_apply`, gets `JournalBackpressure(AppendGap)`, and settles `Fatal`. `append_failure_blocks_the_next_apply_before_an_untracked_hole_grows` pins that sequence.

## Fatal versus operational

`ChainTransition::settle_apply` closes the node for recovery when `classify_apply_error` returns `Fatal` (`crates/chainstate/src/lib.rs:460-470`). `fail_closed_for_recovery` does two things: `admission.close_permanently()` and `request_shutdown()` (`crates/chainstate/src/lib.rs:780-783`). It does not rewrite the head or roll anything back. `getblockchaininfo` then reports `is_apply_halted: true` until the process exits, and the next start replays durable state with a clean engine.

| Class | Examples | Effect |
|---|---|---|
| Fatal | `DurableHeadCommit`, `DurableHeadLineage`, `DurableHeadGapUnrecoverable`, `BlockBodyPersistence`, `UndoPersistence`, `UtxoCommit`, `RecoveryPublication`, any `JournalBackpressure` except `RetentionLimit` | Admission closes permanently, shutdown is requested, no retry is scheduled |
| Operational | `Shutdown`, `ConcurrentChainChange`, `PrevHashMismatch`, `UndoLoad`, `DisconnectNotTip`, `PruneDuringHistoricalValidation`, `JournalBackpressure(RetentionLimit)` | The caller sees an error; the node keeps running or retries under its owning mechanism |
| Permanent | `ProofOfWork`, invalid chain or consensus outcomes | The block and its descendants are invalid; storage is untouched |

The full mapping is `classify_apply_error` (`crates/chainstate/src/window.rs:343`); [`SYNC-04`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md#sync-04-failure-classification-and-recovery-semantics) owns the classification rule. A failed disconnect after mutation began is separate: `DisconnectError::Fatal` and `MarkerStuck` also call `fail_closed_for_recovery` (`crates/chainstate/src/lib.rs:486-499`).

> **Warning** A fatal settlement is not repaired by retrying the same RPC. The head is whatever the last durable batch left; only a restart re-runs reconciliation against that head.

## Worked trace

A regtest node was started on a throwaway directory, three blocks were mined, and the process was killed with `SIGKILL`. Data-directory paths below are shortened to `$DATA`.

```sh
$ bitcoin-rs --network regtest --data-dir $DATA --rpc-bind 127.0.0.1:41999 --dns-seeds-enabled=false
$ curl -s --user "$(cat $DATA/.cookie)" -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"generatetoaddress","params":[1,"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]}' \
  http://127.0.0.1:41999/
{"error":null,"id":"1","result":["05cd0c0af8043fe48413bb58d245a85e74d74ff79398c4cb135385189041fe7b"]}
```

After three such calls, `getblockchaininfo` reported `blocks: 3`, `headers: 3`, and that best block hash. The journal head marker left a readable record of what had committed:

```json
{"base_generation": 0, "base_height": 0, "base_hash": [...], "base_chain_tx_count": 1,
 "start_gen": 0, "start_offset": 0, "journal_gen": 0, "offset": 771,
 "height": 3, "block_hash": [123, 254, ...], "prev_hash": [81, 51, ...],
 "chain_tx_count": 4, "record_count": 3}
```

`offset: 771` equals the byte length of `segment-0000000000.log`, `record_count: 3` counts the three records, and `chain_tx_count: 4` counts genesis plus three coinbases. `block_hash` is the little-endian byte array of the same tip the RPC reported. `SIGKILL` then removed the process with no clean checkpoint, and the restart on the same directory logged:

```text
INFO bitcoin_rs_chainstate::recovery chainstate restore selected restore_source="cold" reason="no_complete_checkpoint"
INFO bitcoin_rs_chainstate::durable replayed the committed-but-unpublished gap; the node resumes on the stored head head_height=3 head_tip=05cd0c0a...fe7b blocks=4 commit_id=4
```

A clean shutdown after 300 regtest blocks also shows compaction. `SIGTERM` published generation 1, and the journal marker became:

```json
{"base_generation": 1, "base_height": 300, "start_gen": 1, "start_offset": 0,
 "journal_gen": 1, "offset": 0, "height": 300, "chain_tx_count": 301, "record_count": 0}
```

The retained segment was gone; `chainstate-journal/` held only `head.json`. The restart logged `restore_source="checkpoint" checkpoint_generation=1 checkpoint_height=300 ... replayed_records=0`. That is compaction working as designed: the checkpoint owns the base, and the journal starts empty.

## Failure modes

- Head row undecodable: open refuses with `durable head row is unreadable; refusing to treat it as absent`. Nothing is repaired in place; the [datadir policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md) applies.
- Failed compare-and-set: `durable head moved since it was read`. The batch wrote nothing, so the loser of a race retries against the new head.
- Wrong lineage: `durable head names tip {head}, not this block's parent {prev}`. The block is not applied and the head is unchanged.
- Unrecoverable gap: `durable head {head_tip} at height {head_height} cannot be reconciled with restored tip ...: {reason}`. Reasons include a missing committed body, a body that does not hash to its committed hash, and a head chain that does not descend from the restored tip. The node fails closed rather than guessing.
- Journal over its limit: repeated `chainstate journal backpressure stopped block apply` followed by one `journal retention pressure; draining it through a checkpoint publication`. If publication cannot run, apply stays refused; the head does not move.
- Journal append failure: one `chainstate journal append failed; recovery may fall back to full re-validation` warning, then the next apply settles fatal on the append gap.
- Journal directory damage: `active journal segment {name} is truncated: length {length} < durable offset {offset}`, or a `head marker checksum mismatch`. Replay is rejected and checkpoint recovery runs; if no checkpoint is complete, startup fails closed. A committed prefix is never truncated.

## Where the invariant is proven

- `RCV-01`, `RCV-02`, `RCV-03`, `RCV-04`, `RCV-09`, `SYNC-05`, `ARCH-07`, and the datadir policy own the rules above.
- `crates/chainstate/src/durable/tests.rs::committed_gap_replays_to_head_without_recommitting_it` proves replay reuses the receipt instead of recommitting.
- `committed_gap_with_missing_body_fails_closed`, `committed_gap_body_must_hash_to_the_head_identity`, `committed_gap_must_descend_from_restored_tip`, `committed_gap_replay_failure_fails_closed`, and `cold_replay_attestation_failure_fails_closed` in the same module prove the refusal paths.
- `committed_gap_append_gap_does_not_enter_retention_relief` proves only `RetentionLimit` takes the checkpoint-and-retry path.
- `crates/storage/src/chainstate_journal/writer/tests/segment_lifecycle.rs::partial_append_rolls_back_tail_and_restart_can_retry`, `torn_tail_beyond_head_is_ignored_on_reopen`, `rejects_reopen_when_active_segment_is_truncated`, and `rotation_head_never_names_a_missing_segment` prove the segment boundary rules; `crates/storage/src/chainstate_journal/writer/tests/durability_boundaries.rs::head_never_advances_without_counted_storage_flush` proves the flush precedes the marker.
- `crates/storage/tests/overhaul_atomic_durability.rs::rocksdb_injected_faults_never_mix_families` proves an injected fault at apply, sync, or flush boundaries never leaves a mixed batch.
- `crates/node/tests/crash_recovery.rs::sigkill_restarts_at_valid_journal_frontier` and `pruned_frontier_survives_sigkill_and_preserves_boundary` prove the process-level kill path; `run_sigkill_scenario` is the driver.
- Historical output from before the RocksDB cutover:

```text
test durable::tests::committed_gap_replays_to_head_without_recommitting_it ... ok
test result: ok. 1 passed; 0 failed; 225 filtered out
test overhaul_atomic_durability::rocksdb_injected_faults_never_mix_families ... ok
test result: ok. 2 passed; 0 failed; 52 filtered out
```

## Boundaries

`SIGKILL` is not power loss. The fault matrix injects lost, failed, and partial writes around apply, sync, and flush, but it runs in one process on one filesystem; device-cache behaviour is unmeasured here. No group-commit latency measurement backs the 64-block redo bound; that bound is a constant in `crates/chainstate/src/window.rs`, not a measured figure. Journal retention defaults are configuration, not a capacity measurement.

Pruning deletes the bodies and undo records this chapter leans on, so the next chapter is [Pruning](pruning.md).
