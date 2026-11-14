# Index state, reconciliation, and bundles

An index row is only readable when the same store batch also moved that capability's watermark. Three mechanisms enforce that rule: the writer fences every commit against a revision and a reset marker, reconciliation rewrites rows until the watermark reaches the applied tip, and a portable bundle refuses to import rows it cannot re-prove against the receiver's own chain.

The operator surface is [transaction and script-hash indexes](../use/indexes.md). This chapter covers the machinery behind it. Contract clauses are in [docs/contracts/indexing.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md).

## What a watermark pins

Four capabilities share one store namespace at `<data-dir>/txindex`: `TxLookup`, `ScriptHistory`, `ScriptLive`, and `CompactFilters` (`crates/projection/src/index/capability.rs:33`). Each has its own watermark key in the `UtxoMeta` column family:

| Capability | Key | Rows it covers |
| :--- | :--- | :--- |
| `TxLookup` | `[0x00, b'T']` | `TxConfirmed` |
| `ScriptHistory` | `[0x00, b'S']` | `Funding`, `Spending` |
| `ScriptLive` | `[0x00, b'L']` | `ScriptLive` |
| `CompactFilters` | `[0x00, b'F']` | filter rows keyed by segment generation and height |

A watermark is 36 bytes: the height little-endian, then the 32-byte block hash (`IndexWatermark::to_bytes`, `crates/projection/src/index/capability.rs`). The little-endian height is deliberate. History row heights are stored inverted big-endian for newest-first scans, but the watermark stays comparable as an integer.

Compact filter rows live in the segment tail: `encode_filter_key` keys each row by segment generation and height, and `encode_filter_value` stores `block_hash || filter_hash || header || gcs` (`crates/projection/src/segment/format.rs`). `build_filter` adds every non-empty output script except `OP_RETURN` and every spent script, and derives the BIP158 hash keys from the first 16 bytes of the block hash (`crates/projection/src/segment/tail.rs`). `append_filter` hashes `filter_hash || previous_header` to extend the BIP157 header chain.

The row format is version 9, written under key `[0x00, b'V']` with value `09 00 00 00` (`INDEX_FORMAT_VERSION_VALUE` in `crates/projection/src/types.rs`). `IndexWriter::open` accepts that value only. Any other stored value returns `UnsupportedTxIndexFormatVersion`; rows with no version marker at all return `LegacyCursorlessIndex` (`crates/projection/src/index/write.rs`). The runtime treats both as a rebuild request: it logs `resetting incompatible derived transaction index for rebuild` and calls `IndexWriter::reset_index` (`crates/projection/src/runtime/startup.rs`). There is no in-place migration.

## The write path is one conditioned batch

`IndexWriter` is the only type allowed to mutate index column families (`IDX-10`). Every block mutation follows the same shape.

1. `prepare_block_with_spent_scripts` parses the block, builds every row, checks that the header hashes to the identity the caller named, sorts the rows, and returns a `PreparedBlock` (`crates/projection/src/index/write.rs`). Nothing is written yet.
2. `commit_forward_with_cursor` reads the fence, requires that the next height is `watermark.height + 1` and that the first block's parent is the watermark hash, then merges the prepared rows into one `BufferedWriteBatch` with the new watermark, the format marker, and any consumer-cursor update (`crates/projection/src/index/write.rs`).
3. `commit_ordinary` adds the next state revision and calls `store.write_durable_if` with six compare conditions: the reset marker, the state revision, and one condition per capability watermark (`crates/projection/src/index/state.rs`).

The conditions are the fence. If another writer moved the reset marker, bumped the revision, or changed any watermark after the fence was captured, the conditional write fails and the commit returns `IndexError::StaleIndexState`. The worker maps that error to `ReconcileAction::Stalled`, drops its pending batch, and re-reads the durable state on the next pass (`crates/projection/src/runtime/reconciliation.rs`). A failed commit therefore cannot publish rows under a stale watermark.

The state revision is an ordinary counter under key `[0x00, b'O']`. It exists so two writers in different processes cannot both succeed: the reset marker alone only guards reset cycles, while the revision detects any interleaved ordinary commit.

### Why the reset marker exists

A selective reset deletes rows across several column families. That takes more than one batch, so the store needs a visible claim that a reset is in progress.

The marker under `[0x00, b'R']` has two shapes (`crates/projection/src/index/state.rs:43`):

```text
Idle  (9 bytes):  0xFF | version u64
Claim (17 bytes): mask u8 | process_epoch u64 | base_version u64
```

`mask` uses one bit per capability (`TxLookup` 0b001, `ScriptHistory` 0b010, `ScriptLive` 0b100, `CompactFilters` 0b1000). `acquire_capability_reset` replaces Idle with Claim in a conditioned batch, records the watermarks and floors to delete in that batch, then `resume_capability_reset` scans and purges the selected families in bounded chunks, and finally writes Idle with `version + 1` and the next state revision (`crates/projection/src/index/state.rs`). Idle versions only increase. A stale process that observed an older Idle value cannot complete a reset against the newer one, which prevents an ABA race.

If a process dies mid-reset, the next `capture_write_fence` sees a Claim, calls `resume_capability_reset`, and returns `IndexError::ResetInProgress` (`crates/projection/src/index/state.rs`). The worker retries. No query runs against the half-purged capability because its watermark was deleted in the claim batch.

## Reconciliation after a restart or a reorg

The worker loop is one `reconcile_once` call per wake or deadline (`crates/projection/src/runtime/reconciliation.rs`). Each pass captures the applied tip and a fresh fence, then works through four steps in order.

### 1. Drop leftover capabilities

If a capability is no longer enabled but still has a watermark, `reconcile_pass` resets it and returns `Progressed` (`crates/projection/src/runtime/reconciliation.rs`). This is the `full` to `utxo` switch and the drop of `TxLookup` when `--txindex` is off (`IDX-04`). Sibling capabilities keep their rows.

### 2. Roll back off-chain watermarks

`rollback_selection` picks the enabled watermark with the greatest height that is not on the ancestry of the applied tip (`crates/projection/src/runtime/reconciliation.rs`). Every capability whose watermark equals that exact `(height, hash)` joins the same reset or rollback group. For each selection, `drain_rollbacks` computes the depth to the common ancestor and compares it with `rollback_rebuild_cutover`, which is 100,000 by default (`crates/projection/src/runtime.rs`). A deeper divergence logs:

```text
stale index watermark exceeds the rollback cutover; rebuilding selected capabilities
```

and resets those capabilities instead of walking back block by block (`IDX-06`).

Otherwise `rollback_one` loads the body at the watermark height, derives the same rows a forward commit would have written, and asks `commit_rollback_one_for_with_cursor_with_spent_scripts` to delete exactly those rows and set each grouped capability's watermark to the previous block (`crates/projection/src/runtime/rollback.rs:261`, `crates/projection/src/index/write.rs`). The call first expands the request to the tail group (`tail_rollback_group`, `crates/projection/src/index/write.rs`), so a rollback of one tail-bound capability moves every tail-bound capability at that height, releases the shared header identity unless an unselected capability still needs it, and refuses a second rollback for an already-moved member (`group_rollback_releases_identity_and_refuses_a_second_member`, `crates/projection/tests/index_roundtrip.rs`). Two details matter:

- Header rows are deleted only when no unselected capability still needs an identity at that height. `unselected_keeps_identity` checks sibling watermarks; when a sibling is also at or above the height, only the selected family's rows are deleted (`crates/projection/src/index/write.rs`).
- `ScriptLive` and `CompactFilters` need spent-output scripts to rebuild their rows. Those come from the block's undo record (`live_anchor`, `crates/projection/src/runtime/rollback.rs`). A missing undo record raises `UndoUnavailable`; `ScriptHistory` and `CompactFilters` become unavailable for the run, and when `ScriptLive` was part of the selection it is reset for a fresh seed (`crates/projection/src/runtime/reconciliation.rs`).

The consumer cursor is recomputed, not replayed: `cursor_for_result` rebuilds it from the previous watermark and the capabilities that remain (`crates/projection/src/runtime/cursor.rs:104`).

### 3. Catch up forward

`forward_selection` takes the smallest next height among enabled capabilities, `watermark.height + 1` or 0 for a capability with no watermark (`crates/projection/src/runtime/reconciliation.rs`). `catch_up_to` then walks the target chain in bounded chunks (`crates/projection/src/runtime/catch_up.rs`):

| Bound | Value | Constant |
| :--- | :--- | :--- |
| Block identities collected per chunk | 65,536 | `IDENTITY_CHUNK_BLOCKS` |
| Blocks prepared per sub-chunk | 256 | `PREPARE_CHUNK_BLOCKS` |
| Bytes prepared per sub-chunk | 32 MiB | `PREPARE_CHUNK_BYTES` |
| Rows per durable batch | 1,000,000 | `DEFAULT_BATCH_LIMITS.max_rows` |
| Bytes per durable batch | 256 MiB | `BATCH_BYTE_LIMIT` |
| Buffered commit delay | 100 ms | `FORWARD_BATCH_DELAY` |

Prepared batches accumulate until one of the row or byte limits is reached. When the batch endpoint is still behind the tip, the worker stores it as `PendingForward` and continues; when the endpoint reaches the tip, it waits up to 100 ms for more work, then commits one atomic batch. That commit is the point where every row and the advanced watermark become durable together.

A block body that is absent stops forward progress for that sub-chunk without inventing rows: `ForwardLeg::BodyAbsent` advances `after_start` past the missing height and the pass returns `Stalled` (`crates/projection/src/runtime/reconciliation.rs`). This is how a pruned node with an index that needs an old body reports a stall instead of a partial claim.

### 4. Settle the cursor

When nothing is left to roll back or replay, `reconcile_once` publishes the `Forward` phase and returns `CaughtUp` (`crates/projection/src/runtime/reconciliation.rs`). The outer loop persists the chain-consumer cursor and waits on the wake channel. A wake during that wait starts the next pass; a wake that arrives while a pass is running is coalesced by the runtime revision counter (`IDX-08`).

## Capability states you can observe

`getcapabilities` exposes one `txindex` row built by `DerivedIndexCapability::report` (`crates/projection/src/runtime/capability.rs:34`). The mapping, in evaluation order, is:

1. Worker failure message, or lifecycle `Opening`, `Failed`, `ShutdownAbandoned` map to the same state.
2. A rolling-back leg maps to `RollingBack { from_height, to_height }`.
3. A script-capability outage with no servable capability left maps to `Failed`.
4. A rebuilding leg maps to `Rebuilding { processed_height, target_height }`.
5. Otherwise progress against the applied tip decides `Ready` or `CatchingUp { processed_height, target_height }`.

`Ready` means the durable watermark equals the applied tip height and hash. It does not mean the worker thread exists.

On a regtest node with `--txindex true`, mined blocks arrive faster than the worker commits:

```json
{"capabilities":[{"compiled":true,"enabled":true,"id":"txindex",
  "state":{"CatchingUp":{"processed_height":0,"target_height":20}}}]}
```

Once the worker catches up:

```json
{"capabilities":[{"compiled":true,"enabled":true,"id":"txindex","state":"Ready"}]}
```

The same moment shows in `getindexinfo` as `{"best_block_height":20,"synced":true}`.

A panic inside the worker is caught in the thread wrapper, logged as `txindex worker panicked`, and published as `Failed` through `fail_worker` (`crates/projection/src/runtime/lifecycle.rs:45`). Block validation and UTXO commits do not wait for the index.

## The portable bundle

A bundle moves `TxLookup` rows only. It is a request, not a mode: the worker runs it once after the store opens and before the first reconcile pass (`crates/projection/src/runtime/startup.rs`). The node does not exit, does not clear the option, and runs the request again on the next start if the option is still present (`IDX-11`).

### Format

A bundle directory contains `txlookup-v1.dat` and `manifest.json`. Export writes the artifact first, fsyncs it, fsyncs the directory, then publishes the manifest with create-new and its own fsync (`crates/projection/src/portable/export.rs`). Files are created with `create_new`, so an existing `manifest.json` is refused as `ExistingBundle` and never overwritten.

The artifact starts with a 73-byte `BRSIXART` header (`crates/projection/src/portable/artifact.rs:35`):

```text
 0..8    magic "BRSIXART"
 8       family (1 = tx_lookup)
 9..13   artifact version, u32 LE
13..17   index format version, u32 LE
17..21   network magic
21..25   base height, u32 BE
25..57   base hash
57..65   record count, u64 LE
65..73   payload bytes, u64 LE
```

Each record is `txid[32] || height u32 BE || count u8 || count * 6-byte TxPosition`. Records are sorted by `(txid[..8], height, txid[8..])`, never by raw key (`crates/projection/src/portable/artifact.rs`).

Real header from a 20-block regtest export:

```text
00000000: 4252 5349 5841 5254 0101 0000 0009 0000  BRSIXART........
00000010: 00fa bfb5 da00 0000 14d7 a239 1f09 0131  ...........9...1
```

`01` is the family, `01 00 00 00` the artifact version, `09 00 00 00` the index format, `fa bf b5 da` the regtest magic, and `00 00 00 14` the base height 20.

### What import checks, and in what order

`restore` validates before it writes (`crates/projection/src/portable/restore.rs`). The order is fixed by `IDX-11` because the first failure a caller sees should be the cheapest one to explain:

1. The manifest: format string, version, exactly one `tx_lookup` capability, exactly one artifact named `txlookup-v1.dat`, base marked `validated: true`, floor at or below base plus one, and no `script_history` capability (`crates/projection/src/portable/manifest.rs:166`). Unknown JSON fields are denied. A manifest over 1 MiB is refused unread.
2. Artifact length against the manifest.
3. SHA-256 and the artifact header (`check_header`, `crates/projection/src/portable/restore.rs`). The header must repeat the family, artifact version, index format, network magic, base, record count, and payload length.
4. Record framing: declared count and payload length, no trailing bytes, 1 to 255 positions per record, heights inside `[floor, base]`, strictly ascending non-overlapping positions inside one serialized block of at most 4,000,000 bytes.
5. Chain identity (`check_identity`, `crates/projection/src/portable/restore.rs`): same network, same index format version, a receiver tip exists, same genesis, the base hash at that height on the tip's ancestry, equal chainwork, base not invalid, and equal cumulative transaction count at the base. `ChainBase::capture` walks the ancestry from the applied tip to the base and refuses a base above the tip (`crates/projection/src/portable/chain.rs:29`). The count comes from the receiver's block tree and bodies, never from the manifest.
6. Freshness: `TxLookup` must have no watermark (`ensure_fresh`, `crates/projection/src/portable/restore.rs`). A ready index is never reset by an import.
7. Locators: every record must resolve through the receiver's block body at that position to a transaction whose full 32-byte id matches. A prefix match never resolves a locator.

Steps 5 and 7 withdraw rather than refuse when the receiver lacks evidence. With no block body source, or with a body a locator needs missing or pruned, restore writes nothing, returns `RestoreWithheld`, logs a warning, and lets ordinary backfill run. Identity refusals reported before a withhold win, and the first terminal locator outcome in record order decides: a mismatch found first is `Locator`, an unavailable body found first withholds.

### What import refuses

| Refusal | Trigger |
| :--- | :--- |
| `TxLookupDisabled` | `--txindex` is not enabled |
| `Manifest` | wrong format or version, unknown field, bad hex, invalid base |
| `UnsupportedCapability("script_history")` | the manifest or an artifact declares history |
| `ArtifactLength`, `ArtifactHash`, `ArtifactHeader`, `ArtifactFraming` | artifact bytes disagree with the manifest |
| `Identity` | network, genesis, format version, base ancestry, chainwork, or transaction count differ |
| `NotFresh` | `TxLookup` already has a watermark |
| `Locator { height }` | a record resolves to a different transaction id |

A bundle has no signature. SHA-256 detects a changed artifact, and the locator check binds records to the receiver's chain; neither authenticates an exporter.

### Partial rows never become queryable

Import attaches sorted rows through `KvStore::ingest_sorted` into `TxConfirmed`. The `TxLookup` watermark and floor appear only in the final commit. The apply pass re-hashes the artifact and aborts before that commit if the bytes changed.

On failure, `discard_partial_rows` clears the written rows immediately when the capability still has no watermark (`crates/projection/src/portable/restore.rs`). If the process dies before cleanup, the next start with `TxLookup` enabled runs `reset_interrupted_import` before any bundle or derivation work and logs:

```text
cleared rows left by an interrupted portable index import
```

(`crates/projection/src/runtime/startup.rs`). That is why a crash mid-import costs the import, not the index.

## Worked trace: export, restore, refuse

The build at HEAD was run on regtest with a throwaway data directory. `$DATA` below stands for that directory; it is not part of the book.

First start the node with the transaction index and mine 20 blocks so the watermark can reach the tip:

```sh
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA/idx \
    --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:41996 \
    --dns-seeds-enabled=false --txindex true
```

Stop it cleanly, then restart with a one-shot export:

```sh
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA/idx \
    --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:41996 \
    --dns-seeds-enabled=false --txindex true \
    --index-bundle-export $DATA/bundle1
{"level":"INFO","fields":{"message":"exported portable txindex bundle",
 "height":20,"records":21,"bytes":976},"target":"bitcoin_rs_projection::runtime::startup"}
```

The manifest carries the identity the importer will re-check:

```json
{
 "format": "bitcoin-rs-index-bundle",
 "version": 1,
 "network": "regtest",
 "genesis_hash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
 "base": {
  "height": 20,
  "hash": "4883ac85963d18d3d05b3cd2bf0f2391ebfe9280e69748d90a3101091f39a2d7",
  "chainwork": "000000000000000000000000000000000000000000000000000000000000002a",
  "chain_tx_count": 21,
  "validated": true
 },
 "index": {
  "mode": "utxo",
  "format_version": 9,
  "capabilities": [{"capability":"tx_lookup","floor":0,"height":20,
    "hash":"4883ac85963d18d3d05b3cd2bf0f2391ebfe9280e69748d90a3101091f39a2d7"}]
 },
 "artifacts": [{"family":"tx_lookup","name":"txlookup-v1.dat",
   "sha256":"7a4fe3677a83003ca70e1b2a41414846707e15f10e367fa6e34f7b51c77b8b9a",
   "bytes":976,"records":21}]
}
```

A fresh data directory at the same tip, with its `txindex` namespace removed, imports it:

```sh
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA/idx2 \
    --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:41997 \
    --dns-seeds-enabled=false --txindex true \
    --index-bundle-import $DATA/bundle1
{"level":"INFO","fields":{"message":"restored portable txindex bundle; ordinary
 reconciliation continues from its base","height":20,"records":21,"rows":21},
 "target":"bitcoin_rs_projection::runtime::startup"}
```

Run the same request again against the now-populated index and freshness refuses it:

```text
{"level":"ERROR","fields":{"message":"portable txindex bundle request refused;
 ordinary reconciliation proceeds","error":"the txindex already has a watermark;
 restore needs a fresh capability"},"target":"bitcoin_rs_projection::runtime::startup"}
```

The read differs from the first run: `records` counts artifact records, `rows` counts stored rows after 8-byte-prefix folding. Reconciliation then starts at base height plus one, exactly as it would for any capability with a watermark.

## Failure modes

| Event | What the worker does | Evidence |
| :--- | :--- | :--- |
| Format version differs | resets the derived store and rebuilds | `UnsupportedTxIndexFormatVersion`, `IDX-05` |
| Reset was interrupted | resumes the claim, returns `ResetInProgress`, retries | `IndexWriteFence` claim branch |
| Watermark diverges deeper than 100,000 | resets selected capabilities, publishes `Rebuilding` | `stale index watermark exceeds the rollback cutover` |
| Body missing during rollback | `ScriptHistory` and `CompactFilters` unavailable, `ScriptLive` reseeded | `IDX-07` |
| Body missing during forward pass | returns `Stalled` and skips that height for the pass | `ForwardLeg::BodyAbsent` |
| Another writer moved the fence | `StaleIndexState`, pending batch dropped, pass retried | `commit_ordinary` |
| Worker panics | logs `txindex worker panicked`, publishes `Failed` | `lifecycle.rs:45` |
| Export lags the tip | refusal logged, reconciliation proceeds | `export refused, index not ready` |
| Import artifact damaged | refusal logged before any write | `ArtifactHash`, `ArtifactHeader` |

A refusal never blocks chain progress. Only a writer or reader failure (`IndexBundleError::Index`) stops the index worker; validation and UTXO commits continue.

## Where the invariants are proven

| Clause | Rule |
| :--- | :--- |
| [`IDX-04`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-04-selective-reset-preserves-sibling-readiness) | selective reset leaves siblings ready |
| [`IDX-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-05-restart-reconciliation-and-schema-version-refusal) | version refusal and restart reconciliation |
| [`IDX-06`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-06-reorganization-rollback-and-forward-reconciliation) | rollback, cutover, forward batches |
| [`IDX-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-07-error-isolation-and-supervised-rebuild) | per-capability isolation |
| [`IDX-10`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-10-atomic-commit-durability-and-recovery) | rows and watermark in one commit |
| [`IDX-11`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-11-portable-index-bundle) | bundle format, checks, refusal order |

Tests that pin the behavior, all verified in the tree:

| Invariant | Test | File |
| :--- | :--- | :--- |
| rollback removes exactly the committed rows | `rollback_removes_every_row_a_matching_commit_wrote` | `crates/projection/src/index/tests.rs` |
| a stale body does not delete a replacement's rows | `a_stale_rollback_body_leaves_a_replacement_blocks_rows_alone` | `crates/projection/src/index/tests.rs` |
| index ahead of the tip is rewound once | `index_ahead_of_restored_tip_is_reported_once_and_rewound` | `crates/projection/src/runtime/recovery_tests.rs` |
| deep rollback rebuilds until caught up | `deep_rollback_rebuilds_and_publishes_rebuild_phase_until_caught_up` | `crates/projection/src/runtime/recovery_tests.rs` |
| export then restore answers equal queries | `export_then_restore_serves_the_same_queries_as_backfill` | `crates/projection/tests/portable_bundle.rs` |
| damaged bundles are refused before writes | `damaged_bundles_are_refused_before_any_write_or_reset` | `crates/projection/tests/portable_bundle.rs` |
| a cancelled restore writes nothing | `cancelled_restore_writes_nothing_and_restart_completes` | `crates/projection/tests/portable_bundle.rs` |
| an interrupted import is cleared on restart | `interrupted_import_is_cleared_on_restart_and_restore_retries` | `crates/projection/tests/portable_bundle.rs` |
| missing bodies withhold, then backfill | `missing_bodies_withhold_readiness_until_ordinary_backfill` | `crates/projection/tests/portable_bundle.rs` |
| manifest round-trips and denies unknown fields | `manifest_round_trips_through_json_and_validates`, `unknown_fields_are_denied_at_every_level` | `crates/projection/src/portable/manifest.rs` |
| history is never a bundle capability | `script_live_is_never_a_capability_and_script_history_is_refused` | `crates/projection/src/portable/manifest.rs` |
| artifact framing refuses each violation | `framing_refuses_each_violation` | `crates/projection/src/portable/artifact.rs` |

The direct query surface, including the covered prefix carried by `AtPrefix` and the historical-prefix error set, is in [use/indexes.md](../use/indexes.md). `CoveredPrefix`, `AtPrefix`, and `HistoricalQueryError` are defined in `crates/projection/src/query_api.rs`. Server-side history paging semantics are owned by `IDX-03` and `IDX-12` and are not restated here.

## What is stricter than Core

Core has no portable index bundle and no equivalent import path, so there is no parity claim to make. Inside this codebase, export is stricter than a plain copy: it refuses unless the `TxLookup` watermark equals the applied tip exactly, so a lagging index is never exported as if it were complete. Restore is stricter than a file copy in the same way: every record must resolve in the receiver's own chain before any row is written.
