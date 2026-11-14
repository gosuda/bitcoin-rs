# Checkpoints and recovery

A checkpoint is an engine image of the published chainstate: the block tree, the `coins` keyspace, and CoinStats, written to `$DATA/chainstate-checkpoints/` with a manifest. It is an accelerator for startup. It is never proof: a replayed suffix still rechecks identities against the durable head, and a checkpoint that disagrees with the durable head is refused, not trusted.

This chapter covers the publish protocol, the restore decision at boot, and the two refusals that protect the checkpoint against in-flight disconnects and an unanchored tip. For the durable head itself and the restore that follows the checkpoint, see [Sync, recovery, and pruning](../run/sync-and-recovery.md) and [Chain state and storage](state-and-storage.md). The normative rules live in [`RCV-*`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md).

## What a checkpoint contains

One generation directory holds four files, named by constants in `crates/storage/src/checkpoint.rs`:

```
chainstate-checkpoints/
+- CURRENT                     # points at the selected generation
+- gen-00000000000000000001/   # one directory per generation
   +- manifest-v1.json         # digests, tips, counts
   +- headers-v1.dat           # block tree, magic "BRSHEAD\0"
   +- chainstate/              # engine checkpoint of the chainstate database
   +- coinstats-v1.dat         # exactly 820 bytes, magic "BRSSTAT\0"
```

`CURRENT` is a small JSON document (`CurrentV1`) that names the generation directory and the SHA-256 of its manifest. Loaders verify the manifest digest before opening any payload, so a stale `CURRENT` that names a deleted or rewritten generation fails closed.

The manifest (`CheckpointManifestV1`) records, among other fields: generation number, network name and magic, genesis hash, applied tip (height, hash, chainwork, chain tx count), best header tip, and per-artifact byte counts, SHA-256 digests, codecs, and versions. The live engine-checkpoint path writes no `utxo` entry; the field is optional and only test fixtures write it.

## The publish protocol

`CheckpointPublisher` (`crates/execution/src/checkpoint/publisher.rs`) drives publication in `publish_transaction`. The node publishes on clean shutdown (`crates/node/src/lifecycle.rs`, the `published clean chainstate checkpoint` line), when recovery work completes, and from the execution maintenance worker at most once every ten minutes while the node runs. The worker publishes only when the applied tip is above the published checkpoint height, so an idle node publishes nothing. The sequence:

1. Pause block admission (`ApplyAdmission::pause`), so the state cannot move under the write.
2. Refuse if a disconnect marker is `InFlight`, or if the applied tip is ahead of the durable head (`CheckpointError::DisconnectInFlight`, `CheckpointError::AheadOfDurableHead`, both raised in `publish_frozen`). The durable head is the commit point; a checkpoint can never legitimately name a tip the head has not certified.
3. Sync and flush the block body store, so the headers restored later have their bodies available.
4. Copy the engine image of the chainstate store into the staging directory (`CheckpointStage::checkpoint_store`, which writes the `chainstate/` subdirectory).
5. Write `headers-v1.dat` and `coinstats-v1.dat`. Each artifact is written through a `HashingWriter` that computes bytes and SHA-256 while writing, then the file is `sync_all`-ed.
6. Check the CoinStats listener snapshot against the applied tip and chain tx count (`check_coinstats_listener`), and confirm the best header tip did not change while writing (`check_best_tip_unchanged`).
7. Write `manifest-v1.json`, fsync the staging directory, `rename_noreplace` the staged directory to its final `gen-...` name, fsync the root, then write `CURRENT` to a temp file and rename it over the old one (`commit_publication`, `crates/storage/src/checkpoint/publish.rs:169-238`). With `CheckpointRetention::Replace`, older generations are removed after the rename.

Generation numbers come from `allocate_generation` (`publish.rs:280`): current generation plus one, skipping any name that already exists on disk. The number is monotonic across restarts and is what log lines and `CURRENT` refer to. A manifest whose `generation` field does not match the staged directory is rejected at commit time.

A checkpoint is a copy of the published state taken under a freeze, so it can lag the durable head only backward. Both refusals in step 2 exist because a crash during a disconnect would otherwise let the checkpoint name a state the head never certified.

## Generation retention

`CheckpointRetention::Replace` keeps exactly one generation: `cleanup_after_publication` removes every directory that is not the newly published one. The assumeutxo historical namespace retains generations explicitly instead (`retire_checkpoint_generations_at`), because startup must be able to name a specific accepted generation from the durable head regardless of what `CURRENT` says.

Publication offers no index seed. The engine-checkpoint writer returns only the published checkpoint reference.

## Restore source selection at boot

`prepare_initial_chainstate` (`crates/execution/src/recovery.rs`) picks the restore source in this order:

```text
full-revalidation marker present?  -> cold  (reason=fork_below_checkpoint_base)
assumeutxo anchor in durable head? -> snapshot
complete checkpoint in CURRENT?    -> checkpoint
otherwise                          -> cold  (reason=no_complete_checkpoint)
```

The cold paths log `restore_source="cold"` with the corresponding `reason` shown above (`recovery.rs`). Checkpoint startup logs `restored chainstate checkpoint` with `height` and `hash` (`crates/node/src/state/open.rs`). These are not a universal `restore_source` log for all three sources.

`ResumeSource` (`recovery.rs:14`) is `Snapshot`, `Cold`, or `Checkpoint`. The non-cold cases:

- **Checkpoint**: verify the manifest digest and the byte counts and SHA-256 digests of `headers-v1.dat` and `coinstats-v1.dat`, rebuild the block tree, and validate the header commitments and CoinStats fields against the manifest. Open the engine image in `chainstate/` through the storage engine. When the manifest carries an engine entry (`EngineArtifactV1`), it pins byte counts and SHA-256 digests for the image's physical files: one digest per file plus a top-level digest over the sorted per-file records. The loader checks each recorded file's byte count and digest and fails closed on missing or changed recorded bytes; the normal hosted load copies the recorded files to scratch and verifies that selected image, so unrecorded files beside it are not copied or loaded. The recorded set excludes lock and log names, and recording a checkpoint refuses a write-ahead log that still carries bytes. The digest authenticates the stored file bytes, not the logical rows, and loading does not recompute CoinStats from the engine's coins. If the applied tip's chain tx count is known, it must match the CoinStats tx count (`validate_chain_tx_count`); ancestors of the applied tip are seeded with the explicit `ChainTxCount::UNKNOWN` sentinel rather than guessed values. Log line: `restored chainstate checkpoint height=... hash=...` (`open.rs`).
- **Snapshot**: the assumeutxo restore path, covered in [Snapshots and assumeutxo](snapshots-and-assumeutxo.md). It runs before the ordinary `CURRENT` lookup: a datadir with a live assumeutxo anchor in its durable head takes the pinned-anchor branch, and `restore_snapshot` still prefers an ordinary checkpoint when one exists that matches the pin's height, hash, commitment, and tx count.

Corrupt checkpoints do not fall back silently. Load errors classify into `CheckpointLoadError`, and anything semantic (bad codec, wrong tip, mutated bytes that fail only semantic checks) surfaces as a `Corrupt` variant whose message says what to do: re-sync. The distinction matters: transient I/O errors stay retryable, but a checkpoint whose contents hash to the manifest digest yet decode wrong is datadir corruption, and the node refuses instead of silently building a different chain. Tests in `crates/execution/src/checkpoint/tests/artifact_consistency.rs` pin this split: `authenticated_header_semantics_require_resync` and `authenticated_coinstats_semantics_require_resync` each mutate one authenticated artifact and require the `Corrupt` error.

## The full-revalidation marker and its retirement

The marker is a file named `full-revalidation` inside `$DATA/` (`FULL_REVALIDATION_MARKER`, `crates/storage/src/recovery_evidence.rs:12`). It is set by `require_full_script_attestation` (`recovery.rs:97`) when the node runs in full validation mode and the durable head's stored script attestation is below `Full`, for example after a `--validation-mode full` switch on a chain built under assume-valid. Its presence forces a cold start: the coin set is discarded and every block is revalidated from genesis, because a chain whose scripts were skipped cannot be patched incrementally.

The marker retires only through a successful checkpoint publication (`retire_full_revalidation_marker`, called from `publish_frozen`). The publication worker computes the fully validated chainstate and records it as the next generation; only then is the marker removed. Two subtleties:

- A retryable I/O failure while removing the marker surfaces as `CheckpointError::FullRevalidationMarker`, owned by the checkpoint worker. It is not checkpoint corruption and does not mark the datadir bad.
- During boot recovery, `publish_recovery_progress` publishes a progress checkpoint without retiring either recovery marker: while replay is still below the durable head, a crash must resume recovery, not mistake the progress checkpoint for a completed repair (`DisconnectRetirement::RecoveryProgress`).

## Disconnect-in-flight refusal

A reorg disconnect is the one operation that moves the coin set backward. If a checkpoint froze the state while a disconnect was in flight, the engine image would not correspond to any committed tip. `publish_frozen` therefore refuses (`CheckpointError::DisconnectInFlight`):

```text
checkpoint refused while disconnect of block {hash} at height {height} is in flight
```

The refusal preserves everything: the marker stays armed, `CURRENT` is untouched, and no generation directory appears. `crates/execution/src/tests/checkpoint_debt_tests.rs::checkpoint_refuses_inflight_disconnect_and_preserves_state` arms a disconnect marker, calls `publish_checkpoint`, and asserts the error plus byte-identical `CURRENT` and directory listing. After the disconnect completes, `settle_disconnect_debt` (`publisher.rs:168`) finds the marker in a completed phase and publishes normally, which also retires the disconnect marker through `undo_store.retire_disconnect_marker`.

## Header checkpoint file

`headers-v1.dat` restores the whole block tree, not only the active chain (`crates/execution/src/checkpoint/headers.rs`). After a fixed 56-byte prefix (magic `BRSHEAD\0`, version, counts, tips) come the active-chain headers in order, then a `u64` side-header count and that many 80-byte headers: the tips of competing forks the node knows about. The file carries two domain-separated SHA-256 commitments over the best chain and the applied prefix, both recorded in the manifest and rechecked at load.

At load, `read_headers` replays the active chain into a fresh `BlockTree`, re-attaches side branches, and rejects a side header that adds no new node, a side section that displaces the checkpoint best tip, or a count that overflows the node-id domain. A version 1 file (active chain only, `ACTIVE_ONLY_HEADER_VERSION`) still loads; the node just relearns side branches from the network.

## Worked trace

Start a regtest node, mine 205 blocks, stop it cleanly, and restart (`$DATA` below is the throwaway data directory):

```sh
$ curl -s --user "$COOKIE" -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"generatetoaddress","params":[205,"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]}' \
  http://127.0.0.1:28443/ >/dev/null
$ kill -TERM <pid>
```

Clean shutdown publishes generation 1 (`crates/node/src/lifecycle.rs`):

```
{"message":"published clean chainstate checkpoint","generation":1},"target":"bitcoin_rs_node::lifecycle"}
```

On disk, `$DATA/chainstate-checkpoints/` now holds `CURRENT` and `gen-00000000000000000001/` with `manifest-v1.json`, `headers-v1.dat`, `chainstate/`, `coinstats-v1.dat`. The manifest names the tip:

```json
{"generation":1,"network":"regtest","applied_tip":{"height":205,
 "hash":"474cb06e60cf1e0e111bacb9efba0a7bb883db107112d1a363c302391637fa7e",
 "chainwork":"...019c","chain_tx_count":206}}
```

Restarting on the same data directory restores from the checkpoint image and logs:

```
{"message":"restored chainstate checkpoint","height":205,
 "hash":"474cb06e60cf1e0e111bacb9efba0a7bb883db107112d1a363c302391637fa7e",
 "target":"bitcoin_rs_node::state::open"}
```

The matching live IBD case (checkpoint restore) is documented with verified output in [First start](../run/first-start.md).

## Failure modes

| Condition | Node behavior | Error or log line |
| --- | --- | --- |
| Disconnect in flight | Refuse; nothing written | `checkpoint refused while disconnect of block {hash} at height {height} is in flight` |
| Tip ahead of durable head | Refuse publication | `checkpoint of tip {tip} at height {tip_height} is ahead of the durable head {head} at height {head_height}` |
| Best tip moved during write | Refuse publication | `best header tip changed during checkpoint` |
| CoinStats listener disagrees with the applied tip or chain tx count | Refuse publication | error from `check_coinstats_listener` |
| Crash mid-publication | Orphaned staging dir ignored; `CURRENT` still names the old generation | startup skips names that are not a valid `CURRENT` target |
| Checkpoint version or codec not current | Fail closed at boot, no silent fallback | `headers checkpoint version {n} is not supported`, `unexpected payload codec CoinStats=...` |
| Artifact contents hash to the manifest but decode wrong | Fail closed at boot | `Corrupt` variants naming the mutated artifact |
| Full-revalidation marker present | Cold start, full resync | `chainstate restore requires full validation restore_source="cold" reason="fork_below_checkpoint_base"` |

## Where the invariants are proven

- [`RCV-10`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md): a checkpoint is not recovery authority; the durable head is. Enforcement lives in the publish-time refusals above.
- [`RCV-14`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md): the publisher freezes the published state before writing and reconciles against the durable head.
- Crash-at-every-boundary coverage: `crates/storage/src/checkpoint/publish.rs` accepts injected failpoints at each write, sync, and rename step (`CheckpointFailpoint`); `crates/execution/src/checkpoint/tests/tip_transitions.rs::failed_publication_preserves_current` fails a publication and requires the old generation to stay intact.
- Disconnect refusal and preservation: `crates/execution/src/tests/checkpoint_debt_tests.rs::checkpoint_refuses_inflight_disconnect_and_preserves_state`.
- Contract-clause and proof coverage counts live in [`docs/contracts/evidence-index.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/evidence-index.md).

Difference from Bitcoin Core worth knowing: Core checkpoints the UTXO set only through `dumptxoutset`/assumeutxo machinery and rebuilds the block tree from headers on restart; bitcoin-rs writes the full tree including side branches into the checkpoint, so a restart preserves knowledge of competing fork tips without a network round trip.
