# Sync, recovery, and pruning

On restart the node restores the newest clean checkpoint it holds, replays the committed gap to the durable head, and continues. After an abrupt kill it does the same replay without a new checkpoint. Transcripts below write `$DATA` for the data directory and `$STATE` for the offline-import certification directory.

## Two kinds of progress

Headers and applied blocks are separate authorities. `getblockchaininfo` reports `headers` and `blocks` separately, and `sync progress` logs both:

```json
{"message":"sync progress","applied_height":1,"header_height":1,"peers":0,"ibd":false}
```

An admitted header is not a validated block. Download-window cursors, scheduled requests, staged bodies, and peer claims are transient work; none of them is a chain authority. [`SYNC-01` and `SYNC-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md) own the distinction.

Optional subsystems, including historical validation, index backfill, mining, and RPC work, must not stop foreground chain progress. [`SYNC-03`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md) states the isolation rule, and [`SYNC-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md) binds publication to a durable commit.

## Failure classes

These outcomes are distinct and map to different operator actions:

A bad header is rejected and the peer's ancestry is not admitted. A body that does not bind to its header keeps the header and lets another peer serve the body. A consensus-invalid body poisons that block and its descendants.

A transient delivery failure retries or hands over to another peer without changing chain state. Missing or pruned history is reported unavailable, never as an empty success.

Durable corruption and an unusable storage engine fail closed. `fail_closed_for_recovery` closes the chainstate for recovery, schedules no retry, and the event loop requests shutdown; teardown publishes no checkpoint and the process exits nonzero. `getblockchaininfo` reports `is_apply_halted: true` until the process exits.

[`SYNC-04`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md) owns the full classification.

## What a crash leaves behind

The durable head is the only commit point. Body and undo bytes are appended and synced first; coins, head, and metadata then commit in one atomic batch. A crash before the batch leaves no authoritative head. A crash after it leaves a head that the next start can replay.

Kill a regtest node with `SIGKILL` after mining three blocks, then start it again on the same directory. The restart log says:

```
{"message":"replayed the committed-but-unpublished gap; the node resumes on the stored head","head_height":3,"head_tip":"4b30ebbed600c12e690cfe5e97bd4fef58bcb818e262e13cf13d282c4041bebe","blocks":4,"commit_id":4}
```

`head_height` is the applied height the durable head certified. `commit_id` advances on every committed connect and disconnect, including reorg disconnects. The mempool snapshot is not written on an abrupt kill, so the next start reports `no mempool snapshot; starting with an empty pool` and then follows the durable chain.

[`RCV-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the ordered commit protocol, and [`RCV-04`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the crash matrix. Mid-frame body append is discarded, an undo row without a committed head is not authoritative, and an ambiguous batch resolves to the prior or the wholly proposed root, never a mix.

## Reorgs and deep rollback

A reorg disconnects the old branch with the exact per-block inverse, then reconnects the new branch through ordinary connect. Missing retained undo fails closed rather than fabricating a rollback. [`RCV-08`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns exact disconnect and reorg.

A rollback deeper than the configured cutover resets the affected derived capabilities and rebuilds them from the durable root, not from a checkpoint. The rebuild stays published as rebuilding until those rows reach the applied tip. A tip change during a rebuild does not abort it; the worker converges on the new applied tip by full hash and `CommitId`. See [`RCV-05` and `RCV-06`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md).

If a disconnected body is missing, the affected capabilities rebuild from canonical retained bodies. A pruned node reports the history unavailable instead of substituting another block at the same height ([`RCV-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md)).

## Pruning during sync

Pruning removes old block bodies below the safety margin while the node keeps syncing. A pruned node advertises `NETWORK_LIMITED`, and history it no longer holds answers unavailable. Do not promise archival service from a pruned node; the [synchronization contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md) states that explicitly.

Prune with the transaction, script, or compact-filter index off. The startup check rejects that combination.

## Offline import

The binary can apply a Core-framed archive without peers, for evidence lanes. All three flags are required together:

```sh
$ ./target/release/bitcoin-rs --corpus archive.bin --manifest manifest.json --state $STATE
```

Passing only some of them is an error:

```sh
$ ./target/release/bitcoin-rs --corpus archive.bin --network regtest --data-dir $DATA
Error: --corpus, --manifest, and --state must be given together
```

The import validates the archive under full validation, publishes the production checkpoint, verifies the stop identity, and writes certified state to `--state`. It refuses a nonzero assume-valid height and refuses any auxiliary index. It is a benchmark and evidence path, not a normal operator sync mode.

This chapter shows no import transcript because an import needs a pinned archive and manifest. The acceptance rules and the exact certification fields are in [Offline full validation](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/offline-full-validation.md).

> **Warning** A node reporting `is_apply_halted: true` has stopped applying blocks and is asking to exit. Restarting replays durable state with a clean engine; retrying the same RPC is not a recovery step.

For conflicting consensus verdicts, follow the [incident runbook](https://github.com/gosuda/bitcoin-rs/blob/main/docs/consensus-divergence.md).

## Next

Stop and upgrade it safely: [Shutdown and upgrades](shutdown-and-upgrade.md).
