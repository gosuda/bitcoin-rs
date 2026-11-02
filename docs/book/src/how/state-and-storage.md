# Chain state and storage

One row decides what survives a crash: the durable head. A committed block is real only after the head row names it and the batch that wrote it returns. Persistent chain state either supports that row or can be rebuilt from the block bodies.

The storage contract is owned by [`crates/storage`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/storage), the coin set by [`crates/utxo`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/utxo), and the transition order by [`crates/chainstate`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/chainstate). The normative commit protocol is [docs/contracts/recovery.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md).

## What is stored

```text
data-dir/
  .lock                     exclusive data-directory lock
  chainstate/               key-value namespace (fjall, redb, or RocksDB)
    UtxoMeta                durable head, script attestation, snapshot status
    ...                     coin shards, undo rows, index rows
  blocks/                   append-only block files
  chainstate-journal/       derived replay journal
  .cookie                   generated RPC credential
  fee-estimator-history.dat fee estimator state
  mempool-snapshot.dat      optional clean-shutdown pool snapshot
```

`.lock` holds a POSIX record lock (`F_SETLK`), which does not conflict with the `flock` that binaries from before this change take. Stop the old process before starting the new one during an upgrade or downgrade; overlapping binaries can otherwise open the same data directory.

The key-value layer is one trait, `KvStore`, with `get`, ordered `iter_prefix`, bounded prefix scans, point-in-time `snapshot`, and one buffered write batch applied by `write`, `write_deferred`, or `write_durable`. `bitcoin-rs-storage` is the only crate allowed to depend on an engine crate (`ARCH-02`). The engine is selected at runtime by `storage.backend` (`fjall` by default, `redb` and `rocksdb` as compiled alternatives). A build that lacks the selected engine refuses to start.

Block bodies do not go through the key-value store. `FlatFileBlockStore` appends them to flat files and addresses them by `BlockFilePosition`; the key-value row holds only the locator.

## The durable head

`DurableHead` carries the commit id, height, tip hash, cumulative transaction count, body extent, undo extent, and the assumeutxo disk status. It is one versioned, CRC-framed row in `UtxoMeta`.

A connect commits in this order:

1. Consensus gates pass before any write.
2. The undo row is persisted and the body appended.
3. The applied header tip advances and the UTXO set mutates through `utxo::contract` (`ARCH-07a`). The raw set mutator is crate-private.
4. Block files are synced.
5. One batch writes the undo rows, body locator rows, the script attestation, and the new head. The head write is a compare-and-set on the previous head, so two writers cannot both advance the tip.
6. The batch receipt returns. Only then does chainstate publish the tip.

The UTXO mutation is not carried inside the head batch. The batch names the undo and body records that make the mutation recoverable, and the compare-and-set makes exactly one head advance win.

Body and undo records are retained under the head's certified extents. When a batch is 64 blocks or 8 MiB, the group flushes as one head commit; the limit is `DURABLE_HEAD_GROUP_BLOCKS` in `crates/chainstate/src/window.rs`.

## Undo and the journal

Undo records are keyed by `(height, block_hash)`, never by height alone. A rollback applies the inverse under a durable disconnect marker, rewinds coin statistics, and completes the marker. `utxo::contract::rollback_block` owns only the fenced set mutation; chainstate owns the journal rewind, durable head advance, and publication around it.

The journal is derived. It batches 500 blocks or 5 seconds, rotates at 256 MiB, and is capped at 2048 MiB or 500 blocks and 30 seconds of lag. The head never waits for the journal:

- A journal append failure logs `chainstate journal append failed; recovery may fall back to full re-validation` and does not undo the committed head.
- Journal backpressure stops block apply rather than growing without bound.
- Boot replay compacts the journal against the durable head.

The [recovery contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the exact frame layout and replay rules.

## Recovery on open

Startup picks the strongest available restore source and says which one it used. A matching durable head needs no replay: the stored tip and the head row agree, so the node opens at that tip. Otherwise it restores the newest complete checkpoint and replays the certified suffix, or replays the journal against the head. With no complete checkpoint, it reports `restore_source=cold` and rebuilds from the durable state and block bodies.

An accepted checkpoint is an accelerator, not proof. Replay still validates the frontier identity against the head, and a mismatch is a replay gap rather than a silent resume. `replayed_frontier_must_match_the_durable_head_identity` pins that check.

## Assumeutxo

A snapshot-loaded node runs two chainstates:

| Role | What it does |
| --- | --- |
| `Ordinary` | Fully validated chainstate |
| `AssumedActive` | Snapshot-loaded chainstate driving the tip; keeps its base height and hash |
| `Historical` | Background chainstate validating from genesis or an accepted checkpoint to the base height |

Exactly one chainstate is active. Only the active one drives mempool admission, mining, RPC and ZMQ effects, indexing, and pruning. Historical events are detached.

Two entry points share one activation owner:

- `loadtxoutset` reads Core's portable v2 file.
- `Node::activate_assumeutxo_snapshot_file` reads bitcoin-rs native v4 input.

Trust comes from the `hash_serialized_3` commitment over the imported coins matching the compiled `assume_utxo_for_height` anchor. Caller-supplied digests and file trailers do not establish trust. Mainnet anchors exist at heights 840,000, 880,000, 910,000, 935,000, and 965,000.

The on-disk status is one of `Uninitialized`, `Validating`, `Finalized`, or `Failed`. The historical chainstate validates up to the base height and compares the reconstructed commitment and transaction count with the pinned metadata. On a match, the active role moves to `Ordinary`, the historical chainstate retires, and the status becomes `Finalized`. On a mismatch, the status becomes `Failed` and the active chainstate is marked permanently closed for recovery.

Reorgs on `AssumedActive` cannot disconnect at or below the snapshot base. Prefix pruning is refused while either chainstate holds a snapshot role. The [architecture contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-07b-assumeutxo-chainstate-roles-and-single-active-authority) owns the details (`ARCH-07b`).

## Attestation levels

Script attestation and snapshot trust are different things. The attestation row records how much script verification the committed chain received:

| Level | Meaning |
| --- | --- |
| `Unattested` | No script verification recorded |
| `AssumeValid` | At least one block in the batch skipped scripts under the pinned anchor |
| `Full` | Every block in the batch executed its scripts |

A commit writes the weakest of the previous level and its own batch level. A `full` start with weaker stored attestation triggers the cold rebuild described in the [validation chapter](validation.md). Snapshot trust is carried separately by the sealed verified state and the compiled anchor.

## Pruning and retention

Pruning is off by default (`prune_target_mb = 0`). When enabled, a requested prune height becomes eligible only after durability is published through the reorg-retention floor, and the retention registry keeps every row at or above the lowest active lease. The safety margin is `CORE_REORG_SAFETY_MARGIN = 288` blocks. Pruning passes write the executed frontier in the same atomic batch as the row deletions (`ARCH-08`).

Pruning is rejected together with `txindex`, `blockfilterindex`, or a script index, because those need history the prune would delete.

## Worked trace

A regtest start and one mined block produce these storage and commit lines. `$DATA` is the data directory passed to `--data-dir`. The binary emits one JSON object per line; fields are shown as `key=value` with the timestamp and unchanged diagnostic fields removed.

```text
INFO bitcoin_rs_chainstate::recovery chainstate restore selected restore_source=cold reason=no_complete_checkpoint
INFO bitcoin_rs_node::state::open opened storage backend with effective cache capacities backend=fjall chainstate_dir=$DATA/chainstate chainstate_cache_bytes=471859200 txindex_cache_bytes=0 total_cache_bytes=471859200
DEBUG bitcoin_rs_chainstate::connect apply_block: tail begin height=1 outcome.hash=5c3d99d734b492661bac6a4e3f5c8d78ad097ad42c0fa6e9814ca6692b4e5b24
DEBUG bitcoin_rs_chainstate::connect apply_block: publish profile height=1 durable_sync_us=4 durable_commit_us=67
INFO bitcoin_rs_node::lifecycle published clean chainstate checkpoint generation=1
```

`restore_source=cold` means no complete checkpoint was available and the node restored from the durable state. `fjall` is the compiled default backend. The publish line follows the durable commit, not the other way around.

## Tests that pin storage

| Invariant | Test | File |
| --- | --- | --- |
| A matching head needs no replay | `matching_durable_head_requires_no_replay` | [`crates/chainstate/src/durable/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/chainstate/src/durable/tests.rs) |
| Replayed frontier matches the head identity | `replayed_frontier_must_match_the_durable_head_identity` | [`crates/chainstate/src/journal/replay_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/chainstate/src/journal/replay_tests.rs) |
| Pruning keeps retained reorg history | `prune_then_reorg_refuses_deleted_history_but_keeps_retained_reorgs` | [`crates/node/src/state/tests/recovery.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/state/tests/recovery.rs) |
| A second open is refused while the first lives | `second_open_while_first_lives_refuses_and_reopen_succeeds_after_drop` | [`crates/node/src/state/tests/data_dir_lock.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/state/tests/data_dir_lock.rs) |

The [node lifecycle](../embed/lifecycle.md) chapter covers the data-directory lock and shutdown checkpoint. The [indexes](index.md) chapter covers the rows the worker adds on top of this state.
