# bitcoin-rs-storage

The backend-neutral storage layer every persisted index and chain-state store sits on: key-value access over named column families, atomic write batches with an explicit durability ladder, append-only flat files for immutable block bodies, and the streaming Core frame format.

`KvStore` is the central trait: `get`, ordered `iter_prefix` iteration, bounded `scan_prefix_bounded` scans under a `PrefixScanLimit`, and point-in-time `snapshot` reads, with all mutations going through backend-specific `WriteBatch` types applied by `write`, by `write_deferred` (visible immediately, crash durability deferred to `flush`), or by `write_durable`. `ColumnFamily` names the logical column families shared by every backend and `StorageError` is the common error type. Concrete backends are feature-gated and exported from the crate root: `FjallStore` (the default), `RocksDbStore`, `RedbStore`, and `MdbxStore`; the implementation modules themselves are private. The specialized redb transaction index has no public concrete type: it is constructed only through the redb-gated `open_redb_tx_index_store` factory, which hides the store behind an opaque `impl KvStore`. Immutable block bodies bypass key-value storage entirely: `FlatFileBlockStore` and `FlatFileBlockReader` manage the append-only flat files with `BlockFilePosition` addressing.

All backends also implement `write_durable_if`: given a conjunction of
`WriteCondition`s — each key `Absent`, or its value `Equals` an `expected` byte
string — it durably applies the entire ordered batch only when every condition
matches the pre-batch state (the batch itself may put or delete condition
keys). The empty slice is an all-true conjunction and commits
unconditionally. Every condition is read and compared before any batch
operation applies: the first mismatch returns `false` with no mutation, while
an unknown family, failed lookup, or backend error on any condition propagates
as `Err` and is never treated as a miss. `true` is returned only after the
commit is durable. The condition reads and the batch commit share one backend
write boundary, so competing writers cannot both observe the same pre-image
and no backend releases its lock or transaction between condition evaluation
and commit.

## Pruning

`pruning` deletes historical block bodies and undo records once the active chain no longer needs them. It is here rather than in a crate of its own (issue #164) because it is a retention policy over rows this crate already owns -- the former `bitcoin-rs-pruning` declared `bitcoin-rs-utxo`, `bitcoin-rs-chain` and `bitcoin` and referenced none of them.

`stage_block_and_undo_prune` stages block-body and undo-row deletion together with prune-height metadata into one caller-owned atomic batch, so node wiring commits them in a single backend commit; `reclaim_staged_flat_block_files` then deletes the staged flat block files, and `PruneOutcome` reports the bytes and rows freed. Undo rows are pruned against the durable tip rather than the in-memory tip, because a crash restores to the last durable checkpoint and must still be able to disconnect back through it -- block bodies are re-downloadable and are not held to that constraint. The per-row machinery is `block_pruner` (`BlockPruner`, `block_body_key`, `BLOCK_DATA_CF`) and `undo_pruner` (`UndoPruner`, `block_undo_key`); `PrunePolicy` carries no behaviour of its own, and the node builds one from configuration and hands it in.

Note that `block_body_key` and `BLOCK_DATA_CF` are not only pruning concerns: they are the block-body key schema, and the node reads bodies through them on the ordinary path.

## Cache budget

`dbcache` is one process-wide budget. `cache_budget::split_cache_budget` divides
it across the persistent namespaces — chainstate 80% and txindex 20% when
enabled — flooring each share and handing the remainder (plus every disabled
namespace's share) to chainstate, so the shares always sum to at most the
budget. Each backend accepts its namespace's share through `open_with_cache`
(`open_redb_tx_index_store_with_cache` for the redb transaction index); fjall
sizes its block cache, redb its page cache, `RocksDB` its LRU block cache, and
MDBX its reserved dirty-page pool. Clamping bounds: budgets land in
`[16 MiB, 1 TiB]`, and the node logs the effective per-namespace capacities at
startup.

## Features

- `fjall` (default): enables the fjall-backed `FjallStore`.
- `rocksdb`: enables the Rust-RocksDB-backed `RocksDbStore`.
- `redb`: enables the redb-backed `RedbStore` and the `open_redb_tx_index_store` transaction-index factory.
- `mdbx`: enables the MDBX-backed `MdbxStore`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
