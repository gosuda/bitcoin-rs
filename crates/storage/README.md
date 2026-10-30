# bitcoin-rs-storage

This crate provides the backend-neutral storage layer that every persisted index and chain-state store sits on. It provides key-value access over named column families and atomic write batches with an explicit durability ladder. It also provides append-only flat files for immutable block bodies, and the streaming Core frame format.

`KvStore` is the central trait. It provides `get`, ordered `iter_prefix` iteration, bounded `scan_prefix_bounded` scans under a `PrefixScanLimit`, and point-in-time `snapshot` reads. All mutations go through one backend-neutral `BufferedWriteBatch` record. The store applies that record by `write`, by `write_deferred` (visible immediately, crash durability deferred to `flush`), or by `write_durable`. `ColumnFamily` names the logical column families shared by every backend. `StorageError` is the common error type. Concrete backends are feature-gated and exported from the crate root: `FjallStore` (the default), `RocksDbStore`, and `RedbStore`. The implementation modules themselves are private. The specialized redb transaction index has no public concrete type. It is constructed only through the redb-gated `open_redb_tx_index_store` factory, which hides the store behind an opaque `impl KvStore`. Immutable block bodies bypass key-value storage entirely. `FlatFileBlockStore` manages the append-only flat files with `BlockFilePosition` addressing (reads go through the store's internal block reader).

All backends also implement `write_durable_if`. The call takes a conjunction
of `WriteCondition`s: each key is `Absent`, or its value `Equals` an `expected`
byte string. The call durably applies the entire ordered batch only when every
condition matches the pre-batch state. The batch itself may put or delete
condition keys. The empty slice is an all-true conjunction and commits
unconditionally. Every condition is read and compared before any batch
operation applies. The first mismatch returns `false` with no mutation. An
unknown family, failed lookup, or backend error on any condition propagates as
`Err` and is never treated as a miss. The call returns `true` only after the
commit is durable. The condition reads and the batch commit share one backend
write boundary. Competing writers therefore cannot both observe the same
pre-image. No backend releases its lock or transaction between condition
evaluation and commit.

## Pruning

`pruning` deletes historical block bodies and undo records once the active chain no longer needs them. It lives here rather than in a crate of its own, because it is a retention policy over rows this crate already owns.

`stage_block_and_undo_prune` stages block-body and undo-row deletion together
with prune-height metadata into one caller-owned atomic batch. Node wiring
therefore commits them in a single backend commit.
`reclaim_staged_flat_block_files` then deletes the staged flat block files.
`PruneOutcome` reports the bytes and rows freed. The code prunes block bodies
and undo rows against the durable tip rather than the in-memory tip. Retained
bodies support local replay after a crash. Retained undo rows support
disconnecting through recovered state. The per-row machinery is `block_pruner`
(`block_body_key`, `BLOCK_DATA_CF`) and `undo` (`block_undo_key`,
`ColumnFamily::UndoData`). `PrunePolicy` is defined in `pruning.rs`. It
converts the configured mebibyte target to bytes and applies the reorg-safety
retention floor. The pruning pass owns deletion. The node builds the policy
from configuration and hands it in.

`block_body_key` and `BLOCK_DATA_CF` are not only pruning concerns. They are the block-body key schema, and the node reads bodies through them on the ordinary path.

`RetentionRegistry` is the retained-history authority. It owns the executed
frontier and the prune reserve/commit protocol. It is the only type that
grants retention. Composition seeds it once from the frontier the store
reports. It then hands out roles rather than the registry. Chainstate
gets `MandatoryRetention`. That role can only acquire and release the pins a
transition re-reads, and it can report what is already gone. An optional
consumer gets `HistoryAccess`, bounded by the budget it was granted. A stalled
consumer therefore stops binding the prune line instead of blocking it.
`node:prune_executed` rows are written in the same durable batch as their
deletions. A restart therefore reconstructs exactly the committed boundary and
refuses a lease over deleted history.

## Cache budget

`dbcache` is one process-wide budget. `cache_budget::split_cache_budget` divides
it across the persistent namespaces — chainstate 80% and txindex 20% when
enabled — flooring each share and handing the remainder (plus every disabled
namespace's share) to chainstate, so the shares always sum to at most the
budget. Each backend accepts its namespace's share through `open_with_cache`
(`open_redb_tx_index_store_with_cache` for the redb transaction index); fjall
sizes its block cache, redb its page cache, and `RocksDB` its LRU block cache.
Clamping bounds: budgets land in
`[16 MiB, 1 TiB]`, and the node logs the effective per-namespace capacities at
startup.

## Store guard

Every file-owning store (`FjallStore`, `RocksDbStore`, `RedbStore`, the redb
transaction index, and `FlatFileBlockStore`) can keep one opaque `StoreGuard`
through `guarded_by` (a builder method; the redb transaction index takes it
as the `guard` argument of `open_redb_tx_index_store_with_cache`).
The guard is the store's last field, so it drops only after the engine or file
handle has closed. The node passes its data-directory lock this way: the lock
lives exactly as long as the last handle that can still write the directory,
however a consumer retains that handle. Storage never inspects the guard.

## Test isolation

Persistence fault slots and injection APIs are compiled only for tests or the
explicit, non-default `test-seam` feature. Real-backend durability tests opt in
through dev-dependencies; production writes retain their ordinary durability
barriers. Storage measurement lives separately in `tools/storage-footprint`
and has no dependency on this crate.

## Features

- `fjall` (default): enables the fjall-backed `FjallStore`.
- `rocksdb`: enables the Rust-RocksDB-backed `RocksDbStore`.
- `test-seam`: exposes fixture persistence injection; not a production default.
- `redb`: enables the redb-backed `RedbStore` and the `open_redb_tx_index_store` transaction-index factory.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
