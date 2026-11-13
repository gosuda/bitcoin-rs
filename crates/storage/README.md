# bitcoin-rs-storage

This crate provides the backend-neutral storage layer that every persisted index and chain-state store sits on. It provides key-value access over named column families and atomic write batches with an explicit durability ladder. It also provides append-only flat files for immutable block bodies, and the streaming Core frame format.

`KvStore` is the central trait. It provides `get`, ordered `iter_prefix` iteration, bounded `scan_prefix_bounded` scans under a `PrefixScanLimit`, and point-in-time `snapshot` reads. All mutations go through one backend-neutral `BufferedWriteBatch` record. The store applies that record by `write`, by `write_deferred` (visible immediately, crash durability deferred to `flush`), or by `write_durable`. `ColumnFamily` names the logical column families shared by every backend. `StorageError` is the common error type. RocksDB is the mandatory default storage engine, always compiled and exported as `RocksDbStore`. The implementation modules themselves are private. Retired runtime engines (`FjallStore`, `RedbStore`, and the specialized redb transaction index) have been removed from the node; legacy datadirs are migrated offline using `tools/storage-convert`. Immutable block bodies bypass key-value storage entirely. `FlatFileBlockStore` manages the append-only flat files with `BlockFilePosition` addressing (reads go through the store's internal block reader).

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

## Storage engines

`bitcoin-rs-storage` supports three storage engines behind the unified `KvStore` facade:

- `rocksdb`: The mandatory default storage engine, always compiled and exported as `RocksDbStore`. Backed by RocksDB 11.12 via `rust-rocksdb`.
- `surrealkv`: Optional storage engine adapter exported as `SurrealKvStore`, enabled via the `surrealkv` cargo feature. Backed by SurrealKV 1.x.
- `mdbx`: Optional storage engine adapter exported as `MdbxStore`, enabled via the `mdbx` cargo feature. Backed by libmdbx via `signet-libmdbx`.

The storage engine is selected at runtime with `--storage-backend`, `BITCOIN_RS_STORAGE_BACKEND`, or TOML `storage_backend`, which accepts `rocksdb`, `surrealkv`, or `mdbx`.

The engine crate allow-list and backend feature-forwarding rules are owned by `ARCH-02` and `ARCH-03` in the [architecture contract](../../docs/contracts/architecture.md). This section describes the adapters and their runtime selection only.

## Pruning

`pruning` deletes historical block bodies and undo records once the active chain no longer needs them. It lives here rather than in a crate of its own, because it is a retention policy over rows this crate already owns.

`stage_block_and_undo_prune` stages block-body and undo-row deletion together with prune-height metadata into one caller-owned atomic batch. Node wiring therefore commits them in a single backend commit. `reclaim_staged_flat_block_files` then deletes the staged flat block files. `PruneOutcome` reports the bytes and rows freed. The code prunes block bodies and undo rows against the durable tip rather than the in-memory tip. Retained bodies support local replay after a crash. Retained undo rows support disconnecting through recovered state. The per-row machinery is `block_pruner` (`block_body_key`, `BLOCK_DATA_CF`) and `undo` (`block_undo_key`, `ColumnFamily::UndoData`). `PrunePolicy` is defined in `pruning.rs`. It converts the configured mebibyte target to bytes and applies the reorg-safety retention floor. The pruning pass owns deletion. The node builds the policy from configuration and hands it in.

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

`dbcache` is one process-wide budget, clamped to `[16 MiB, 1 TiB]`.
`cache_budget::split_cache_budget_with_txindex` first divides it across the
persistent namespaces: txindex receives 20%, floored to whole bytes, and
chainstate receives the remainder.
`cache_budget::split_cache_budget_without_txindex` gives the whole budget to
chainstate when the transaction index is disabled.

The chainstate allowance is then split equally between the storage engine and
the `CoinStore` cache. The engine receives half, floored to whole bytes; coins
receive the remainder, including the extra byte when the allowance is odd.
The backend receives only the engine share through `open_with_cache`; RocksDB
uses it to size its LRU block cache. MDBX ignores the engine share; that share
is not reassigned to coins. The txindex share is unchanged.

The startup log's `chainstate_cache_bytes` field reports the full chainstate
allowance before the engine/coin split, not either owner's capacity.
`txindex_cache_bytes` and `total_cache_bytes` retain their namespace and total
budget meanings. These are cache allowances, not a process RSS limit.

## Store guard

Every file-owning store (`RocksDbStore` and `FlatFileBlockStore`) can keep one
opaque `StoreGuard` through `guarded_by`. This is a builder method.
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

- `surrealkv`: enables the optional SurrealKV storage backend.
- `mdbx`: enables the optional libmdbx storage backend.
- `test-seam`: exposes fixture persistence injection; not a production default.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
