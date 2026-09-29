# bitcoin-rs-utxo

The in-memory UTXO set: 256 first-byte shards, each a `hashbrown::HashTable` of compact transaction-level records behind a `parking_lot::RwLock`, together with the native snapshot format and the versioned undo codec that make checkpoint load and block disconnect possible.

`UtxoSet` owns the state, and chainstate drives it through one narrow
contract (`contract`): `build_block_changes` turns a validated block into its
`BlockChanges` plus the `UndoBatch` and `BlockValueTotals` consensus checks
need, `commit_block_changes` applies that `BlockChanges`, and `persist_block_undo` /
`load_block_undo` / `rollback_block` carry a block's undo through
persistence and disconnect under the durable marker. Everything contract-
owned is named from `bitcoin_rs_utxo::contract`; the crate root keeps only
the read, snapshot, window-overlay (`WindowOverlay`, `WindowOverlayError`),
and statistics names. `get` returns the `TxOut` payload
while `get_entry` returns the one `UtxoCoin` shape, and
`has_live_outputs_for_txid` supplies the transaction-level BIP30
duplicate-spend predicate.
`with_stable_view` blocks commits while a `UtxoSetView` reads the whole set,
computes the Core `hash_serialized_3` commitment, and scans for exact
scriptPubKey matches; `track_coin_stats` attaches the single
`CoinStatsListener` whose MuHash and accounting follow every commit.

`UtxoAdd<T>` and `BlockChanges<T>` use `TxOut` by default and `&TxOut` for
zero-copy block application. Both commit through `commit_block_changes`; there is no separate
borrowed mutation API. Removal-only batches specify `BlockChanges` explicitly
because they carry no output from which to infer `T`.

Snapshot loading is a clean-cutover contract: `read_snapshot_strict_v4` accepts only complete version-4 snapshots, including the declared record count, the 384-byte MuHash trailer, and end-of-file. Versions 2 and 3 are rejected; an incompatible checkpoint requires an explicit datadir resync.

## Statistics

`stats` holds running UTXO-set statistics: derived computation over the set above, merged in from the former `bitcoin-rs-coinstats` crate (issue #164) because it reads authoritative UTXO state rather than owning any of its own.

`MuHash3072` is Bitcoin Core's 3072-bit `MuHash` as a running numerator/denominator (`insert`, `remove`, `combine`, `finalize_hash` yielding the Core-compatible `uint256`). `CoinStats` folds the live set through `insert_utxo`/`remove_utxo` and serializes to a stable byte layout. `CoinStatsListener` keeps stats behind a lock, applies the block-level delta in `finish_block`, and exposes `rewind_block` as the explicit inverse for disconnects. It is the one listener the set holds: shard-level commit events stay inside the crate. `CoinStatsAccumulator` serves checkpoint traversals -- `with_parallel_muhash` buffers exact coin preimages and combines ordered insert-only partial `MuHash` values, `without_muhash` skips hashing entirely. `scan_coin_stats` recomputes on demand from a `UtxoSetView` (Core's on-demand model, no rolling listener required), and `store_coin_stats`/`load_coin_stats` persist rows keyed by little-endian height.

The checkpoint manifest records this component under the current codec identifier `"bitcoin-rs-coinstats-v1"`. That is an on-disk value; changes to it require a datadir schema epoch bump and explicit resync.

## Features

- `rocksdb`, `fjall`, `redb`: forward the storage-backend selection into the `storage` crate.
- `test-seam`: enables `UtxoReader::fixture_set` so that test builds expose the raw `UtxoSet` through the reader; production builds never compile it, keeping the full mutation path `utxo::contract` private.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
