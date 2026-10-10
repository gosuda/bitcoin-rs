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

`UtxoReader` is what a consumer receives instead of the set. It carries the
coin lookups, the `has_live_outputs_for_txid` duplicate-spend predicate, and
both stable whole-set reads (`with_stable_view`, `lock_stable_view`), and it
cannot reach `contract`: the set stays with its mutation owner. Under the
`test-seam` feature `UtxoReader::fixture_set` reveals the set so a fixture
can commit through `contract`; production builds do not compile it.

`UtxoAdd<T>` and `BlockChanges<T>` use `TxOut` by default and `&TxOut` for
zero-copy block application. Both commit through `commit_block_changes`; there is no separate
borrowed mutation API. Removal-only batches specify `BlockChanges` explicitly
because they carry no output from which to infer `T`.

Native checkpoint loading is a clean-cutover contract: `read_snapshot_strict_v4` accepts only complete version-4 snapshots, including the declared record count, the 384-byte MuHash trailer, and end-of-file. Versions 2 and 3 are rejected; an incompatible checkpoint requires an explicit datadir resync.

## Bitcoin Core portable snapshots

`core_snapshot::read_metadata` parses only the fixed Core v2 header. Its network
magic, base hash and output count remain untrusted. `read_and_verify` selects a
compiled `AssumeUtxoData` by network and base hash, stages the existing owned
UTXO records, and recomputes `hash_serialized_3` against that anchor before any
hash-table insertion. The same per-coin serializer serves the existing UTXO
stable-view commitment. After the commitment matches, record payloads move into
the existing `UtxoSet` without copying. Height
and cumulative transaction count come from the compiled pin, never the file.
A successful result establishes pinned-state consistency; historical validation
from genesis remains the chainstate manager's responsibility.

The portable reader does not alter the source or a datadir. It handles Core's
txid groups, CompactSize counts/indices, subtract-one Core VARINT fields, amount
compression and all six special script encodings. Core's uncompressed P2PK forms
(4/5) require a valid curve point; compressed forms (2/3) preserve the original
bytes even when they are not a curve point, matching Core's codec. Malformed
uncompressed keys and scripts longer than 10,000 bytes are rejected directly;
the reader does not imitate Core's malformed-input script substitutions.

`SnapshotLimits` bounds encoded bytes (including the header), live output count,
aggregate decompressed script bytes, and outputs per txid before growing the
corresponding state. Defaults are 32 GiB encoded bytes, 250 million coins,
32 GiB aggregate scripts and one million outputs per group. Before authentication,
strict txid order and per-group numeric-vout sorting detect duplicates without
hashing attacker-controlled keys. A temporary vector owns the existing compact
records; its allocation remains while authenticated payloads move into the UTXO
hash table. Forged collision families are rejected before that insertion boundary.
No alternate coin model or durable staging format is introduced. The EOF check
reads at most one additional byte. These limits bound work and retained input-derived
state, not process RSS. Staged record owners, group sorting and the final UTXO
set remain memory-resident and have additional allocation overhead; large-file runs require
operator-selected budgets and measured RSS. Header inspection does not scan or
validate the body.

The reference format is
[Bitcoin Core v31.1 SnapshotMetadata](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/node/utxo_snapshot.h),
[the snapshot writer](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/rpc/blockchain.cpp#L3252),
and [Coin compression](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/compressor.h).
The [Core-produced regtest fixture](tests/fixtures/core-v2/README.md) includes
provenance and a reproduction command. This library support does not implement
node RPC activation, process lifecycle interoperability, or snapshot export.

## Statistics

`stats` holds running UTXO-set statistics: derived computation over the set above, merged in from the former `bitcoin-rs-coinstats` crate (issue #164) because it reads authoritative UTXO state rather than owning any of its own.

`MuHash3072` is Bitcoin Core's 3072-bit `MuHash` as a running numerator/denominator (`insert`, `remove`, `combine`, `finalize_hash` yielding the Core-compatible `uint256`). `CoinStats` folds the live set through `insert_utxo`/`remove_utxo` and serializes to a stable byte layout. `CoinStatsListener` keeps stats behind a lock, applies the block-level delta in `finish_block`, and exposes `rewind_block` as the explicit inverse for disconnects. It is the one listener the set holds: shard-level commit events stay inside the crate. `CoinStatsAccumulator` serves checkpoint traversals -- `with_parallel_muhash` buffers exact coin preimages and combines ordered insert-only partial `MuHash` values, `without_muhash` skips hashing entirely. `scan_coin_stats` recomputes on demand from a `UtxoSetView` (Core's on-demand model, no rolling listener required).

The checkpoint manifest records this component under the current codec identifier `"bitcoin-rs-coinstats-v1"`. That is an on-disk value; changes to it require a datadir schema epoch bump and explicit resync.

## Features

- `rocksdb`, `fjall`, `redb`: forward the storage-backend selection into the `storage` crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
