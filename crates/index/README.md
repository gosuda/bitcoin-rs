# bitcoin-rs-index

Owns the confirmed-transaction index: compact rows over the workspace key-value
store and versioned `TxLookup`/`ScriptHistory`/`ScriptLive` watermarks that pin
rows to an exact active-chain prefix. `ScriptLive` is the compact reverse view
of the authoritative UTXO set: each row stores an empty value and a complete
outpoint after an eight-byte script-hash prefix.

`Indexer<S: KvStore>` walks a serialized block once (`ingest_block`) and writes txid,
script-funding, previous-outpoint spending, and live-outpoint rows (counted by
`IndexRowCounts`); `iter_funding_rows` and `iter_live_outpoints` scan a
scripthash prefix, and `resolve_script_history` exact-resolves
the lossy 8-byte prefix against a `BlockSource` that fetches block bytes by height and
range. `PreparedBlock`/`PreparedBatch` under `PreparedBatchLimits` bound one atomic
forward write by row count and encoded bytes, and `IndexWriter` is the mutation-only
handle for durable prepared writes. `IndexWatermark` is the durable
`(height, full block hash)` cursor — encoded as `height || hash`, readable from a snapshot —
while the `IndexReader` trait captures a point-in-time `TxIndexSnapshot` for bounded
typed scans (`TxIndexScan`). The datadir-wide `CURRENT_SCHEMA` marker owns the
compatibility boundary for these rows; an incompatible datadir fails before the index
store opens. Around the rows sit the stable types (`ScriptHash`, `HashPrefixRow`,
`HeaderRow`, `TxidRow`, `SpendingPrefixRow`), `MempoolRowWriter` for unconfirmed rows
and generic script-history resolution.

## Features
- `rocksdb`: enables the `RocksDB` backend in `bitcoin-rs-storage`
- `fjall`: enables the fjall backend in `bitcoin-rs-storage`
- `redb`: enables the redb backend in `bitcoin-rs-storage`
- `mdbx`: enables the MDBX backend in `bitcoin-rs-storage`

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
