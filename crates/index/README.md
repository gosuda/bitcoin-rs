# bitcoin-rs-index

Owns the confirmed-transaction index: compact rows over the workspace key-value
store and versioned `TxLookup`/`ScriptHistory`/`ScriptLive` watermarks that pin
rows to an exact active-chain prefix. `ScriptLive` is the compact reverse view
of the authoritative UTXO set: each row stores an empty value and a complete
outpoint after an eight-byte script-hash prefix.

`IndexWriter` is the sole mutation owner: it walks a serialized block once
(`prepare_block` / `prepare_block_with_spent_scripts`) and commits bounded
`PreparedBatch` writes of txid, script-funding, previous-outpoint spending,
and live-outpoint rows (counted by `IndexRowCounts`). `Indexer<S: KvStore>`
is the read side over the same store. `iter_funding_rows` and `iter_live_outpoints` scan a
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
`ScriptHashRow`, `ScriptLiveRow`, `SpendingPrefixRow`, `TxPosition`) and generic
script-history resolution.

## Implementation boundaries

`lib.rs` exports the public API through the private `index.rs` facade.
Its private modules separate block preparation
(`block`, `prepared`), canonical row mutation (`rows`), durable writes (`write`),
and coherent fences/reset recovery (`state`). Read-side scans (`reader`,
`snapshot`) and exact resolution (`resolve`) remain separate from mutations;
`capability` and `error` own shared representations and typed outcomes.
The facade limits shared implementation details to the index module. Backend
opening and legacy-format rebuild decisions live in `runtime/startup.rs`.
Public paths and on-disk encodings do not depend on this layout.

## Features
- `silent-payments`: experimental, stateless BIP352 v0 public tweak codec over
  complete prevout scripts or a certified `BlockSpends`. No startup scan,
  durable rows, wallet keys or network endpoints. See the
  [feasibility note](../../docs/silent-payments.md).
- `rocksdb`: enables the `RocksDB` backend in `bitcoin-rs-storage`
- `fjall`: enables the fjall backend in `bitcoin-rs-storage`
- `redb`: enables the redb backend in `bitcoin-rs-storage`

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
