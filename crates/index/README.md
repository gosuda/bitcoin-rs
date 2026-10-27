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
is the read side over the same store. `iter_funding_rows`, `iter_spending_rows`, and
`iter_live_outpoints` scan a lossy 8-byte prefix. Funding and spending rows come back in
chronological (big-endian height) order; live outpoints come back in key byte order.
Exact resolution of those rows against full block identity lives in the runtime query
engine, which reads row-scoped block ranges by height.
`PreparedBlock`/`PreparedBatch` under `PreparedBatchLimits` bound one atomic
forward write by row count and encoded bytes, and `IndexWriter` is the mutation-only
handle for durable prepared writes. `IndexWatermark` is the durable
`(height, full block hash)` cursor — encoded as `height || hash`, readable from a snapshot —
while the `IndexReader` trait captures a point-in-time `TxIndexSnapshot` for bounded
typed scans (`TxIndexScan`). The index durability marker (`[0x00, b'V']`, currently row-format 5) owns the
compatibility boundary for these rows; a mismatch refuses open and recovery full-resets for rebuild, while the datadir-wide `CURRENT_SCHEMA` covers only authoritative chainstate bytes. Around the rows sit the stable types (`ScriptHash`, `HashPrefixRow`,
`ScriptHashRow`, `ScriptLiveRow`, `SpendingPrefixRow`, `TxPosition`).

## Implementation boundaries

`lib.rs` exports the public API through the private `index.rs` facade.
Its private modules separate block preparation
(`block`, `prepared`), canonical row mutation (`rows`), durable writes (`write`),
and coherent fences/reset recovery (`state`). Read-side scans (`reader`,
`snapshot`) remain separate from mutations;
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
