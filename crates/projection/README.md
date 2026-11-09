# bitcoin-rs-projection

Owns the confirmed-transaction index: compact rows over the workspace key-value
store and versioned `TxLookup`/`ScriptHistory`/`ScriptLive` watermarks that pin
rows to an exact active-chain prefix. `ScriptLive` is the compact reverse view
of the authoritative UTXO set: each row stores a complete outpoint after an
eight-byte script-hash prefix, with a value carrying the full script hash and
the coin's value, height, and coinbase flag in compact varint form.

`IndexWriter` is the sole mutation owner. It prepares each block from its committed
facts (`prepare_block_from_facts`), or from the serialized body on the gap fallback
(`prepare_block_with_spent_scripts`), which parses the body once. Each `PreparedBatch`
commit writes block headers and live-outpoint rows; transaction, script-history, and
compact-filter rows go to the segment tail. `Indexer<S: KvStore>` is the read side over
the same store, and `iter_live_outpoints` scans a lossy 8-byte prefix. Live outpoints
come back in key byte order.
`PreparedBlock`/`PreparedBatch` under `PreparedBatchLimits` bound one atomic
forward write by row count and encoded bytes, and `IndexWriter` is the mutation-only
handle for durable prepared writes. `IndexWatermark` is the durable
`(height, full block hash)` cursor, encoded as `height || hash` and readable from a snapshot.
The `IndexReader` trait captures a point-in-time `TxIndexSnapshot` for bounded
typed scans (`TxIndexScan`). The index durability marker (`[0x00, b'V']`, currently row-format 6) owns the
compatibility boundary for these rows. A mismatch refuses open, and recovery full-resets for rebuild. The datadir-wide `CURRENT_SCHEMA` covers only authoritative chainstate bytes. The stable types are `ScriptHash`, `HashPrefixRow`,
`ScriptHashRow`, `ScriptHistoryOccurrence`, `ScriptLiveRow`, `SpendingPrefixRow`, `TxPosition`.

## Implementation boundaries

The runtime query engine owns exact transaction resolution; `Indexer` exposes
row scans and watermark reads rather than a second resolution policy.
`TxQueryError::Unavailable(TxUnavailableCause)` gives callers typed refusal
causes, while the query branches still decide whether absence is proven.

`QueryBudget` retains one verified decoded block per query, keyed by height and
full block hash. Consecutive reads of that identity reuse the block without
another body read or byte charge; changing identity evicts it before fetching.
Positioned reads and full-block fallback share the row's resolved block hash.
These are implemented query behaviors, not measured latency or RSS gains.

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
- `surrealkv`: forwards the optional SurrealKV backend feature to `bitcoin-rs-storage`
- `mdbx`: forwards the optional libmdbx backend feature to `bitcoin-rs-storage`
- `test-seam`: exposes in-workspace test composition; production dependencies never enable it

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
