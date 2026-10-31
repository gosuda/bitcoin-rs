# Script history and live-index on-disk format

This document owns the on-disk format of the derived index. It states the row families, row-format 6, the ordering rule, and the write-amplification bench that decides the backend.

## Durability gate

`IndexWriter::open` accepts one durability marker in `ColumnFamily::UtxoMeta`: key `[0x00, b'V']`, value `06 00 00 00`. The marker covers key layout and row-value widths. Any other marker returns `IndexError::UnsupportedTxIndexFormatVersion`. `open_writer` in `crates/index/src/runtime/startup.rs` then resets the derived namespace and rebuilds it from chainstate. There is no translator, no legacy reader, and no in-place upgrade. Authoritative chainstate bytes are untouched. The datadir-wide `CURRENT_SCHEMA` does not move.

## Row families

| Family | Key | Value | Purpose |
|---|---|---|---|
| `TxConfirmed` | txid prefix (8) + big-endian height (4) | 6-byte `TxPosition` per transaction | transaction lookup and page cursors |
| `Funding` | script prefix (8) + inverted big-endian height (4) | 71-byte occurrence per transaction | script history, funding and spending |
| `Spending` | outpoint prefix (8) + big-endian height (4) | 6-byte `TxPosition` per spending transaction | `spender` and outspend reads |
| `ScriptLive` | script prefix (8) + txid (32) + vout u24 (3) | empty | current unspent locators |
| `BlockHeaders` | 80-byte header | empty | identity rows |
| `UtxoMeta` | reserved `0x00`-prefixed and tagged keys | version, watermarks, filters | gate and metadata |

One block commits all of its rows and the capability watermark in one store batch (`IDX-10`).

## The occurrence row

One row holds every occurrence of one script at one height.

- The key is the first eight bytes of the script hash, then the height with every bit inverted, big-endian.
- Inverting the height makes ascending key order newest height first. A page starts at the tip or at a cursor height and reads forward. No reverse scan exists in any backend.
- The value is one or more occurrences, each 71 bytes: script hash (32), transaction id (32, little-endian), `TxPosition` (6), flags (1).
- Flag bit 0 means the transaction funds the script. Flag bit 1 means the transaction spends an output of the script. A transaction that does both appears once with both bits set.
- An empty value, a length that is not a multiple of 71, or a flag byte with an unknown bit is corrupt derived state. Queries refuse it and direct a rebuild.
- The eight-byte prefix is lossy. Every occurrence carries the full script hash, so a prefix collision is filtered without reading a block.

The spent script of a spending occurrence comes from authoritative UTXO state, or from the block's undo record during rollback. A missing spent script fails preparation with `MissingSpentCoin`. A spending occurrence is never written for an unknown script.

## Read cost

`confirmed_history` reads every occurrence of one script in height order. It serves address summaries and historical snapshots.

`confirmed_history_page` serves one newest-first page. Its cursor is an exclusive `(height, serialized-block byte offset)` pair. `history_cursor` resolves an API-09 transaction id to that pair. One page reads at most one height-row scan per 32 rows, and it reads no block body. A page therefore costs the same for a script with 100, 1,000, or 10,000 occurrences.

## Write-amplification bench

`crates/index/benches/write_amplification.rs` builds one deterministic synthetic chain of 20,000 blocks. The chain pays three script buckets and spends the previous block's coinbase. The bench commits the chain three times into a fresh store: `tx_lookup` alone, `script_history` alone, and `script_live` alone.

Run one backend at a time:

```bash
RUSTC_WRAPPER= cargo bench -p bitcoin-rs-index --features fjall --bench write_amplification
RUSTC_WRAPPER= cargo bench -p bitcoin-rs-index --features redb --bench write_amplification
RUSTC_WRAPPER= cargo bench -p bitcoin-rs-index --features rocksdb --bench write_amplification
```

Each run prints one line per family with these fields:

| Field | Meaning |
|---|---|
| `write_bytes` | process `write_bytes` from `/proc/self/io`, sampled around the forward commits |
| `logical_bytes` | `PreparedBlock::encoded_bytes` summed over the commits |
| `amplification_permille` | `write_bytes * 1000 / logical_bytes` |
| `build_ms` | forward-commit wall time for the whole chain |
| `snapshot_open_us` | time to open a reader snapshot after the build |
| `footprint_bytes` | store-directory bytes above the post-open baseline |
| `query_p50_us`, `query_p95_us`, `query_p99_us`, `query_max_us` | the family's row scan over 200 samples |
| `reorg_us` | rollback of the last 6 blocks through the fenced rollback path |

The chain is layout-valid only. Custom input outpoints do not name real predecessor transactions, so the bench measures row encoding and never consensus validity. It makes no mainnet projection.

### Decision rule

Keep Fjall as the index namespace default unless another backend writes at least 2 times fewer physical bytes, and its query p95 and build time are no more than 10 percent worse. Record the measured table and the decision below. When another backend wins, make it the default for new index namespaces; the format gate rebuilds any existing index.

## Measured results

Run: 2026-10-31, one host, `RUSTC_WRAPPER= cargo bench -p bitcoin-rs-index --features fjall --bench write_amplification`. Scope: the synthetic 20,000-block chain, one run per family, Fjall only.

| Family | Backend | physical writes | logical_bytes | build_ms | on-disk attribution | query_p50_us | query_p95_us | query_p99_us | query_max_us | reorg_us |
|---|---|---|---|---|---|---|---|---|---|---|
| `tx_lookup` | Fjall | unavailable | 4,840,000 | 1,260 | unavailable | 0 | 1 | 1 | 8 | 348 |
| `script_history` | Fjall | unavailable | 30,727,461 | 1,414 | unavailable | 27,342 | 32,821 | 39,612 | 64,077 | 1,151 |
| `script_live` | Fjall | unavailable | 23,959,226 | 2,163 | unavailable | 131,998 | 163,136 | 182,714 | 185,327 | 947 |

Limits of these numbers, read before using them:

- `physical writes` is `unavailable`. The run reported 0 counted `write(2)` bytes, and the store directory showed a 0-byte delta from its post-open baseline. The bench did not trace which backend mechanism absorbed the writes, so it attributes neither of those observations to a cause and reports no amplification.
- On-disk attribution is `unavailable` for the same observed reason: the directory did not grow past the baseline taken right after open, so per-family on-disk bytes cannot be separated on this backend with this method.
- `query_p50_us` for `tx_lookup` is below one microsecond. The field is integer microseconds, so 0 means "under 1 us".
- `script_live` row scans are slower than `script_history` row scans in this run. The measured call is the raw locator scan, so the bench does not attribute the difference to a cause.
- `snapshot_open_us` replaces the earlier `reopen_ms` field. It measures creating a reader snapshot on the still-open store, not closing and reopening the backend. Every run reported under one millisecond.

Decision: keep Fjall as the index namespace default. The decision rule needs physical bytes, and this host cannot measure them for Fjall. A backend swap needs a run that produces a non-zero physical-write count for each family; until then, no other backend has evidence against Fjall. Redb and RocksDB rows are absent because a full run per backend needs a clean bench build for each feature set; run them with the same command and `--features redb` or `--features rocksdb`.
