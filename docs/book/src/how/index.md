# Indexes

Indexes are optional derived state. Every index is off by default, and when one is enabled a single worker thread maintains all of them from committed chain events. The node's applied tip never waits for index writes.

The index lives in [`crates/projection`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/projection). Its contract is [docs/contracts/indexing.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md).

| Index | Enabled by | What it answers |
| --- | --- | --- |
| `TxLookup` | `--txindex true` (`indexes.txindex`) | Transaction by txid, including historical `getrawtransaction` |
| `ScriptLive` | `--scriptindex=utxo` (`indexes.script_index`) | Unspent outputs for a script hash |
| `ScriptHistory` | `--scriptindex=full` | Funding, spending, and history for a script hash |
| Compact filters | `--blockfilterindex` (`indexes.blockfilterindex`) | BIP158 basic filters for filter-serving peers |

`--scriptindex` also accepts `--script-index` and a bare form, which means `full`. `--txindex` requires an explicit `true` or `false`; a bare `--txindex` is a CLI error.

Pruning is refused when any index is enabled, because each one needs history that the prune would delete.

## Wake and catch-up

```text
chainstate commit
  |
  v
publish_applied (ChainSnapshot: epoch, sequence, tip)
  |
  v
ChainFollowers::wake_index
  |  revision += 1, try_send on bounded(1)
  v
index worker thread (bitcoin-rs-txindex)
  |  select shutdown before wake
  |  read revision, reconcile rows against the chain snapshot
  v
IndexWriter batch (rows + consumer cursor in one commit)
```

The wake carries no payload. A revision counter is the signal, and the bounded channel coalesces bursts, so one wake covers any number of commits that arrived before the worker looked (`IDX-08`). Shutdown has priority over wake. The worker catches panics, publishes a `Failed` capability state, and lets the node keep running; apply never depends on index writes (`IDX-07`).

At startup the worker reconciles stored watermarks against the durable head. If the index is ahead of a restored tip it rewinds; if it is behind, it catches up. A rollback deeper than 100,000 blocks cuts over to a full rebuild (`IDX-06`).

## Rows, watermarks, and cursors

Each capability stores its rows plus a watermark that pins them to an active-chain prefix. The watermark and the rows commit in one batch, so a reader never sees rows from a chain the watermark does not name. The consumer cursor `{epoch, sequence, height, hash}` commits in the same batch (`EVT-03`). Rows left by a failed commit are unqueryable because the watermark did not move.

A coverage floor is a per-capability row that states the lowest height from which that capability's history is provable. `TxLookup` stores its floor under one key and `ScriptHistory` under another. A floor of zero means genesis; a positive floor means the history starts above genesis, from pruning or a seeded import. Historical prefix queries use these floors to refuse claims they cannot support.

Row format has a version marker, currently row-format 8. `ScriptLive` rows have 43-byte keys: an 8-byte script-hash prefix followed by the outpoint. Each row value carries the full script hash and the coin's value, height, and coinbase flag in compact varint form, so readers exact-check the script without another store read: a prefix collision cannot return another script's output.

## Strict reads and prefix reads

Two read shapes exist and they do not mix:

- `ScriptLive` reads are self-contained and lock-free (format 8, PRJ-11); they read stored coin payloads directly without acquiring a chain-transition lock or consulting the authoritative UTXO set.
- Historical prefix reads are the three synchronous `Node` calls `transaction_at_prefix`, `script_history_at_prefix`, and `spender_at_prefix`. They take no live-UTXO or transition lock and return `Answer<T>` with a server-selected `CoveredPrefix { floor, height, hash }`.

A historical query pins its serving view epoch and declared capability coverage once. Queries inside coverage return immutable answers regardless of concurrent chain extension or reorg (QRY-03). Queries outside declared coverage return `Unavailable(OutsideCoverage)` (QRY-05). Full history requires floor 0; a standalone spend lookup may return a scoped `None` (`IDX-12`).

Absence means absent in the returned range on the returned chain. It never means globally absent, unspent, or nonexistent, and no mempool data is merged in.

## Capabilities

`Node::capabilities()` returns a `CapabilitySnapshot` with one row, id `txindex`. The row carries `compiled`, `enabled`, and one state: `Ready`, `CatchingUp`, `RollingBack`, `Rebuilding`, `Failed`, `Disabled`, `Opening`, or `ShutdownAbandoned`. Script-history and compact-filter state do not appear in this snapshot, so use it to judge the transaction index, not every index.

RPC `getcapabilities` exposes the same extension shape. RPC `getindexinfo` is registered as implemented but not verified against Core.

The script-hash candidate limit is 25,000 by default. A query above it returns `ScriptHashLimitExceeded`, which Esplora maps to HTTP 422.

## Index bundles

The portable bundle is a one-shot import or export of `TxLookup` only. `--index-bundle-import` and `--index-bundle-export` require `--txindex`, write `manifest.json` last, and check full identity on import. A missing body withholds rather than silently skips (`IDX-11`).

## Worked trace

A regtest node started with `--txindex true --scriptindex=full` logs index store recovery before workers start. `$DATA` is the data directory passed to `--data-dir`:

```text
$ bitcoin-rs --network regtest --data-dir $DATA \
    --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 \
    --txindex true --scriptindex=full
{"timestamp":"2026-11-01T17:01:17.243411Z","level":"INFO","fields":{"message":"index store recovery in progress","capability":"txindex","namespace":"txindex","backend":"rocksdb","elapsed_secs":0},"target":"bitcoin_rs_projection::runtime::startup"}
```

The `txindex` namespace exists only because the index was enabled. With all indexes off, the node starts no worker and creates no index namespace (`IDX-01`).

The worker's catch-up and row writes do not log at `info` in this build, so the observable result is the capability state and the query answers, not a per-block line.

## Contract clauses

| Clause | Rule |
| --- | --- |
| `IDX-01` | Flags and enablement; one worker; all off means no worker or namespace |
| `IDX-02` | Only explicit `--txindex` advertises Core txindex and historical `getrawtransaction` |
| `IDX-03` | Query gating, snapshot consistency, and the 25,000 script-hash limit |
| `IDX-04` | A degraded capability resets alone; siblings keep serving |
| `IDX-05` | Restart reconciliation and refusal of foreign schema versions |
| `IDX-06` | Reorg rollback, forward groups, and rebuild above 100,000 blocks |
| `IDX-07` | Error isolation and supervised rebuild |
| `IDX-08` | Coalesced wake with shutdown precedence |
| `IDX-09` | Canonical row cardinality and replay before workers spawn |
| `IDX-10` | One writer, rows and watermark in one batch |
| `IDX-11` | Portable bundle import and export for `TxLookup` |
| `IDX-12` | Historical prefix queries and scoped absence |

## Tests that pin the index

| Invariant | Test | File |
| --- | --- | --- |
| A positive floor scopes absence and refuses a low anchor | `historical_tx_positive_floor_scopes_absence_and_rejects_anchor_below_floor` | [`crates/projection/src/runtime/query_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/projection/src/runtime/query_tests.rs) |
| Full history above a positive floor is unproven | `historical_full_history_positive_floor_is_unproven` | [`crates/projection/src/runtime/query_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/projection/src/runtime/query_tests.rs) |
| A coverage floor is stamped and cleared on reset | `anchor_watermark_stamps_a_coverage_floor_that_reset_clears` | [`crates/projection/src/index/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/projection/src/index/tests.rs) |
| Cursor paging neither skips nor repeats | `cursor_page_continues_without_skipping_or_repeating` | [`crates/projection/src/runtime/query/scripts.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/projection/src/runtime/query/scripts.rs) |
| Starting workers twice is idempotent | `start_index_workers_twice_is_idempotent` | [`crates/node/src/state/tests/index.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/state/tests/index.rs) |

The [state and storage](state-and-storage.md) chapter covers the durable records the worker reads, and the [architecture](architecture.md) chapter covers the wake call site.
