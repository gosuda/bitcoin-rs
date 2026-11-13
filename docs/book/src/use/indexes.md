# Transaction and script-hash indexes

Enable `--txindex` for transaction-id lookup and `--scriptindex=utxo` or `--scriptindex=full` for address queries and script history. Indexes are off by default, and none of them may be combined with pruning.

## What each index answers

| Option | Values | What it enables |
| --- | --- | --- |
| `--txindex` | `true` or `false` | Transaction-id lookup across confirmed blocks, the Core `txindex` row in `getindexinfo`, and `/rest/tx` for non-mempool transactions. |
| `--scriptindex` | `utxo`, `full`, or a boolean | `utxo` builds only the live unspent view behind address and scripthash UTXO queries. `full` adds confirmed script history and spender queries. `true`, `1`, and `yes` mean `full`; `false`, `0`, and `no` mean disabled. A bare flag means `full`. |
| `--blockfilterindex` | `true` or `false` | Basic BIP158 compact filters served by `getblockfilter`, and the `basic block filter index` row in `getindexinfo`. |

There is no history-only mode. `--scriptindex` also accepts the visible alias `--script-index`. The TOML key is `script_index`, the environment name is `BITCOIN_RS_SCRIPTINDEX`, and there is no `bitcoin.conf` alias for it. `bitcoin.conf` maps `txindex` and `blockfilterindex`; set the script index through TOML, environment, or the command line.

Enabling any of the three spawns one derived-index worker. The worker commits block rows and the capability watermark in one store batch. With every index off, the node opens no derived worker and no index namespace.

The three settings are independent. A TOML file can set all of them:

```toml
txindex = true
script_index = "full"
blockfilterindex = true
```

`--txindex=true` and `--blockfilterindex=true` require an explicit value, while `--scriptindex=full` may omit it. Indexing refuses a pruned node with `transaction, script and compact-filter indexing are not compatible with -prune`.

## Check readiness

The index namespace lives under `<data-dir>/txindex`. A capability is ready only when its durable watermark equals the applied tip height and hash. It is never ready just because the worker thread exists.

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":25,"method":"getindexinfo","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result'
{
  "txindex": {
    "best_block_height": 101,
    "synced": true
  }
}
```

`getindexinfo` advertises Core `txindex` only when `--txindex` was set explicitly. Script capabilities do not create that row. `getcapabilities` reports the worker and its state:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":30,"method":"getcapabilities","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result'
{
  "capabilities": [
    {
      "compiled": true,
      "enabled": true,
      "id": "txindex",
      "state": "Ready"
    }
  ]
}
```

A lagging, rebuilding, rolling-back, or disabled capability refuses a query. It never returns stale rows and never turns unavailability into an empty success. JSON-RPC reports a transaction-index query that is catching up as `-32603` with `transaction index is still catching up; retry later`. REST and Esplora answer 503. A required capability missing from configuration is unavailable with a disabled reason, not a retry.

## What `gettxoutproof` needs

`gettxoutproof` without a `blockhash` does not require `txindex` when the requested outpoint is unspent. It probes the txids in ascending order against the UTXO set, answers from the block that holds an unspent output, and reads no block body first.

With no unspent coin, the method consults `txindex` about the first txid only. With neither source it answers `-5` (`Transaction not yet in block`). A block that does not hold every requested txid also answers `-5`. With an explicit `blockhash`, only that block is read.

## Enable address history

Address and scripthash routes need `--scriptindex`. Both modes serve unspent outputs. `full` also serves confirmed history, spender queries, and the `txs` routes:

```
$ curl -s http://127.0.0.1:45869/api/address/mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r | jq '.chain_stats'
{
  "tx_count": 101,
  "funded_txo_count": 101,
  "funded_txo_sum": 505000000000,
  "spent_txo_count": 0,
  "spent_txo_sum": 0
}
```

Without a script index the same node answers `script index is disabled` with HTTP 503. `scripthash-limit` bounds the candidate funding positions, matching outputs, or live locators scanned per query. The default is 25,000. A query that exceeds the allowance fails explicitly; Esplora maps that refusal to HTTP 422. Statistics are exact or the query fails, never capped.

History pages keep the full funding and spender scan because an old output can have a recent spender. A cursor page needs `txindex`, since the cursor is a transaction id resolved through the lookup rows.

## State and recovery

On startup the worker reads its persisted watermarks and reconciles against the restored chain:

- A watermark that is an ancestor of the restored tip connects forward.
- A watermark on an abandoned branch rolls back to the common ancestor and connects forward.
- A rollback deeper than 100,000 blocks resets the capability and backfills from the active chain instead of walking block by block.
- A schema or format version foreign to this build resets and rebuilds the affected store. There is no in-place migration.
- An invalid watermark resets only the degraded capability. A body that pruning has already deleted, when rollback needs it, takes the affected capability offline instead of resetting everything: compact filters and `ScriptLive` become unavailable while their rows and watermark remain, and the remaining selected capabilities (such as `TxLookup` and `ScriptHistory`) reset and rebuild from the active chain. Sibling capabilities keep serving while their watermarks match the tip.
- An ordinary read turns a corrupt flat-file frame into a missing body. Forward catch-up and rollback both stall on a missing body whose history is still retained: the affected capabilities keep their rows, make no progress past the unreadable block, and are retried after a quiet period instead of being reset. A stored body that passes the frame check and then fails parsing fails the worker with `IndexError::BlockParse` instead of resetting.
- A missing undo record has narrower effects: `ScriptLive` resets, `ScriptHistory` becomes unavailable for the run when it needs the missing spent script, and compact filters become unavailable for the run. Durable rows and watermarks are preserved.

Index writes never gate block validation or UTXO commits. A fatal storage error or panic marks the worker failed and stops it; chain progress continues. Queries then report unavailable until you restart and the worker reconciles.

Restore the required history and restart to retry. A filter-only failure refuses filters but leaves transaction queries and durable filter progress intact.

## Move an index with a bundle

`--index-bundle-export <dir>` writes a portable transaction-lookup bundle once, after the store opens and before the first reconcile pass. `--index-bundle-import <dir>` reads one back. Both require `--txindex`, both are one-shot requests, and neither has a `bitcoin.conf` alias.

A bundle is a directory containing `txlookup-v1.dat` and `manifest.json`. The worker writes the manifest last. The manifest binds the network, genesis hash, a validated base (height, hash, chainwork, transaction count), the index format version, the covered height, and the artifact digest and length.

The node does not exit after the request, and it does not remove the option. Remove it yourself; a later start that still sets it runs the request again.

The owning clauses are [IDX-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-01-capability-configuration-and-internal-enablement), [IDX-03](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-03-query-gating-and-snapshot-consistency), [IDX-05](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-05-restart-reconciliation-and-schema-version-refusal), and [IDX-11](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md#idx-11-portable-index-bundle). The UTXO-set fallback for `gettxoutproof` is owned by [API-02](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-02-json-rpc-mechanics-and-the-wallet-free-surface).

Next: [Mining and the native pool](mining-and-pool.md) build candidates on top of this state.
