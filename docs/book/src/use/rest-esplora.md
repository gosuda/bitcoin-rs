# REST and Esplora

Turn on REST with `--rest=true`. Esplora-compatible routes are always served on the JSON-RPC listener under `/api` and `/esplora`. REST is off by default; those Esplora routes answer even when it is off.

> **Warning**: REST and Esplora are unauthenticated, as in Core. Anyone who can reach the listener can read chain and mempool data and can POST a transaction. Keep the listener on loopback or behind your own access control.

## Enable and place the listeners

Any of these enables the `/rest/*` routes:

```
bitcoin-rs --rest=true ...
BITCOIN_RS_REST=true bitcoin-rs ...
```

In TOML set `rest = true`; in `bitcoin.conf` set `rest=1`.

Without `--public-bind`, one listener serves JSON-RPC, REST, and Esplora. With `--public-bind`, that second listener serves REST and Esplora, and the `--rpc-bind` listener serves management JSON-RPC only. A JSON-RPC request sent to the public listener gets 404.

REST disabled means `/rest/*` returns 404. It does not fall through to JSON-RPC:

```
$ curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:45871/rest/chaininfo.json
404
```

## REST routes

Routes are GET-only except for `POST /rest/getutxos.bin` and `POST /rest/getutxos.hex`. A format suffix selects the encoding: `.json` for `application/json`, `.hex` for `text/plain`, `.bin` for `application/octet-stream`.

- `/rest/tx/{txid}` looks up a transaction. A confirmed transaction outside the mempool needs the transaction index; a lagging or disabled index answers 503, not an empty body.
- `/rest/block/{hash}` and `/rest/block/notxdetails/{hash}` return a block. The second form replaces transaction objects with transaction ids.
- `/rest/blockpart/{hash}` returns the raw block and accepts only hex or binary.
- `/rest/chaininfo` returns a chain summary. It accepts JSON only.
- `/rest/mempool/info` and `/rest/mempool/contents` return the pool summary or its contents.
- `/rest/headers/{hash}?count=N` walks forward by height from an active-chain hash. `count` defaults to 5 and must be between 1 and 2,000.
- `/rest/getutxos/{txid}-{vout}...` looks up at most 15 outpoints. Add `/checkmempool` to include pool-created outputs, which carry Core's height sentinel `2147483647`.
- `/rest/blockhashbyheight/{height}` returns the active hash at that height.
- `/rest/deploymentinfo` reports native activation and script flags.
- `/rest/spenttxouts/{hash}` serves retained spent outputs. Pruned or uncertified undo is unavailable rather than empty.

These ran against a regtest node:

```
$ curl -s http://127.0.0.1:45869/rest/chaininfo.json | jq '{chain,blocks,bestblockhash}'
{
  "chain": "regtest",
  "blocks": 101,
  "bestblockhash": "51fe1358296693f404117437d98d059ab79e8548251c84564a461d133eeae813"
}
$ curl -s http://127.0.0.1:45869/rest/tx/2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690.hex | head -c 80
020000000001010000000000000000000000000000000000000000000000000000000000000000ff
$ curl -s http://127.0.0.1:45869/rest/getutxos/checkmempool/2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690-0.json | jq '{bitmap,chainHeight,value:.utxos[0].value,height:.utxos[0].height}'
{
  "bitmap": "1",
  "chainHeight": 101,
  "value": 50.00000000,
  "height": 1
}
$ curl -s "http://127.0.0.1:45869/rest/headers/3e9c8412d0f5dc91599df01fae2e7336f52e94bac9ddaf4402240b8f2abcbb01.json?count=2" | jq '[.[] | {height,hash}]'
[
  {
    "height": 1,
    "hash": "3e9c8412d0f5dc91599df01fae2e7336f52e94bac9ddaf4402240b8f2abcbb01"
  },
  {
    "height": 2,
    "hash": "448bbb50963ff7320fd9928b09ae4d6950403ebb84202d5d831fc6a64debc78f"
  }
]
```

`POST /rest/getutxos.bin` takes one boolean byte followed by a CompactSize count and that many outpoints: a 32-byte transaction hash in consensus byte order, then a little-endian `u32` output index. The `.hex` form takes the same bytes as hex. The body is capped at 2,048 bytes, and the decoded vector at 15 outpoints. This decoder intentionally corrects Core 31.1's string-length-prefix behavior, so byte-for-byte POST parity with Core is a declared deviation.

## REST status codes

- 400 for malformed hashes, heights, outpoints, `count` values, and POST bodies.
- 404 for an unknown route, a disabled REST gateway, a missing format suffix, or a well-formed identifier the node has never seen.
- 503 when a required capability is not ready at the requested tip, when the chain generation moved during assembly, or when the two concurrent materialization permits are busy. Retry after a short delay.
- 404 for a header hash that is not on the active chain, even when the header exists on a side branch.

A coherent response never mixes a tip from one commit with coins or mempool rows from another. Unavailable is not empty: a lagging or disabled index never yields a successful empty body.

## Esplora routes

`/api` is the public Esplora dialect. `/esplora` is the backend superset used by mempool. Both project the same node and index state. Requests inside `/api` never fall through to JSON-RPC, and unprefixed Esplora paths return 404 so `/` stays JSON-RPC. `/api/v1` belongs to the external mempool application, not to this node.

Public routes include:

- `/api/blocks/tip/height`, `/api/blocks/tip/hash`, `/api/blocks`, `/api/blocks/{start_height}`, and `/api/block-height/{height}`.
- `/api/block/{hash}`, `/api/block/{hash}/header`, `/api/block/{hash}/status`, `/api/block/{hash}/raw`, `/api/block/{hash}/txs`, and `/api/block/{hash}/txids`.
- `/api/tx/{txid}`, `/api/tx/{txid}/hex`, `/api/tx/{txid}/raw`, `/api/tx/{txid}/status`, `/api/tx/{txid}/merkle-proof`, and `/api/tx/{txid}/outspends`.
- `/api/address/{address}` and `/api/scripthash/{hash}` with `utxo`, `txs`, `txs/summary`, `txs/mempool`, and `txs/chain` subpaths.
- `/api/mempool`, `/api/mempool/txids`, `/api/mempool/recent`, and `/api/fee-estimates`.
- `POST /api/tx` broadcasts hex with a fixed 10,000,000 sat/kvB request ceiling. A rejection is HTTP 400 with the reason.

Address and scripthash routes need a script index. Without one the answer is an explicit 503, not an empty list:

```
$ curl -s http://127.0.0.1:45869/api/blocks/tip/height
101
$ curl -s http://127.0.0.1:45869/api/address/mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r/utxo | jq '.[0]'
{
  "txid": "2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690",
  "vout": 0,
  "status": {
    "confirmed": true,
    "block_height": 1,
    "block_hash": "3e9c8412d0f5dc91599df01fae2e7336f52e94bac9ddaf4402240b8f2abcbb01",
    "block_time": 1793551288
  },
  "value": 5000000000
}
$ curl -s -w ' %{http_code}\n' http://127.0.0.1:45871/api/address/mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r/utxo
script index is disabled 503
```

`/api/fee-estimates` returns an empty object when the estimator has no data. That is a valid answer, not a failure:

```
$ curl -s http://127.0.0.1:45869/api/fee-estimates
{}
```

`/api/address-prefix/{prefix}` answers 503 because this node has no address index.

Chain history is paginated at 25 transactions per page. Cursors are exact lowercase txids. A malformed, uppercase, prefixed, unknown, or missing cursor restarts from the beginning; a valid cursor excludes itself and earlier entries. A lagging, rebuilding, or disabled capability returns the declared unavailable response instead of an empty success. Index lag and reorg map to 503; a storage failure maps to 500.

The backend dialect adds `/esplora/internal/mempool/txs`, `/esplora/internal/block/{hash}/txs`, `/esplora/internal/txs`, and the batched outspend POST routes. Only declared backend routes exist.

## Listener behavior and limits

The listener routes by HTTP method and path. It does not inspect the `Host` header, so a reverse proxy must enforce host rules. Other methods on REST paths return 404; `HEAD /rest/chaininfo.json` is 404.

Only the public Esplora surface sends CORS headers. REST and the backend Esplora surface send none. `--esplora-max-queries` limits concurrent expensive reads and defaults to 2. Shared materialization permits for full blocks and spent outputs can refuse a read with 503 under load.

The owner of every rule is [docs/rest-interface.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rest-interface.md). Clause [API-03](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-03-rest-dialect) governs REST status codes, and [API-09](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-09-esplora-dialects) governs the two Esplora dialects. The wallet-facing projection is described in [docs/contracts/wallet-facing.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/wallet-facing.md).

Next: [ZeroMQ notifications](zmq.md) publish block and mempool events as they commit.
