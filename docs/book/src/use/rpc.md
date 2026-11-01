# RPC

Send JSON-RPC over HTTP POST to the management listener. On mainnet the default bind is `127.0.0.1:8332`. On regtest it is `127.0.0.1:18443`. `--rpc-bind` changes it. `--public-bind` moves REST and Esplora reads to a second listener, and the first keeps JSON-RPC only.

## Authenticate

The node accepts HTTP Basic credentials. It has three sources:

| Source | How it works |
| --- | --- |
| Generated cookie (default) | When neither `--rpc-user` nor `--rpc-password` nor `--rpc-cookie` is set, the node writes `<data-dir>/.cookie` with mode `0600` and content `__cookie__:<64 hex digits>`. |
| Basic flags | `--rpc-user` and `--rpc-password` must both be nonempty. The password `bitcoin-rs` is refused as a known legacy default. |
| Cookie path | `--rpc-cookie <path>` reads the same `user:password` file format from a path you choose. |

A non-loopback `--rpc-bind` requires explicit basic credentials. A generated cookie is allowed only on a loopback bind.

Bitcoin Core's salted `rpcauth=` line is not implemented. The `bitcoin.conf` mapping accepts `rpcuser`, `rpcpassword`, and `rpccookiefile` only.

Read the cookie and pass it to curl. `$DATA` stands for the data directory:

```
$ datadir=$DATA
$ curl -s --user "$(cat "$datadir/.cookie")" --data-binary '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45875/
{"id":1,"jsonrpc":"2.0","result":0}
```

A missing or wrong credential gets HTTP 401 with `WWW-Authenticate: Basic realm="jsonrpc"`. REST and Esplora requests on the same listener are not authenticated.

## Send a request

POST to `/` with `content-type: application/json`. The body carries `method`, `params`, and an optional `id`. `params` may be an array (positional), an object (named), or `null`. Named and positional forms have the same meaning.

A `jsonrpc` field selects the dialect. `"2.0"` gets a v2 envelope. An absent or explicit-null field gets the legacy envelope. A non-null value other than `"1.0"` or `"2.0"` is refused before the method runs.

Compare the same failure in both dialects:

```
$ curl -s -w '%{http_code} %{content_type}\n' --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":20,"method":"getnewaddress","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45869/
{"error":{"code":-32601,"message":"method not found: getnewaddress"},"id":20,"jsonrpc":"2.0"}200 application/json
$ curl -s -w '%{http_code} %{content_type}\n' --user book:bookpass --data-binary '{"id":21,"method":"getnewaddress","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45869/
{"error":{"code":-32601,"message":"method not found: getnewaddress"},"id":21,"result":null}404 application/json
```

A v2 dispatch error keeps HTTP 200. The legacy dialect maps `-32600` to 400, `-32601` to 404, and other dispatch errors to 500.

## Five representative calls

These ran against a regtest node with `txindex=true` and 101 generated blocks.

Chain summary:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":2,"method":"getblockchaininfo","params":[]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result | {chain,blocks,headers,bestblockhash,initialblockdownload}'
{
  "chain": "regtest",
  "blocks": 101,
  "headers": 101,
  "bestblockhash": "51fe1358296693f404117437d98d059ab79e8548251c84564a461d133eeae813",
  "initialblockdownload": false
}
```

Block by height. `getblockhash` returns the display-order hash; `getblock` verbosity 1 returns the header fields plus transaction ids:

```
$ hash=$(curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":3,"method":"getblockhash","params":[101]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq -r .result)
$ curl -s --user book:bookpass --data-binary "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"getblock\",\"params\":[\"$hash\",1]}" -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result | {height,hash,confirmations,nTx,previousblockhash}'
{
  "height": 101,
  "hash": "51fe1358296693f404117437d98d059ab79e8548251c84564a461d133eeae813",
  "confirmations": 1,
  "nTx": 1,
  "previousblockhash": "51535f835f4960870dae5364537c637835d37d4a2ba5c3ab4949211e71c65418"
}
```

A confirmed transaction outside the mempool needs `--txindex`, as in the call below. Without it, `getrawtransaction` answers `-5`:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":5,"method":"getrawtransaction","params":["2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690",1]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result | {txid,confirmations,blockhash}'
{
  "txid": "2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690",
  "confirmations": 101,
  "blockhash": "3e9c8412d0f5dc91599df01fae2e7336f52e94bac9ddaf4402240b8f2abcbb01"
}
```

An unspent output and its proof. `gettxoutproof` without a block hash finds the block from the UTXO set first, so this call does not need `txindex`:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":6,"method":"gettxout","params":["2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690",0]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result | {confirmations,coinbase,value,address:.scriptPubKey.address}'
{
  "confirmations": 101,
  "coinbase": true,
  "value": 50.0,
  "address": "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"
}
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":7,"method":"gettxoutproof","params":[["2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690"]]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | head -c 120
{"id":7,"jsonrpc":"2.0","result":"0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f9006ebd66972ea
```

Preview and broadcast. This unsigned transaction spends a matured coinbase output without a signature. Preview reports the script failure, and broadcast maps it to `-26`:

```
$ hex=$(curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":8,"method":"createrawtransaction","params":[[{"txid":"2b0377553a272c9e56fcd932fc8d2e7b1358187b2814348e9cea7269d6eb0690","vout":0}],{"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r":49.999}]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq -r .result)
$ curl -s --user book:bookpass --data-binary "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"testmempoolaccept\",\"params\":[[\"$hex\"]]}" -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result[0]'
{
  "allowed": false,
  "reject-reason": "script-verify-flag-failed",
  "txid": "62ec9f19431503e7dca3db0ca892a9dafbd43e06d8b75f244b1306cf2c73241a",
  "wtxid": "62ec9f19431503e7dca3db0ca892a9dafbd43e06d8b75f244b1306cf2c73241a"
}
$ curl -s --user book:bookpass --data-binary "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"sendrawtransaction\",\"params\":[\"$hex\"]}" -H 'content-type: application/json' http://127.0.0.1:45869/
{"error":{"code":-26,"message":"consensus-verification-failed"},"id":10,"jsonrpc":"2.0"}
```

## Batch and notifications

A batch is a JSON array. Members answer in request order, and each member carries its own error. The limit is 1,000 members:

```
$ curl -s -w '%{http_code}\n' --user book:bookpass --data-binary '[{"jsonrpc":"2.0","id":22,"method":"getblockcount","params":[]},{"jsonrpc":"2.0","id":23,"method":"getbestblockhash","params":[]}]' -H 'content-type: application/json' http://127.0.0.1:45869/
[{"id":22,"jsonrpc":"2.0","result":101},{"id":23,"jsonrpc":"2.0","result":"51fe1358296693f404117437d98d059ab79e8548251c84564a461d133eeae813"}]200
```

A member without `id` is a notification. A batch made only of notifications answers 204 with no body:

```
$ curl -s -w '%{http_code}\n' --user book:bookpass --data-binary '[{"jsonrpc":"2.0","method":"getblockcount","params":[]}]' -H 'content-type: application/json' http://127.0.0.1:45869/
204
```

A batch above the limit is refused before any member runs:

```
{"error":{"code":-32600,"message":"Batch size limit exceeded"},"id":null,"result":null}
```

An empty array answers 200 with `[]`. Request bodies are capped at 16 MiB.

## Errors that differ from Core

The registry row for a method owns its notes. These codes are the recurring differences:

- `-32601` covers wallet methods and every unimplemented Core method. Bitcoin-rs has no wallet, so `getnewaddress`, `getbalance`, `signrawtransactionwithwallet`, and similar names answer method not found.
- Pool methods return `-32603` with `Pool service is disabled` when the `pool` feature is compiled but the service is off. They return `-32601` when the feature is absent.
- `-32602` covers some parameter-shape errors where Core returns `-1` help text or `-3` for a hole created by named arguments. `createrawtransaction` and `gettxspendingprevout` declare this deviation.
- `-32603` covers disabled features and internal unavailability. `compressrawtransaction` without `--compressed-transactions` and a transaction-index lookup that is still catching up both use it.
- `-5` is transaction not found. Without `--txindex`, `getrawtransaction` on a confirmed transaction answers `{"code":-5,"message":"not found: transaction not found"}`.
- `-22`, `-25`, and `-26` keep Core's deserialization, verification-error, and verification-rejected codes. The unsigned broadcast above used `-26`.

`getblock` verbosity 2 and 3 also differ: fees and prevouts come from retained certified undo, so an old stale body whose receipt is no longer retained omits those fields.

## What owns compatibility

`REGISTRY` in `crates/rpc/src/registry.rs` is the single inventory for JSON-RPC, REST, and ZMQ. Each row binds one name to one status: `Supported`, `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`, or `Unimplemented`. The dispatcher and the manifest are generated from the same rows, and a test checks them in both directions.

The generated reference is [docs/rpc-reference.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rpc-reference.md). Do not edit it by hand. Regenerate it with:

```
REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test suite manifest_coverage::regenerate_reference -- --ignored
```

`crates/rpc/core-compat.toml` pins the reference identities: the released Bitcoin Core 31.1 artifacts, the development kernel tree used by the oracle lane, and two replay corpora. Its `differential_harness` flag is currently `false`, so no row can claim `Supported`.

The generated reference reports 0 Supported, 34 Deviation, 56 Implemented (unverified), 14 Extension, and 83 Unimplemented rows. "Implemented (unverified)" means the method ships. It does not mean its values were compared with Core.

The behavior clauses are owned by the external API contract, starting at [API-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-01-single-manifest-owner) and [API-02](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-02-json-rpc-mechanics-and-the-wallet-free-surface). Contract gaps stay gaps.

Next: [REST and Esplora](rest-esplora.md) run on the same listener and share the registry.
