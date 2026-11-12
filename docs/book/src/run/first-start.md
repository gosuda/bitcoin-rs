# First start

Start a regtest node with an explicit data directory and loopback listeners, then drive it over RPC. Regtest needs no peers and mines locally. `$DATA` below stands for the data directory you pass to `--data-dir`.

```sh
$ ./target/release/bitcoin-rs \
  --network regtest \
  --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 \
  --rpc-bind 127.0.0.1:0 \
  --dns-seeds-enabled=false
```

`127.0.0.1:0` asks the operating system for a free port. Regtest defaults are `18444` for P2P and `18443` for RPC; use those numbers if you want fixed ports.

The node writes JSON logs to stderr. On startup it reports the RPC address it bound:

```
{"timestamp":"...","level":"INFO","fields":{"message":"rpc listener bound","addr":"127.0.0.1:41701","surface":"Shared"},"target":"bitcoin_rs_node::lifecycle"}
{"timestamp":"...","level":"INFO","fields":{"message":"p2p listener bound","addr":"127.0.0.1:0"},"target":"bitcoin_rs_wire::service"}
```

The P2P line repeats the configured listen address, so with `:0` it does not tell you the chosen port. The RPC line reports the bound address. Use fixed ports when another program needs to dial P2P.

## Read the cookie

The node generates `.cookie` in the data directory with mode `0600`. RPC requests authenticate with its contents.

```sh
$ cat $DATA/.cookie
__cookie__:d2e4ffab2ef6846eb7aab8b682365cc4bb54785aaaedcf80b9aa264094cd60e1
```

The value is fresh on each start. Read it after the node is listening, not before.

## Query the chain

```sh
$ curl -s --user "$(cat $DATA/.cookie)" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:41701/
```

Trimmed to the fields that matter at height zero:

```json
{
  "result": {
    "chain": "regtest",
    "blocks": 0,
    "headers": 0,
    "bestblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "initialblockdownload": true,
    "is_apply_halted": false,
    "is_closed_for_recovery": false,
    "pruned": false,
    "size_on_disk": 329,
    "verificationprogress": 2.0126254166018888e-06
  }
}
```

`blocks` counts applied blocks. `headers` counts admitted headers. They are separate facts, and a gap between them is normal during sync.

## Mine a block

`generatetoaddress` is the documented solo-mining generate path. It solves a fresh candidate, submits it through the chainstate owner, and returns the block hash.

```sh
$ curl -s --user "$(cat $DATA/.cookie)" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"generatetoaddress","params":[1,"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]}' \
  http://127.0.0.1:41701/
{"error":null,"id":"1","result":["4c3aaf6b9cdcd6bc22e27dc41d6aeca2c4429747b896a3bf6938549dfeec4691"]}
```

Query again and the applied tip has moved:

```json
{
  "result": {
    "chain": "regtest",
    "blocks": 1,
    "headers": 1,
    "bestblockhash": "4c3aaf6b9cdcd6bc22e27dc41d6aeca2c4429747b896a3bf6938549dfeec4691",
    "initialblockdownload": false,
    "size_on_disk": 624,
    "verificationprogress": 1.0
  }
}
```

Each submitted block is a separate commit. A call that asks for several blocks and fails partway leaves the blocks that already committed in place; read the applied tip and retry from there. The rule is [`API-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md).

> **Warning** `mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn` is a test address whose private key is publicly known. Mine to it on regtest only, and generate a fresh address for anything holding value.

## Stop the node

Press Ctrl-C, or send `SIGTERM` from another shell:

```sh
$ kill -TERM <pid>
```

A clean shutdown publishes a chainstate checkpoint, saves fee-estimator history, and writes a mempool snapshot:

```
{"timestamp":"...","level":"INFO","fields":{"message":"published clean chainstate checkpoint","generation":1},"target":"bitcoin_rs_node::lifecycle"}
{"timestamp":"...","level":"INFO","fields":{"message":"saved fee-estimator history","path":"$DATA/fee-estimator-history.dat","bytes":57965},"target":"bitcoin_rs_mempool::fee_history"}
{"timestamp":"...","level":"INFO","fields":{"message":"prepared mempool snapshot","transactions":0,"bytes":84,"elapsed_ms":"0"},"target":"bitcoin_rs_mempool::snapshot"}
{"timestamp":"...","level":"INFO","fields":{"message":"bitcoin-rs node exited cleanly"},"target":"bitcoin_rs_node::lifecycle"}
```

The process exits with status 0. Starting again on the same data directory restores the checkpoint and reports it:

```
{"timestamp":"...","level":"INFO","fields":{"message":"chainstate restore selected","restore_source":"checkpoint","checkpoint_generation":1,"checkpoint_height":1,"height":1,"hash":"4c3aaf6b9cdcd6bc22e27dc41d6aeca2c4429747b896a3bf6938549dfeec4691","replayed_records":0,"chain_tx_count":2,"replay_seconds":0.000111078},"target":"bitcoin_rs_execution::recovery"}
```

Sync progress is logged every 60 seconds, with applied blocks and headers reported separately:

```
{"timestamp":"...","level":"INFO","fields":{"message":"sync progress","applied_height":1,"header_height":1,"peers":0,"ibd":false},"target":"bitcoin_rs_node::p2p::sync::telemetry"}
```

## Next

Change the configuration without editing the start command: [Configuration](configuration.md).
