# Getting started

From a clone to a syncing node. Each step says what you should see, so you can
tell it worked before moving on.

Before you start: do not run this on mainnet as your only node. Reorganisation
handling and transaction relay have known limitations documented in
[README.md](README.md#known-gaps). The filter index is not backfilled across a
gap.

## Prerequisites

A Rust toolchain for edition 2024, plus `cmake` and `libboost-dev`. The last
two are needed because the default build compiles libbitcoinkernel from C++
sources.

On Debian or Ubuntu:

```sh
sudo apt-get install -y cmake libboost-dev
```

## Step 1: build

```sh
cargo build --release -p bitcoin-rs
```

This produces `./target/release/bitcoin-rs`. The default features are
`rocksdb`, `fjall`, `redb`, `mdbx`, and `kernel`, so all four storage backends
and the kernel verifier are compiled in.

If you cannot install the C++ dependencies, build the portable node instead.
It must still name a storage backend, because bare `--no-default-features`
compiles in none and the node then refuses to start:

```sh
cargo build --release -p bitcoin-rs --no-default-features --features fjall
```

The portable verifier supports only Taproot key-path spends. It cannot validate
non-Taproot spends or Taproot script-path spends, so a mainnet sync stops early.
Use it for development, not for following the chain.

## Step 2: choose a storage backend

fjall is the default. Pass `--storage-backend` to pick another:

```sh
./target/release/bitcoin-rs --storage-backend rocksdb
```

Valid values are `fjall`, `rocksdb`, `mdbx`, and `redb`. All four hold the same
chain state; they differ in write amplification and memory profile. If you have
no reason to change it, keep fjall.

You can also set it in the environment:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

## Step 3: start the node

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Defaults worth knowing:

| flag | default |
|---|---|
| `--data-dir` | `.bitcoin-rs` |
| `--network` | mainnet (`mainnet`, `testnet3`, `testnet4`, `signet`, `regtest`) |
| `--rpc-bind` | `127.0.0.1:8332` on mainnet, the network's Core port otherwise |
| `--rpc-user` / `--rpc-password` | `bitcoin-rs` / `bitcoin-rs` |
| `--dbcache-mb` | 450 |
| `--prune-target-mb` | 0, meaning no pruning |
| `--txindex` | off |
| `--scriptindex` | off |

The node logs its startup and the address the RPC listener bound to. If you see
that line, it is running.

`--txindex` advertises Bitcoin Core-compatible transaction lookup support.
`--scriptindex` enables current address/scripthash UTXO queries and confirmed
funding/spending history.
`--txindex` remains independent and is required for confirmed transaction
lookups such as `/tx/<txid>` when the transaction is not in the mempool.
Esplora is served by the node HTTP listener at the standard root (for example
`/blocks/tip/height`, `/tx/<txid>`, `/address/<address>/utxo`, and `POST /tx`).
Address and scripthash routes return `503` until `--scriptindex` catches up, or
when it is disabled. These index modes are incompatible with pruning
because backfill and reorg repair require durable block bodies.

The ScriptIndex format does not migrate an existing legacy index. At startup,
the node deletes incompatible derived index data in bounded batches and rebuilds
it before exposing `--scriptindex` or `--txindex` queries.

Change the RPC credentials before exposing the port anywhere. The defaults are
a development convenience, not a secret. `--rpc-cookie` takes a Core-style
cookie file instead.

## Step 4: check sync progress

The JSON-RPC surface uses Bitcoin Core's method names, so Core's client tools
work against it.

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

The response carries the current height and best block hash. Call it twice a
minute apart: if the height moved, the node is syncing.

For just the tip:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:8332/
```

The full list of implemented methods is the dispatch table in
`crates/rpc/src/handlers.rs`. There is no wallet: private-key and
wallet-construction methods are not implemented, while the key-free PSBT
utilities and descriptor helpers remain for external-signer workflows.

## Verifying everything yourself

Mainnet skips historical script verification below the pinned assume-valid
anchor. To verify every script from genesis:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --assume-valid-height 0
```

This is much slower. It is the right setting for benchmarking and for anyone
who does not want to trust the anchor.

## Next

- [../README.md](../README.md) for the full default posture and the measured
  benchmark.
- [README.md](README.md) for the documentation index.
- [solutions/](solutions/) before debugging something that smells like it has
  been hit before.
