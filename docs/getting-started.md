# Getting started

From a clone to a syncing node. Each step explains what you should see so you can
verify progress before moving on.

## Prerequisites

- A Rust toolchain for edition 2024 (MSRV 1.95.0 or newer).
- No C++ compiler or system libraries for the default binary build. It is
  pure Rust and uses the native script interpreter, which verifies legacy,
  P2SH, SegWit v0, and Taproot key-path and script-path spends. Core's
  committed script and transaction vectors pin zero native mismatches
  (`crates/script/tests/core_vectors.rs`). `libbitcoinkernel` remains the
  library default and the Compose image engine until issue #213 promotes
  native (`docs/contracts/validation-default.md`). To use that engine in the
  binary, enable the `kernel` feature.

If you plan to compile with the `kernel` feature to run `libbitcoinkernel` as
an independent verification oracle, install `cmake` and `libboost-dev`:

```sh
# Required for the kernel verification-oracle feature
sudo apt-get install -y cmake libboost-dev
```

## Step 1: build

Build the node with default features:

```sh
cargo build --release -p bitcoin-rs
```

This produces `./target/release/bitcoin-rs`. The default features are the
`fjall` and `redb` storage backends and `zmq` sequence publishing; `kernel` is
not among them, so this binary validates with the native interpreter.

To compile with `libbitcoinkernel` as an independent verification oracle:

```sh
cargo build --release -p bitcoin-rs --features kernel
```

## Step 2: choose a storage backend

`fjall` is the default storage engine. `redb` is also compiled in default builds.
Pass `--storage-backend` to select a backend:

```sh
./target/release/bitcoin-rs --storage-backend redb
```

You can also set it via environment variable:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

Alternative C++ storage backends (`rocksdb`, `mdbx`) are available through
non-default Cargo features:

```sh
cargo build --release -p bitcoin-rs --features rocksdb
```

## Step 3: start the node

Start the node on mainnet:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Configuration defaults:

| Flag | Default |
|---|---|
| `--data-dir` | `.bitcoin-rs` |
| `--network` | `mainnet` (`mainnet`, `testnet3`, `testnet4`, `signet`, `regtest`, `drynet4`) |
| `--storage-backend` | `fjall` |
| `--rpc-bind` | `127.0.0.1:8332` on mainnet, network Core port otherwise |
| `--rest` | off (enables unauthenticated Core-compatible REST routes on the RPC port) |
| `--rpc-user` / `--rpc-password` | `bitcoin-rs` / `bitcoin-rs` |
| `--dbcache-mb` | 450 (split 80/20 across chainstate and txindex when enabled, with disabled shares going to chainstate) |
| `--prune-target-mb` | 0 (no pruning) |
| `--txindex` | off |
| `--scriptindex` | off (accepts `full`, `utxo`, or boolean; defaults to `full` when passed without a value) |
| `--features kernel` (build-time) | off in default binary; enables `libbitcoinkernel` as a verification oracle |

The node logs its startup banner, effective cache allocation, and the address
the JSON-RPC listener bound to.

`--txindex` enables Bitcoin Core-compatible transaction lookup support.
`--scriptindex` (`full`, or the historical boolean `true`) enables address and
scripthash UTXO queries plus confirmed funding/spending history via
Esplora-compatible HTTP endpoints. `--scriptindex=utxo` maintains only the
compact live-output view: current UTXO routes work once that view is ready,
while history, statistics, pagination, and confirmed outspend routes return
HTTP 503 as a disabled capability rather than as a lagging backfill. Address
and scripthash UTXO routes return HTTP 503 until the live view catches up, or
when ScriptIndex is disabled. `--rest` enables the unauthenticated Core REST
gateway (`/rest/tx`, `/rest/block`, `/rest/headers`, etc.) alongside JSON-RPC.

The datadir schema marker covers the transaction and script indexes as well as
chainstate. An unmarked or incompatible datadir fails before any derived index
store opens; the operator must replace or quarantine it and resync. A marked
current datadir can then build `--scriptindex` and `--txindex` state from the
active chain.

Change the RPC credentials before exposing the port anywhere. The defaults are
a development convenience, not a secret. `--rpc-cookie` takes a Core-style
cookie file instead.

## Step 4: check sync progress

The JSON-RPC surface uses Bitcoin Core method names:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

The response includes the current validated height, best block hash, and sync
progress. Call it twice a minute apart to confirm height advances.

To query just the tip hash:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:8332/
```

[rpc-reference.md](rpc-reference.md), generated from `MANIFEST` in
`crates/rpc/src/manifest.rs`, lists every implemented, deviating, and
unimplemented Core method. There is no internal wallet: private-key and
wallet-construction methods are absent, while key-free PSBT utilities
(`combinepsbt`, `finalizepsbt`) and descriptor helpers (`getdescriptorinfo`,
`deriveaddresses`) remain for external signers.

## External wallet

Point any Esplora client at `/api` on the JSON-RPC listener.
`--scriptindex` must be on, or address and scripthash routes return HTTP 503.

[bitcoin-wallet](https://github.com/gosuda/bitcoin-wallet) (`btcw`) is the
named external consumer:

Start the node in one terminal:

```sh
./target/release/bitcoin-rs \
  --network regtest \
  --scriptindex \
  --data-dir .bitcoin-rs-regtest \
  --rpc-bind 127.0.0.1:18443
```

Then, in a second terminal, run the wallet while the node is still running:

```sh
btcw balance -n regtest -u http://127.0.0.1:18443/api
```

`/api` is the public Esplora surface (the mempool.space electrs prefix).
JSON-RPC keeps the listener root. `/api/v1` is Mempool's API on the
explorer port, not an Esplora alias on this node. Mempool backend bulk
helpers live under `/esplora`, not `/api`.

The wallet stays in that repository. This node only serves the public
surface documented in [contracts/wallet-facing.md](contracts/wallet-facing.md).

## Verifying everything yourself

Mainnet skips historical script checks below the pinned assume-valid anchor.
To verify every script from genesis:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --assume-valid-height 0
```

This runs full script execution on every transaction from block 0. It is the
recommended mode for benchmarking and independent consensus audits.

## Next

- [../README.md](../README.md) for architecture overview and benchmark records
- [../CONTRIBUTING.md](../CONTRIBUTING.md) for development workflows and testing
- [README.md](README.md) for the documentation index
- [contracts/](contracts/) for normative architecture and protocol contracts
