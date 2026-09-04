# Getting started

From a clone to a syncing node. Each step explains what you should see so you can
verify progress before moving on.

## Prerequisites

- A Rust toolchain for edition 2024 (MSRV 1.95.0 or newer).
- The default binary build is pure Rust and requires no C++ compiler or system
  libraries. It uses the native Rust script interpreter, which verifies
  legacy, P2SH, SegWit v0, and Taproot key-path and script-path spends.
  Core's committed script and transaction vectors currently pin zero native
  mismatches. `libbitcoinkernel` remains the library production default and
  the Compose image engine until issue #213 promotes native
  (`docs/contracts/validation-default.md`). For that engine, enable the
  `kernel` feature.

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

This produces `./target/release/bitcoin-rs`. The default configuration includes
the `fjall` storage backend, `redb`, and `zmq` sequence publishing. The default
binary build uses the native Rust script interpreter for every consensus spend
class. Library crates and the Compose image still default to
`libbitcoinkernel` (`docs/contracts/validation-default.md`).

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

The dispatch table in `crates/rpc/src/handlers.rs` implements supported Core
methods. There is no internal wallet: private-key and wallet-construction
methods are absent, while key-free PSBT utilities (`combinepsbt`, `finalizepsbt`)
and descriptor helpers remain for external signers.

## External wallet

Point any Esplora client at the same listener. `--scriptindex` must be on,
or address and scripthash routes return HTTP 503.

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
btcw balance -n regtest -u http://127.0.0.1:18443
btcw balance -n regtest -u http://127.0.0.1:18443/api
```

`/api` and `/api/v1` are aliases of the Esplora surface at the listener
root, so a mempool.space-style base URL works without a reverse proxy.

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
