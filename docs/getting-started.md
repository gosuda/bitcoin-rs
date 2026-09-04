# Getting started

From a clone to a syncing node. Each step explains what you should see so you can
verify progress before moving on.

## Prerequisites

- A Rust toolchain for edition 2024 (MSRV 1.95.0 or newer).
- The default binary build is pure Rust and requires no C++ compiler or system
  libraries. It uses the portable Rust script interpreter, which verifies
  Taproot key-path spends only and cannot validate ordinary mainnet spends
  (see #166). For production consensus validation, enable the `kernel` feature.

If you plan to compile with the `kernel` feature for production consensus
validation via `libbitcoinkernel`, install `cmake` and `libboost-dev`:

```sh
# Required for the kernel consensus engine feature
sudo apt-get install -y cmake libboost-dev
```

## Step 1: build

Build the node with default features:

```sh
cargo build --release -p bitcoin-rs
```

This produces `./target/release/bitcoin-rs`. The default configuration includes
the `fjall` storage backend, `redb`, and `zmq` sequence publishing. The default
binary build uses the portable Rust script interpreter, which verifies Taproot
key-path spends only; other script classes (Legacy, SegWit v0, Taproot
script-path) are stubbed pending a full opcode interpreter (see #166). A
mainnet sync with this build stops at the first real spend.

To compile with `libbitcoinkernel` as the consensus engine for full script
validation across all script classes:

```sh
cargo build --release -p bitcoin-rs --features kernel
```

## Step 2: start the node

The process CLI is a launcher. Start the default mainnet node:

```sh
./target/release/bitcoin-rs
```

Select a network, a data directory, or a configuration file:

```sh
./target/release/bitcoin-rs --network testnet4
./target/release/bitcoin-rs --data-dir .bitcoin-rs
./target/release/bitcoin-rs --config node.toml
```

`--help` and `--version` are standard clap behavior. `--bitcoin-conf` loads a
Bitcoin Core `bitcoin.conf` as the lowest file layer. Every other node setting
is configuration, not a flag: TOML, `BITCOIN_RS_*` environment variables, or
`bitcoin.conf`.

Launcher flags:

| Flag | Default | Purpose |
|---|---|---|
| `--config` | unset | bitcoin-rs TOML configuration file |
| `--bitcoin-conf` | unset | Bitcoin Core `bitcoin.conf` |
| `--network` | `mainnet` (`mainnet`, `testnet3`, `testnet4`, `signet`, `regtest`, `drynet4`) | consensus rules and P2P bootstrap profile |
| `--data-dir` | `.bitcoin-rs` | node data directory |

The node logs its startup banner, effective cache allocation, and the address
the JSON-RPC listener bound to.

`fjall` is the default storage engine. `redb` is also compiled in default
builds. Alternative C++ storage backends (`rocksdb`, `mdbx`) are available
through non-default Cargo features:

```sh
cargo build --release -p bitcoin-rs --features rocksdb
```

Change the RPC credentials before exposing the port anywhere. The defaults are
a development convenience, not a secret.

## Step 3: check sync progress

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

## Advanced configuration

Runtime settings resolve in this order, later layers winning:

```text
defaults < bitcoin.conf < TOML < environment < CLI overlay
```

The CLI overlay can set only `--network` and `--data-dir`. File and environment
layers carry the rest.

Example TOML:

```toml
network = "mainnet"
data_dir = ".bitcoin-rs"
storage_backend = "redb"
rpc_bind = "127.0.0.1:8332"
rpc_user = "bitcoin-rs"
rpc_password = "choose-a-secret"
rpc_cookie = "/path/to/.cookie"
rest = false
dbcache_mb = 450
prune_target_mb = 0
txindex = false
script_index = "full"
log_level = "info"
metrics_bind = "127.0.0.1:9090"
p2p_listen = ["0.0.0.0:8333"]
dns_seeds_enabled = true
connect = []
assume_valid_height = 0

[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:28332"
topics = ["sequence"]
```

Equivalent environment variables use the `BITCOIN_RS_` prefix (`STORAGE_BACKEND`,
`RPC_BIND`, `RPC_USER`, `RPC_PASSWORD`, `RPC_COOKIE`, `REST`, `DBCACHE_MB`,
`PRUNE_TARGET_MB`, `TXINDEX`, `SCRIPTINDEX`, `LOG_LEVEL`, `METRICS_BIND`,
`P2P_LISTEN`, `DNS_SEEDS_ENABLED`, `CONNECT`, `ASSUME_VALID_HEIGHT`,
`P2P_MAGIC`).

`txindex = true` enables Bitcoin Core-compatible transaction lookup support.
`script_index = "full"` (or `BITCOIN_RS_SCRIPTINDEX=true`) enables address and
scripthash UTXO queries and confirmed funding/spending history exposed via
Esplora-compatible HTTP endpoints. Address and scripthash routes return HTTP
503 until the script index catches up, or when it is disabled.

The datadir schema marker covers the transaction and script indexes as well as
chainstate. An unmarked or incompatible datadir fails before any derived index
store opens; the operator must replace or quarantine it and resync. A marked
current datadir can then build script-index and txindex state from the active
chain.

## Verifying everything yourself

Mainnet skips historical script checks below the pinned assume-valid anchor.
To verify every script from genesis, set `assume_valid_height = 0` in TOML or
`BITCOIN_RS_ASSUME_VALID_HEIGHT=0`:

```sh
BITCOIN_RS_ASSUME_VALID_HEIGHT=0 ./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

This runs full script execution on every transaction from block 0. It is the
recommended mode for benchmarking and independent consensus audits.

## Next

- [../README.md](../README.md) for architecture overview and benchmark records
- [../CONTRIBUTING.md](../CONTRIBUTING.md) for development workflows and testing
- [README.md](README.md) for the documentation index
- [contracts/](contracts/) for normative architecture and protocol contracts
