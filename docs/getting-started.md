# Getting started

## Prerequisites

The repository development toolchain is `stable`; the workspace MSRV is Rust `1.95.0`. See [policies/source-compatibility.md](policies/source-compatibility.md).

The default binary is kernel-free. Building the optional `kernel` lane also needs CMake and Boost on Debian/Ubuntu:

```sh
sudo apt-get install -y cmake libboost-dev
```

## Build

Use a lane deliberately:

| Lane | Command | Purpose |
| --- | --- | --- |
| Default | `cargo build --locked --release -p bitcoin-rs` | Normal binary: `fjall`, `redb`, `zmq`; no kernel |
| Minimal native | `cargo build --locked --release -p bitcoin-rs --no-default-features --features fjall` | One storage backend, optional extensions off |
| Kernel | `CARGO_TARGET_DIR=target/oracle cargo build --locked --release -p bitcoin-rs --features kernel` | Optional `bitcoinkernel` validation/oracle lane |

Keep the kernel lane in a separate `CARGO_TARGET_DIR` when proving a kernel-free build. BIP324 is target work only; there is currently no `bip324` Cargo feature.

## Configuration

Precedence, low to high:

1. defaults
2. `--config` TOML
3. `--bitcoin-conf`
4. `BITCOIN_RS_*` environment variables
5. CLI flags

A later layer overrides only fields it supplies. Network-dependent validation, including mining payout addresses, runs after merge. Runtime test controls are not public configuration.

Common network names are `mainnet`, `signet`, `testnet4`, and `regtest`; retained aliases are documented by the compatibility contracts.

## Storage

`fjall` is the default backend; `redb` is also compiled into the default binary.

```sh
./target/release/bitcoin-rs --storage-backend redb
```

or:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

RocksDB is a non-default backend used as a shipped alternative and comparison engine.

## Start the node

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Important defaults:

| Setting | Default |
| --- | --- |
| network | `mainnet` |
| data dir | `.bitcoin-rs` |
| storage backend | `fjall` |
| RPC bind | `127.0.0.1:8332` on mainnet |
| REST | off |
| RPC basic auth | `bitcoin-rs` / `bitcoin-rs` unless cookie auth is configured |
| dbcache | 450 MiB |
| pruning | off |
| txindex | off |
| scriptindex | off |
| fast sync | off |
| metrics listener | off |
| mining payout | unset |

Change the default RPC credentials before exposing the port.

`--txindex` is the explicit Core-compatible txindex promise. `--scriptindex=utxo` enables the live script view; `--scriptindex=full` also enables confirmed script history. `--rest=true` enables the unauthenticated Core REST routes on the RPC listener.

`--fast-sync` (also `BITCOIN_RS_FAST_SYNC` or `fast_sync` in TOML) relaxes the block-download policy: the node targets 32 outbound peers instead of 8, fans block requests out as soon as two eligible outbound peers are connected instead of eight, and divides the 256-block download window across the eligible peers with a floor of 8 blocks per peer instead of 16 (two peers get 128 each; the 8-block floor is reached at 32 peers). Consensus validation is unchanged. The mode is opt-in and its throughput has not been measured against the default.

## Check progress

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

For the tip hash only, use `getbestblockhash` with the same empty parameter list.

[rpc-reference.md](rpc-reference.md) is generated from the live RPC manifest and records implemented, deviating, and unimplemented methods. The node has no in-tree wallet or private-key custody; key-free descriptor/PSBT helpers remain available for external signers.

## Capability state

Index-backed queries expose the owner's capability state rather than treating unavailable data as empty. [contracts/indexing.md](contracts/indexing.md) owns the state vocabulary, readiness conditions, and exact query gating.

## Public consumers

### Esplora

Public Esplora routes live under `/api`. Script/address routes require the applicable script-index capability. `/esplora` is the versioned backend superset; `/api/v1` belongs to the external mempool application, not this node.

Example regtest startup:

```sh
./target/release/bitcoin-rs \
  --network regtest \
  --scriptindex \
  --data-dir .bitcoin-rs-regtest \
  --rpc-bind 127.0.0.1:18443
```

The wallet-facing contract is [contracts/wallet-facing.md](contracts/wallet-facing.md).

### REST

`--rest=true` (or `rest=1` in `bitcoin.conf`) serves Core-compatible REST on the RPC port without authentication. The CLI option takes an explicit boolean; bare `--rest` is not the enablement syntax. See [rest-interface.md](rest-interface.md).

### ZMQ

ZMQ endpoint groups are configured with `[[notifications.zmq]]` (`endpoint`, `topics`, optional `hwm`). `getzmqnotifications` reports the live configuration. `bitcoin_rs_rpc::zmq` owns topic framing and transport compatibility.

## Datadir compatibility

Follow [policies/db-migration.md](policies/db-migration.md) for authoritative and owner-local format changes. Never treat a schema mismatch as permission to rewrite or delete an operator datadir implicitly.

The durable-root recovery model and its evidence status are owned by [contracts/recovery.md](contracts/recovery.md).

## Measure storage

`--measure-storage` records logical and physical datadir accounting and exits:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --measure-storage \
  --measure-storage-output footprint.json \
  --measure-storage-stop-height <height> \
  --measure-storage-stop-hash <hash> \
  --storage-high-water-bytes <bytes>
```

Only a measured physical high-water can prove the storage budget; a point-in-time filesystem snapshot is a lower bound. See [contracts/storage-footprint.md](contracts/storage-footprint.md).

## Validation mode

`--validation-mode` (also `BITCOIN_RS_VALIDATION_MODE` or `validation_mode` in TOML) selects which historical script verification the apply path may skip. Non-script consensus checks always run.

- `assume-valid` (default): Bitcoin Core `-assumevalid` semantics. Scripts are skipped through `--assume-valid-height` only while the active chain contains the pinned network anchor.
- `full`: every script executes; `--assume-valid-height` is ignored.
- `fast`: scripts are skipped for every block that lies on the best header chain strictly below its tip, so only the block at the tip executes scripts while catching up. Blocks on competing branches always run scripts. This trusts the most-work header chain and is independent of `--fast-sync`.

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --validation-mode full
```

## Validation engine

`--validation-engine` (also `BITCOIN_RS_VALIDATION_ENGINE` or `validation_engine` in TOML) selects which script-verification engine validation runs on. The setting is resolved once at startup and passed to every script-verification seam; `--validation-mode` above is a separate policy and is unchanged. Layers run in the documented precedence — defaults, then config file, then environment, then CLI — so an operator override at any of them wins over the layer below.

- `native` (default): the native Rust interpreter. It is compiled in every build.
- `kernel`: Bitcoin Core's C++ engine (`libbitcoinkernel`). Requires a build with `--features kernel` (plus `cmake` and `libboost-dev`). The feature compiles kernel support in; the setting selects it.

Setting `kernel` on a build without the `kernel` feature fails at startup with an unsupported-build error — ``validation engine `kernel` is not supported by this build: bitcoinkernel support is not compiled in (enable the `kernel` feature)`` — before chain state opens or workers start. There is no silent engine substitution.

```sh
cargo build --release -p bitcoin-rs --features kernel
./target/release/bitcoin-rs --data-dir .bitcoin-rs --validation-engine kernel
```

Direct `bitcoin-rs-consensus` library callers have no config file, environment, or CLI to set: `kernel::BlockParse::parse(raw, engine)`, `kernel::verify_tx_scripts(tx, spent, flags, engine)`, and `verify_transaction(..., engine)` take a `bitcoin_rs_consensus::ValidationEngine` value at each call. A binary embedder that wants one setting should resolve `ValidationEngine` itself and pass it down exactly as `bitcoin-rs-node` does.

## Operator migration: validation engine

- No change for `bin/bitcoin-rs` users who never set an engine: the binary's default was already kernel-free and remains `native`. Direct library users take the next bullet instead.
- `crates/consensus`, `crates/chainstate`, and `crates/node` library builds changed behavior: their defaults used to compile **and implicitly select** `kernel`, and now compile nothing kernel-related and default to `native`. A library user who relied on the old kernel default must both enable the `kernel` feature and select `validation_engine = "kernel"` (binary config, env, or CLI) — or, for a direct `bitcoin-rs-consensus` caller, pass `ValidationEngine::Kernel` to the verify/parse entries described above.
- To use bitcoinkernel, do both: build with `--features kernel` and set `validation_engine = "kernel"` (TOML), `BITCOIN_RS_VALIDATION_ENGINE=kernel` (env), or `--validation-engine kernel` (CLI).
- Setting `kernel` without the feature fails at startup with the unsupported-build error above.
- Bare `bitcoin-rs` runs native. The shipped Docker image compiles kernel support (`--features fjall,kernel`) and selects `kernel` at the **config-file** layer (`/etc/bitcoin-rs/default.toml`), so bare `docker run` keeps today's kernel behavior while `BITCOIN_RS_VALIDATION_ENGINE=native` or a config file mounted over that one still override it without touching CMD. A CLI override (`--validation-engine`) replaces CMD wholesale under docker semantics — `docker run IMAGE args` runs `bitcoin-rs args` — so going that route means repeating the whole argument list (`--config --data-dir --rpc-bind --p2p-listen` included).
- `--validation-mode` / `validation_mode` (Full/AssumeValid/Fast) is the separate script-skip policy and is unchanged.

## More

- [README.md](README.md): documentation index and release gates
- [contracts/](contracts/): normative contracts
- [../CONTRIBUTING.md](../CONTRIBUTING.md): development workflow
