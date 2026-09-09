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

Alternative backends such as RocksDB and MDBX are non-default features used for comparison and testing.

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
| metrics listener | off |
| mining payout | unset |

Change the default RPC credentials before exposing the port.

`--txindex` is the explicit Core-compatible txindex promise. `--scriptindex=utxo` enables the live script view; `--scriptindex=full` also enables confirmed script history. `--rest=true` enables the unauthenticated Core REST routes on the RPC listener.

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

The target durable-root recovery model and its current evidence status are summarized in [chainstate-recovery.md](chainstate-recovery.md) and owned normatively by [contracts/recovery.md](contracts/recovery.md).

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

## Full script verification

To disable assume-valid script skipping:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --assume-valid-height 0
```

## More

- [README.md](README.md): documentation index and release gates
- [contracts/](contracts/): normative contracts
- [../CONTRIBUTING.md](../CONTRIBUTING.md): development workflow
