# Getting started

From a clone to a syncing node. Each step explains what you should see so you can
verify progress before moving on.

## Prerequisites

- A Rust toolchain for edition 2024, pinned to 1.95.0 by `rust-toolchain.toml`.
  Run `rustc --version` and `cargo --version` first; a different toolchain is
  not a supported build.
- No C++ compiler or system libraries for the default binary. The default and
  minimal builds are pure Rust. Validation uses the native script interpreter
  with strict-Rust cryptography for legacy, P2SH, SegWit v0, and Taproot
  key-path and script-path spends. There is no C fallback on the validation
  path.

If you plan to compile the `kernel` oracle lane, install `cmake` and
`libboost-dev`:

```sh
# Required only for the kernel oracle lane
sudo apt-get install -y cmake libboost-dev
```

## Step 1: build a lane

There are four build lanes. Pick one on purpose; they are proven separately and
are not interchangeable evidence for each other.

| Lane | Command | Use it for |
| --- | --- | --- |
| Default full node | `cargo build --locked --release -p bitcoin-rs` | Normal operation. Features `fjall`, `redb`, and `zmq`; no kernel |
| Minimal native | `cargo build --locked --release -p bitcoin-rs --no-default-features --features fjall` | One backend, every optional extension off; the smallest supported node |
| Oracle | `CARGO_TARGET_DIR=target/oracle cargo build --locked --release -p bitcoin-rs --features kernel` | Differential evidence against `libbitcoinkernel`. Not a fallback, not a production default |
| Optional-on | `cargo build --locked --release -p bitcoin-rs --features bip324` | BIP324 v2 transport. Off by default; enabling it changes no validation result |

The oracle lane must resolve in its own `CARGO_TARGET_DIR`. A workspace build
that unifies `kernel` with the default features invalidates any kernel-free
claim about the resulting binary.

Each command produces `target/release/bitcoin-rs` (or
`target/oracle/release/bitcoin-rs` for the oracle lane). Alternative C++
storage backends (`rocksdb`, `mdbx`) remain non-default Cargo features for
comparison work only.

## Step 2: understand configuration precedence

Configuration merges from five sources, lowest to highest:

1. built-in defaults;
2. the TOML file named by `--config`;
3. the Bitcoin Core-style file named by `--bitcoin-conf`;
4. environment variables with the `BITCOIN_RS_` prefix;
5. command-line flags.

A later source overrides only the fields it supplies; nested fields it omits
keep the earlier value. The `bitcoin.conf` network section (`[main]`, `[test]`,
`[testnet4]`, `[signet]`, `[regtest]`) is selected from the network resolved
through TOML, environment, and CLI, so a CLI `--network` decides which section
applies before that section is read.

Validation happens after the merge. A mining payout address that does not match
the resolved network is rejected at startup, whichever source supplied it.
Runtime and test controls (fault injection, test clocks) are not public
configuration and cannot be set from any of these sources.

Accepted network spellings: `main`, `mainnet`, `bitcoin`, `test`, `testnet`,
`testnet3`, `testnet4`, `signet`, `regtest`, `drynet4`. Supported deployments
are mainnet, signet, testnet4, and regtest; testnet3 is accepted only where the
compatibility contract explicitly retains it.

## Step 3: choose a storage backend

`fjall` is the default and the recorded production backend. `redb` is compiled
into the default lane. Select with `--storage-backend`:

```sh
./target/release/bitcoin-rs --storage-backend redb
```

or through the environment:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

## Step 4: start the node

Start the node on mainnet:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Configuration defaults:

| Flag | Default |
|---|---|
| `--data-dir` | `.bitcoin-rs` |
| `--network` | `mainnet` |
| `--storage-backend` | `fjall` |
| `--rpc-bind` | `127.0.0.1:8332` on mainnet, the network's Core port otherwise |
| `--rest` | off (enables unauthenticated Core-compatible REST routes on the RPC port) |
| `--rpc-user` / `--rpc-password` | `bitcoin-rs` / `bitcoin-rs` |
| `--rpc-cookie` | unset (Core-style cookie file instead of user and password) |
| `--dbcache-mb` | 450 |
| `--prune-target-mb` | 0 (no pruning) |
| `--txindex` | off |
| `--scriptindex` | off (accepts `full`, `utxo`, or boolean; `full` when passed without a value) |
| `--p2p-listen`, `--connect`, `--dns-seeds-enabled` | network defaults; `--connect` limits outbound peers to the listed endpoints |
| `--metrics-bind` | unset (Prometheus listener off) |
| `--mining-payout-address` | unset (GBT templates carry no payout script) |
| `--assume-valid-height` | the hash-pinned mainnet anchor; `0` verifies every script |

The node logs its startup banner, the resolved configuration, the effective
cache allocation, and the address the JSON-RPC listener bound to.

`--txindex` is the explicit Core `txindex` promise. `--scriptindex=full` builds
the live script view and the confirmed funding and spending history behind the
Esplora address and scripthash routes. `--scriptindex=utxo` builds only the live
view: current UTXO routes answer once that view is `Ready`; history, statistics,
pagination, and confirmed outspend routes report the capability as disabled.
`--rest` enables the unauthenticated Core REST gateway on the RPC port.

Change the RPC credentials before exposing the port anywhere. The defaults are
a development convenience, not a secret.

## Step 5: keep the datadir fresh

The datadir carries a schema marker, `CURRENT_SCHEMA`, that covers the
authoritative chainstate bytes. A binary whose `CURRENT_SCHEMA` differs from
the marker refuses to open the datadir with `incompatible_schema` and stops.
There is no converter, no in-place migration, and no reader for an older
layout. To move to a new schema, start the new binary against an explicitly
named fresh datadir and let it sync from the network; leave the old datadir in
place until you choose to remove it. The node never rewrites, opens, or
deletes an incompatible datadir on its own.

Estimator, peer-discovery, and index files carry their own version fields. A
corrupt or unknown owner-local file never stops the node: fee estimation
reports insufficient data, discovery reseeds, and the affected index
capability reports `Rebuilding` or `Disabled` and rebuilds from the chain. The
rejected file is left in place until you rebuild it deliberately.

The full rule set is in [policies/db-migration.md](policies/db-migration.md).

## Step 6: check sync progress

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
(`combinepsbt`, `finalizepsbt`), descriptor helpers (`getdescriptorinfo`,
`deriveaddresses`), and `scantxoutset` remain for external signers.

## Step 7: read the status vocabulary

Every status surface (RPC `getindexinfo`, REST, Esplora, metrics) reports each
optional capability (`TxLookup`, `ScriptLive`, `ScriptHistory`) with one shared
state and one runtime revision:

| State | Meaning | What to do |
| --- | --- | --- |
| `Disabled` | Not configured | Enable the flag if you need the routes |
| `Opening` | Durable metadata is being inspected after start | Wait |
| `CatchingUp` | Backfilling toward the active tip | Wait; routes report unavailable, not empty |
| `Ready` | Watermark equals the active tip by height and hash | Queries answer |
| `RollingBack` | Reversing blocks after a reorg | Wait |
| `Rebuilding` | Reset and rebuild of that capability only | Wait; chain sync is unaffected |
| `Failed` | Worker stopped on an error | Read the log; chain validation continues |
| `Shutdown` | Node is stopping | None |

A capability that is not `Ready` at the queried tip returns a typed unavailable
or retry result. It never returns an empty successful answer. Readiness of a
confirmed index does not make a mixed confirmed-and-mempool response coherent;
those additionally require a stable chain generation.

## Step 8: connect consumers

### Esplora

Point any Esplora client at `/api` on the JSON-RPC listener. `--scriptindex`
must be on, or address and scripthash routes report the capability as
disabled.

[bitcoin-wallet](https://github.com/gosuda/bitcoin-wallet) (`btcw`) is the
named external consumer. Start the node in one terminal:

```sh
./target/release/bitcoin-rs \
  --network regtest \
  --scriptindex \
  --data-dir .bitcoin-rs-regtest \
  --rpc-bind 127.0.0.1:18443
```

Then run the wallet in a second terminal:

```sh
btcw balance -n regtest -u http://127.0.0.1:18443/api
```

`/api` is the public Esplora surface. `/esplora` is the versioned superset the
unmodified `mempool/mempool` backend consumes (`/internal/txs`,
`/internal/mempool/txs`, `/internal/block/{hash}/txs`, batched outspends,
address summaries). `/api/v1` is Mempool's own API on the explorer port, not a
route on this node. Both dialects project the same node state; neither is a
separate database or node mode. The wallet keeps its keys; the node serves
only the surface in [contracts/wallet-facing.md](contracts/wallet-facing.md).

### REST

`--rest` (or `rest=1` in `bitcoin.conf`) serves the Core REST routes on the
RPC port without authentication. See [rest-interface.md](rest-interface.md).

### ZMQ

The default lane publishes the Core-compatible `pubsequence` topic when a ZMQ
endpoint group is configured as a `[[notifications.zmq]]` table (with
`endpoint`, `topics`, and optional `hwm`) in the TOML file; the configured
endpoint is reported by `getzmqnotifications`. Block connect (`C`) and
disconnect (`D`) events and mempool admission (`A`) and removal (`R`) events
carry the mempool sequence assigned to the change.

## Measuring storage

`--measure-storage` measures the datadir ledgers and exits without starting
the node:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --measure-storage \
  --measure-storage-output footprint.json \
  --measure-storage-stop-height <height> \
  --measure-storage-stop-hash <hash> \
  --storage-high-water-bytes <bytes>
```

The output separates the logical owner ledger (serialized bytes per column
family) from the physical namespace ledger (allocated filesystem blocks). Only
the physical ledger counts against the 1 TB default full-tip budget, and only a
conservative high-water from an isolated filesystem or project quota
(`--storage-high-water-bytes`) can prove the peak; a plain snapshot is a lower
bound. The record format and pairing rules are in
[contracts/storage-footprint.md](contracts/storage-footprint.md).

## Verifying everything yourself

Mainnet skips historical script checks below the pinned assume-valid anchor.
To verify every script from genesis:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --assume-valid-height 0
```

This runs full script execution on every transaction from block 0. It is the
recommended mode for benchmarking and independent consensus audits.

## Next

- [../README.md](../README.md) for the architecture overview and benchmark records
- [../CONTRIBUTING.md](../CONTRIBUTING.md) for development workflows and testing
- [README.md](README.md) for the documentation index, lanes, and release gates
- [contracts/](contracts/) for normative architecture and protocol contracts
