<p align="center">
  <img src="logo.png" alt="bitcoin-rs logo" width="320">
</p>

# bitcoin-rs

**Build on Bitcoin. Inside Rust.**

[Getting started](docs/getting-started.md) ·
[Documentation](docs/README.md) ·
[Compatibility matrix](docs/api/ecosystem-compat.toml) ·
[Contributing](CONTRIBUTING.md) ·
[Benchmarks and limitations](docs/benchmarks/end-to-end-sync.md)

---

## What is this

`bitcoin-rs` is an independent Bitcoin full-node daemon and embeddable Rust workspace. Developers run a node from source or attach typed components directly to node state, with Core-compatible P2P, JSON-RPC, REST, ZMQ, and Esplora HTTP on the outside.

Unlike the `rust-bitcoin` library crates it builds on, `bitcoin-rs` owns chainstate, storage, sync, mempool, mining templates, and servers.

- **Embeddable core**. `bitcoin_rs_node::Node` boots the daemon's service graph in-process (`start`, `snapshot`, `broadcast`, `shutdown`) ([embedding](docs/contracts/embedding.md)).
- **Owned indexes**. `txindex`, `blockfilterindex`, and `scriptindex` power Esplora `/api` plus key-free descriptor and PSBT helpers; keys stay outside the node ([wallet surface](docs/contracts/wallet-facing.md)).
- **Selectable verification**. Native Rust interpreter by default; `libbitcoinkernel` via `--features kernel` plus `--validation-engine kernel`.
- **Checked compatibility**. External behavior verified against Bitcoin Core 31.1, vectors, and differentials ([validation](docs/validation-tooling.md)); no parity, production, or mainnet claims ([limits](#compatibility-and-limitations)).

Licensed [Apache-2.0](LICENSE); Rust 2024 edition, MSRV `1.99.0`.

```sh
curl -s --user "$(cat .bitcoin-rs-regtest/.cookie)" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:18443/
# {"jsonrpc":"2.0","result":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206","id":"1"}

curl -s http://127.0.0.1:18443/api/blocks/tip/height
# 0
```

Contents: [Install](#install) · [Quick start](#quick-start) · [Why an independent architecture](#why-an-independent-architecture) · [Architecture](#architecture) · [Compatibility and limitations](#compatibility-and-limitations) · [Development](#development) · [License](#license)

---

## Install

`bitcoin-rs` is built from source. No GitHub Release binary is published, so source checkout is the path below.

### Prerequisites

| Requirement | Details |
| --- | --- |
| Rust toolchain | `stable` with Rust 2024 edition support and workspace MSRV `1.99.0` ([`rust-toolchain.toml`](rust-toolchain.toml), [source compatibility policy](docs/policies/source-compatibility.md)) |
| Default build (`fjall`, `redb`, `zmq`) | C and C++ compilers plus `ar` (`build-essential` on Debian/Ubuntu); ZeroMQ is compiled from bundled sources, so no system ZeroMQ headers, `pkg-config`, `cmake`, or `libsodium` are needed |
| Minimal lane (`--no-default-features --features fjall`) | Drops the bundled-ZeroMQ C++ build; a C compiler is still required for vendored secp256k1 and mimalloc |
| Optional `--features kernel` | `cmake`, `libboost-dev`, and a C++ compiler for `libbitcoinkernel` |
| Optional `--features rocksdb` | `clang` and `libclang-dev` |

### Build from source

Clone the repository and compile the `bitcoin-rs` binary:

```sh
git clone https://github.com/gosuda/bitcoin-rs.git
cd bitcoin-rs

# Local exploration profile (inherits release, disables fat LTO, raises codegen-units)
cargo build --locked --profile quickstart -p bitcoin-rs

# Or minimal native build without the ZeroMQ C library
cargo build --locked --profile quickstart -p bitcoin-rs --no-default-features --features fjall
```

For sustained synchronization or benchmarking, compile with `--release` (`cargo build --locked --release -p bitcoin-rs`) and record the exact profile and feature flags with any measurement. See [Getting started](docs/getting-started.md) for Docker and optional `kernel` build lanes.

---

## Quick start

Start a local `regtest` node bound to loopback first. The bare `bitcoin-rs` command defaults to `mainnet` (`127.0.0.1:8332`, `0.0.0.0:8333`, data directory `.bitcoin-rs`); passing `--network regtest`, `--p2p-listen 127.0.0.1:18444`, and `--dns-seeds-enabled=false` keeps the first run isolated without dialing public peers.

### 1. Start a local regtest node

```sh
./target/quickstart/bitcoin-rs \
  --network regtest \
  --data-dir .bitcoin-rs-regtest \
  --p2p-listen 127.0.0.1:18444 \
  --dns-seeds-enabled=false \
  --rpc-bind 127.0.0.1:18443 \
  --scriptindex=utxo &
NODE_PID=$!
```

On startup, `bitcoin-rs` initializes the regtest genesis block, writes a fresh per-start Basic-auth cookie (`__cookie__:<random>`) to `.bitcoin-rs-regtest/.cookie` (mode `0600` on Unix), and binds the HTTP listener on `127.0.0.1:18443`.

### 2. Query JSON-RPC and Esplora HTTP

```sh
curl -s --user "$(cat .bitcoin-rs-regtest/.cookie)" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"getblockcount","params":[]}' \
  http://127.0.0.1:18443/
# {"jsonrpc":"2.0","result":0,"id":"1"}

curl -s http://127.0.0.1:18443/api/blocks/tip/hash
# 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
```

### 3. Stop the node cleanly

Lifecycle control is handled by process signals (`SIGINT` or `SIGTERM`), not a `stop` JSON-RPC method (`stop` is unimplemented over RPC):

```sh
kill -INT "$NODE_PID"
wait "$NODE_PID"
```

### Mainnet, assume-valid, and kernel verification

Running `./target/release/bitcoin-rs --data-dir .bitcoin-rs` without `--network` starts on `mainnet` using `fjall` storage, native Rust script verification, BIP324 v2 P2P transport, and loopback JSON-RPC on `127.0.0.1:8332`. Mainnet defaults to `--validation-mode assume-valid`, skipping historical script execution through the pinned assume-valid anchor (`938343`) while the active chain contains that anchor; pass `--validation-mode full` or `--assume-valid-height 0` to verify every script from genesis.

Consult [docs/getting-started.md](docs/getting-started.md) for layered configuration precedence (defaults, `--config` TOML, `--bitcoin-conf`, `BITCOIN_RS_*` environment variables, and CLI flags), storage backends (`fjall`, `redb`, `rocksdb`), pruning, REST (`--rest=true`), ZMQ, and optional `--features kernel` / `--validation-engine kernel` builds.

---

## Why an independent architecture

[Bitcoin Core](https://github.com/bitcoin/bitcoin) is the reference implementation of Bitcoin, and its conservatism and compatibility discipline are central to network stability. Those same priorities make large internal redesigns costly to explore inside one codebase.

`bitcoin-rs` tests what a Bitcoin full node looks like when designed from scratch in Rust around explicit ownership boundaries:

- **Consensus and wire compatibility at the boundary, replaceable internals.** External protocol behavior is checked against Bitcoin Core, `libbitcoinkernel`, test vectors, and external consumers, while internal data structures, concurrency, and storage engines remain free to evolve ([ecosystem compatibility contract](docs/contracts/ecosystem-compatibility.md)).
- **Canonical coin state and integrated indexing.** Instead of requiring separate Electrum or explorer indexers to duplicate chain state for common queries, the node owns the UTXO set and optional `txindex`, `blockfilterindex`, and `scriptindex` (`utxo` or `full`) consumers with explicit readiness gating ([indexing contract](docs/contracts/indexing.md)).
- **In-process composition without an async runtime mandate.** Core services run on a synchronous crossbeam event loop and bounded worker threads. Embedders call `bitcoin_rs_node::Node` from their own executor without the node spawning a private Tokio runtime ([embedding contract](docs/contracts/embedding.md)).

---

## Architecture

The workspace is a five-layer, one-way dependency graph: `bin/bitcoin-rs` and `crates/node` compose the runtime; `crates/rpc` owns the external protocols; `chain`, `chainstate`, `utxo`, `p2p`, `mempool`, `index`, and `mining` own domain state; `crates/storage` confines every storage engine (`fjall`, `redb`, `rocksdb`); `primitives`, `script`, and `consensus` stay free of I/O. The daemon and `Node::start` share one lifecycle, and `libbitcoinkernel` FFI stays behind the optional `kernel` feature. Details live in the [architecture contract](docs/contracts/architecture.md) and [embedding contract](docs/contracts/embedding.md).

---

## Compatibility and limitations

External interoperability is tracked per surface in [`docs/api/ecosystem-compat.toml`](docs/api/ecosystem-compat.toml) ([contract](docs/contracts/ecosystem-compatibility.md)); per-method RPC status in [`docs/rpc-reference.md`](docs/rpc-reference.md); evidence lanes in [`docs/validation-tooling.md`](docs/validation-tooling.md).

Externally verified on regtest against unmodified Bitcoin Core 31.1: P2P v1 wire, BIP152 compact blocks, BIP324 v2 transport, and BIP157/158 filters. Proactive block announcements still await a retained qualification run. JSON-RPC, REST, ZMQ, Esplora, and mining templates are implemented with in-tree suites. BIP352 Silent Payments and the Stratum V2 adapter are experimental. Wallet RPCs and Core IPC are intentionally unsupported; `stop` is unimplemented over RPC ([rpc-reference](docs/rpc-reference.md)), so shutdown uses process signals.

No claim is made of full Core parity, production safety, or mainnet qualification. [Synchronization evidence](docs/benchmarks/end-to-end-sync.md) owns all benchmark methodology; its target end-state cells are `planned_not_executed`, so quote no speed comparison from historical runs.

Maps: [docs index](docs/README.md), [contracts](docs/contracts/README.md), [BIP support](docs/bip-support.md), [concepts](CONCEPTS.md).

---

## Development

[`scripts/ci-pr.sh`](scripts/ci-pr.sh) is the canonical local and CI gate runner ([`CONTRIBUTING.md`](CONTRIBUTING.md)):

```sh
# Format, dependency policy, lint, and fast per-crate tests (PR gate)
./scripts/ci-pr.sh fmt
./scripts/ci-pr.sh deny
./scripts/ci-pr.sh clippy
./scripts/ci-pr.sh test-crates

# Or run individual workspace Cargo commands (kernel-free by default)
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Heavy binary and workspace test lanes (`./scripts/ci-pr.sh test-binary` and `./scripts/ci-pr.sh test-workspace`) first provision pinned Bitcoin Core reference fixtures via `bash scripts/provision-ci-reference-fixtures.sh core`.

Contributions, bug reports, and opt-in BIP prototypes are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for commit conventions, merge-queue requirements, crate-layer rules, and how to [propose and implement BIPs](CONTRIBUTING.md#proposing-and-implementing-bips).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
