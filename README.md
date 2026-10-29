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

Contents: [Install](#install) · [Quick start](#quick-start) · [Why bitcoin-rs](#why-bitcoin-rs) · [Experimental BIP Adoption](#experimental-bip-adoption) · [Architecture](#architecture) · [Compatibility and limitations](#compatibility-and-limitations) · [Development](#development) · [License](#license)

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

## Why bitcoin-rs

Bitcoin Core's conservatism, stability, and compatibility discipline are major reasons for its success; those same safeguards make large architectural changes difficult to explore within that codebase. `bitcoin-rs` preserves Bitcoin's consensus while making architectural experimentation practical: build alternatives, verify them against reproducible evidence, and keep iterating on the implementation.

### Why now?

Bitcoin behavior can be checked against Bitcoin Core, `libbitcoinkernel`, historical chain data, consensus test vectors, fuzzing, and differential tests, which makes an independent implementation practical to verify.

### What can be improved

- **Performance is a first-class requirement.** Synchronization, storage, memory ownership, concurrency, caching, I/O, and indexing can all be reconsidered; improvements must be demonstrated with matched whole-node benchmarks against Core.
- **The UTXO set is the node's authoritative coin state.** The node owns the canonical UTXO set used for validation and an integrated script index exposed through Esplora-compatible APIs. Wallet-specific keys, policies, and metadata remain outside the node.
- **Modularity keeps the core isolated and components composable.** Clear dependency and failure boundaries keep extensions from destabilizing validation or chainstate while allowing components to be reused independently.
- **Rust-native integration is a primary path.** Applications and extensions attach to the node as typed, in-process components instead of routing through serialized RPC or separate processes.

---

## Experimental BIP Adoption

Experiments stay small, reversible, and opt-in: active mainnet consensus is unchanged, and unactivated consensus proposals are tested only on regtest or explicitly isolated test networks. Adoption is evaluated through reference vectors, external interoperability, and measured resource costs.

See the [BIP adoption policy](docs/policies/bip-adoption.md) for the research-to-shipped process, the [BIP support matrix](docs/bip-support.md) for current implementation status, and [contributing BIPs](CONTRIBUTING.md#proposing-and-implementing-bips) to propose an experiment.

---

## Architecture

The workspace is a five-layer, one-way dependency graph: `bin/bitcoin-rs` and `crates/node` compose the runtime; `crates/rpc` owns the external protocols; `chain`, `chainstate`, `utxo`, `p2p`, `mempool`, `index`, and `mining` own domain state; `crates/storage` confines every storage engine (`fjall`, `redb`, `rocksdb`); `primitives`, `script`, and `consensus` stay free of I/O. The daemon and `Node::start` share one lifecycle, and `libbitcoinkernel` FFI stays behind the optional `kernel` feature. Details live in the [architecture contract](docs/contracts/architecture.md) and [embedding contract](docs/contracts/embedding.md).

---

## Compatibility and limitations

External interoperability is tracked per surface in [`docs/api/ecosystem-compat.toml`](docs/api/ecosystem-compat.toml) ([contract](docs/contracts/ecosystem-compatibility.md)); per-method RPC status in [`docs/rpc-reference.md`](docs/rpc-reference.md); evidence lanes in [`docs/validation-tooling.md`](docs/validation-tooling.md).

Externally verified on regtest against unmodified Bitcoin Core 31.1: P2P v1 wire, BIP152 compact blocks, BIP324 v2 transport, and BIP157/158 filters. Proactive block announcements still await a retained qualification run. JSON-RPC, REST, ZMQ, Esplora, and mining templates are implemented with in-tree suites. BIP352 Silent Payments and the Stratum V2 adapter are experimental. Wallet RPCs and Core IPC are intentionally unsupported; `stop` is unimplemented over RPC ([rpc-reference](docs/rpc-reference.md)), so shutdown uses process signals.

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
