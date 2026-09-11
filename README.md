# bitcoin-rs

## Build on Bitcoin. Inside Rust.

A Bitcoin full-node project for developers exploring typed Rust integration,
node-owned indexing, and familiar Bitcoin interfaces.

**Run locally. Inspect the contracts. Share one reproducible result.**

[Getting started](docs/getting-started.md) ·
[Documentation](docs/README.md) ·
[Contributing](CONTRIBUTING.md) ·
[Benchmarks and limitations](docs/benchmarks/end-to-end-sync.md)

Start with local developer evaluation, not production migration. A successful
startup or RPC response is not a consensus-equivalence, recovery, or security
certification. Use disposable test data and never publish credentials or
identifying wallet queries.

[![CI](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

## Why evaluate bitcoin-rs?

- **Typed Rust integration.** Explore the async `Node` embedding API for
  in-process integrations alongside the HTTP JSON-RPC path.
- **Node-owned indexing.** Evaluate integrated ScriptIndex and Esplora APIs
  without a separate indexer process. Indexes are optional; check configuration
  and capability readiness before relying on a query. Wallet keys, policies,
  and metadata remain outside the node.
- **Explicit build lanes.** The default binary enables `fjall`, `redb`, and
  `zmq`, but excludes `libbitcoinkernel`. Consensus/node library defaults and
  the Compose image differ. The
  [validation-default contract](docs/contracts/validation-default.md) owns that
  split; a kernel-free binary is not a blanket claim about native dependencies
  across all build configurations.

The project explores alternative full-node architecture and AI-assisted
engineering. Bitcoin Core, consensus vectors, and differential tests provide
independent references; a different implementation or development process does
not remove the obligation to demonstrate correctness. Inspect the
[constraint register](CONSTRAINTS.md) and distinguish implemented behavior,
required evidence, and measured results.

## Features

- Consensus validation: the native Rust interpreter verifies Legacy, SegWit v0,
  and Taproot key-path and script-path spends. Core's committed `script_tests`,
  `tx_valid`, and `tx_invalid` vectors pin zero native mismatches. Script checks
  run in parallel across rayon workers with sighash midstate reuse per
  transaction. `--features kernel` routes the same checks through
  `libbitcoinkernel` (Bitcoin Core's C++ engine) as an independent oracle.
- Kernel feature: `--features kernel` enables `libbitcoinkernel`. The
  `crates/consensus` and `crates/node` library crates still default to `kernel`;
  the `bin/bitcoin-rs` binary defaults to `["fjall", "redb", "zmq"]` (no kernel)
  and does not link `libbitcoinkernel`. Issue #213 keeps that split until
  native wins the signed-spend and full-replay gates; see the
  [validation-default contract](docs/contracts/validation-default.md).
- Pure-Rust storage defaults: LSM-tree storage backed by `fjall` by default,
  with `redb` compiled in and `rocksdb` available through an optional Cargo
  feature.
- Sharded UTXO cache: a 256-shard in-memory UTXO set (`hashbrown::HashTable` of
  compact records behind `parking_lot::RwLock`) with checkpoint-based crash
  recovery and effective `--dbcache-mb` budget allocation.
- Asynchronous index consumer: `txindex` reconciles over a monotonic chain
  snapshot and event hint channel without blocking block validation.
- Integrated ScriptIndex and Esplora APIs: address and scripthash UTXO indexing
  and confirmed transaction history served directly over HTTP.
- Mempool mutation gateway: centralized mutation tracking publishing ordered
  accept and remove events over ZMQ `pubsequence`.
- Block template assembly: mining candidate generation via `getblocktemplate`.
- Core-compatible RPC and typed embedding: synchronous HTTP JSON-RPC using Core
  method names and wire formats (walletless, no private keys), plus a typed
  async `Node` embedding API for in-process Rust integrations.

## Quick start

Build and run the kernel-free default binary with the quick-start profile.
Consult [Getting started](docs/getting-started.md) for build lanes and
prerequisites before choosing features:

```sh
cargo build --profile quickstart -p bitcoin-rs
./target/quickstart/bitcoin-rs --data-dir .bitcoin-rs
```

Use the `quickstart` profile for initial exploration. For sustained IBD or
benchmarking, use `cargo build --release -p bitcoin-rs` and record the exact
profile and feature set with the result. No build-time ratio is claimed here.

This starts a mainnet node storing state in `.bitcoin-rs` and listening for
JSON-RPC on `127.0.0.1:8332`.

Verify the node is responding and syncing:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

### Kernel oracle build

To route script verification through `libbitcoinkernel` instead of the native
interpreter, install C++ dependencies (`cmake` and `libboost-dev` on
Debian/Ubuntu), then pass `--features kernel`:

```sh
cargo build --release -p bitcoin-rs --features kernel
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

## Benchmark status

[End-to-end synchronization evidence](docs/benchmarks/end-to-end-sync.md) is the
owner of methodology, measurements, artifact custody, and limitations. It
retains historical bounded results from superseded engines, including both
faster local replays and slower daemon IBD results. Those figures are not
current end-state proof or a general speed comparison with Bitcoin Core.

The owner's end-state cells are marked `planned_not_executed`. Historical raw
JSON was retired by #224; retained digests can identify an external copy, but
are not a replacement for the raw evidence. This README makes no current
performance-superiority claim. Consult the owner document for the status of
each workload before quoting a result.

## Architecture

```
Surfaces:      bin/bitcoin-rs, crates/rpc
Capabilities:  crates/index, crates/mining, crates/mempool
Node services: crates/node, crates/p2p, crates/storage
Core & domain: crates/consensus, crates/script, crates/utxo, crates/chain, crates/primitives
```

- Validation: script execution runs in parallel across rayon workers, with
  sighash midstate reuse per transaction. The native interpreter covers every
  consensus spend class. Under the `kernel` feature, `libbitcoinkernel` is the
  verifier instead.
- Kernel boundary: `crates/consensus/src/kernel.rs` contains all
  `libbitcoinkernel` types behind `#[cfg(feature = "kernel")]`. Kernel types
  never leak into node state or apply logic.
- Storage: `crates/storage` provides backend abstraction. The active engine is
  configured at startup (`fjall`, `redb`, or `rocksdb`).
- Indexing: `txindex` runs as an independent consumer, advancing its cursor and
  rollback metadata atomically.

## Default posture

| Setting | Default |
|---|---|
| Storage backend | `fjall` |
| Validation engine | Native Rust interpreter (default binary); `libbitcoinkernel` with `--features kernel` and as the consensus/node library default |
| Kernel feature | Off in default binary build; on in `crates/consensus` and `crates/node` library defaults |
| Database cache | 450 MiB (`--dbcache-mb`, split 80/20 when txindex is enabled) |
| Multi-peer download | On (8 outbound peers, 256-block window) |
| Transaction index | Off |
| Script index | Off |
| Pruning | Off |

Mainnet defaults to skipping historical script verification up to the pinned
assume-valid anchor. Pass `--assume-valid-height 0` to verify all scripts from
genesis.

## Build and test

```sh
# Build default binary (kernel-free)
cargo build --release -p bitcoin-rs

# Run workspace unit and integration tests
cargo test --workspace

# Lint all targets
cargo clippy --workspace --all-targets -- -D warnings
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for local
verification commands, CI workflows, and crate architecture conventions.

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — Node setup and configuration
- [docs/README.md](docs/README.md) — Documentation index
- [docs/contracts/](docs/contracts/) — Normative architecture and protocol contracts
- [CONCEPTS.md](CONCEPTS.md) — Domain terminology and concepts

- [CONTRIBUTING.md](CONTRIBUTING.md) — Development workflow and CI guidelines

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). See
[LICENSE](LICENSE) for full details.
