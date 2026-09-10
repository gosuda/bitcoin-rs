# bitcoin-rs

**Go deeper into Bitcoin. Build in Rust.**

A modular Bitcoin full-node project for Rust developers. Explore node internals,
evaluate typed in-process access, or work with wallet-free public interfaces.
Start with a local test node and follow the component that interests you.

[Try regtest locally](docs/getting-started.md#esplora) ·
[Explore the architecture](docs/contracts/architecture.md) ·
[Read the evidence](docs/benchmarks/end-to-end-sync.md)

This is `gosuda/bitcoin-rs`, a separate project from
[`rust-bitcoin/rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin).

The default binary runs the native script interpreter without
`libbitcoinkernel`. Enable `--features kernel` to use that independent oracle.
The consensus and node library crates retain different defaults, governed by the
[validation-default contract](docs/contracts/validation-default.md). Other
dependencies can still require native build tools; see
[build prerequisites](CONTRIBUTING.md#prerequisites).

[![CI](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

## Why bitcoin-rs

**Explore Bitcoin, one module at a time.** The workspace separates protocol
types, script checks, storage, networking, indexes, and node assembly. The
[architecture contract](docs/contracts/architecture.md) defines the dependency
boundaries and records extraction work that remains. A crate boundary is not a
promise of a stable standalone API or an isolated plugin runtime.

**Connect a Rust application through typed node access.** The
[`Node` API](docs/contracts/embedding.md) exposes lifecycle operations, snapshots,
and capabilities without serializing those calls through JSON-RPC. Startup and
shutdown still drive synchronous work despite their async signatures.

**Keep wallet keys outside the node.** Explore public Esplora routes and
wallet-free JSON-RPC. The [wallet-facing contract](docs/contracts/wallet-facing.md)
and [RPC reference](docs/rpc-reference.md) describe the available operations,
index requirements, and compatibility limits. A familiar HTTP dialect is not
proof that every wallet or external client version works.

Bitcoin consensus is the compatibility target. Architectural experiments need
independent tests and reproducible evidence; neither a new implementation nor a
passing bounded test establishes exhaustive equivalence. This introduction does
not claim production readiness, an independent security audit, or a current
speed advantage over Bitcoin Core.

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
  so a default binary build excludes the kernel. Issue #213 keeps that split until
  native wins the signed-spend and full-replay gates
  (`docs/contracts/validation-default.md`).
- Pure-Rust storage defaults: LSM-tree storage backed by `fjall` by default,
  with `redb` compiled in, and `rocksdb`/`mdbx` available through optional Cargo
  features.
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

For a bounded first evaluation, use the [regtest setup](docs/getting-started.md#esplora).
The commands below instead start mainnet with the kernel-free default binary:

```sh
cargo build --locked --profile quickstart -p bitcoin-rs
./target/quickstart/bitcoin-rs --data-dir .bitcoin-rs
```

The `quickstart` profile drops LTO and raises codegen-units for exploration.
For sustained IBD or benchmarking, use `cargo build --release` instead. Build
time and runtime comparisons require measurements on the selected platform.

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

<a id="measured-performance"></a>

## Historical performance

These are historical candidate measurements, not evidence for the current
implementation. The benchmark owner records the end-state comparison cells as
`planned_not_executed`; those cells must not be presented as passed.

The bounded disk-backed campaign is documented in
[docs/benchmarks/end-to-end-sync.md](docs/benchmarks/end-to-end-sync.md) (commit
`de8001e`, mainnet blocks 0 to 150,000, full validation with
`--assume-valid-height 0`, CPU set 0–31 on Intel Xeon Gold 6138):

| Workload | bitcoin-rs median | Bitcoin Core 31.1 median | Ratio |
|---|---:|---:|---:|
| Full-validation local replay | 39.25s | 64.92s | 1.654x |
| Whole benchmark process wall | 42.03s | 67.02s | 1.595x |
| Bounded single-peer daemon IBD | 89.58s | 73.46s | 0.820x |

These measurements reflect a bounded 0–150,000 historical block range before
SegWit and Taproot activation. Full-tip live network sync measurements remain
pending fresh benchmarking runs. These results do not establish a current
speed advantage over Bitcoin Core. See
[docs/benchmarks/end-to-end-sync.md](docs/benchmarks/end-to-end-sync.md) for full
methodology, hardware constraints, and artifact custody.

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
  configured at startup (`fjall`, `redb`, `rocksdb`, or `mdbx`).
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
